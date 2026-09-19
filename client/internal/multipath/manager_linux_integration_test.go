//go:build privileged

package multipath

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestManagerLifecycle exercises the real manager against the kernel: path
// interface creation, source routes, the ECMP route group, prober-driven
// failover, and full teardown. It must run as root, ideally inside a network
// namespace: sudo ip netns exec mptest go test -tags privileged ...
func TestManagerLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	const (
		mainIface   = "mpt0"
		dummy       = "mpd0"
		remoteDummy = "mpd1"
		remoteAddr  = "10.0.0.2"
		localAddr1  = "10.255.1.1"
		localAddr2  = "10.255.2.1"
		overlay     = "100.64.0.0/10"
	)

	originalHashPolicy := readHashPolicy(t)

	localKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	remoteKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	// Main overlay interface, configured like the engine leaves it.
	require.NoError(t, netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: mainIface, MTU: 1420}}))
	defer deleteLink(mainIface)
	mainLink, err := netlink.LinkByName(mainIface)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(mainLink))

	wg, err := wgctrl.New()
	require.NoError(t, err)
	defer wg.Close()
	require.NoError(t, wg.ConfigureDevice(mainIface, wgtypes.Config{
		PrivateKey:   &localKey,
		ReplacePeers: true,
	}))

	// Underlay dummy with the path addresses and a reachable remote address.
	require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dummy}}))
	defer deleteLink(dummy)
	dummyLink, err := netlink.LinkByName(dummy)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(dummyLink))
	for _, addr := range []string{localAddr1, localAddr2} {
		require.NoError(t, netlink.AddrAdd(dummyLink, &netlink.Addr{
			IPNet: &net.IPNet{IP: net.ParseIP(addr), Mask: net.CIDRMask(32, 32)},
		}))
	}

	// The remote address lives on its own interface so the route lookup finds
	// a unicast route rather than the loopback device.
	require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: remoteDummy}}))
	defer deleteLink(remoteDummy)
	remoteLink, err := netlink.LinkByName(remoteDummy)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(remoteLink))
	require.NoError(t, netlink.AddrAdd(remoteLink, &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP(remoteAddr), Mask: net.CIDRMask(32, 32)},
	}))

	cfg := Config{
		Enabled:        true,
		Mode:           "flow",
		MaxPaths:       2,
		LocalAddresses: []netip.Addr{netip.MustParseAddr(localAddr1), netip.MustParseAddr(localAddr2)},
		OverlayV4:      netip.MustParsePrefix(overlay),
		WgIface:        mainIface,
		PrivateKey:     localKey,
		MTU:            1420,
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, manager)

	peerKey := remoteKey.PublicKey().String()
	paths, err := manager.LocalPaths(peerKey)
	require.NoError(t, err)
	require.Len(t, paths, 1, "one extra path is configured")
	assert.Equal(t, netip.MustParseAddr(localAddr1), paths[0].Addr)
	assert.NotZero(t, paths[0].Port)
	assert.NotZero(t, paths[0].ProbePort)

	pathIface := pathIfaceName(peerKey, 1)
	requireLinkExists(t, pathIface)

	// Remote prober: echoes our probes and sends its own.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remoteConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(remoteAddr), Port: 0})
	require.NoError(t, err)
	remoteProbePort, err := udpPort(remoteConn)
	require.NoError(t, err)
	remoteProber := newProber(log.NewEntry(log.StandardLogger()), remoteConn, ctx)
	defer remoteProber.stop()

	allowed := []netip.Prefix{
		netip.MustParsePrefix("100.64.1.1/32"),
		netip.MustParsePrefix("192.168.50.0/24"),
	}
	require.NoError(t, manager.Configure(peerKey, []PathEndpoint{{
		Addr:      netip.MustParseAddr(remoteAddr),
		Port:      51899,
		ProbePort: remoteProbePort,
	}}, allowed))

	// Source route forces the outer flow to use the path's local address.
	srcRoute := findRoute(t, netip.MustParsePrefix(remoteAddr+"/32"))
	require.NotNil(t, srcRoute, "source route for the remote underlay address is missing")
	assert.Equal(t, net.ParseIP(localAddr1).To4(), srcRoute.Src.To4())

	remoteProber.start(paths[0].Addr, paths[0].ProbePort, nil)

	// Probes succeed and promote the path into the route group.
	require.Eventually(t, func() bool {
		states := manager.PathStates(peerKey)
		return len(states) == 1 && states[0].State == PathStateUp && states[0].RTT > 0
	}, 10*time.Second, 100*time.Millisecond, "path must come up and report RTT")

	// ECMP group covers the peer overlay /32 through main and path interface.
	require.Eventually(t, func() bool {
		ecmp := findRoute(t, netip.MustParsePrefix("100.64.1.1/32"))
		return ecmp != nil && len(ecmp.MultiPath) == 2
	}, 5*time.Second, 100*time.Millisecond, "ECMP route for the overlay address must be installed")
	assert.Equal(t, 1, readHashPolicy(t))

	// The routed /24 must not get a route group.
	assert.Nil(t, findRoute(t, netip.MustParsePrefix("192.168.50.0/24")))

	// Stop the remote echo: the path is demoted and the route group removed.
	remoteProber.stop()
	demoted := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		states := manager.PathStates(peerKey)
		if len(states) == 1 {
			t.Logf("path state=%s rtt=%v loss=%v", states[0].State, states[0].RTT, states[0].Loss)
			if states[0].State == PathStateDown {
				demoted = true
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.True(t, demoted, "path must be demoted after probe loss")
	assert.Nil(t, findRoute(t, netip.MustParsePrefix("100.64.1.1/32")), "route group must be removed when the only path is down")

	// A new remote echo brings it back.
	remoteConn2, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(remoteAddr), Port: 0})
	require.NoError(t, err)
	remoteProbePort2, err := udpPort(remoteConn2)
	require.NoError(t, err)
	remoteProber2 := newProber(log.NewEntry(log.StandardLogger()), remoteConn2, ctx)
	defer remoteProber2.stop()
	remoteProber2.start(paths[0].Addr, paths[0].ProbePort, nil)

	// The remote probe port changed; reconfigure so the prober targets it.
	require.NoError(t, manager.Configure(peerKey, []PathEndpoint{{
		Addr:      netip.MustParseAddr(remoteAddr),
		Port:      51899,
		ProbePort: remoteProbePort2,
	}}, allowed))

	require.Eventually(t, func() bool {
		states := manager.PathStates(peerKey)
		return len(states) == 1 && states[0].State == PathStateUp
	}, 10*time.Second, 100*time.Millisecond, "path must recover when probes return")
	require.Eventually(t, func() bool {
		route := findRoute(t, netip.MustParsePrefix("100.64.1.1/32"))
		return route != nil && len(route.MultiPath) == 2
	}, 5*time.Second, 100*time.Millisecond, "route group must be restored on recovery")

	// RemovePeer tears everything down.
	manager.RemovePeer(peerKey)
	requireLinkGone(t, pathIface)
	assert.Nil(t, findRoute(t, netip.MustParsePrefix(remoteAddr+"/32")), "source route must be removed")
	assert.Nil(t, findRoute(t, netip.MustParsePrefix("100.64.1.1/32")), "route group must be removed")

	require.NoError(t, manager.Close())
	assert.Equal(t, originalHashPolicy, readHashPolicy(t), "hash policy must be restored")
}

func findRoute(t *testing.T, prefix netip.Prefix) *netlink.Route {
	t.Helper()
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	require.NoError(t, err)
	for i := range routes {
		r := routes[i]
		if r.Dst == nil {
			continue
		}
		if r.Dst.String() == prefix.String() {
			return &routes[i]
		}
	}
	return nil
}

func requireLinkExists(t *testing.T, name string) {
	t.Helper()
	_, err := netlink.LinkByName(name)
	require.NoError(t, err, "path interface %s must exist", name)
}

func requireLinkGone(t *testing.T, name string) {
	t.Helper()
	_, err := netlink.LinkByName(name)
	require.Error(t, err, "path interface %s must be removed", name)
}

func deleteLink(name string) {
	if link, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkDel(link)
	}
}

func readHashPolicy(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile(hashPolicyPath)
	require.NoError(t, err)
	value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	return value
}
