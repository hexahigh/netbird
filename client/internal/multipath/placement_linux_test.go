//go:build linux

package multipath

import (
	"errors"
	"net/netip"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeProbe struct {
	slaveList []string
	member    func(devIndex, port int) string
	measures  int
}

func (f *fakeProbe) slaves(netip.Addr) (string, []string) {
	return "bond0", f.slaveList
}

func (f *fakeProbe) measure(peer *peerPaths, devIndex int, _ []string) (string, error) {
	f.measures++
	port := 0
	for _, p := range peer.extras {
		if p.linkIndex == devIndex {
			port = int(p.port)
		}
	}
	return f.member(devIndex, port), nil
}

func newTestManager(mainIface int) *linuxManager {
	return &linuxManager{
		cfg:              Config{WgPort: 51820, MaxPaths: 2},
		log:              log.WithField("component", "multipath-test"),
		peers:            make(map[string]*peerPaths),
		mainIface:        mainIface,
		extraAddrs:       []netip.Addr{netip.MustParseAddr("10.10.0.11")},
		setDevicePort:    func(_ string, port int) (int, error) { return port, nil },
		routeCheck:       func(_, _ netip.Addr) error { return nil },
		portsChanged:     make(chan string, 4),
		placementPending: make(map[string]bool),
	}
}

func TestRemoteSignature(t *testing.T) {
	a := []PathEndpoint{{Addr: netip.MustParseAddr("10.10.0.21"), Port: 51821, ProbePort: 51822}}
	b := []PathEndpoint{{Addr: netip.MustParseAddr("10.10.0.21"), Port: 51821, ProbePort: 51822}}
	c := []PathEndpoint{{Addr: netip.MustParseAddr("10.10.0.22"), Port: 51821, ProbePort: 51822}}

	assert.Equal(t, remoteSignature(a), remoteSignature(b))
	assert.NotEqual(t, remoteSignature(a), remoteSignature(c))
}

func TestConfigureKeepsUnroutablePeerSinglePath(t *testing.T) {
	m := newTestManager(100)
	checks := 0
	m.routeCheck = func(_, _ netip.Addr) error {
		checks++
		return errors.New("no route")
	}
	peer := &peerPaths{
		key:        "peer-key",
		extras:     make(map[int]*pathState),
		overlayIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
	}
	m.peers[peer.key] = peer
	allowed := []netip.Prefix{netip.MustParsePrefix("100.64.1.1/32")}
	remote := []PathEndpoint{{Addr: netip.MustParseAddr("10.10.0.21"), Port: 51821, ProbePort: 51822}}

	require.NoError(t, m.Configure(peer.key, remote, allowed))
	assert.Equal(t, 1, checks)
	assert.Empty(t, peer.extras, "no path interfaces for an unreachable peer")
	assert.NotEmpty(t, peer.unreachableSig)

	// The same remote list must not recreate anything or retry the check.
	require.NoError(t, m.Configure(peer.key, remote, allowed))
	assert.Equal(t, 1, checks, "the unreachable decision is remembered")

	paths, err := m.LocalPaths(peer.key)
	require.NoError(t, err)
	assert.Empty(t, paths, "unreachable peers are not advertised")

	// A changed remote list is retried.
	remote2 := []PathEndpoint{{Addr: netip.MustParseAddr("10.10.0.22"), Port: 51821, ProbePort: 51822}}
	require.NoError(t, m.Configure(peer.key, remote2, allowed))
	assert.Equal(t, 2, checks)
}

func testPeer() (*peerPaths, *pathState) {
	p := &pathState{
		idx:       1,
		name:      "wtp-test1",
		linkIndex: 200,
		port:      51900,
		remote:    PathEndpoint{Addr: netip.MustParseAddr("10.10.0.21"), Port: 51901, ProbePort: 51902},
	}
	peer := &peerPaths{
		key:        "peer-key",
		extras:     map[int]*pathState{1: p},
		overlayIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
	}
	return peer, p
}

func TestPlacementMovesPathOffMainMember(t *testing.T) {
	const mainIface = 100
	m := newTestManager(mainIface)
	peer, p := testPeer()

	probe := &fakeProbe{
		slaveList: []string{"eno0", "eno1"},
		member: func(devIndex, port int) string {
			if devIndex == mainIface || port == 51900 {
				return "eno0"
			}
			return "eno1"
		},
	}

	m.placeWithProbeLocked(peer, probe)

	assert.Equal(t, "eno1", p.member, "path must be moved to the free member")
	assert.NotEqual(t, uint16(51900), p.port, "a new port must be selected")
	select {
	case key := <-m.portsChanged:
		assert.Equal(t, "peer-key", key, "the peer must be told to refresh its paths")
	default:
		t.Fatal("expected a port change notification")
	}
}

func TestPlacementGivesUpWhenHashIgnoresPorts(t *testing.T) {
	const mainIface = 100
	m := newTestManager(mainIface)
	peer, p := testPeer()

	probe := &fakeProbe{
		slaveList: []string{"eno0", "eno1"},
		member:    func(int, int) string { return "eno0" },
	}
	m.placeWithProbeLocked(peer, probe)

	assert.Equal(t, "eno0", p.member)
	assert.Equal(t, uint16(51900), p.port, "the original port is restored when nothing moves")
	assert.LessOrEqual(t, probe.measures, maxPlacementAttempts+1, "the loop must be bounded")
	select {
	case <-m.portsChanged:
		t.Fatal("no notification when the port did not move")
	default:
	}

	// The same input must not be measured again.
	before := probe.measures
	m.placeWithProbeLocked(peer, probe)
	assert.Equal(t, before, probe.measures, "unchanged inputs skip the measurement")
}

func TestPlacementSkipsNonBond(t *testing.T) {
	m := newTestManager(100)
	peer, p := testPeer()

	probe := &fakeProbe{
		slaveList: []string{"eno0"},
		member:    func(int, int) string { return "eno0" },
	}
	m.placeWithProbeLocked(peer, probe)

	assert.Empty(t, p.member)
	assert.Zero(t, probe.measures)
}

func TestPickSlave(t *testing.T) {
	before := map[string]uint64{"a": 100, "b": 100}
	after := map[string]uint64{"a": 100 + 500, "b": 100 + 9000}

	slave, err := pickSlave(before, after, []string{"a", "b"}, 12000)
	require.NoError(t, err)
	assert.Equal(t, "b", slave)

	// Nothing moved.
	_, err = pickSlave(before, before, []string{"a", "b"}, 12000)
	assert.Error(t, err)

	// Too small to trust.
	after = map[string]uint64{"a": 100 + 10, "b": 100 + 20}
	_, err = pickSlave(before, after, []string{"a", "b"}, 12000)
	assert.Error(t, err)

	// Ambiguous: both members carried a similar share.
	after = map[string]uint64{"a": 100 + 6000, "b": 100 + 7000}
	_, err = pickSlave(before, after, []string{"a", "b"}, 12000)
	assert.Error(t, err)
}

func TestAllocatePortInBlock(t *testing.T) {
	m := newTestManager(100)
	m.cfg.WgPort = 51820
	peer, p := testPeer()
	p.port = 0
	m.peers[peer.key] = peer

	first, err := m.allocatePortLocked(0, p)
	require.NoError(t, err)
	p.port = uint16(first)
	assert.GreaterOrEqual(t, first, m.cfg.WgPort+1)
	assert.Less(t, first, m.cfg.WgPort+1+pathPortRangeSize)

	p2 := &pathState{idx: 2, name: "wtp-test2", linkIndex: 201}
	peer.extras[2] = p2
	second, err := m.allocatePortLocked(0, p2)
	require.NoError(t, err)
	assert.NotEqual(t, first, second, "each path gets its own port")
	assert.Less(t, second, m.cfg.WgPort+1+pathPortRangeSize)
}
