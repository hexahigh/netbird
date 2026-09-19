package multipath

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	log "github.com/sirupsen/logrus"
)

func TestNormalizeAddrs(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("192.168.6.161"),
		netip.MustParseAddr("::ffff:192.168.6.161"), // v4-mapped duplicate
		netip.MustParseAddr("127.0.0.1"),            // loopback
		netip.MustParseAddr("0.0.0.0"),              // unspecified
		{},
		netip.MustParseAddr("192.168.6.162"),
	}
	got := normalizeAddrs(addrs)
	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("192.168.6.161"),
		netip.MustParseAddr("192.168.6.162"),
	}, got)
}

func TestValidEndpoints(t *testing.T) {
	got := validEndpoints([]PathEndpoint{
		{},
		{Addr: netip.MustParseAddr("10.0.0.1")},
		{Addr: netip.MustParseAddr("10.0.0.2"), Port: 51821, ProbePort: 51822},
		{Addr: netip.MustParseAddr("0.0.0.0"), Port: 1},
	})
	require.Len(t, got, 1)
	assert.Equal(t, uint16(51821), got[0].Port)
}

func TestOverlayAddrs(t *testing.T) {
	overlay := netip.MustParsePrefix("100.64.0.0/16")
	allowed := []netip.Prefix{
		netip.MustParsePrefix("100.64.1.1/32"), // peer overlay address
		netip.MustParsePrefix("192.168.50.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.65.0.0/24"),
	}
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("100.64.1.1")}, overlayAddrs(allowed, overlay))
	assert.Nil(t, overlayAddrs(allowed, netip.Prefix{}))
}

func TestPathIfaceName(t *testing.T) {
	a := pathIfaceName("peer-a", 1)
	b := pathIfaceName("peer-b", 1)
	assert.NotEqual(t, a, b)
	assert.LessOrEqual(t, len(a), 15, "interface names are limited to IFNAMSIZ")
	assert.Contains(t, a, pathIfacePrefix)
}

// TestProberDetectsLiveness runs two probers against each other over loopback
// and checks the up transition and the down transition when one side stops.
func TestProberDetectsLiveness(t *testing.T) {
	logger := log.NewEntry(log.StandardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listen := func() (*net.UDPConn, uint16) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		port, err := udpPort(conn)
		require.NoError(t, err)
		return conn, port
	}

	connA, portA := listen()
	connB, portB := listen()

	pa := newProber(logger, connA, ctx)
	pb := newProber(logger, connB, ctx)

	upA := make(chan bool, 8)
	pa.start(netip.MustParseAddr("127.0.0.1"), portB, func(up bool) { upA <- up })
	pb.start(netip.MustParseAddr("127.0.0.1"), portA, func(bool) {})

	select {
	case up := <-upA:
		require.True(t, up, "prober must come up when replies arrive")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for prober up")
	}

	rtt, loss := pa.stats()
	assert.Greater(t, rtt, time.Duration(0))
	assert.Less(t, loss, 0.5)

	pb.stop()

	select {
	case up := <-upA:
		require.False(t, up, "prober must go down when replies stop")
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for prober down")
	}
	_, loss = pa.stats()
	assert.Greater(t, loss, 0.0)

	pa.stop()
}
