//go:build linux

package multipath

import (
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
		cfg:              Config{WgPort: 51820},
		log:              log.WithField("component", "multipath-test"),
		peers:            make(map[string]*peerPaths),
		mainIface:        mainIface,
		setDevicePort:    func(_ string, port int) (int, error) { return port, nil },
		portsChanged:     make(chan string, 4),
		placementPending: make(map[string]bool),
	}
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

func TestCandidatePort(t *testing.T) {
	m := newTestManager(100)
	m.cfg.WgPort = 51820

	first := m.candidatePort("peer-key", 1, 0)
	second := m.candidatePort("peer-key", 1, 1)
	assert.NotEqual(t, first, second)
	assert.NotEqual(t, m.cfg.WgPort, first)
	assert.Greater(t, first, m.cfg.WgPort)
	assert.Less(t, first, 65535)
}
