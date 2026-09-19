//go:build linux

package multipath

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	// burstBytes is the size of the placement burst. It has to stand out
	// against the background traffic of the bond over the measurement window.
	burstBytes = 16 << 20
	// burstWriteTimeout bounds how long a single placement burst may take.
	burstWriteTimeout = 2 * time.Second
	// minBurstBytes is the smallest burst that still gives a usable signal.
	minBurstBytes = 4 << 20
	// sessionWarmupBytes is the size of each warm-up burst sent until the
	// path's WireGuard session is established.
	sessionWarmupBytes = 8 << 10
	// sessionWarmupTimeout bounds how long placement waits for that session.
	sessionWarmupTimeout = 3 * time.Second
	// handshakeFreshness is how recent a handshake must be for the session to
	// count as usable.
	handshakeFreshness = 30 * time.Second
	// maxPlacementFailures bounds placement retries when measurement keeps
	// failing, for example while a path session cannot be established.
	maxPlacementFailures = 5
	// placementRetryDelay is the pause before a failed measurement is retried.
	placementRetryDelay = 2 * time.Second
	// counterSettleDelay lets the bond qdisc drain into the slaves before the
	// transmit counters are read; reading earlier misses the burst.
	counterSettleDelay = 300 * time.Millisecond
	// burstPort is the destination port of the placement burst. Traffic to it
	// is expected to be dropped by the remote peer; only the local egress
	// bond member matters.
	burstPort = 9
	// maxPlacementAttempts is the number of listen ports tried before
	// concluding the bond hash cannot be moved with ports.
	maxPlacementAttempts = 6
	// placementSlaveMargin is the fraction of the burst a slave must have
	// carried to be considered the egress member.
	placementSlaveMargin = 4
	// maxPlacementRounds bounds the port re-roll exchanges between two peers
	// so a pair whose bond hash oscillates cannot loop.
	maxPlacementRounds = 6
)

// placementProbe measures which bond member a path's outer flow uses.
type placementProbe interface {
	// slaves returns the bond name and slave names of the underlay route to
	// remote, or empty names when the route does not leave through a bond.
	slaves(remote netip.Addr) (string, []string)
	// measure steers the peer's overlay traffic through devIndex, sends a
	// burst, and returns the bond slave that carried it.
	measure(peer *peerPaths, devIndex int, slaves []string) (string, error)
}

// linuxProbe is the real probe: overlay routes are steered with netlink, the
// burst is a UDP stream to the peer's overlay address, and the member is the
// slave whose transmit counter grew the most.
type linuxProbe struct {
	m *linuxManager
}

func (p *linuxProbe) slaves(remote netip.Addr) (string, []string) {
	routes, err := netlink.RouteGet(remote.AsSlice())
	if err != nil || len(routes) == 0 {
		return "", nil
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil || link.Type() != "bond" {
		return "", nil
	}
	name := link.Attrs().Name
	raw, err := os.ReadFile(filepath.Join("/sys/class/net", name, "bonding/slaves"))
	if err != nil {
		return "", nil
	}
	slaves := strings.Fields(string(raw))
	if len(slaves) < 2 {
		return "", nil
	}
	return name, slaves
}

func (p *linuxProbe) measure(peer *peerPaths, devIndex int, slaves []string) (string, error) {
	m := p.m
	if len(peer.overlayIPs) == 0 {
		return "", errors.New("no overlay address to probe")
	}
	if !m.cfg.LocalOverlay.IsValid() || m.cfg.LocalOverlay.Is6() {
		return "", errors.New("no local IPv4 overlay address")
	}

	// Steer the peer's overlay addresses through the interface under test so
	// the burst egresses through it, then restore the route group.
	steered := make([]netip.Addr, 0, len(peer.overlayIPs))
	for _, overlay := range peer.overlayIPs {
		route := &netlink.Route{
			Dst:       prefixToIPNet(netip.PrefixFrom(overlay, overlay.BitLen())),
			LinkIndex: devIndex,
		}
		if err := netlink.RouteReplace(route); err != nil {
			restoreRoutes(m, peer, steered)
			return "", fmt.Errorf("steer overlay via %d: %w", devIndex, err)
		}
		steered = append(steered, overlay)
	}
	defer restoreRoutes(m, peer, steered)

	// A path interface without a WireGuard session drops the burst instead of
	// encrypting it, so warm the session up first.
	if devIndex != m.mainIface {
		if err := m.waitForPathSession(peer, devIndex); err != nil {
			return "", err
		}
	}

	before, err := readSlaveCounters(slaves)
	if err != nil {
		return "", err
	}
	sent, err := m.burst(peer.overlayIPs[0], burstBytes)
	if err != nil {
		return "", err
	}
	if sent < minBurstBytes {
		return "", fmt.Errorf("burst too small: %d bytes", sent)
	}
	time.Sleep(counterSettleDelay)
	after, err := readSlaveCounters(slaves)
	if err != nil {
		return "", err
	}
	return pickSlave(before, after, slaves, sent)
}

// waitForPathSession sends small steered bursts until the path's WireGuard
// session is up, so the measurement burst is actually encrypted.
func (m *linuxManager) waitForPathSession(peer *peerPaths, devIndex int) error {
	name := ""
	for _, p := range peer.extras {
		if p != nil && p.linkIndex == devIndex {
			name = p.name
			break
		}
	}
	if name == "" || m.hasRecentHandshake(name) {
		return nil
	}

	deadline := time.Now().Add(sessionWarmupTimeout)
	for time.Now().Before(deadline) {
		if _, err := m.burst(peer.overlayIPs[0], sessionWarmupBytes); err != nil {
			return err
		}
		if m.hasRecentHandshake(name) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("path %s session did not come up", name)
}

func (m *linuxManager) hasRecentHandshake(name string) bool {
	dev, err := m.wg.Device(name)
	if err != nil {
		return false
	}
	for _, peer := range dev.Peers {
		if !peer.LastHandshakeTime.IsZero() && time.Since(peer.LastHandshakeTime) < handshakeFreshness {
			return true
		}
	}
	return false
}

func restoreRoutes(m *linuxManager, peer *peerPaths, steered []netip.Addr) {
	for _, overlay := range steered {
		m.deleteRoute(overlay)
	}
	m.applyRouteLocked(peer)
}

func readSlaveCounters(slaves []string) (map[string]uint64, error) {
	counters := make(map[string]uint64, len(slaves))
	for _, slave := range slaves {
		raw, err := os.ReadFile(filepath.Join("/sys/class/net", slave, "statistics/tx_bytes"))
		if err != nil {
			return nil, fmt.Errorf("read %s counters: %w", slave, err)
		}
		var value uint64
		if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &value); err != nil {
			return nil, fmt.Errorf("parse %s counters: %w", slave, err)
		}
		counters[slave] = value
	}
	return counters, nil
}

// pickSlave returns the slave that carried the largest share of the burst.
func pickSlave(before, after map[string]uint64, slaves []string, sent int) (string, error) {
	best := ""
	var bestDelta, secondDelta uint64
	for _, slave := range slaves {
		delta := after[slave] - before[slave]
		if delta > bestDelta {
			secondDelta = bestDelta
			bestDelta = delta
			best = slave
		} else if delta > secondDelta {
			secondDelta = delta
		}
	}
	if best == "" {
		return "", errors.New("no member counters moved")
	}
	if bestDelta < uint64(sent)/placementSlaveMargin {
		return "", fmt.Errorf("no clear member: largest delta %d of %d bytes", bestDelta, sent)
	}
	if secondDelta > 0 && bestDelta < secondDelta*2 {
		return "", fmt.Errorf("member delta too close: %d vs %d", bestDelta, secondDelta)
	}
	return best, nil
}

// burst sends an unconnected UDP stream to the peer overlay address. The
// remote peer is expected to drop it (port 9); only the local egress path and
// its bond member matter. The socket is unconnected so ICMP unreachable
// replies do not abort the stream.
func (m *linuxManager) burst(dst netip.Addr, maxBytes int) (int, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: m.cfg.LocalOverlay.AsSlice()})
	if err != nil {
		return 0, fmt.Errorf("open burst socket: %w", err)
	}
	defer conn.Close()

	target := &net.UDPAddr{IP: dst.AsSlice(), Port: burstPort}
	payload := make([]byte, 1400)
	sent := 0
	deadline := time.Now().Add(burstWriteTimeout)
	for sent < maxBytes && time.Now().Before(deadline) {
		n, err := conn.WriteToUDP(payload, target)
		if err != nil {
			if sent > 0 {
				break
			}
			return 0, fmt.Errorf("send burst: %w", err)
		}
		sent += n
	}
	return sent, nil
}

// placeWithProbeLocked matches each path to a bond member that the main
// connection does not use. Callers must hold m.mu.
func (m *linuxManager) placeWithProbeLocked(peer *peerPaths, probe placementProbe) {
	if probe == nil || m.setDevicePort == nil || len(peer.overlayIPs) == 0 {
		return
	}
	remote := firstRemoteLocked(peer)
	if !remote.IsValid() {
		return
	}
	sig := placementSignature(peer)
	if peer.placedSig == sig {
		return
	}
	if peer.placementRounds >= maxPlacementRounds {
		m.log.Debugf("skipping placement for peer %s after %d rounds", peer.key, peer.placementRounds)
		peer.placedSig = sig
		return
	}
	peer.placementRounds++

	bond, slaves := probe.slaves(remote)
	if len(slaves) < 2 {
		peer.placedSig = sig
		peer.placementRounds = 0
		return
	}

	mainMember, err := probe.measure(peer, m.mainIface, slaves)
	if err != nil {
		peer.placementFailures++
		if peer.placementFailures <= maxPlacementFailures {
			m.log.Debugf("cannot measure the main bond member on %s yet: %v", bond, err)
			m.schedulePlacementRetry(peer.key)
		} else {
			m.log.Warnf("giving up bond member placement for peer %s: %v", peer.key, err)
			peer.placedSig = sig
		}
		return
	}
	changed := false
	placed := make(map[string]string)
	for idx := 1; idx <= len(peer.extras); idx++ {
		p := peer.extras[idx]
		if p == nil || !p.remote.IsValid() {
			continue
		}
		pathChanged, err := m.placePathLocked(peer, p, mainMember, slaves, probe)
		if err != nil {
			peer.placementFailures++
			if peer.placementFailures <= maxPlacementFailures {
				m.log.Debugf("cannot place path %s yet: %v", p.name, err)
				m.schedulePlacementRetry(peer.key)
			} else {
				m.log.Warnf("giving up bond member placement for peer %s: %v", peer.key, err)
				peer.placedSig = sig
			}
			return
		}
		changed = changed || pathChanged
		if p.member != "" {
			placed[p.name] = p.member
		}
	}
	m.log.Infof("peer %s main path on bond member %s, paths on %v", peer.key, mainMember, placed)

	peer.placementFailures = 0
	peer.placedSig = sig
	if changed {
		m.notifyPortsChangedLocked(peer.key)
		return
	}
	// The placement is stable; allow future rounds after a topology change.
	peer.placementRounds = 0
}

// schedulePlacementRetry retries a failed measurement after a short delay,
// which covers a path whose WireGuard session is not up yet.
func (m *linuxManager) schedulePlacementRetry(peerKey string) {
	time.AfterFunc(placementRetryDelay, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.closed {
			return
		}
		if _, ok := m.peers[peerKey]; !ok {
			return
		}
		m.schedulePlacementLocked(peerKey)
	})
}

// placementSignature identifies one placement input: the remote endpoints, the
// local ports and the overlay addresses. Repeated offers with the same inputs
// skip the measurement.
func placementSignature(peer *peerPaths) string {
	var b strings.Builder
	for idx := 1; idx <= len(peer.extras); idx++ {
		p := peer.extras[idx]
		if p == nil {
			continue
		}
		fmt.Fprintf(&b, "%d/%s/%d/%s/%d;", idx, p.remote.Addr, p.remote.Port, p.local, p.port)
	}
	for _, overlay := range peer.overlayIPs {
		fmt.Fprintf(&b, "%s;", overlay)
	}
	return b.String()
}

// placePathLocked gives one path a listen port whose egress member differs
// from the main path's. It returns true when the port changed. When no port
// moves the path off the main member, for example because the bond hash does
// not include ports, the original port is restored so the peer is not sent
// chasing ports that do not help. A measurement failure is returned so the
// caller can retry once the path session is up.
func (m *linuxManager) placePathLocked(peer *peerPaths, p *pathState, mainMember string, slaves []string, probe placementProbe) (bool, error) {
	originalPort := p.port
	collisions := 0
	for attempt := 0; attempt <= maxPlacementAttempts; attempt++ {
		member, err := probe.measure(peer, p.linkIndex, slaves)
		if err != nil {
			m.revertPortLocked(p, originalPort)
			return false, err
		}
		p.member = member
		if member != mainMember {
			return p.port != originalPort, nil
		}
		collisions++
		if collisions >= maxPlacementAttempts {
			m.log.Warnf("multipath: path %s stays on bond member %s, the bond hash does not move with ports", p.name, mainMember)
			m.revertPortLocked(p, originalPort)
			return false, nil
		}
		if err := m.rerollPortLocked(peer, p, attempt+1); err != nil {
			m.log.Warnf("multipath: cannot move path %s off member %s: %v", p.name, mainMember, err)
			m.revertPortLocked(p, originalPort)
			return false, nil
		}
	}
	m.revertPortLocked(p, originalPort)
	return false, nil
}

// revertPortLocked restores a path's original listen port after a placement
// attempt gave up.
func (m *linuxManager) revertPortLocked(p *pathState, original uint16) {
	if p.port == original || m.setDevicePort == nil {
		return
	}
	if actual, err := m.setDevicePort(p.name, int(original)); err == nil && actual > 0 {
		p.port = uint16(actual)
	}
}

// rerollPortLocked gives a path a new listen port from the path port range.
// Callers must hold m.mu.
func (m *linuxManager) rerollPortLocked(_ *peerPaths, p *pathState, attempt int) error {
	preferred := int(p.port) + 1 + attempt
	if preferred > m.cfg.WgPort+pathPortRangeSize {
		preferred = m.cfg.WgPort + 1
	}
	port, err := m.allocatePortLocked(preferred, p)
	if err != nil {
		return err
	}
	p.port = uint16(port)
	return nil
}

// portUsedLocked reports whether a port is already used by one of the paths of
// another peer or by another path of the same peer. Callers must hold m.mu.
func (m *linuxManager) portUsedLocked(port int, exclude *pathState) bool {
	for _, peer := range m.peers {
		for _, p := range peer.extras {
			if p == exclude {
				continue
			}
			if int(p.port) == port {
				return true
			}
		}
	}
	return false
}

func firstRemoteLocked(peer *peerPaths) netip.Addr {
	for idx := 1; idx <= len(peer.extras); idx++ {
		if p := peer.extras[idx]; p != nil && p.remote.Addr.IsValid() {
			return p.remote.Addr
		}
	}
	return netip.Addr{}
}
