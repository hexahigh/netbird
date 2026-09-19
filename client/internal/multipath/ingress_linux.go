//go:build linux

package multipath

import (
	"fmt"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	// ingressCheckInterval is how often the receive spread is checked while
	// paths carry traffic.
	ingressCheckInterval = 3 * time.Second
	// ingressSampleWindow is the counter window of one check.
	ingressSampleWindow = 1200 * time.Millisecond
	// ingressMinBytes is the smallest received overlay traffic that gives a
	// usable signal.
	ingressMinBytes = 8 << 20
	// ingressMemberShare is the share of the member traffic one member must
	// carry for the ingress to count as funnelled into a single member.
	ingressMemberShare = 0.9
	// maxIngressRounds bounds the port re-rolls driven by ingress spread.
	maxIngressRounds = 8
)

// ingressLoop notices when the peer's path flows all arrive on one bond member
// and moves this side's path port, because this side's port is the peer's
// destination port and the switch's LAG hash decides the member from it.
func (m *linuxManager) ingressLoop() {
	ticker := time.NewTicker(ingressCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkIngress()
		}
	}
}

func (m *linuxManager) checkIngress() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	type target struct {
		key    string
		remote PathEndpoint
		paths  []*pathState
	}
	var targets []target
	for key, peer := range m.peers {
		if peer.ingressRounds >= maxIngressRounds {
			continue
		}
		paths := m.peerPathListLocked(peer)
		up := make([]*pathState, 0, len(paths))
		for _, p := range paths {
			if p.state == PathStateUp && p.remote.IsValid() {
				up = append(up, p)
			}
		}
		if len(up) == 0 || !m.cfg.LocalOverlay.IsValid() {
			continue
		}
		targets = append(targets, target{key: key, remote: up[0].remote, paths: up})
	}
	m.mu.Unlock()

	for _, t := range targets {
		if m.checkPeerIngress(t.key, t.remote, t.paths) {
			m.rerollIngressPath(t.key, t.paths)
			continue
		}
		// The spread is fine; allow future rounds after a topology change.
		m.mu.Lock()
		if peer, ok := m.peers[t.key]; ok && peer.ingressRounds > 0 {
			peer.ingressRounds = 0
		}
		m.mu.Unlock()
	}
}

// checkPeerIngress samples overlay receive counters and bond member counters
// and reports whether all received overlay traffic landed on one member.
func (m *linuxManager) checkPeerIngress(peerKey string, remote PathEndpoint, paths []*pathState) bool {
	_, slaves := m.probe.slaves(remote.Addr)
	if len(slaves) < 2 {
		return false
	}
	names := make([]string, 0, len(paths))
	for _, p := range paths {
		names = append(names, p.name)
	}

	mainBefore, pathBefore, err := m.readRxCounters(peerKey, names)
	if err != nil {
		return false
	}
	slaveBefore, err := readSlaveRxCounters(slaves)
	if err != nil {
		return false
	}

	time.Sleep(ingressSampleWindow)

	mainAfter, pathAfter, err := m.readRxCounters(peerKey, names)
	if err != nil {
		return false
	}
	slaveAfter, err := readSlaveRxCounters(slaves)
	if err != nil {
		return false
	}

	overlayRx := mainAfter - mainBefore
	for name := range pathAfter {
		if delta := pathAfter[name] - pathBefore[name]; delta > 0 {
			overlayRx += delta
		}
	}
	if overlayRx < ingressMinBytes {
		return false
	}

	slaveDeltas := make(map[string]uint64, len(slaves))
	for _, slave := range slaves {
		slaveDeltas[slave] = slaveAfter[slave] - slaveBefore[slave]
	}
	return ingressFunnelled(overlayRx, slaveDeltas)
}

// ingressFunnelled reports whether the received overlay traffic is
// concentrated on a single bond member.
func ingressFunnelled(overlayRx uint64, slaveDeltas map[string]uint64) bool {
	if overlayRx < ingressMinBytes {
		return false
	}
	var total, max uint64
	for _, delta := range slaveDeltas {
		total += delta
		if delta > max {
			max = delta
		}
	}
	if total == 0 {
		return false
	}
	return float64(max) >= ingressMemberShare*float64(total)
}

// readRxCounters returns the peer's received bytes on the main interface and
// on each path interface.
func (m *linuxManager) readRxCounters(peerKey string, names []string) (uint64, map[string]uint64, error) {
	main, err := m.peerRxBytes(m.cfg.WgIface, peerKey)
	if err != nil {
		return 0, nil, err
	}
	out := make(map[string]uint64, len(names))
	for _, name := range names {
		rx, err := m.peerRxBytes(name, peerKey)
		if err != nil {
			return 0, nil, err
		}
		out[name] = rx
	}
	return main, out, nil
}

func (m *linuxManager) peerRxBytes(name, peerKey string) (uint64, error) {
	dev, err := m.wg.Device(name)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", name, err)
	}
	for _, peer := range dev.Peers {
		if peer.PublicKey.String() == peerKey {
			return uint64(peer.ReceiveBytes), nil
		}
	}
	return 0, fmt.Errorf("peer %s not found on %s", peerKey, name)
}

// rerollIngressPath moves one path to a new listen port so the peer's flows
// arrive with a different destination port, which changes the switch's member
// choice, then asks the peer to refresh its endpoints.
func (m *linuxManager) rerollIngressPath(peerKey string, paths []*pathState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, ok := m.peers[peerKey]
	if !ok {
		return
	}
	if peer.ingressRounds >= maxIngressRounds {
		return
	}
	peer.ingressRounds++
	target := paths[0]
	if err := m.rerollPortLocked(peer, target, peer.ingressRounds); err != nil {
		m.log.Warnf("multipath: cannot move path %s for ingress spread: %v", target.name, err)
		return
	}
	m.log.Infof("received flows were funnelled into one bond member, moved path %s to port %d", target.name, target.port)
	m.notifyPortsChangedLocked(peerKey)
}

func readSlaveRxCounters(slaves []string) (map[string]uint64, error) {
	counters := make(map[string]uint64, len(slaves))
	for _, slave := range slaves {
		link, err := netlink.LinkByName(slave)
		if err != nil {
			return nil, err
		}
		stats := link.Attrs().Statistics
		if stats == nil {
			return nil, fmt.Errorf("no statistics for %s", slave)
		}
		counters[slave] = stats.RxBytes
	}
	return counters, nil
}
