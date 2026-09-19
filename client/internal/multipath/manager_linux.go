//go:build linux

package multipath

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	pathIfacePrefix = "wtp"

	// keepaliveInterval matches the main peer so path sessions stay alive and
	// NAT mappings do not expire.
	keepaliveInterval = 25 * time.Second

	hashPolicyPath = "/proc/sys/net/ipv4/fib_multipath_hash_policy"
	// hashPolicyL4 makes the kernel hash the inner flow's 5-tuple, which is
	// what spreads TCP flows over several paths.
	hashPolicyL4 = 1

	maxPathIfaces = 7 // MaxPaths includes the main connection.
)

// NewManager creates the Linux multipath manager. It returns a nil manager
// when multipath is disabled.
func NewManager(cfg Config) (Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.MaxPaths < 2 {
		return nil, fmt.Errorf("multipath: max paths must be at least 2, got %d", cfg.MaxPaths)
	}
	if cfg.MaxPaths > maxPathIfaces+1 {
		return nil, fmt.Errorf("multipath: max paths must be at most %d, got %d", maxPathIfaces+1, cfg.MaxPaths)
	}
	if len(normalizeAddrs(cfg.LocalAddresses)) == 0 {
		return nil, errors.New("multipath: no usable local path addresses configured")
	}
	if cfg.Mode != "flow" {
		log.Warnf("multipath: mode %q is not supported in kernel mode, using flow", cfg.Mode)
	}
	if cfg.OverlayV4.IsValid() && cfg.OverlayV4.Addr().Is6() {
		cfg.OverlayV4 = netip.Prefix{}
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}

	wg, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("multipath: open wgctrl: %w", err)
	}

	mainLink, err := netlink.LinkByName(cfg.WgIface)
	if err != nil {
		wg.Close()
		return nil, fmt.Errorf("multipath: find main interface %s: %w", cfg.WgIface, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := &linuxManager{
		cfg:          cfg,
		log:          log.WithField("component", "multipath"),
		wg:           wg,
		ctx:          ctx,
		cancel:       cancel,
		peers:        make(map[string]*peerPaths),
		mainIface:    mainLink.Attrs().Index,
		extraAddrs:   normalizeAddrs(cfg.LocalAddresses),
		ifaceDirty:   make(chan struct{}, 1),
		portsChanged: make(chan string, 8),
		placementCh:  make(chan string, 64),
	}
	m.probe = &linuxProbe{m: m}
	m.setDevicePort = m.setPort
	m.placementPending = make(map[string]bool)
	go m.observerLoop()
	go m.notifyLoop()
	go m.placementLoop()
	go m.ingressLoop()
	return m, nil
}

type linuxManager struct {
	cfg Config
	log *log.Entry
	wg  *wgctrl.Client

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	peers  map[string]*peerPaths
	closed bool

	// routeMu serializes netlink route operations. Path state changes arrive
	// from prober goroutines while status and configuration run concurrently.
	routeMu sync.Mutex

	mainIface  int
	extraAddrs []netip.Addr

	// hashPolicy tracks whether this process changed the multipath hash policy
	// so it can be restored on close.
	hashPolicyMu     sync.Mutex
	hashPolicyOrig   int
	hashPolicyChange bool

	// ifaceDirty signals the observer loop that the set of path interfaces
	// changed, so observers (the firewall) can be updated without holding m.mu.
	ifaceDirty    chan struct{}
	observerMu    sync.Mutex
	observer      func([]string)
	observerState []string

	// placement measures the bond member of each path and moves a path whose
	// port lands on the same member as the main connection. It runs on a
	// worker so an offer is never delayed by a measurement.
	probe            placementProbe
	setDevicePort    func(name string, port int) (int, error)
	portsChanged     chan string
	placementCh      chan string
	placementMu      sync.Mutex
	placementPending map[string]bool
}

type peerPaths struct {
	key        string
	allowedIPs []netip.Prefix
	overlayIPs []netip.Addr
	psk        *wgtypes.Key
	// placedSig is the last placement input, so repeated offers do not rerun
	// the measurement; placementRounds bounds re-rolls between two peers, and
	// placementFailures bounds retries when a measurement keeps failing.
	placedSig         string
	placementRounds   int
	placementFailures int
	ingressRounds     int

	// extras are the path interfaces beyond the main connection, keyed by the
	// path index in the advertised list.
	extras map[int]*pathState
	// installed is the set of overlay addresses with a route group installed.
	installed []netip.Addr
}

type pathState struct {
	idx       int
	name      string
	local     netip.Addr
	port      uint16
	probePort uint16
	linkIndex int
	remote    PathEndpoint
	state     PathState
	member    string
	prober    *prober
	srcRoute  *netlink.Route
}

// LocalPaths returns the extra paths advertised to a peer, creating the path
// interfaces and probe sockets on first call.
func (m *linuxManager) LocalPaths(peerKey string) ([]PathEndpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, errors.New("multipath: manager is closed")
	}

	peer, err := m.ensurePeerLocked(peerKey)
	if err != nil {
		return nil, err
	}
	if err := m.ensurePathsLocked(peer); err != nil {
		return nil, err
	}

	paths := make([]PathEndpoint, 0, len(peer.extras))
	for idx := 1; idx <= len(peer.extras); idx++ {
		p := peer.extras[idx]
		if p == nil {
			continue
		}
		paths = append(paths, PathEndpoint{Addr: p.local, Port: p.port, ProbePort: p.probePort})
	}
	m.markInterfacesDirty()
	return paths, nil
}

// Configure applies the remote peer's paths and installs the route group.
func (m *linuxManager) Configure(peerKey string, remote []PathEndpoint, allowedIPs []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("multipath: manager is closed")
	}

	peer, err := m.ensurePeerLocked(peerKey)
	if err != nil {
		return err
	}
	peer.allowedIPs = allowedIPs
	peer.overlayIPs = overlayAddrs(allowedIPs, m.cfg.OverlayV4)

	remote = validEndpoints(remote)
	wanted := len(remote)
	if wanted > len(m.extraAddrs) {
		wanted = len(m.extraAddrs)
	}
	if wanted > m.cfg.MaxPaths-1 {
		wanted = m.cfg.MaxPaths - 1
	}

	if wanted == 0 {
		m.removeExtrasLocked(peer)
		m.clearRouteLocked(peer)
		m.markInterfacesDirty()
		return nil
	}

	if err := m.ensurePathsLocked(peer); err != nil {
		return err
	}
	// Drop extras the remote does not use.
	for idx, p := range peer.extras {
		if idx > wanted {
			m.removePathLocked(peer, p)
		}
	}

	remoteKey, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return fmt.Errorf("multipath: parse peer key: %w", err)
	}

	for idx := 1; idx <= wanted; idx++ {
		p := peer.extras[idx]
		if p == nil {
			return fmt.Errorf("multipath: path %d was not created", idx)
		}
		if err := m.configurePathLocked(peer, p, remoteKey, remote[idx-1]); err != nil {
			return err
		}
	}

	m.applyRouteLocked(peer)
	m.markInterfacesDirty()
	m.schedulePlacementLocked(peer.key)
	return nil
}

// SetPresharedKey applies a preshared key to every path peer of a peer.
func (m *linuxManager) SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error {
	m.mu.Lock()
	var paths []*pathState
	if peer, ok := m.peers[peerKey]; ok {
		peer.psk = &psk
		paths = m.peerPathListLocked(peer)
	}
	m.mu.Unlock()

	remoteKey, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return fmt.Errorf("multipath: parse peer key: %w", err)
	}

	var merr error
	for _, p := range paths {
		cfg := wgtypes.Config{
			Peers: []wgtypes.PeerConfig{{
				PublicKey:    remoteKey,
				PresharedKey: &psk,
				UpdateOnly:   updateOnly,
			}},
		}
		if err := m.wg.ConfigureDevice(p.name, cfg); err != nil {
			merr = errors.Join(merr, fmt.Errorf("set psk on %s: %w", p.name, err))
		}
	}
	return merr
}

// RemovePeer tears down every path and route of a peer.
func (m *linuxManager) RemovePeer(peerKey string) {
	m.mu.Lock()
	peer, ok := m.peers[peerKey]
	if ok {
		delete(m.peers, peerKey)
	}
	m.mu.Unlock()

	if !ok {
		return
	}

	for _, p := range peer.extras {
		m.destroyPath(p)
	}
	m.clearRoute(peer)
	m.markInterfacesDirty()
}

// Interfaces returns the names of all active path interfaces.
func (m *linuxManager) Interfaces() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.interfaceNamesLocked()
}

// SetInterfaceObserver registers a callback for path interface changes and
// pushes the current state.
func (m *linuxManager) SetInterfaceObserver(fn func([]string)) {
	m.observerMu.Lock()
	m.observer = fn
	m.observerMu.Unlock()
	m.markInterfacesDirty()
}

func (m *linuxManager) markInterfacesDirty() {
	select {
	case m.ifaceDirty <- struct{}{}:
	default:
	}
}

func (m *linuxManager) observerLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.ifaceDirty:
			m.observerMu.Lock()
			fn := m.observer
			m.observerMu.Unlock()
			if fn != nil {
				fn(m.Interfaces())
			}
		}
	}
}

func (m *linuxManager) interfaceNamesLocked() []string {
	var names []string
	for _, peer := range m.peers {
		for idx := 1; idx <= len(peer.extras); idx++ {
			if p := peer.extras[idx]; p != nil {
				names = append(names, p.name)
			}
		}
	}
	return names
}

// PathStates reports the current state of a peer's paths.
func (m *linuxManager) PathStates(peerKey string) []PathStatus {
	m.mu.Lock()
	peer, ok := m.peers[peerKey]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	states := make([]PathStatus, 0, len(peer.extras))
	for idx := 1; idx <= len(peer.extras); idx++ {
		p := peer.extras[idx]
		if p == nil {
			continue
		}
		states = append(states, PathStatus{
			Local:     PathEndpoint{Addr: p.local, Port: p.port, ProbePort: p.probePort},
			Remote:    p.remote,
			Interface: p.name,
			Member:    p.member,
			State:     p.state,
		})
	}
	probers := make([]*prober, 0, len(states))
	for idx := 1; idx <= len(peer.extras); idx++ {
		if p := peer.extras[idx]; p != nil {
			probers = append(probers, p.prober)
		}
	}
	m.mu.Unlock()

	for i, p := range probers {
		if p == nil {
			continue
		}
		states[i].RTT, states[i].Loss = p.stats()
	}
	for i := range states {
		if states[i].Interface == "" {
			continue
		}
		dev, err := m.wg.Device(states[i].Interface)
		if err != nil {
			continue
		}
		for _, pr := range dev.Peers {
			states[i].TxBytes = pr.TransmitBytes
			states[i].RxBytes = pr.ReceiveBytes
			states[i].LastHandshake = pr.LastHandshakeTime
		}
	}
	return states
}

// Close stops all path interfaces and restores the hash policy.
func (m *linuxManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	peers := make([]*peerPaths, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, peer)
	}
	m.peers = make(map[string]*peerPaths)
	m.mu.Unlock()

	m.cancel()

	for _, peer := range peers {
		for _, p := range peer.extras {
			m.destroyPath(p)
		}
		m.clearRoute(peer)
	}

	m.restoreHashPolicy()
	return m.wg.Close()
}

func (m *linuxManager) ensurePeerLocked(peerKey string) (*peerPaths, error) {
	peer, ok := m.peers[peerKey]
	if ok {
		return peer, nil
	}
	if _, err := wgtypes.ParseKey(peerKey); err != nil {
		return nil, fmt.Errorf("multipath: invalid peer key %q: %w", peerKey, err)
	}
	peer = &peerPaths{
		key:    peerKey,
		extras: make(map[int]*pathState),
	}
	m.peers[peerKey] = peer
	return peer, nil
}

// ensurePathsLocked creates one path interface per configured extra address.
// Callers must hold m.mu.
func (m *linuxManager) ensurePathsLocked(peer *peerPaths) error {
	max := m.cfg.MaxPaths - 1
	if max > len(m.extraAddrs) {
		max = len(m.extraAddrs)
	}
	for idx := 1; idx <= max; idx++ {
		if peer.extras[idx] != nil {
			continue
		}
		p, err := m.createPathLocked(peer, idx, m.extraAddrs[idx-1])
		if err != nil {
			return err
		}
		peer.extras[idx] = p
	}
	return nil
}

// createPathLocked creates one path interface, its probe socket, and its
// WireGuard device configuration. The peer endpoint is configured later.
// Callers must hold m.mu.
func (m *linuxManager) createPathLocked(peer *peerPaths, idx int, local netip.Addr) (*pathState, error) {
	name := pathIfaceName(peer.key, idx)
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: int(m.cfg.MTU)}}
	if err := netlink.LinkAdd(link); err != nil {
		if !strings.Contains(err.Error(), "file exists") {
			return nil, fmt.Errorf("multipath: create %s: %w", name, err)
		}
		if err := netlink.LinkDel(link); err != nil {
			return nil, fmt.Errorf("multipath: remove stale %s: %w", name, err)
		}
		if err := netlink.LinkAdd(link); err != nil {
			return nil, fmt.Errorf("multipath: create %s: %w", name, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		_ = netlink.LinkDel(link)
		return nil, fmt.Errorf("multipath: bring up %s: %w", name, err)
	}
	attrs := link.Attrs()
	if attrs == nil {
		_ = netlink.LinkDel(link)
		return nil, fmt.Errorf("multipath: missing attributes for %s", name)
	}

	if err := m.configureDevice(name, peer.key, idx); err != nil {
		_ = netlink.LinkDel(link)
		return nil, err
	}
	dev, err := m.wg.Device(name)
	if err != nil {
		_ = netlink.LinkDel(link)
		return nil, fmt.Errorf("multipath: read %s: %w", name, err)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local.AsSlice(), Port: 0})
	if err != nil {
		_ = netlink.LinkDel(link)
		return nil, fmt.Errorf("multipath: probe socket on %s: %w", local, err)
	}
	probePort, err := udpPort(conn)
	if err != nil {
		conn.Close()
		_ = netlink.LinkDel(link)
		return nil, err
	}

	p := &pathState{
		idx:       idx,
		name:      name,
		local:     local,
		port:      uint16(dev.ListenPort),
		probePort: probePort,
		linkIndex: attrs.Index,
		state:     PathStateInactive,
	}
	p.prober = newProber(m.log.WithField("path", name), conn, m.ctx)
	return p, nil
}

// configureDevice creates the WireGuard device of a path. The listen port is
// derived from the peer key so it is stable across restarts and unique among
// peers, which makes the outer tuple, and with it the bond member assignment,
// reproducible. If the port is taken, fall back to a kernel-assigned one.
func (m *linuxManager) configureDevice(name, peerKey string, idx int) error {
	cfg := wgtypes.Config{
		PrivateKey:   &m.cfg.PrivateKey,
		ReplacePeers: true,
	}
	if port := m.candidatePort(peerKey, idx, 0); port > 0 && port <= 65535 {
		cfg.ListenPort = &port
	}
	if err := m.wg.ConfigureDevice(name, cfg); err != nil {
		if cfg.ListenPort == nil {
			return fmt.Errorf("multipath: configure %s: %w", name, err)
		}
		m.log.Warnf("port %d is not available for %s, using a random port: %v", *cfg.ListenPort, name, err)
		cfg.ListenPort = nil
		if err := m.wg.ConfigureDevice(name, cfg); err != nil {
			return fmt.Errorf("multipath: configure %s: %w", name, err)
		}
	}
	return nil
}

// setPort changes a path's WireGuard listen port and returns the port the
// kernel bound.
func (m *linuxManager) setPort(name string, port int) (int, error) {
	value := port
	if err := m.wg.ConfigureDevice(name, wgtypes.Config{ListenPort: &value}); err != nil {
		return 0, err
	}
	dev, err := m.wg.Device(name)
	if err != nil {
		return 0, err
	}
	return dev.ListenPort, nil
}

// notifyLoop hands port changes to the peer connection, outside the manager
// lock, so the remote peer can be told about the new endpoints.
func (m *linuxManager) notifyLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case key := <-m.portsChanged:
			if m.cfg.OnPathsChanged != nil {
				m.cfg.OnPathsChanged(key)
			}
		}
	}
}

func (m *linuxManager) notifyPortsChangedLocked(peerKey string) {
	select {
	case m.portsChanged <- peerKey:
	default:
	}
}

// schedulePlacementLocked queues a peer for bond member placement, coalescing
// repeated requests. Callers must hold m.mu.
func (m *linuxManager) schedulePlacementLocked(peerKey string) {
	m.placementMu.Lock()
	defer m.placementMu.Unlock()

	if m.placementPending[peerKey] {
		return
	}
	m.placementPending[peerKey] = true
	select {
	case m.placementCh <- peerKey:
	default:
		// Queue full: drop the request, a later Configure retries it.
		delete(m.placementPending, peerKey)
	}
}

// placementLoop runs the bond member measurements one at a time. Slave
// counters are shared by every path, so measurements must not overlap.
func (m *linuxManager) placementLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case key := <-m.placementCh:
			m.placementMu.Lock()
			delete(m.placementPending, key)
			m.placementMu.Unlock()

			m.mu.Lock()
			if peer, ok := m.peers[key]; ok && !m.closed {
				m.placeWithProbeLocked(peer, m.probe)
			}
			m.mu.Unlock()
		}
	}
}

// configurePathLocked points one path at its remote endpoint: a source route
// for the outer underlay traffic, the WireGuard peer, and the prober.
// Callers must hold m.mu.
func (m *linuxManager) configurePathLocked(peer *peerPaths, p *pathState, remoteKey wgtypes.Key, remote PathEndpoint) error {
	p.remote = remote

	if err := m.setSourceRoute(p, remote); err != nil {
		return err
	}

	allowed := make([]net.IPNet, 0, len(peer.allowedIPs))
	for _, prefix := range peer.allowedIPs {
		allowed = append(allowed, *prefixToIPNet(prefix))
	}
	endpoint := &net.UDPAddr{IP: remote.Addr.AsSlice(), Port: int(remote.Port)}
	cfg := wgtypes.Config{
		PrivateKey: &m.cfg.PrivateKey,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   remoteKey,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  allowed,
			Endpoint:                    endpoint,
			PersistentKeepaliveInterval: durationPtr(keepaliveInterval),
			PresharedKey:                peer.psk,
		}},
	}
	if err := m.wg.ConfigureDevice(p.name, cfg); err != nil {
		return fmt.Errorf("multipath: configure peer on %s: %w", p.name, err)
	}

	// A path starts outside the route group and is promoted only after the
	// prober has seen replies, so a path that never comes up cannot blackhole
	// a share of the flows.
	if p.state == PathStateInactive {
		p.state = PathStateDown
	}
	// start is idempotent and also refreshes the probe target when the remote
	// path is reconfigured with a new probe port.
	p.prober.start(remote.Addr, remote.ProbePort, func(up bool) {
		m.setPathState(peer.key, p.idx, up)
	})
	return nil
}

// setSourceRoute adds a host route for the remote underlay address with the
// path's local address as the preferred source. It must be installed before
// the WireGuard peer endpoint so the endpoint's cached route picks it up.
func (m *linuxManager) setSourceRoute(p *pathState, remote PathEndpoint) error {
	if p.srcRoute != nil {
		if p.srcRoute.Dst != nil && p.srcRoute.Dst.IP.Equal(remote.Addr.AsSlice()) {
			return nil
		}
		m.removeSourceRoute(p)
	}

	routes, err := netlink.RouteGet(remote.Addr.AsSlice())
	if err != nil {
		return fmt.Errorf("multipath: route to %s: %w", remote.Addr, err)
	}
	if len(routes) == 0 {
		return fmt.Errorf("multipath: no route to %s", remote.Addr)
	}
	underlay := routes[0]
	route := &netlink.Route{
		Dst:       prefixToIPNet(netip.PrefixFrom(remote.Addr, remote.Addr.BitLen())),
		LinkIndex: underlay.LinkIndex,
		Src:       p.local.AsSlice(),
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("multipath: add source route for %s: %w", remote.Addr, err)
	}
	p.srcRoute = route
	return nil
}

func (m *linuxManager) removeSourceRoute(p *pathState) {
	if p.srcRoute == nil {
		return
	}
	if err := netlink.RouteDel(p.srcRoute); err != nil {
		m.log.Debugf("remove source route %s: %v", p.srcRoute.Dst, err)
	}
	p.srcRoute = nil
}

// applyRouteLocked installs the ECMP route group for the peer's overlay
// addresses, including only paths that are up. Callers must hold m.mu.
func (m *linuxManager) applyRouteLocked(peer *peerPaths) {
	devs := []int{m.mainIface}
	for idx := 1; idx <= len(peer.extras); idx++ {
		p := peer.extras[idx]
		if p == nil || p.state != PathStateUp || !p.remote.IsValid() {
			continue
		}
		devs = append(devs, p.linkIndex)
	}

	// Keep the group only while at least two paths are up and there is an
	// overlay address to spread; otherwise remove every installed group.
	keep := make(map[netip.Addr]bool)
	if len(devs) >= 2 {
		for _, overlay := range peer.overlayIPs {
			keep[overlay] = true
		}
	}
	for _, old := range peer.installed {
		if !keep[old] {
			m.deleteRoute(old)
		}
	}
	peer.installed = nil

	if len(devs) < 2 || len(peer.overlayIPs) == 0 {
		return
	}

	m.ensureHashPolicy()

	for _, overlay := range peer.overlayIPs {
		m.replaceRoute(overlay, devs)
	}
	peer.installed = append([]netip.Addr(nil), peer.overlayIPs...)
}

func (m *linuxManager) replaceRoute(overlay netip.Addr, devs []int) {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()

	nexthops := make([]*netlink.NexthopInfo, 0, len(devs))
	for _, dev := range devs {
		nexthops = append(nexthops, &netlink.NexthopInfo{LinkIndex: dev, Hops: 1})
	}
	route := &netlink.Route{
		Dst:       prefixToIPNet(netip.PrefixFrom(overlay, overlay.BitLen())),
		MultiPath: nexthops,
	}
	// Pin the inner source to our overlay address. Without it the source is
	// selected from the hash-selected nexthop's device, and a path interface
	// has no address of its own, so locally generated flows could leave with
	// an unrelated source address and be dropped by the peer.
	if m.cfg.LocalOverlay.IsValid() && m.cfg.LocalOverlay.Is4() {
		route.Src = m.cfg.LocalOverlay.AsSlice()
	}
	if err := netlink.RouteReplace(route); err != nil {
		m.log.Errorf("install multipath route for %s: %v", overlay, err)
	}
}

// clearRouteLocked removes the peer's route group so traffic falls back to the
// main connection. Callers must hold m.mu.
func (m *linuxManager) clearRouteLocked(peer *peerPaths) {
	if len(peer.installed) == 0 {
		return
	}
	for _, overlay := range peer.installed {
		m.deleteRoute(overlay)
	}
	peer.installed = nil
}

func (m *linuxManager) clearRoute(peer *peerPaths) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clearRouteLocked(peer)
}

func (m *linuxManager) deleteRoute(overlay netip.Addr) {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()

	route := &netlink.Route{
		Dst: prefixToIPNet(netip.PrefixFrom(overlay, overlay.BitLen())),
	}
	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, os.ErrNotExist) {
		m.log.Debugf("remove multipath route for %s: %v", overlay, err)
	}
}

// setPathState is called by the prober when a path goes up or down.
func (m *linuxManager) setPathState(peerKey string, idx int, up bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, ok := m.peers[peerKey]
	if !ok {
		return
	}
	p := peer.extras[idx]
	if p == nil {
		return
	}
	newState := PathStateDown
	if up {
		newState = PathStateUp
	}
	if p.state == newState {
		return
	}
	p.state = newState
	m.log.Infof("path %s (peer %s) is %s", p.name, peerKey, newState)
	m.applyRouteLocked(peer)
}

// removeExtrasLocked destroys every extra path of a peer. Callers must hold m.mu.
func (m *linuxManager) removeExtrasLocked(peer *peerPaths) {
	for _, p := range peer.extras {
		m.destroyPath(p)
	}
	peer.extras = make(map[int]*pathState)
}

// removePathLocked destroys one extra path. Callers must hold m.mu.
func (m *linuxManager) removePathLocked(peer *peerPaths, p *pathState) {
	delete(peer.extras, p.idx)
	m.destroyPath(p)
}

// destroyPath stops probing and removes the interface. It does not take m.mu:
// callers either hold it or have already detached the path from its peer.
func (m *linuxManager) destroyPath(p *pathState) {
	if p.prober != nil {
		p.prober.stop()
	}
	m.removeSourceRoute(p)
	if link, err := netlink.LinkByName(p.name); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			m.log.Debugf("remove path interface %s: %v", p.name, err)
		}
	}
}

func (m *linuxManager) peerPathListLocked(peer *peerPaths) []*pathState {
	if peer == nil {
		return nil
	}
	paths := make([]*pathState, 0, len(peer.extras))
	for idx := 1; idx <= len(peer.extras); idx++ {
		if p := peer.extras[idx]; p != nil {
			paths = append(paths, p)
		}
	}
	return paths
}

// ensureHashPolicy switches IPv4 multipath hashing to the 5-tuple when it is
// not already L4, remembering the original value.
func (m *linuxManager) ensureHashPolicy() {
	m.hashPolicyMu.Lock()
	defer m.hashPolicyMu.Unlock()

	if m.hashPolicyChange {
		return
	}
	raw, err := os.ReadFile(hashPolicyPath)
	if err != nil {
		m.log.Warnf("read %s: %v", hashPolicyPath, err)
		return
	}
	orig, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		m.log.Warnf("parse %s: %v", hashPolicyPath, err)
		return
	}
	m.hashPolicyOrig = orig
	if orig == hashPolicyL4 {
		return
	}
	if orig != 0 && orig != 2 {
		m.log.Warnf("multipath hashing is policy %d, leaving it unchanged; per-flow distribution may not work", orig)
		return
	}
	if err := os.WriteFile(hashPolicyPath, []byte(strconv.Itoa(hashPolicyL4)), 0o644); err != nil {
		m.log.Warnf("set %s: %v", hashPolicyPath, err)
		return
	}
	m.hashPolicyChange = true
	m.log.Infof("set IPv4 multipath hash policy to %d for per-flow path selection", hashPolicyL4)
}

func (m *linuxManager) restoreHashPolicy() {
	m.hashPolicyMu.Lock()
	defer m.hashPolicyMu.Unlock()

	if !m.hashPolicyChange {
		return
	}
	if err := os.WriteFile(hashPolicyPath, []byte(strconv.Itoa(m.hashPolicyOrig)), 0o644); err != nil {
		m.log.Warnf("restore %s: %v", hashPolicyPath, err)
		return
	}
	m.hashPolicyChange = false
}

func normalizeAddrs(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	seen := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

func validEndpoints(in []PathEndpoint) []PathEndpoint {
	out := make([]PathEndpoint, 0, len(in))
	for _, e := range in {
		e.Addr = e.Addr.Unmap()
		if e.Addr.IsValid() && !e.Addr.IsUnspecified() && e.Port != 0 {
			out = append(out, e)
		}
	}
	return out
}

// overlayAddrs returns the peer's own overlay addresses: host prefixes inside
// the local overlay network. Routed prefixes are larger and are ignored.
func overlayAddrs(allowed []netip.Prefix, overlay netip.Prefix) []netip.Addr {
	if !overlay.IsValid() {
		return nil
	}
	var out []netip.Addr
	for _, p := range allowed {
		p = p.Masked()
		if p.Bits() != p.Addr().BitLen() {
			continue
		}
		if overlay.Contains(p.Addr()) {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
}

func udpPort(conn *net.UDPConn) (uint16, error) {
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, errors.New("multipath: unexpected probe socket address")
	}
	return uint16(addr.Port), nil
}

func pathIfaceName(peerKey string, idx int) string {
	return fmt.Sprintf("%s%05x%d", pathIfacePrefix, peerHash(peerKey)&0xfffff, idx)
}

// peerHash is a stable hash of a peer key, used for interface names and
// deterministic path ports.
func peerHash(peerKey string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(peerKey); i++ {
		h ^= uint32(peerKey[i])
		h *= 16777619
	}
	return h
}

func durationPtr(d time.Duration) *time.Duration {
	return &d
}
