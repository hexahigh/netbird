// Package multipath spreads a peer's overlay traffic over several underlay
// paths. The main WireGuard connection stays the first path; extra paths are
// additional kernel WireGuard interfaces that share the same keypair, with a
// per-flow ECMP route selecting between them.
package multipath

import (
	"io"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PathState describes whether a path currently carries traffic.
type PathState string

const (
	// PathStateInactive means the path has no remote endpoint configured yet.
	PathStateInactive PathState = "inactive"
	// PathStateUp means probes succeed and the path is in the route group.
	PathStateUp PathState = "up"
	// PathStateDown means probes fail and the path is not in the route group.
	PathStateDown PathState = "down"
)

// PathEndpoint identifies one underlay path endpoint. The local and remote
// endpoint of a path are both described by this type.
type PathEndpoint struct {
	Addr      netip.Addr
	Port      uint16
	ProbePort uint16
}

// IsValid reports whether the endpoint carries a usable unicast address.
func (e PathEndpoint) IsValid() bool {
	return e.Addr.IsValid() && !e.Addr.IsUnspecified() && e.Port != 0
}

func (e PathEndpoint) String() string {
	if !e.Addr.IsValid() {
		return "invalid"
	}
	return netip.AddrPortFrom(e.Addr, e.Port).String()
}

// PathStatus is the observable state of one path.
type PathStatus struct {
	Local         PathEndpoint
	Remote        PathEndpoint
	Interface     string
	State         PathState
	TxBytes       int64
	RxBytes       int64
	LastHandshake time.Time
	RTT           time.Duration
	Loss          float64
}

// Config holds the local multipath settings.
type Config struct {
	Enabled bool
	// Mode is the scheduling mode. Only "flow" is supported in kernel mode.
	Mode string
	// MaxPaths is the total number of paths including the main connection.
	MaxPaths int
	// LocalAddresses are the extra underlay addresses to bind paths to. The
	// address used by the main connection must not be listed.
	LocalAddresses []netip.Addr
	// OverlayV4 is the local overlay IPv4 network, used to tell the peer's own
	// overlay addresses apart from routed prefixes in its allowed IPs.
	OverlayV4 netip.Prefix
	// WgIface is the main WireGuard interface name.
	WgIface string
	// PrivateKey is the local WireGuard private key, shared by all path
	// interfaces.
	PrivateKey wgtypes.Key
	// MTU is applied to every path interface.
	MTU uint16
}

// Manager owns the extra underlay paths of every peer.
type Manager interface {
	io.Closer

	// LocalPaths returns the extra paths advertised for a peer, creating the
	// path interfaces on first call.
	LocalPaths(peerKey string) ([]PathEndpoint, error)

	// Configure applies the remote peer's advertised paths. Passing an empty
	// slice removes the extra paths for this peer.
	Configure(peerKey string, remote []PathEndpoint, allowedIPs []netip.Prefix) error

	// SetPresharedKey applies a preshared key to every path peer.
	SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error

	// RemovePeer tears down all paths and routes of a peer.
	RemovePeer(peerKey string)

	// PathStates returns the current path status of a peer.
	PathStates(peerKey string) []PathStatus
}
