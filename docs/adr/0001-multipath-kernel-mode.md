# ADR 0001: Kernel-mode multipath with ECMP over shared-key path interfaces

Status: accepted for the fork

## Context

A single WireGuard UDP flow cannot use more than one member of an LACP bond.
Measured on the glemmen cluster: a 2x1 Gbit layer 3+4 bond carries about
900 Mbit/s for a NetBird peer, while plain VXLAN spreads eight inner TCP flows
across both members at about 1.8 Gbit/s. Aggregation requires several outer
flows for the same peer plus a scheduler that assigns inner traffic to them.

The interface runs in kernel WireGuard mode on Linux. Kernel WireGuard has one
UDP socket per interface and one endpoint per peer, and it moves a peer's
endpoint to the source of any authenticated packet it receives, so several
sockets for the same peer on one interface are not usable.

## Decision

Scheduling is done by the kernel with an ECMP route per peer overlay address.
Path 0 is the existing connection. Paths 1..N-1 are extra kernel WireGuard
interfaces (`wtp...`) that:

- share the main interface's static keypair,
- have their own listen port, MTU, and peer endpoint,
- send outer traffic from their own underlay address through a preferred
  source host route installed before the peer endpoint, and
- carry an independent WireGuard session with the same remote key.

`ip route replace <peer overlay>/32 nexthop dev wt0 nexthop dev wtp1 ...`
spreads inner flows. `fib_multipath_hash_policy` is set to 1 so the hash uses
the inner 5-tuple, and is restored on close. A UDP echo prober per path
removes a dead interface from the route group and puts it back on recovery.
No key material is exchanged and the signal protocol only gains the list of
path endpoints.

## Why not the alternatives

- **Userspace TUN scheduler with per-path keypairs.** This was the original
  plan. It needs a per-path key exchange, a forwarding process in the data
  path, and raw-socket or mark-based injection into the per-path interfaces.
  ECMP moves the same decision into the kernel routing table with no
  userspace forwarding and no new keys.
- **nftables marks plus policy routing.** Locally generated packets get their
  route before the output hook runs, so a mark cannot reselect the path.
  Only forwarded (for example pod) traffic would be spread. Rejected.
- **A local proxy that forwards encrypted WireGuard packets over several
  paths.** The proxy sees only encrypted packets, so it cannot hash the inner
  flow; per-packet round robin would reorder TCP. Rejected.
- **Reusing one keypair on several interfaces.** Accepted and validated on
  the cluster. WireGuard sessions are per interface and peer, so each path
  handshakes independently with the same static key. This removes the key
  exchange entirely.

## Consequences

- The active interface remains path 0, so a single path keeps working exactly
  as before and peers without the capability are unaffected.
- IPv4 overlay addresses get route groups. IPv6 overlay multipath is not
  possible with ECMP: the kernel rejects device-only IPv6 multipath nexthops
  and WireGuard interfaces have no gateway. IPv6 traffic keeps using the main
  path.
- A single TCP flow stays on one path by design. Only `flow` scheduling is
  available in kernel mode.
- `fib_multipath_hash_policy` is a host-wide setting. It is set only while
  multipath routes exist and restored on close.
- Every path interface carries the same peer traffic, so the firewall must
  cover them. The nftables rules match a named interface set instead of a
  single name. When the active backend cannot do this, multipath is disabled
  rather than running with uncovered interfaces.
- Rosenpass rotates preshared keys per peer through the main interface. Path
  interfaces receive the same keys on creation and on every rotation, and a
  path created after a rotation is seeded from the current key.
- Interface count grows with peers times paths, so the path count is capped
  (default 2, maximum 8).
- Two path tuples can still land on the same member because the bond hash is
  not portable. Path listen ports are therefore deterministic, with a
  key-order based offset so the two ends differ, and
  `NB_MULTIPATH_PORT_OFFSET` shifts one end on hardware whose hash needs a
  different placement. Operators verify member usage with the counters. A
  runtime collision detector that re-rolls the port would remove the
  per-topology tuning and is left as follow-up work.
- The privileged lifecycle test covers path setup, promotion, demotion,
  recovery, and teardown, but not the LAG member distribution, which depends
  on the switch and is verified manually on the cluster.
