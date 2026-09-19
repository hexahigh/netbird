# Multipath

Multipath spreads a peer connection over several underlay paths so that a
single overlay peer can use more than one physical link at a time. It exists
for the case where the underlay cannot spread the traffic itself: a single
WireGuard UDP flow takes exactly one member of an LACP bond, no matter how
many inner TCP streams run over it.

The feature is off by default.

## Requirements

- Linux with kernel WireGuard (the userspace and netstack interface modes fall
  back to a single path).
- At least two underlay addresses on the peer machines, each reachable from
  the other peer. The addresses must be on the path the switch can spread
  across, usually aliases on the bonded interface.
- Version 0.80 or newer on both ends. Peers negotiate the capability in the
  signal channel; a peer that does not advertise it stays on a single path.
- A firewall backend that can cover extra interfaces. The nftables backend
  does. When another backend is active, multipath is disabled instead of
  running with uncovered interfaces.

## Switching it on

```
netbird up --multipath \
  --multipath-local-addresses 10.10.0.11 \
  --multipath-max-paths 2
```

Each node lists the addresses that the *other* node should use for its
additional paths. The address used by the main connection must not be listed;
the first extra address becomes path 1, the next path 2, and so on. Both peers
pair their paths by position, so node A's path 1 talks to node B's path 1.

Flags and environment variables:

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--multipath` | `NB_MULTIPATH` | `false` | Enable extra underlay paths. |
| `--multipath-max-paths` | `NB_MULTIPATH_MAX_PATHS` | `2` | Total paths per peer, including the main connection (2-8). |
| `--multipath-local-addresses` | `NB_MULTIPATH_LOCAL_ADDRESSES` | empty | Extra underlay addresses, comma separated. |
| `--multipath-mode` | `NB_MULTIPATH_MODE` | `flow` | Path selection mode. Kernel mode supports `flow` only. |

Settings are persisted in the profile like other `netbird up` options.

## How it works

The existing connection stays path 0. Every additional path is a kernel
WireGuard interface (`wtp...`) that shares the main interface's keypair and
carries its own listen port and peer endpoint. Each path emits outer traffic
from its own underlay address, so a layer 3 bond hash sees distinct address
pairs for the paths.

One ECMP route per peer overlay address spreads the inner flows:

```
100.64.0.3/32
    nexthop dev wt0
    nexthop dev wtp9bea91
```

The kernel hashes the inner 5-tuple (`fib_multipath_hash_policy=1`), so a TCP
flow stays on one path while independent flows spread. Packets inside one
flow are never reordered. The policy is saved and restored when the client
stops.

Each path runs a small UDP echo prober on a separate port. A path that misses
three probes is removed from the route group; three successful probes put it
back. The relay remains the fallback when every direct path is gone.

Bond member placement is measured, not guessed. When a path is configured the
client steers the peer's overlay traffic through the path, sends a short UDP
burst, and reads the bond member counters to see which member carried it. If
the path landed on the same member as the main connection, the client moves it
to a different listen port and measures again, then tells the remote peer the
new endpoint with a fresh offer. The measurement adapts to any bond hash
policy, and it is skipped on underlays that are not bonds. The chosen member is
logged per path and repeated offers with the same endpoints skip the
measurement.

## Status and metrics

`netbird status --json` lists the paths of each peer:

```json
"paths": [
  {
    "local": "10.10.0.11:44851",
    "remote": "10.10.0.21:43573",
    "interface": "wtp9bea91",
    "state": "up",
    "transferSent": 123,
    "transferReceived": 456,
    "lastWireguardHandshake": "2026-09-19T14:34:51Z",
    "loss": 0
  }
]
```

With `--enable-local-metrics`, per-path metrics are exposed on the local
endpoint:

- `netbird_peer_path_up{peer,path,local,remote}`
- `netbird_peer_path_rtt_seconds{peer,path}`
- `netbird_peer_path_loss_ratio{peer,path}`
- `netbird_peer_path_transmit_bytes_total{peer,path}`
- `netbird_peer_path_receive_bytes_total{peer,path}`

## Limitations

- Kernel WireGuard on Linux only. The userspace data plane is unchanged.
- Flow hashing only. A single inner flow stays on one path, so a single
  `iperf3 -c ... -P 1` stream does not exceed one link.
- IPv4 overlay addresses are spread. IPv6 overlay traffic keeps using the
  main path because the kernel rejects device-only IPv6 multipath nexthops.
- One pair of path interfaces per peer and path, so the interface count grows
  with peers times paths. Keep `--multipath-max-paths` small.
- Both underlay addresses should be behind the same bond. Placement moves the
  path flows to different members automatically, but a bond hash that ignores
  ports cannot be influenced from the client.
- Relay, lazy connections and Rosenpass keep working: a lazy peer only gets
  paths while its connection is open, and Rosenpass keys are applied to every
  path interface. Multipath is not a replacement for the relay fallback.

## Benchmark on a local test cluster

Two nodes on the same layer 2 segment, each with a 2x1 Gbit LACP bond and one
extra underlay address. Replace the example addresses and interface names with
the ones on your test nodes.

```bash
# Node A (underlay 192.168.1.10, overlay 100.64.0.2)
sudo ip addr add 192.168.1.11/24 dev bond0
netbird up --multipath --multipath-local-addresses 192.168.1.11

# Node B (underlay 192.168.1.20, overlay 100.64.0.3)
sudo ip addr add 192.168.1.21/24 dev bond0
netbird up --multipath --multipath-local-addresses 192.168.1.21

# Aggregate throughput, expecting close to the sum of the links
iperf3 -c 100.64.0.3 -P 8 -t 20

# Single stream stays on one link
iperf3 -c 100.64.0.3 -P 1 -t 10

# Bond member usage during a run
for i in eth0 eth1; do
  echo "$i $(cat /sys/class/net/$i/statistics/tx_bytes)"
done
```

Failover check, on the receiving node:

```bash
sudo iptables -I INPUT 1 -s 192.168.1.11 -j DROP   # drop path 1
# throughput drops to one link, the connection stays up
sudo iptables -D INPUT -s 192.168.1.11 -j DROP     # recover
```

Measured on a local test cluster (kernel WireGuard, 2x1 Gbit LACP):

| Test | Result |
| --- | --- |
| `iperf3 -P 8` with two paths | 1799-1803 Mbit/s, 0 retransmits |
| `iperf3 -P 1` | 896 Mbit/s |
| UDP, single flow at 850 Mbit/s offered | 0.82% loss |
| Path 1 blocked during a 30s `-P 8` run | 1806 Mbit/s, then 901 Mbit/s on the main path for 10s, recovery to 1109 Mbit/s |
| Bond member split during `-P 8` | roughly half of the bytes on each member |

## Troubleshooting

- `netbird status --json` shows no paths: check that both peers run a
  multipath-capable build, `--multipath` is enabled, and the extra addresses
  exist locally (`ip -brief addr`).
- Paths exist but stay `down`: the probe port is not reachable. Check that the
  addresses are routable between the nodes and that no firewall drops UDP
  between the path addresses. Probes use an ephemeral UDP port on the path
  address, not the WireGuard port.
- Aggregation does not exceed one link: check the client log for the per-path
  bond member line. A bond hash that ignores ports (for example a layer 2
  policy) cannot be spread by moving path ports and is reported as such.
- Placement measurements need real traffic: the log line appears a moment
  after the path comes up. Without a WireGuard session on the path the burst
  is not encrypted and the member cannot be measured.
- Multipath is disabled with a firewall error: the active firewall backend
  cannot cover extra interfaces. Use nftables or disable the NetBird firewall.
