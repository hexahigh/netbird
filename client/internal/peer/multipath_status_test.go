package peer

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/multipath"
)

func TestFullStatusToProtoPaths(t *testing.T) {
	handshake := time.Unix(1700000000, 0)
	fs := FullStatus{
		PathProvider: func(peerKey string) []multipath.PathStatus {
			if peerKey != "peer-key" {
				return nil
			}
			return []multipath.PathStatus{{
				Local:         multipath.PathEndpoint{Addr: netip.MustParseAddr("192.168.6.161"), Port: 51821, ProbePort: 51822},
				Remote:        multipath.PathEndpoint{Addr: netip.MustParseAddr("192.168.6.171"), Port: 51821, ProbePort: 51822},
				Interface:     "wtp1",
				State:         multipath.PathStateUp,
				TxBytes:       100,
				RxBytes:       200,
				LastHandshake: handshake,
				RTT:           5 * time.Millisecond,
				Loss:          0.25,
			}}
		},
		Peers: []State{{
			Mux:        new(sync.RWMutex),
			PubKey:     "peer-key",
			ConnStatus: StatusConnected,
		}},
	}

	pb := fs.ToProto()
	require.Len(t, pb.GetPeers(), 1)
	require.Len(t, pb.GetPeers()[0].GetPaths(), 1)

	path := pb.GetPeers()[0].GetPaths()[0]
	assert.Equal(t, "192.168.6.161:51821", path.GetLocal())
	assert.Equal(t, "192.168.6.171:51821", path.GetRemote())
	assert.Equal(t, "wtp1", path.GetIface())
	assert.Equal(t, "up", path.GetState())
	assert.Equal(t, int64(100), path.GetTxBytes())
	assert.Equal(t, int64(200), path.GetRxBytes())
	assert.Equal(t, handshake.Unix(), path.GetLastHandshake())
	assert.Equal(t, int64(5), path.GetRttMillis())
	assert.Equal(t, 0.25, path.GetLoss())
}
