package client

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/shared/signal/proto"
)

func TestMarshalCredentialMultipath(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	msg, err := MarshalCredential(key, "remote-key", CredentialPayload{
		Type:       proto.Body_OFFER,
		Credential: &Credential{UFrag: "ufrag", Pwd: "pwd"},
		Features:   []uint32{DirectCheck, Multipath},
		MultipathPaths: []PathEndpoint{
			{IP: netip.MustParseAddr("192.168.6.161"), Port: 51821, ProbePort: 51822},
			{IP: netip.MustParseAddr("fd00::1"), Port: 51823, ProbePort: 51824},
		},
	})
	require.NoError(t, err)

	assert.Equal(t, []uint32{DirectCheck, Multipath}, msg.GetBody().GetFeaturesSupported())

	paths := msg.GetBody().GetMultipathPaths()
	require.Len(t, paths, 2, "both endpoints must be marshalled")
	assert.Equal(t, []byte{192, 168, 6, 161}, paths[0].GetIp())
	assert.Equal(t, uint32(51821), paths[0].GetPort())
	assert.Equal(t, uint32(51822), paths[0].GetProbePort())
	assert.Len(t, paths[1].GetIp(), 16)
	assert.Equal(t, uint32(51823), paths[1].GetPort())
}

func TestMarshalCredentialDropsInvalidPaths(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	msg, err := MarshalCredential(key, "remote-key", CredentialPayload{
		Type:       proto.Body_ANSWER,
		Credential: &Credential{UFrag: "ufrag", Pwd: "pwd"},
		MultipathPaths: []PathEndpoint{
			{Port: 51820},
			{IP: netip.MustParseAddr("10.0.0.1")},
			{IP: netip.MustParseAddr("10.0.0.2"), Port: 51821},
		},
	})
	require.NoError(t, err)
	require.Len(t, msg.GetBody().GetMultipathPaths(), 1)
	assert.Equal(t, uint32(51821), msg.GetBody().GetMultipathPaths()[0].GetPort())
}
