package internal

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

func TestDecodeMultipathPaths(t *testing.T) {
	got := decodeMultipathPaths([]*sProto.PathEndpoint{
		{Ip: netip.MustParseAddr("192.168.6.161").AsSlice(), Port: 51821, ProbePort: 51822},
		{Ip: netip.MustParseAddr("fd00::1").AsSlice(), Port: 51823, ProbePort: 51824},
		{Ip: netip.MustParseAddr("192.168.6.162").AsSlice(), Port: 0},
		{Ip: []byte{1, 2, 3}},
		{Ip: netip.MustParseAddr("192.168.6.163").AsSlice(), Port: 70000},
		nil,
	})

	assert.Equal(t, 2, len(got), "only well-formed endpoints are decoded")
	assert.Equal(t, netip.MustParseAddr("192.168.6.161"), got[0].Addr)
	assert.Equal(t, uint16(51821), got[0].Port)
	assert.Equal(t, uint16(51822), got[0].ProbePort)
	assert.Equal(t, netip.MustParseAddr("fd00::1"), got[1].Addr)
}
