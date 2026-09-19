//go:build linux

package multipath

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIngressFunnelled(t *testing.T) {
	mb := uint64(1 << 20)

	assert.False(t, ingressFunnelled(16*mb, map[string]uint64{"a": 8 * mb, "b": 8 * mb}),
		"an even split is not funnelled")
	assert.True(t, ingressFunnelled(16*mb, map[string]uint64{"a": 16 * mb, "b": mb}),
		"one member carrying almost everything is funnelled")
	assert.False(t, ingressFunnelled(2*mb, map[string]uint64{"a": 2 * mb, "b": 0}),
		"too little traffic to judge")
	assert.False(t, ingressFunnelled(16*mb, map[string]uint64{"a": 0, "b": 0}),
		"no counters moved")
	assert.False(t, ingressFunnelled(8*mb, map[string]uint64{"a": 6 * mb, "b": 5 * mb}),
		"background traffic can dominate one member without overlay concentration")
}
