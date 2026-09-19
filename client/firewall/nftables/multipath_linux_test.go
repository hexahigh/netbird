//go:build !android

package nftables

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type mpIfaceMock struct{ name string }

func (m mpIfaceMock) Name() string            { return m.name }
func (m mpIfaceMock) Address() wgaddr.Address { return wgaddr.Address{} }

// TestIfaceNamesIncludePaths checks that the iptables-format accept rules and
// the interface list cover multipath path interfaces in addition to the main
// interface.
func TestIfaceNamesIncludePaths(t *testing.T) {
	j := mpIfaceMock{name: "wt0"}
	r := &family{
		wgIface:     j,
		extraIfaces: map[string]bool{"wtp1": true, "wtp2": true},
	}

	names := r.ifaceNames()
	assert.ElementsMatch(t, []string{"wt0", "wtp1", "wtp2"}, names)

	expected := [][]string{
		{"-i", "wt0", "-j", "ACCEPT"},
		{"-o", "wt0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		{"-i", "wtp1", "-j", "ACCEPT"},
		{"-o", "wtp1", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		{"-i", "wtp2", "-j", "ACCEPT"},
		{"-o", "wtp2", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	assert.ElementsMatch(t, expected, r.getAcceptForwardRules())

	inputExpected := [][]string{
		{"-i", "wt0", "-j", "ACCEPT"},
		{"-i", "wtp1", "-j", "ACCEPT"},
		{"-i", "wtp2", "-j", "ACCEPT"},
	}
	assert.ElementsMatch(t, inputExpected, r.getAcceptInputRules())
}
