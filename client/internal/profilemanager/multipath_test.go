package profilemanager

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultipathConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	enabled := true
	mode := "flow"
	maxPaths := 3
	addrs := []string{"192.168.6.161", "192.168.6.162"}

	config, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:              path,
		Multipath:               &enabled,
		MultipathMode:           &mode,
		MultipathMaxPaths:       &maxPaths,
		MultipathLocalAddresses: addrs,
	})
	require.NoError(t, err)
	assert.True(t, config.Multipath)
	assert.Equal(t, "flow", config.MultipathMode)
	assert.Equal(t, 3, config.MultipathMaxPaths)
	assert.Equal(t, addrs, config.MultipathLocalAddresses)

	reloaded, err := GetConfig(path)
	require.NoError(t, err)
	assert.True(t, reloaded.Multipath)
	assert.Equal(t, "flow", reloaded.MultipathMode)
	assert.Equal(t, 3, reloaded.MultipathMaxPaths)
	assert.Equal(t, addrs, reloaded.MultipathLocalAddresses)
}

func TestMultipathConfigDefaults(t *testing.T) {
	config, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	})
	require.NoError(t, err)
	assert.False(t, config.Multipath)
	assert.Equal(t, "flow", config.MultipathMode)
	assert.Equal(t, 2, config.MultipathMaxPaths)
}
