//go:build !linux

package multipath

// NewManager reports that kernel multipath is not supported on this platform.
// The caller keeps the feature disabled.
func NewManager(_ Config) (Manager, error) {
	return nil, nil
}
