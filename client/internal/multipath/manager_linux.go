//go:build linux

package multipath

// NewManager is wired up in a later commit. Until then the feature is inert on
// Linux and the client keeps using the main connection only.
func NewManager(_ Config) (Manager, error) {
	return nil, nil
}
