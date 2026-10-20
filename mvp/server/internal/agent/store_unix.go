//go:build !windows

package agent

// NewPlatformStore is the credential store of this platform: one file per
// secret in a 0700 directory, each file 0600.
func NewPlatformStore(dir string) (*FileStore, error) { return NewFileStore(dir) }
