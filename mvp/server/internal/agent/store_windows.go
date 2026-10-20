//go:build windows

package agent

// NewPlatformStore is the credential store of this platform: files under dir,
// each value wrapped with Windows DPAPI.
func NewPlatformStore(dir string) (*FileStore, error) {
	return newFileStore(dir, dpapiProtect, dpapiUnprotect)
}
