//go:build !unix

package config

import "os"

// checkKEKOwner: there is no portable owner check outside unix.
func checkKEKOwner(os.FileInfo, string) error { return nil }
