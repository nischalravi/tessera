package rotation

import "os"

func osWriteFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }
