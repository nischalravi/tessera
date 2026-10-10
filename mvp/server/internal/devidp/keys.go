package devidp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// KeyFile is the OIDC signing key's file name inside the key directory.
const KeyFile = "oidc-signing-key.pem"

// LoadOrCreateKey returns the RS256 signing key stored in dir, generating it
// (PKCS#8 PEM, mode 0600, directory 0700) on first use. The dev IdP's keys are
// separate from Tessera's. A key file readable by group or others is refused.
func LoadOrCreateKey(dir string) (*rsa.PrivateKey, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(KeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		return createKey(root)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("devidp: %s is accessible by other users (mode %v); chmod 600 it", KeyFile, st.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("devidp: %s is not a PKCS#8 PEM private key", KeyFile)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok || rk.N.BitLen() < rsaKeyBits {
		return nil, fmt.Errorf("devidp: %s must hold an RSA key of at least %d bits", KeyFile, rsaKeyBits)
	}
	return rk, nil
}

func createKey(root *os.Root) (*rsa.PrivateKey, error) {
	k, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	// Write to a temporary file and rename, so a failed write never leaves a
	// truncated key behind.
	tmp := KeyFile + ".tmp"
	_ = root.Remove(tmp)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		_ = root.Remove(tmp)
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return nil, err
	}
	return k, root.Rename(tmp, KeyFile)
}
