package sftpdrop

import "testing"

// Fake is a running fake SFTP server for the external tests (governed_test.go).
type Fake struct {
	Port        string
	Fingerprint string
	KeyPEM      string
	Dir         string
	Write       func(name, content string)
}

// StartFake starts the in-process SFTP server over a temporary directory.
func StartFake(t *testing.T) Fake {
	t.Helper()
	signer, pem := newKey(t)
	s := startServer(t, signer.PublicKey())
	return Fake{Port: itoa(s.port()), Fingerprint: s.fingerprint(), KeyPEM: pem, Dir: s.dir, Write: func(n, c string) { s.write(t, n, c) }}
}
