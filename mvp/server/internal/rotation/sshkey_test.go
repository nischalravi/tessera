package rotation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// readSSHString reads a length-prefixed string.
func readSSHString(t *testing.T, b []byte) (s, rest []byte) {
	t.Helper()
	if len(b) < 4 {
		t.Fatal("short buffer")
	}
	n := int(binary.BigEndian.Uint32(b))
	if len(b) < 4+n {
		t.Fatal("short string")
	}
	return b[4 : 4+n], b[4+n:]
}

func TestNewSSHKeyPair_WireFormat(t *testing.T) {
	pubLine, privPEM, err := newSSHKeyPair("tessera-test")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(pubLine)
	if len(fields) != 2 || fields[0] != "ssh-ed25519" {
		t.Fatalf("public key %q", pubLine)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	typ, rest := readSSHString(t, blob)
	pub, rest := readSSHString(t, rest)
	if string(typ) != "ssh-ed25519" || len(pub) != ed25519.PublicKeySize || len(rest) != 0 {
		t.Fatalf("public blob: %q %d %d", typ, len(pub), len(rest))
	}

	block, _ := pem.Decode([]byte(privPEM))
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		t.Fatalf("private key PEM: %v", block)
	}
	b := block.Bytes
	magic := []byte("openssh-key-v1\x00")
	if !bytes.HasPrefix(b, magic) {
		t.Fatal("missing the openssh-key-v1 magic")
	}
	b = b[len(magic):]
	var s []byte
	for _, want := range []string{"none", "none", ""} {
		s, b = readSSHString(t, b)
		if string(s) != want {
			t.Fatalf("cipher/kdf header %q, want %q", s, want)
		}
	}
	if binary.BigEndian.Uint32(b) != 1 {
		t.Fatal("want one key")
	}
	pubBlob, b := readSSHString(t, b[4:])
	if !bytes.Equal(pubBlob, blob) {
		t.Error("the embedded public key differs from the authorized_keys line")
	}
	section, b := readSSHString(t, b)
	if len(b) != 0 || len(section)%8 != 0 {
		t.Fatalf("private section: %d bytes left, length %d", len(b), len(section))
	}
	if !bytes.Equal(section[:4], section[4:8]) {
		t.Error("the check integers differ")
	}
	typ, section = readSSHString(t, section[8:])
	pub2, section := readSSHString(t, section)
	priv, section := readSSHString(t, section)
	comment, pad := readSSHString(t, section)
	if string(typ) != "ssh-ed25519" || !bytes.Equal(pub2, pub) || string(comment) != "tessera-test" {
		t.Errorf("private section: %q %q", typ, comment)
	}
	if len(priv) != ed25519.PrivateKeySize || !bytes.Equal(priv[32:], pub) {
		t.Errorf("private key is %d bytes", len(priv))
	}
	for i, p := range pad {
		if int(p) != i+1 {
			t.Errorf("padding %v", pad)
			break
		}
	}
	// the key pair works
	msg := []byte("deploy")
	if !ed25519.Verify(pub, msg, ed25519.Sign(priv, msg)) {
		t.Error("the private key does not match the public key")
	}
}

// When OpenSSH is installed it must accept the key and print the same public key.
func TestNewSSHKeyPair_OpenSSHAccepts(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	pubLine, privPEM, err := newSSHKeyPair("tessera-test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id")
	if err := writeFile0600(path, privPEM); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(keygen, "-y", "-f", path).CombinedOutput() // #nosec G204 -- fixed binary, temp path
	if err != nil {
		t.Fatalf("ssh-keygen -y: %v: %s", err, out)
	}
	if got := strings.Fields(string(out)); len(got) < 2 || got[0]+" "+got[1] != pubLine {
		t.Errorf("ssh-keygen derived %q, want %q", out, pubLine)
	}
}

func writeFile0600(path, content string) error { return osWriteFile(path, []byte(content)) }
