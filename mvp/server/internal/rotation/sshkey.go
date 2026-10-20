package rotation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
)

// newSSHKeyPair generates an Ed25519 key pair for a GitHub deploy key: the
// public key in authorized_keys form and the private key in the unencrypted
// OpenSSH format (PEM type "OPENSSH PRIVATE KEY"), without x/crypto/ssh.
func newSSHKeyPair(comment string) (publicKey, privateKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	const keyType = "ssh-ed25519"
	blob := sshString(nil, []byte(keyType))
	blob = sshString(blob, pub)
	publicKey = keyType + " " + base64.StdEncoding.EncodeToString(blob)

	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		return "", "", err
	}
	var section []byte
	section = append(section, check[:]...)
	section = append(section, check[:]...)
	section = sshString(section, []byte(keyType))
	section = sshString(section, pub)
	section = sshString(section, priv) // seed || public key, 64 bytes
	section = sshString(section, []byte(comment))
	for i := byte(1); len(section)%8 != 0; i++ {
		section = append(section, i)
	}

	out := []byte("openssh-key-v1\x00")
	out = sshString(out, []byte("none")) // cipher
	out = sshString(out, []byte("none")) // kdf
	out = sshString(out, nil)            // kdf options
	out = binary.BigEndian.AppendUint32(out, 1)
	out = sshString(out, blob)
	out = sshString(out, section)
	privateKey = string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: out}))
	return publicKey, privateKey, nil
}

func sshString(dst, s []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s))) // #nosec G115 -- lengths here are a few dozen bytes
	return append(dst, s...)
}
