package seal

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var (
	tenA = tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	tenB = tenancy.MustParse("00000000-0000-4000-8000-0000000000b1")
)

func agentAAD(t *testing.T, tn tenancy.ID, agent, conn, job string) []byte {
	t.Helper()
	aad, ok := AgentAAD(tn, agent, conn, job)
	if !ok {
		t.Fatal("AgentAAD refused valid ids")
	}
	return aad
}

func TestAgentSealRoundTrip(t *testing.T) {
	priv, err := GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseAgentPublicKey(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	aad := agentAAD(t, tenA, "agent-1", "conn-1", "job-1")
	secret := []byte("scim-bearer-token-0123456789")
	sealed, err := SealToAgent(pub, secret, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) || sealed[0] != AgentVersion || len(sealed) != 1+AgentKeySize+12+len(secret)+16 {
		t.Fatalf("sealed blob looks wrong: version %#x, %d bytes", sealed[0], len(sealed))
	}
	got, err := OpenFromAgent(priv, sealed, aad)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open = %q, %v", got, err)
	}
	// every seal is different (fresh ephemeral key and nonce)
	again, _ := SealToAgent(pub, secret, aad)
	if bytes.Equal(sealed, again) {
		t.Error("two seals of the same value are identical")
	}
}

// A blob opens only for the agent it was sealed to, and only with the binding
// it was sealed under: another tenant, agent, connection or job cannot open it.
func TestAgentSealBinding(t *testing.T) {
	priv, _ := GenerateAgentKey()
	other, _ := GenerateAgentKey()
	aad := agentAAD(t, tenA, "agent-1", "conn-1", "job-1")
	sealed, err := SealToAgent(priv.PublicKey(), []byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		key *ecdh.PrivateKey
		aad []byte
	}{
		"another agent's key":   {other, aad},
		"another tenant":        {priv, agentAAD(t, tenB, "agent-1", "conn-1", "job-1")},
		"another agent id":      {priv, agentAAD(t, tenA, "agent-2", "conn-1", "job-1")},
		"another connection":    {priv, agentAAD(t, tenA, "agent-1", "conn-2", "job-1")},
		"another job":           {priv, agentAAD(t, tenA, "agent-1", "conn-1", "job-2")},
		"no binding":            {priv, nil},
		"another purpose (KEK)": {priv, AAD(tenA, "provisioning_targets", "credential_enc", "agent-1")},
	} {
		if _, err := OpenFromAgent(tc.key, sealed, tc.aad); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: opened (%v)", name, err)
		}
	}
	// tampering with any part fails: version, ephemeral key, nonce, ciphertext, tag, truncation
	for i := range sealed {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0x01
		if _, err := OpenFromAgent(priv, bad, aad); err == nil {
			t.Fatalf("a flipped bit at byte %d still opened", i)
		}
	}
	for _, n := range []int{0, 1, 10, 45, len(sealed) - 1} {
		if _, err := OpenFromAgent(priv, sealed[:n], aad); err == nil {
			t.Errorf("a blob cut to %d bytes opened", n)
		}
	}
	// the server's KEK sealing and the agent sealing are different formats: neither opens the other
	s, _ := New(bytes.Repeat([]byte{7}, KeySize))
	kekBlob, _ := s.Seal([]byte("secret"), aad)
	if _, err := OpenFromAgent(priv, kekBlob, aad); err == nil {
		t.Error("a KEK-sealed blob opened as an agent blob")
	}
	if _, err := s.Open(sealed, aad); err == nil {
		t.Error("an agent blob opened under the KEK")
	}
}

func TestAgentPublicKeyValidation(t *testing.T) {
	priv, _ := GenerateAgentKey()
	if _, err := ParseAgentPublicKey(priv.PublicKey().Bytes()); err != nil {
		t.Errorf("valid key: %v", err)
	}
	for name, b := range map[string][]byte{
		"empty": nil, "short": make([]byte, 31), "long": make([]byte, 33),
		"all zero (low order)": make([]byte, 32), "one (low order)": append([]byte{1}, make([]byte, 31)...),
	} {
		if _, err := ParseAgentPublicKey(b); !errors.Is(err, ErrAgentKey) {
			t.Errorf("%s accepted (%v)", name, err)
		}
	}
	if id := AgentKeyID(priv.PublicKey().Bytes()); len(id) != 16 || id != AgentKeyID(priv.PublicKey().Bytes()) {
		t.Errorf("key id = %q", id)
	}
}

func TestAgentAADRefusesBadParts(t *testing.T) {
	for name, parts := range map[string][3]string{
		"empty agent": {"", "c", "j"}, "empty connection": {"a", "", "j"}, "empty job": {"a", "c", ""},
		"separator in agent": {"a|b", "c", "j"}, "separator in job": {"a", "c", "j|k"},
	} {
		if _, ok := AgentAAD(tenA, parts[0], parts[1], parts[2]); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, ok := AgentAAD(tenancy.ID{}, "a", "c", "j"); ok {
		t.Error("the zero tenant was accepted")
	}
	if _, err := SealToAgent(nil, []byte("x"), []byte("aad")); err == nil {
		t.Error("sealed to no key")
	}
}
