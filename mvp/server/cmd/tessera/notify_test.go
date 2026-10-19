package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestNotifySealPassword: the password is read from stdin and printed sealed
// under the KEK; it is never echoed, and only that KEK opens it.
func TestNotifySealPassword(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	db := filepath.Join(t.TempDir(), "t.db")
	stdin = strings.NewReader("s3cret-relay-password\n")
	t.Cleanup(func() { stdin = os.Stdin })
	var out, errb bytes.Buffer
	if err := run(context.Background(), []string{"notify", "seal-password", "-db", db}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	sealed := strings.TrimSpace(out.String())
	if strings.Contains(out.String()+errb.String(), "s3cret") {
		t.Fatal("the password was echoed")
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("output %q is not base64: %v", sealed, err)
	}
	cfg, err := config.Load(func(k string) string { return map[string]string{"TESSERA_ENV": "dev"}[k] })
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := cfg.Sealer(config.DevKEKPath(db)) // the dev KEK the command generated
	if err != nil {
		t.Fatal(err)
	}
	if pw, err := sealer.Open(raw, seal.AAD(tenancy.Platform, "smtp", "password")); err != nil || string(pw) != "s3cret-relay-password" {
		t.Errorf("open = %q, %v", pw, err)
	}
	// the sealed value is accepted by the configuration it is meant for
	if _, err := config.Load(func(k string) string {
		return map[string]string{"TESSERA_ENV": "dev", "TESSERA_SMTP_HOST": "smtp.example.com", "TESSERA_SMTP_FROM": "t@example.com",
			"TESSERA_SMTP_USERNAME": "u", "TESSERA_SMTP_PASSWORD_SEALED": sealed}[k]
	}); err != nil {
		t.Errorf("config refused the sealed password: %v", err)
	}
}

func TestNotifyUsage(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{{"notify"}, {"notify", "frobnicate"}} {
		if err := run(context.Background(), args, &out, &errb); err == nil {
			t.Errorf("%v: want an error", args)
		}
	}
	if !strings.Contains(errb.String(), "seal-password") {
		t.Errorf("usage = %q", errb.String())
	}
	t.Setenv("TESSERA_ENV", "dev")
	stdin = strings.NewReader("\n")
	t.Cleanup(func() { stdin = os.Stdin })
	if err := run(context.Background(), []string{"notify", "seal-password", "-db", filepath.Join(t.TempDir(), "t.db")}, &out, &errb); err == nil {
		t.Error("an empty password was sealed")
	}
}
