package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupsPolicyValidate(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	good := `permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo") when { principal in Tessera::Group::"ref:a" && principal.type == "person" };`
	write("groups/app/foo.cedar", good)
	var out, errb bytes.Buffer
	if err := run(t.Context(), []string{"groups", "policy", "validate", "-dir", dir}, &out, &errb); err != nil || !strings.Contains(out.String(), "policy files OK") {
		t.Fatalf("good: %v\n%s%s", err, out.String(), errb.String())
	}
	write("groups/app/bad.cedar", `permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:bad") when { context.x == "1" };`)
	write("groups/app/neg.cedar", `permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:neg") when { !(principal in Tessera::Group::"ref:a") };`)
	out.Reset()
	err := run(t.Context(), []string{"groups", "policy", "validate", "-dir", dir}, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "finding") || !strings.Contains(out.String(), "bad.cedar:1:") ||
		!strings.Contains(out.String(), "context is not available") {
		t.Fatalf("bad: %v\n%s", err, out.String())
	}
	for _, args := range [][]string{{"groups"}, {"groups", "policy"}, {"groups", "policy", "apply"}, {"groups", "policy", "validate", "-dir", filepath.Join(dir, "none")},
		{"groups", "policy", "validate", "-dir", t.TempDir()}} {
		if err := run(t.Context(), args, &out, &errb); err == nil {
			t.Errorf("%v succeeded", args)
		}
	}
	// two files for one group are a finding
	write("groups/app/neg.cedar", good)
	write("groups/app/bad.cedar", good)
	out.Reset()
	if err := run(t.Context(), []string{"groups", "policy", "validate", "-dir", dir}, &out, &errb); err == nil || !strings.Contains(out.String(), "duplicate_group") {
		t.Errorf("duplicate group: %v\n%s", err, out.String())
	}
}
