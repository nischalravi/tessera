package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRoundTrip(t *testing.T) {
	res := compileFixture(t, "upstream-v1", "2026-10-01", true)
	enc, err := Encode(res.Compiled)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	v := res.Compiled.Version
	writeFile(t, CompiledPath(dir, v), string(enc))

	c, err := Load(dir, v)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version() != v || c.NumActions() != 11 {
		t.Errorf("version %s, %d actions", c.Version(), c.NumActions())
	}
	if got := names(c, c.Expand("kms:*")); !equalStrings(got, []string{"kms:CreateGrant", "kms:Decrypt", "kms:Encrypt"}) {
		t.Errorf("Expand = %v", got)
	}
	// same answers as the catalog built directly from the compile result
	direct, err := New(res.Compiled)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"*", "s3:*", "s3:Get*", "kms:*Grant"} {
		if !equalStrings(names(c, c.Expand(p)), names(direct, direct.Expand(p))) {
			t.Errorf("Expand(%q) differs between loaded and direct catalog", p)
		}
	}

	list, err := ListCompiled(dir)
	if err != nil || len(list) != 1 || list[0].Version != v || list[0].Snapshot != "2026-10-01" {
		t.Errorf("ListCompiled = %+v, %v", list, err)
	}
}

func TestLoadRejects(t *testing.T) {
	res := compileFixture(t, "upstream-v1", "2026-10-01", true)
	enc, err := Encode(res.Compiled)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	v := res.Compiled.Version
	writeFile(t, CompiledPath(dir, v), string(enc))

	// a file stored under another (valid) version name is refused
	other := "2026-10-01-0123456789abcdef"
	writeFile(t, CompiledPath(dir, other), string(enc))
	if _, err := Load(dir, other); err == nil || !strings.Contains(err.Error(), "holds version") {
		t.Errorf("renamed artifact: %v", err)
	}
	// a damaged file is refused
	damaged := "2026-10-02-0123456789abcdef"
	writeFile(t, CompiledPath(dir, damaged), string(enc[:len(enc)-20]))
	if _, err := Load(dir, damaged); err == nil {
		t.Error("truncated artifact")
	}
	for _, bad := range []string{"", "latest", "../" + v, v + "/../x", strings.ToUpper(v), "2026-10-01", "2026-13-01-zzzzzzzzzzzzzzzz"} {
		if _, err := Load(dir, bad); err == nil || !strings.Contains(err.Error(), "invalid catalog version") {
			t.Errorf("Load(%q) = %v", bad, err)
		}
	}
	if _, err := Load(dir, "2030-01-01-0123456789abcdef"); err == nil {
		t.Error("missing artifact")
	}
	if _, err := Load(t.TempDir(), v); err == nil {
		t.Error("empty catalog directory")
	}
}

func TestListCompiledAndSnapshots(t *testing.T) {
	dir := t.TempDir()
	if l, err := ListCompiled(dir); err != nil || l != nil {
		t.Errorf("missing directory: %v %v", l, err)
	}
	if l, err := ListSnapshots(dir); err != nil || l != nil {
		t.Errorf("missing directory: %v %v", l, err)
	}
	for _, f := range []string{"2026-10-08-aaaaaaaaaaaaaaaa", "2026-10-01-bbbbbbbbbbbbbbbb"} {
		writeFile(t, CompiledPath(dir, f), "x")
	}
	writeFile(t, filepath.Join(dir, "compiled", "notes.txt"), "x")
	writeFile(t, filepath.Join(dir, "compiled", "junk.json.gz"), "x")
	l, err := ListCompiled(dir)
	if err != nil || len(l) != 2 || l[0].Snapshot != "2026-10-01" || l[1].Snapshot != "2026-10-08" {
		t.Errorf("ListCompiled = %+v, %v", l, err)
	}
	for _, d := range []string{"2026-10-08", "2026-10-01", "tmp", ".tmp-2026-10-09-x"} {
		if err := os.MkdirAll(filepath.Join(dir, "snapshots", d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(dir, "snapshots", "2026-10-09"), "a file, not a snapshot")
	s, err := ListSnapshots(dir)
	if err != nil || !equalStrings(s, []string{"2026-10-01", "2026-10-08"}) {
		t.Errorf("ListSnapshots = %v, %v", s, err)
	}
}

func TestNewRejectsInconsistentCompiled(t *testing.T) {
	base := func() *Compiled {
		return &Compiled{Schema: SchemaVersion, Snapshot: "2026-10-01", Services: []CService{
			{Prefix: "a", Actions: []CAction{{Name: "a:One"}}},
			{Prefix: "b", Actions: []CAction{{Name: "b:Two"}}},
		}}
	}
	if _, err := New(base()); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Compiled)
		want   string
	}{
		{"services out of order", func(c *Compiled) { c.Services[0], c.Services[1] = c.Services[1], c.Services[0] }, "out of order"},
		{"duplicate service", func(c *Compiled) { c.Services[1].Prefix = "a" }, "out of order"},
		{"invalid prefix", func(c *Compiled) { c.Services[0].Prefix = "A" }, "invalid"},
		{"duplicate action", func(c *Compiled) { c.Services[0].Actions = append(c.Services[0].Actions, CAction{Name: "a:ONE"}) }, "duplicate action"},
		{"action in the wrong service", func(c *Compiled) { c.Services[0].Actions[0].Name = "b:One" }, "not in service"},
	}
	for _, tc := range tests {
		c := base()
		tc.mutate(c)
		if _, err := New(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: New = %v, want %q", tc.name, err, tc.want)
		}
	}
	if _, err := New(nil); err == nil {
		t.Error("nil")
	}
	// an empty catalog is usable: nothing matches
	c, err := New(&Compiled{Schema: SchemaVersion, Snapshot: "2026-10-01"})
	if err != nil || c.Expand("*").Len() != 0 || c.KeyType("x:y") == 0 {
		t.Errorf("empty catalog: %v", err)
	}
}
