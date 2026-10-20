package loaders_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestFiles_PerTenant: a file source is confined to <data dir>/<tenant id>/. A
// loader of tenant A cannot read what tenant B put in the shared data directory,
// by a relative path, an absolute path or a symbolic link; it reads its own.
func TestFiles_PerTenant(t *testing.T) {
	h := newHarness(t)
	other := tenancy.MustParse("00000000-0000-4000-8000-0000000000f8")
	otherDir := filepath.Join(h.base, other.String())
	if err := os.MkdirAll(otherDir, 0o750); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(otherDir, "theirs.csv")
	if err := os.WriteFile(secret, []byte(people(seq(0, 5)...)), 0o600); err != nil {
		t.Fatal(err)
	}
	// a file straight in the shared directory belongs to no tenant
	if err := os.WriteFile(filepath.Join(h.base, "shared.csv"), []byte(people(seq(0, 5)...)), 0o600); err != nil {
		t.Fatal(err)
	}
	h.write("mine.csv", people(seq(0, 3)...))

	try := func(name, cfgPath string) *store.GrpLoaderRun {
		t.Helper()
		spec := loaders.Spec{Name: name, Type: loaders.TypeCSV, TargetFolder: string(h.folder(name)),
			Config: []byte(fmt.Sprintf(`{"path":%q,"group":"g","subject_column":"id"}`, cfgPath))}
		var l *store.GrpLoader
		err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
			var err error
			l, err = loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now}, spec, "")
			return err
		})
		if err != nil {
			// refused when saved: also fine (relative escapes and absolute paths)
			return nil
		}
		return h.run(l, store.RunFull)
	}
	if r := try("own", "mine.csv"); r == nil || r.Status != store.RunApplied {
		t.Fatalf("own file = %+v", r)
	}
	for name, p := range map[string]string{
		"relative": "../" + other.String() + "/theirs.csv",
		"absolute": secret,
		"shared":   "../shared.csv",
		"no such":  other.String() + "/theirs.csv", // inside A's directory it does not exist
	} {
		if r := try(strings.ReplaceAll(name, " ", ""), p); r != nil && r.Status != store.RunFailed {
			t.Errorf("%s path %q: run = %+v, want a refusal", name, p, r)
		}
	}
	// a symbolic link in A's directory to B's file, to B's directory and to the shared file
	for name, target := range map[string]string{"linkfile.csv": secret, "linkdir": otherDir, "linkshared.csv": filepath.Join(h.base, "shared.csv")} {
		if err := os.Symlink(target, filepath.Join(h.dir, name)); err != nil {
			t.Skipf("no symbolic links: %v", err)
		}
	}
	for name, p := range map[string]string{"sfile": "linkfile.csv", "sdir": "linkdir/theirs.csv", "sshared": "linkshared.csv"} {
		r := try(name, p)
		if r == nil || r.Status != store.RunFailed || !strings.Contains(*r.Error, "source_file_outside") {
			t.Errorf("link %q: run = %+v, want source_file_outside", p, r)
		}
	}
	// the tenant's own directory may itself not be a link out of the data directory
	h.svc.DataDir = filepath.Join(h.base, other.String()) // a data dir whose tenant subdirectory does not exist
	if r := try("nodir", "mine.csv"); r == nil || r.Status != store.RunFailed || !strings.Contains(*r.Error, "source_file_missing") {
		t.Errorf("tenant without a directory: run = %+v", r)
	}
	// and no group of tenant A was ever filled from B's file
	for _, g := range []string{"own:g", "relative:g", "absolute:g", "shared:g", "sfile:g", "sdir:g", "sshared:g"} {
		h.read(func(tx *store.TenantTx) error {
			if grp, err := tx.GrpGroupByName(g); err == nil && g != "own:g" {
				if n, _ := tx.GrpEffectiveCount(grp.ID, store.MembersListID(tid)); n != 0 {
					t.Errorf("group %s has %d members", g, n)
				}
			}
			return nil
		})
	}
	wantMembers(t, h, "own:g", seq(0, 3))
}
