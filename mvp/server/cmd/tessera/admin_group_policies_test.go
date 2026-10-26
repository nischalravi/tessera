package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestAdminCheckGroupPolicies (issue #698): the check re-parses the stored policy
// group sources with the Cedar-aligned fragment, lists the ones that now need a
// rewrite with line and column, and exits non-zero while there are any.
func TestAdminCheckGroupPolicies(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	ctx := context.Background()
	dir := t.TempDir()
	db := filepath.Join(dir, "t.db")
	st, err := store.OpenFresh(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if out, err := adminRun(t, db, "create-tenant", "-slug", "acme", "-name", "Acme Corp"); err != nil {
		t.Fatalf("create-tenant: %v %s", err, out)
	}
	if out, err := adminRun(t, db, "check-group-policies", "-tenant", "acme"); err != nil || !strings.Contains(out, "0 of 0") {
		t.Fatalf("empty tenant: %v %s", err, out)
	}
	st, err = store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var acme store.Tenant
	if err := st.ReadSystem(ctx, "test", func(s *store.SystemTx) error {
		var err error
		acme, err = s.TenantBySlug("acme")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	const head = `permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:%s")`
	srcs := map[string]string{
		"good": strings.Replace(head, "%s", "good", 1) + ` when { principal has department && principal.department == "cs" };`,
		"old":  strings.Replace(head, "%s", "old", 1) + ` when { principal.type in ["person", "agent"] };`,
	}
	if err := st.InTenant(ctx, acme.ID, func(tx *store.TenantTx) error {
		root := &store.Folder{CreatedAt: now}
		if err := tx.InsertGrpFolder(root); err != nil {
			return err
		}
		pid := root.ID
		fo := &store.Folder{ParentID: &pid, Extension: "app", DisplayExtension: "app", Name: "app", DisplayName: "app", CreatedAt: now}
		if err := tx.InsertGrpFolder(fo); err != nil {
			return err
		}
		for name, src := range srcs {
			g := &store.NativeGroup{FolderID: fo.ID, Extension: name, DisplayExtension: name, Name: "app:" + name, DisplayName: name, CreatedAt: now}
			if err := tx.InsertGrpGroup(g); err != nil {
				return err
			}
			if err := tx.SetGrpPolicySource(&store.GrpPolicySource{GroupID: g.ID, Origin: store.PolicyOriginRepo, Path: "groups/" + name + ".cedar",
				CommitSHA: "c1", Cedar: src, CedarSHA256: "h" + name, CompiledSHA256: "k" + name, AppliedAt: now}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	out, err := adminRun(t, db, "check-group-policies", "-tenant", "acme")
	if err == nil || !strings.Contains(out, "groups/old.cedar") || !strings.Contains(out, `.contains(principal.type)`) ||
		strings.Contains(out, "groups/good.cedar") || !strings.Contains(out, "1 of 2") {
		t.Errorf("check-group-policies: %v\n%s", err, out)
	}
	if out, err := adminRun(t, db, "check-group-policies", "-tenant", "nobody"); err == nil {
		t.Errorf("an unknown tenant: %s", out)
	}
}
