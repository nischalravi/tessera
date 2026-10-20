package provisioning

import (
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func TestService_SecretsAreSealedAndBound(t *testing.T) {
	x := newHarness(t, 1)
	p, _ := x.prov("scim", `{}`)
	var raw *store.Provisioner
	x.read(func(tx *store.TenantTx) error {
		var err error
		raw, err = tx.Provisioner(p.ID)
		return err
	})
	if len(raw.SecretEnc) == 0 || strings.Contains(string(raw.SecretEnc), "s3cr3t-token") {
		t.Fatalf("stored secret = %q", raw.SecretEnc)
	}
	sealer := x.svc.Sealer
	if _, err := sealer.Open(raw.SecretEnc, seal.AAD(tid, "grp_provisioners", "secret_enc", p.ID)); err != nil {
		t.Fatalf("the secret does not open under its own context: %v", err)
	}
	for name, aad := range map[string][]byte{
		"another provisioner": seal.AAD(tid, "grp_provisioners", "secret_enc", "someone-else"),
		"another column":      seal.AAD(tid, "grp_provisioners", "config", p.ID),
		"another table":       seal.AAD(tid, "containment_credentials", "secret_enc", p.ID),
		"another tenant":      seal.AAD(tenancy.MustParse("00000000-0000-4000-8000-0000000000d8"), "grp_provisioners", "secret_enc", p.ID),
	} {
		if _, err := sealer.Open(raw.SecretEnc, aad); err == nil {
			t.Errorf("the secret opened under %s", name)
		}
	}
	// the names of the credentials are known, their values are not
	if got := x.svc.SecretKeysSet(tid, raw); len(got) != 1 || got[0] != "token" {
		t.Errorf("SecretKeysSet = %v", got)
	}
	// updating other fields keeps the secret; replacing it changes it
	x.must(func(e model.Env) error {
		name := "renamed"
		u, err := x.svc.Update(e.Tx, x.now, "t", p.ID, UpdateInput{Version: raw.Version, Name: &name})
		if err != nil {
			return err
		}
		if string(u.SecretEnc) != string(raw.SecretEnc) {
			t.Error("a rename changed the stored secret")
		}
		u, err = x.svc.Update(e.Tx, x.now, "t", p.ID, UpdateInput{Version: u.Version, Secret: map[string]string{"token": "new-token-value"}})
		if err != nil {
			return err
		}
		if string(u.SecretEnc) == string(raw.SecretEnc) {
			t.Error("replacing the credential kept the old secret")
		}
		b, err := sealer.Open(u.SecretEnc, secretAAD(tid, p.ID))
		if err != nil || !strings.Contains(string(b), "new-token-value") {
			t.Errorf("new secret = %s, %v", b, err)
		}
		return nil
	})
	// without a key there is nowhere safe to put a credential
	x.svc.Sealer = nil
	err := x.run(func(e model.Env) error {
		_, err := x.svc.Create(e.Tx, x.now, "t", CreateInput{Name: "nokek", TargetType: TypeSCIM2, Config: scimConfig(nil), Secret: map[string]string{"token": "x"}})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "key-encryption key") {
		t.Errorf("create without a KEK = %v", err)
	}
}

func TestService_LifecycleRules(t *testing.T) {
	x := newHarness(t, 2)
	g := x.group(x.root, "eng")
	p, _ := x.prov("scim", `{}`)
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	mode := store.ProvModeActive
	update := func(in UpdateInput) error {
		return x.run(func(e model.Env) error {
			cur, err := e.Tx.Provisioner(p.ID)
			if err != nil {
				return err
			}
			if in.Version == 0 {
				in.Version = cur.Version
			}
			_, err = x.svc.Update(e.Tx, x.now, "t", p.ID, in)
			return err
		})
	}
	// a provisioner is enabled only after a reviewed run
	if err := update(UpdateInput{Mode: &mode}); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("enabling a never-run provisioner = %v, want ErrReviewRequired", err)
	}
	f := x.targets[p.ID]
	f.failRead = errors.New("down")
	_, _ = x.svc.Run(t.Context(), tid, p.ID, RunOptions{Kind: store.RunFull})
	if err := update(UpdateInput{Mode: &mode}); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("enabling after a failed run = %v, want ErrReviewRequired", err)
	}
	f.failRead = nil
	x.full(p.ID)
	if err := update(UpdateInput{Mode: &mode}); err != nil {
		t.Fatalf("enabling after a reviewed run: %v", err)
	}
	// pausing and resuming do not need another review
	paused := store.ProvModePaused
	if err := update(UpdateInput{Mode: &paused}); err != nil {
		t.Fatal(err)
	}
	if err := update(UpdateInput{Mode: &mode}); err != nil {
		t.Fatalf("resuming: %v", err)
	}
	// stale versions, bad values, a taken name
	if err := update(UpdateInput{Version: 1}); !errors.Is(err, store.ErrVersionConflict) {
		t.Errorf("a stale version = %v", err)
	}
	bad := "not valid"
	for name, in := range map[string]UpdateInput{
		"mode":     {Mode: ptr("turbo")},
		"schedule": {FullSchedule: &bad},
		"name":     {Name: ptr("!!")},
		"failsafe": {Failsafe: []byte(`{"max_delete_percent": 200}`)},
		"config":   {Config: []byte(`{"account_system":"dir","group_name":"{{"}`)},
		"secret":   {Secret: map[string]string{"signing_secret": "x"}},
	} {
		err := update(in)
		if err == nil || !errors.Is(err, ErrConfig) {
			t.Errorf("update %s = %v, want an ErrConfig", name, err)
		}
	}
	x.prov("other", `{}`)
	if err := update(UpdateInput{Name: ptr("other")}); err == nil {
		t.Error("renaming onto a taken name was accepted")
	} else if dup := (*DuplicateError)(nil); !errors.As(err, &dup) {
		t.Errorf("rename onto a taken name = %v", err)
	}
	// approving the failsafe needs the limits to apply
	x.must(func(e model.Env) error {
		if err := x.svc.RequestFull(e.Tx, x.now, "a", p.ID, true); err != nil {
			t.Errorf("approving in active mode: %v", err)
		}
		return nil
	})
	if err := update(UpdateInput{Mode: &paused}); err != nil {
		t.Fatal(err)
	}
	if err := x.run(func(e model.Env) error { return x.svc.RequestFull(e.Tx, x.now, "a", p.ID, false) }); !errors.Is(err, ErrPaused) {
		t.Errorf("a sync request while paused = %v", err)
	}
	// a mark needs a real folder or group of the tenant
	for name, in := range map[string]MarkInput{
		"group scope":    {ObjectType: "group", ObjectID: string(g), Scope: "sub", Include: true},
		"folder scope":   {ObjectType: "folder", ObjectID: string(x.root), Scope: "self", Include: true},
		"unknown group":  {ObjectType: "group", ObjectID: "00000000-0000-4000-8000-00000000dead", Include: true},
		"unknown kind":   {ObjectType: "user", ObjectID: string(g), Include: true},
		"metadata array": {ObjectType: "group", ObjectID: string(g), Include: true, Metadata: []byte(`{"a":[1]}`)},
		"metadata name":  {ObjectType: "group", ObjectID: string(g), Include: true, Metadata: []byte(`{"a b":"x"}`)},
	} {
		err := x.run(func(e model.Env) error { _, err := x.svc.SetMark(e.Tx, x.now, "t", p.ID, in); return err })
		if !errors.Is(err, ErrConfig) {
			t.Errorf("mark %s = %v, want an ErrConfig", name, err)
		}
	}
	// deleting removes everything of the provisioner
	x.must(func(e model.Env) error { return x.svc.Delete(e.Tx, x.now, "t", p.ID) })
	x.read(func(tx *store.TenantTx) error {
		if _, err := tx.Provisioner(p.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("provisioner after delete: %v", err)
		}
		if ms, _ := tx.ProvMarks(p.ID); len(ms) != 0 {
			t.Errorf("%d marks left", len(ms))
		}
		if rs, _ := tx.SyncRuns(p.ID, 10, 0); len(rs) != 0 {
			t.Errorf("%d runs left", len(rs))
		}
		return nil
	})
}

func ptr[T any](v T) *T { return &v }

func TestFailsafeDefaults(t *testing.T) {
	l, err := ParseFailsafe(nil)
	if err != nil || l.Resolve() != (Limits{MaxDeletes: 1000, MaxDeletePercent: 2, MaxGroupDeletes: 0}) {
		t.Errorf("defaults = %+v, %v", l.Resolve(), err)
	}
	l, err = ParseFailsafe([]byte(`{"max_deletes": 0, "max_group_deletes": 3}`))
	if err != nil || l.Resolve().MaxDeletes != 0 || l.Resolve().MaxGroupDeletes != 3 || l.Resolve().MaxDeletePercent != 2 {
		t.Errorf("explicit zero = %+v, %v", l.Resolve(), err)
	}
	for _, bad := range []string{`{"max_deletes": -1}`, `{"max_delete_percent": 101}`, `{"max_group_deletes": 1000000}`, `{"nope": 1}`, `[]`} {
		if _, err := ParseFailsafe([]byte(bad)); err == nil {
			t.Errorf("failsafe %s was accepted", bad)
		}
	}
	// the arithmetic: the absolute limit, the share, and the floor under which the share is ignored
	lim := Limits{MaxDeletes: 10, MaxDeletePercent: 2, MaxGroupDeletes: 1}
	for _, c := range []struct {
		t     Totals
		total int
		full  bool
		trips bool
	}{
		{Totals{MemberRemoves: 10}, 100000, true, false},
		{Totals{MemberRemoves: 11}, 100000, true, true},
		{Totals{MemberRemoves: 3}, 100, true, true},   // 3% of 100
		{Totals{MemberRemoves: 2}, 100, true, false},  // 2%
		{Totals{MemberRemoves: 3}, 100, false, false}, // the share applies to full runs only
		{Totals{MemberRemoves: 5}, 49, true, false},   // under the floor
		{Totals{GroupDeletes: 1}, 100, true, false},
		{Totals{GroupDeletes: 2}, 100, true, true},
	} {
		if got := len(lim.failsafe(c.t, c.total, c.full)) > 0; got != c.trips {
			t.Errorf("failsafe(%+v, %d, full=%v) trips = %v, want %v", c.t, c.total, c.full, got, c.trips)
		}
	}
}
