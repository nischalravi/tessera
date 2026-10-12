package rotation

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func problemCode(err error) string {
	var p *Problem
	if asProblem(err, &p) {
		return p.Code
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return ""
}

func (h *harness) tryWrite(fn func(tx *store.TenantTx, now time.Time) error) error {
	return h.db.InTenant(h.ctx(), h.tenant, func(tx *store.TenantTx) error { return fn(tx, h.clock()) })
}

func TestPutAdapter_Validation(t *testing.T) {
	h := newHarness(t)
	good := map[string]string{"access_key_id": "AKIAROTATORADAPTER01", "secret_access_key": "abcdefghij0123456789"}
	cases := map[string]struct {
		in   AdapterInput
		code string
	}{
		"empty name":            {AdapterInput{Name: "", Type: TypeVault}, "invalid_name"},
		"name with a space":     {AdapterInput{Name: "a b", Type: TypeVault}, "invalid_name"},
		"unknown type":          {AdapterInput{Name: "x", Type: "ldap"}, "invalid_type"},
		"unknown config key":    {AdapterInput{Name: "x", Type: TypeVault, Config: map[string]string{"address": "https://v.example", "role": "x"}, Credential: map[string]string{"token": "s.0123456789"}}, "invalid_config"},
		"vault without address": {AdapterInput{Name: "x", Type: TypeVault, Credential: map[string]string{"token": "s.0123456789"}}, "invalid_config"},
		"address with userinfo": {AdapterInput{Name: "x", Type: TypeVault, Config: map[string]string{"address": "https://u:p@v.example"}, Credential: map[string]string{"token": "s.0123456789"}}, "invalid_config"},
		"address with a query":  {AdapterInput{Name: "x", Type: TypeVault, Config: map[string]string{"address": "https://v.example?x=1"}, Credential: map[string]string{"token": "s.0123456789"}}, "invalid_config"},
		"address is not a URL":  {AdapterInput{Name: "x", Type: TypeVault, Config: map[string]string{"address": "vault"}, Credential: map[string]string{"token": "s.0123456789"}}, "invalid_config"},
		"ftp address":           {AdapterInput{Name: "x", Type: TypeVault, Config: map[string]string{"address": "ftp://v.example"}, Credential: map[string]string{"token": "s.0123456789"}}, "invalid_config"},
		"bad region":            {AdapterInput{Name: "x", Type: TypeAWSIAM, Config: map[string]string{"region": "mars"}, Credential: good}, "invalid_config"},
		"bad namespace":         {AdapterInput{Name: "x", Type: TypeVault, Config: map[string]string{"address": "https://v.example", "namespace": "a b"}, Credential: map[string]string{"token": "s.0123456789"}}, "invalid_config"},
		"missing token":         {AdapterInput{Name: "x", Type: TypeVault, Config: map[string]string{"address": "https://v.example"}}, "invalid_credential"},
		"token with spaces":     {AdapterInput{Name: "x", Type: TypeGitHub, Credential: map[string]string{"token": "has spaces in it"}}, "invalid_credential"},
		"bad access key id":     {AdapterInput{Name: "x", Type: TypeAWSIAM, Credential: map[string]string{"access_key_id": "nope", "secret_access_key": "abcdefghij0123456789"}}, "invalid_credential"},
		"unknown credential":    {AdapterInput{Name: "x", Type: TypeGitHub, Credential: map[string]string{"token": "ghp_0123456789", "extra": "x"}}, "invalid_credential"},
		"bad fail_at":           {AdapterInput{Name: "x", Type: TypeFake, Config: map[string]string{"fail_at": "lunch"}}, "invalid_config"},
		"valid github":          {AdapterInput{Name: "gh", Type: TypeGitHub, Credential: map[string]string{"token": "ghp_0123456789"}}, ""},
		"valid aws":             {AdapterInput{Name: "aws", Type: TypeAWSSM, Config: map[string]string{"region": "eu-west-1"}, Credential: good}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := h.tryWrite(func(tx *store.TenantTx, now time.Time) error {
				_, _, err := h.svc.PutAdapter(tx, tc.in, "tester", now)
				return err
			})
			if got := problemCode(err); got != tc.code {
				t.Errorf("code %q (%v), want %q", got, err, tc.code)
			}
		})
	}
	t.Run("plain http is refused in prod", func(t *testing.T) {
		prod := &Service{Sealer: h.sealer, Env: config.Prod}
		err := h.tryWrite(func(tx *store.TenantTx, now time.Time) error {
			_, _, err := prod.PutAdapter(tx, AdapterInput{Name: "v", Type: TypeVault, Config: map[string]string{"address": "http://vault.example"},
				Credential: map[string]string{"token": "s.0123456789"}}, "tester", now)
			return err
		})
		if problemCode(err) != "invalid_config" {
			t.Errorf("err %v", err)
		}
	})
}

func TestAdapterCredentialIsSealedAndNeverReturned(t *testing.T) {
	h := newHarness(t)
	view := h.putAdapter(AdapterInput{Name: "vault-prod", Type: TypeVault, Config: map[string]string{"address": "https://vault.example"},
		Credential: map[string]string{"token": vaultToken}})
	if !view.CredentialSet || strings.Contains(strings.Join(mapValues(view.Config), " "), vaultToken) {
		t.Errorf("view %+v", view)
	}
	var row *store.RotationAdapter
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		var err error
		row, err = tx.RotationAdapter(view.ID)
		return err
	})
	if strings.Contains(string(row.SecretEnc), vaultToken) {
		t.Fatal("the credential is stored in the clear")
	}
	plain, err := h.sealer.Open(row.SecretEnc, sealAAD(h.tenant, row.ID))
	if err != nil || !strings.Contains(string(plain), vaultToken) {
		t.Fatalf("the sealed credential does not open under its own AAD: %v", err)
	}
	// bound to tenant and row: copying the blob elsewhere does not open
	other := store.NewID()
	if _, err := h.sealer.Open(row.SecretEnc, sealAAD(h.tenant, other)); err == nil {
		t.Error("the blob opened under another adapter's AAD")
	}
	if _, err := h.sealer.Open(row.SecretEnc, sealAAD(mustOtherTenant(), row.ID)); err == nil {
		t.Error("the blob opened under another tenant's AAD")
	}
	// updating without a credential keeps the sealed one; a new one replaces it
	before := string(row.SecretEnc)
	h.putAdapter(AdapterInput{Name: "vault-prod", Type: TypeVault, Config: map[string]string{"address": "https://vault2.example"}})
	h.read(func(tx *store.TenantTx, _ time.Time) error { row, _ = tx.RotationAdapter(view.ID); return nil })
	if string(row.SecretEnc) != before || !strings.Contains(row.Config, "vault2.example") {
		t.Error("an update without a credential changed the sealed credential or ignored the config")
	}
	h.putAdapter(AdapterInput{Name: "vault-prod", Type: TypeVault, Config: map[string]string{"address": "https://vault2.example"},
		Credential: map[string]string{"token": "s.aDifferentToken01"}})
	h.read(func(tx *store.TenantTx, _ time.Time) error { row, _ = tx.RotationAdapter(view.ID); return nil })
	if string(row.SecretEnc) == before {
		t.Error("a new credential did not replace the sealed one")
	}
	if got := h.actions("rotation.adapter."); !slices.Equal(got, []string{"rotation.adapter.created", "rotation.adapter.updated", "rotation.adapter.updated"}) {
		t.Errorf("audit %v", got)
	}
	assertNoSecrets(t, h, vaultToken, "s.aDifferentToken01")
	// no key-encryption key: a credential cannot be stored
	nokek := &Service{Env: config.Dev}
	err = h.tryWrite(func(tx *store.TenantTx, now time.Time) error {
		_, _, err := nokek.PutAdapter(tx, AdapterInput{Name: "g", Type: TypeGitHub, Credential: map[string]string{"token": "ghp_0123456789"}}, "t", now)
		return err
	})
	if problemCode(err) != "sealing_unavailable" {
		t.Errorf("without a KEK: %v", err)
	}
	// a type cannot change
	err = h.tryWrite(func(tx *store.TenantTx, now time.Time) error {
		_, _, err := h.svc.PutAdapter(tx, AdapterInput{Name: "vault-prod", Type: TypeGitHub, Credential: map[string]string{"token": "ghp_0123456789"}}, "t", now)
		return err
	})
	if problemCode(err) != "type_change" {
		t.Errorf("type change: %v", err)
	}
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestPutPolicy_ValidationAndUpsert(t *testing.T) {
	h := newHarness(t)
	h.putAdapter(AdapterInput{Name: "aws-prod", Type: TypeAWSIAM, Credential: awsCredMap()})
	h.putAdapter(AdapterInput{Name: "gh", Type: TypeGitHub, Credential: map[string]string{"token": ghToken}})
	h.putAdapter(AdapterInput{Name: "vault-prod", Type: TypeVault, Config: map[string]string{"address": "https://vault.example"}, Credential: map[string]string{"token": vaultToken}})
	s := func(v string) *string { return &v }
	cases := map[string]struct {
		in   PolicyInput
		code string
	}{
		"bad kind":                               {PolicyInput{Kind: "Access Key", MaxAgeDays: 90}, "invalid_kind"},
		"bad system":                             {PolicyInput{Kind: "access_key", System: "AWS!", MaxAgeDays: 90}, "invalid_system"},
		"zero max age":                           {PolicyInput{Kind: "access_key", MaxAgeDays: 0}, "invalid_max_age"},
		"huge max age":                           {PolicyInput{Kind: "access_key", MaxAgeDays: 4000}, "invalid_max_age"},
		"negative grace":                         {PolicyInput{Kind: "access_key", MaxAgeDays: 90, GraceHours: -1}, "invalid_grace"},
		"huge grace":                             {PolicyInput{Kind: "access_key", MaxAgeDays: 90, GraceHours: 721}, "invalid_grace"},
		"path traversal chars":                   {PolicyInput{Kind: "access_key", MaxAgeDays: 90, DestPath: "kv/../x;rm"}, "invalid_dest_path"},
		"unknown placeholder":                    {PolicyInput{Kind: "access_key", MaxAgeDays: 90, DestPath: "kv/{password}"}, "invalid_dest_path"},
		"unknown adapter":                        {PolicyInput{Kind: "access_key", MaxAgeDays: 90, Adapter: s("nope")}, "unknown_adapter"},
		"adapter kind mismatch":                  {PolicyInput{Kind: "access_key", MaxAgeDays: 90, Adapter: s("gh"), Destination: s("vault-prod"), DestPath: "kv/x"}, "adapter_kind_mismatch"},
		"destination missing":                    {PolicyInput{Kind: "access_key", MaxAgeDays: 90, Adapter: s("aws-prod")}, "destination_required"},
		"destination path only":                  {PolicyInput{Kind: "access_key", MaxAgeDays: 90, Adapter: s("aws-prod"), Destination: s("vault-prod")}, "destination_required"},
		"destination is an IAM adapter":          {PolicyInput{Kind: "access_key", MaxAgeDays: 90, Adapter: s("aws-prod"), Destination: s("aws-prod"), DestPath: "x"}, "invalid_destination"},
		"destination path invalid for the vault": {PolicyInput{Kind: "access_key", MaxAgeDays: 90, Adapter: s("aws-prod"), Destination: s("vault-prod"), DestPath: "justamount"}, "invalid_dest_path"},
		"auto without adapter":                   {PolicyInput{Kind: "access_key", MaxAgeDays: 90, AutoRotate: true}, "auto_without_adapter"},
		"manual policy":                          {PolicyInput{Kind: "pat", MaxAgeDays: 90}, ""},
		"full policy":                            {PolicyInput{Kind: "access_key", System: "aws", MaxAgeDays: 90, GraceHours: 24, Adapter: s("aws-prod"), Destination: s("vault-prod"), DestPath: "kv/{system}/{name}"}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := h.tryWrite(func(tx *store.TenantTx, now time.Time) error {
				_, _, err := h.svc.PutPolicy(tx, tc.in, "tester", now)
				return err
			})
			if got := problemCode(err); got != tc.code {
				t.Errorf("code %q (%v), want %q", got, err, tc.code)
			}
		})
	}
	// the same kind and system replaces the policy
	var created bool
	var v *PolicyView
	h.write(func(tx *store.TenantTx, now time.Time) error {
		var err error
		v, created, err = h.svc.PutPolicy(tx, PolicyInput{Kind: "access_key", System: "aws", MaxAgeDays: 45, GraceHours: 2, Adapter: s("aws-prod"),
			Destination: s("vault-prod"), DestPath: "kv/{name}", AutoRotate: true}, "tester", now)
		return err
	})
	if created || v.MaxAgeDays != 45 || v.Mode != "automatic" {
		t.Errorf("update: created=%v %+v", created, v)
	}
	var n int
	h.read(func(tx *store.TenantTx, _ time.Time) error { ps, _ := tx.RotationPolicies(); n = len(ps); return nil })
	if n != 2 { // "manual policy" and "full policy"
		t.Errorf("%d policies", n)
	}
	// an adapter a policy uses cannot be deleted
	err := h.tryWrite(func(tx *store.TenantTx, now time.Time) error {
		a, err := tx.RotationAdapterByName("aws-prod")
		if err != nil {
			return err
		}
		return h.svc.DeleteAdapter(tx, a.ID, "tester", now)
	})
	if problemCode(err) != "adapter_in_use" {
		t.Errorf("delete of an adapter in use: %v", err)
	}
}

func TestPlan_DecidesPerSecret(t *testing.T) {
	h := newHarness(t)
	fakePolicy(h, 12, nil)
	sim := "sim"
	h.putPolicy(PolicyInput{Kind: "deploy_key", MaxAgeDays: 30, Adapter: nil})    // manual by policy
	h.putPolicy(PolicyInput{Kind: "password", System: "workday", MaxAgeDays: 30}) // manual by policy
	h.putAdapter(AdapterInput{Name: "gh", Type: TypeGitHub, Credential: map[string]string{"token": ghToken}})
	gh := "gh"
	h.putPolicy(PolicyInput{Kind: "deploy_key", System: "github", MaxAgeDays: 30, Adapter: &gh, Destination: &sim, DestPath: "kv/{name}"})
	rot := h.addSecret("aws", "access_key", "AKIAPLAN1", "AKIAPLANEXAMPLE000001", 100*24*time.Hour)
	young := h.addSecret("aws", "access_key", "AKIAPLAN2", "AKIAPLANEXAMPLE000002", 5*24*time.Hour)
	pat := h.addSecret("github", "pat", "ci-pat", "pat-1", 400*24*time.Hour)
	app := h.addSecret("github", "github_app", "ci-app", "app-1", 400*24*time.Hour)
	nopolicy := h.addSecret("okta", "api_token", "okta-token", "tok-1", 10*24*time.Hour)
	badref := h.addSecret("github", "deploy_key", "bad-key", "not-a-ref", 100*24*time.Hour)
	goodkey := h.addSecret("github", "deploy_key", "good-key", "larkspur/payments#7", 100*24*time.Hour)
	inflight := h.addSecret("aws", "access_key", "AKIAPLAN3", "AKIAPLANEXAMPLE000003", 100*24*time.Hour)
	h.startRotation(inflight)

	byID := map[int64]*PlanItem{}
	h.read(func(tx *store.TenantTx, now time.Time) error {
		items, err := h.svc.Plan(tx, nil, now)
		for _, it := range items {
			byID[it.SecretID] = it
		}
		return err
	})
	type want struct {
		action  string
		reason  string // substring
		overdue bool
	}
	for name, tc := range map[string]struct {
		id int64
		w  want
	}{
		"overdue access key":        {rot, want{ActionRotate, "", true}},
		"young access key":          {young, want{ActionRotate, "", false}},
		"personal access token":     {pat, want{ActionManual, "personal access tokens", false}},
		"github app key":            {app, want{ActionManual, "GitHub App", false}},
		"kind with no policy":       {nopolicy, want{ActionManual, "no rotation policy", false}},
		"deploy key with a bad ref": {badref, want{ActionBlocked, "owner>/<repo>#<deploy key id>", true}},
		"deploy key":                {goodkey, want{ActionRotate, "", true}},
		"rotation already running":  {inflight, want{ActionInFlight, "already", true}},
	} {
		it := byID[tc.id]
		if it == nil {
			t.Errorf("%s: not in the plan", name)
			continue
		}
		if it.Action != tc.w.action || !strings.Contains(it.Reason, tc.w.reason) || it.Overdue != tc.w.overdue {
			t.Errorf("%s: action %s reason %q overdue %v; want %s %q %v", name, it.Action, it.Reason, it.Overdue, tc.w.action, tc.w.reason, tc.w.overdue)
		}
	}
	it := byID[rot]
	if it.Adapter == nil || *it.Adapter != "sim" || it.GraceHours != 12 || it.DestPath != "kv/aws/akiaplan1" || len(it.Steps) < 6 {
		t.Errorf("rotate item %+v", it)
	}
	if it.Owner == nil || it.Owner.Name == "" {
		t.Errorf("the service account's owner is not resolved: %+v", it.Owner)
	}
	if it := byID[goodkey]; !slices.ContainsFunc(it.Warnings, func(w string) bool { return strings.Contains(w, "cannot deactivate") }) {
		t.Errorf("a provider that cannot disable must warn: %v", it.Warnings)
	}
	if it := byID[goodkey]; !slices.ContainsFunc(it.Steps, func(s string) bool { return strings.HasPrefix(s, "Skip disabling") }) {
		t.Errorf("steps %v", it.Steps)
	}
	// planning is read-only: it queued nothing
	var jobs int
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		j, _ := tx.RotationJobs(store.RotationJobFilter{})
		jobs = len(j)
		return nil
	})
	if jobs != 1 {
		t.Errorf("%d jobs after planning, want the one started above", jobs)
	}
	err := h.tryWrite(func(tx *store.TenantTx, now time.Time) error {
		_, err := h.svc.Plan(tx, []int64{987654321}, now)
		return err
	})
	if problemCode(err) != "not_found" {
		t.Errorf("unknown secret: %v", err)
	}
}

func TestStartRotationRefusals(t *testing.T) {
	h := newHarness(t)
	fakePolicy(h, 0, nil)
	pat := h.addSecret("github", "pat", "ci-pat", "pat-1", 400*24*time.Hour)
	ok := h.addSecret("aws", "access_key", "AKIAREF1", "AKIAREFEXAMPLE0000001", 100*24*time.Hour)
	try := func(id int64) error {
		return h.tryWrite(func(tx *store.TenantTx, now time.Time) error {
			_, err := h.svc.StartRotation(tx, id, "tester", now)
			return err
		})
	}
	if got := problemCode(try(pat)); got != "manual_rotation_required" {
		t.Errorf("manual secret: %q", got)
	}
	if got := problemCode(try(987654)); got != "not_found" {
		t.Errorf("unknown secret: %q", got)
	}
	if err := try(ok); err != nil {
		t.Fatal(err)
	}
	if got := problemCode(try(ok)); got != "in_flight" {
		t.Errorf("second rotation of the same secret: %q", got)
	}
}

func TestCancelAndRetryRules(t *testing.T) {
	h := newHarness(t)
	fakePolicy(h, 24, nil)
	sid := h.addSecret("aws", "access_key", "AKIACANCEL", "AKIACANCELEXAMPLE0001", 100*24*time.Hour)
	id := h.startRotation(sid)
	call := func(f func(tx *store.TenantTx, now time.Time) error) error { return h.tryWrite(f) }
	if got := problemCode(call(func(tx *store.TenantTx, now time.Time) error { _, err := h.svc.RetryJob(tx, id, "t", now); return err })); got != "not_failed" {
		t.Errorf("retry of a pending job: %q", got)
	}
	if err := call(func(tx *store.TenantTx, now time.Time) error { _, err := h.svc.CancelJob(tx, id, "t", now); return err }); err != nil {
		t.Fatal(err)
	}
	h.expectState(id, store.RotCancelled)
	if n := h.tick(); n != 0 {
		t.Error("a cancelled job ran")
	}
	// a new job may now start, and once it has begun it can no longer be cancelled
	id2 := h.startRotation(sid)
	h.step(id2, store.RotHandedOver)
	if got := problemCode(call(func(tx *store.TenantTx, now time.Time) error {
		_, err := h.svc.CancelJob(tx, id2, "t", now)
		return err
	})); got != "not_pending" {
		t.Errorf("cancel of a started job: %q", got)
	}
	for _, fn := range []func(tx *store.TenantTx, now time.Time) error{
		func(tx *store.TenantTx, now time.Time) error {
			_, err := h.svc.RetryJob(tx, "00000000-0000-4000-8000-00000000dead", "t", now)
			return err
		},
		func(tx *store.TenantTx, now time.Time) error {
			_, err := h.svc.CancelJob(tx, "00000000-0000-4000-8000-00000000dead", "t", now)
			return err
		},
	} {
		if got := problemCode(call(fn)); got != "not_found" {
			t.Errorf("unknown job: %q", got)
		}
	}
}

func TestOverview(t *testing.T) {
	h := newHarness(t)
	fakePolicy(h, 0, nil)
	old := h.addSecret("aws", "access_key", "AKIAOV1", "AKIAOVEXAMPLE00000001", 100*24*time.Hour)
	h.addSecret("aws", "access_key", "AKIAOV2", "AKIAOVEXAMPLE00000002", 3*24*time.Hour)
	h.addSecret("okta", "api_token", "okta", "tok", 400*24*time.Hour)
	h.startRotation(old)
	var rows []SecretStatus
	h.read(func(tx *store.TenantTx, now time.Time) error {
		var err error
		rows, err = h.svc.Overview(tx, now)
		return err
	})
	byName := map[string]SecretStatus{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	if r := byName["AKIAOV1"]; !r.Overdue || r.ActiveJob == nil || r.ActiveJob.State != store.RotPending || r.Mode != "scheduled" || r.Action != ActionInFlight {
		t.Errorf("AKIAOV1 %+v", r)
	}
	if r := byName["AKIAOV2"]; r.Overdue || r.ActiveJob != nil || r.MaxAgeDays == nil || *r.MaxAgeDays != 90 {
		t.Errorf("AKIAOV2 %+v", r)
	}
	if r := byName["okta"]; r.Mode != "none" || r.Action != ActionManual {
		t.Errorf("okta %+v", r)
	}
	if !rows[0].Overdue {
		t.Errorf("an overdue secret should come first: %v", rows[0].Name)
	}
}

// ---------------------------------------------------------------- bulk "vendor compromised"

func bulkSetup(t *testing.T) (*harness, []int64) {
	h := newHarness(t)
	h.putAdapter(AdapterInput{Name: "sim", Type: TypeFake})
	sim := "sim"
	h.putPolicy(PolicyInput{Kind: "access_key", MaxAgeDays: 90, GraceHours: 48, Adapter: &sim, Destination: &sim, DestPath: "kv/{name}"})
	h.putPolicy(PolicyInput{Kind: "api_token", MaxAgeDays: 90, GraceHours: 48, Adapter: &sim, Destination: &sim, DestPath: "kv/{name}"})
	ids := []int64{
		h.addSecret("snowflake", "api_token", "sf-token-1", "sf-1", 10*24*time.Hour),
		h.addSecret("snowflake", "api_token", "sf-token-2", "sf-2", 200*24*time.Hour),
		h.addSecret("snowflake", "keypair", "sf-key", "sf-3", 200*24*time.Hour), // no way to rotate: manual
		h.addSecret("aws", "access_key", "AKIAOTHER", "AKIAOTHEREXAMPLE00001", 10*24*time.Hour),
	}
	return h, ids
}

func TestBulkVendorCompromise_PlanThenExecute(t *testing.T) {
	h, ids := bulkSetup(t)
	var plan *BulkPlan
	h.read(func(tx *store.TenantTx, now time.Time) error {
		var err error
		plan, err = h.svc.BulkPlanFor(tx, "snowflake", now)
		return err
	})
	if plan.Counts != (BulkCounts{Total: 3, Rotate: 2, Manual: 1}) {
		t.Fatalf("counts %+v", plan.Counts)
	}
	for _, it := range plan.Items {
		if it.System != "snowflake" {
			t.Errorf("the plan includes %s on %s", it.Name, it.System)
		}
		if it.Action == ActionRotate && it.GraceHours != 0 {
			t.Errorf("%s: a compromised credential gets no grace period, plan says %d h", it.Name, it.GraceHours)
		}
	}
	var jobs int
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		j, _ := tx.RotationJobs(store.RotationJobFilter{})
		jobs = len(j)
		return nil
	})
	if jobs != 0 {
		t.Fatal("the dry run queued jobs")
	}
	// the confirmation must carry the plan that was shown, and a reason
	exec := func(in BulkInput) (*BulkView, error) {
		var v *BulkView
		err := h.tryWrite(func(tx *store.TenantTx, now time.Time) error {
			var err error
			v, err = h.svc.ExecuteBulk(tx, in, "tester", now)
			return err
		})
		return v, err
	}
	if _, err := exec(BulkInput{System: "snowflake", Reason: "short", PlanHash: plan.Hash}); problemCode(err) != "reason_required" {
		t.Errorf("short reason: %v", err)
	}
	if _, err := exec(BulkInput{System: "snowflake", Reason: "Snowflake breach notice 2026-10", PlanHash: "stale"}); problemCode(err) != "plan_changed" {
		t.Errorf("stale hash: %v", err)
	}
	if _, err := exec(BulkInput{System: "nosuchsystem", Reason: "Snowflake breach notice 2026-10", PlanHash: plan.Hash}); problemCode(err) != "no_secrets" {
		t.Errorf("unknown system: %v", err)
	}
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		j, _ := tx.RotationJobs(store.RotationJobFilter{})
		jobs = len(j)
		return nil
	})
	if jobs != 0 {
		t.Fatal("a refused execution queued jobs")
	}
	view, err := exec(BulkInput{System: "snowflake", Reason: "Snowflake breach notice 2026-10", PlanHash: plan.Hash})
	if err != nil {
		t.Fatal(err)
	}
	if view.Counts.Rotate != 2 || len(view.Jobs) != 2 || view.Progress[store.RotPending] != 2 {
		t.Fatalf("bulk view: counts %+v jobs %d progress %v", view.Counts, len(view.Jobs), view.Progress)
	}
	for _, j := range view.Jobs {
		if j.Origin != store.RotOriginVendor || j.GraceHours != 0 || j.BulkID == nil || *j.BulkID != view.ID || j.System != "snowflake" {
			t.Errorf("job %+v", j)
		}
	}
	// every owner is told: two rotations queued, one rotation to do by hand
	ev := h.notes.events()
	slices.Sort(ev)
	if !slices.Equal(ev, []string{EventManualRequired, EventVendorCompromise, EventVendorCompromise}) {
		t.Errorf("notifications %v", ev)
	}
	got := h.actions("rotation.")
	if !slices.Contains(got, "rotation.bulk.executed") || strings.Count(strings.Join(got, " "), "rotation.job.queued") != 2 {
		t.Errorf("audit %v", got)
	}
	// the other system's credentials were not touched
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		all, _ := tx.RotationJobs(store.RotationJobFilter{})
		for _, j := range all {
			if j.SecretID == ids[3] {
				t.Errorf("a job for the aws secret: %+v", j)
			}
		}
		return nil
	})
	// running the engine completes both: no grace period, and each is verified before deletion
	for i := 0; i < 5; i++ {
		h.tick()
	}
	done := 0
	for _, j := range view.Jobs {
		if h.job(j.ID).State == store.RotOldDeleted {
			done++
		}
	}
	if done != 2 {
		t.Errorf("%d of 2 jobs completed", done)
	}
	// a second run right away sees the secrets as rotated: the plan changed, so the old hash no longer applies
	if _, err := exec(BulkInput{System: "snowflake", Reason: "Snowflake breach notice 2026-10", PlanHash: plan.Hash}); problemCode(err) != "plan_changed" {
		t.Errorf("re-running a finished plan: %v", err)
	}
	// the run stays on record
	var bulks []BulkView
	h.read(func(tx *store.TenantTx, now time.Time) error {
		var err error
		bulks, err = h.svc.Bulks(tx, now)
		return err
	})
	if len(bulks) != 1 || bulks[0].Progress[store.RotOldDeleted] != 2 || bulks[0].Reason != "Snowflake breach notice 2026-10" {
		t.Errorf("bulks %+v", bulks)
	}
}

func TestBulkPlanHashChangesWithThePlan(t *testing.T) {
	h, _ := bulkSetup(t)
	hash := func() string {
		var p *BulkPlan
		h.read(func(tx *store.TenantTx, now time.Time) error {
			var err error
			p, err = h.svc.BulkPlanFor(tx, "snowflake", now)
			return err
		})
		return p.Hash
	}
	a, b := hash(), hash()
	if a != b {
		t.Error("the plan hash is not stable")
	}
	h.addSecret("snowflake", "api_token", "sf-token-3", "sf-4", 1*24*time.Hour) // a new credential appears
	if hash() == a {
		t.Error("a new credential did not change the plan hash")
	}
}

// ---------------------------------------------------------------- JML hook and notifications

func TestQueueForLeaver(t *testing.T) {
	h := newHarness(t)
	fakePolicy(h, 48, nil)
	covered := h.addSecret("aws", "access_key", "AKIALEAVE1", "AKIALEAVEEXAMPLE0001", 10*24*time.Hour)
	uncovered := h.addSecret("okta", "api_token", "okta-t", "tok-9", 10*24*time.Hour)
	var queued, none, again bool
	h.write(func(tx *store.TenantTx, now time.Time) error {
		var err error
		if queued, err = h.svc.QueueForLeaver(tx, covered, "hris.execute", now); err != nil {
			return err
		}
		if none, err = h.svc.QueueForLeaver(tx, uncovered, "hris.execute", now); err != nil {
			return err
		}
		again, err = h.svc.QueueForLeaver(tx, covered, "hris.execute", now)
		return err
	})
	if !queued || none || !again {
		t.Errorf("queued=%v uncovered=%v again=%v; want true false true", queued, none, again)
	}
	var j *store.RotationJob
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		all, _ := tx.RotationJobs(store.RotationJobFilter{SecretID: covered})
		if len(all) != 1 {
			t.Fatalf("%d jobs", len(all))
		}
		j = all[0]
		return nil
	})
	if j.Origin != store.RotOriginJML || j.GraceHours != 0 {
		t.Errorf("a leaver's secret is rotated at once: origin %s grace %d", j.Origin, j.GraceHours)
	}
}

func TestAuditNotifier(t *testing.T) {
	h := newHarness(t)
	h.write(func(tx *store.TenantTx, now time.Time) error {
		n := Notification{Event: EventCompleted, SecretID: 7, SecretName: "AKIAN", System: "aws", Subject: "Rotated AKIAN", Owner: &Owner{IdentityID: 3, Name: "Dave"}}
		if err := (AuditNotifier{}).Notify(tx.Context(), tx, n); err != nil {
			return err
		}
		n.Owner, n.Event = nil, EventFailed
		return (AuditNotifier{}).Notify(tx.Context(), tx, n)
	})
	text := h.auditText()
	if !strings.Contains(text, `"owner":"Dave"`) || !strings.Contains(text, `"escalated_to":"tenant administrators"`) {
		t.Errorf("audit:\n%s", text)
	}
}

// A secret whose owner has left is escalated rather than sent to the leaver.
func TestOwnerWhoLeftEscalates(t *testing.T) {
	h := newHarness(t)
	fakePolicy(h, 0, nil)
	sid := h.addSecret("aws", "access_key", "AKIAOWN", "AKIAOWNEXAMPLE00000001", 100*24*time.Hour)
	id := h.startRotation(sid)
	h.write(func(tx *store.TenantTx, now time.Time) error {
		ids, _, err := tx.IdentityMap()
		if err != nil {
			return err
		}
		for _, i := range ids {
			if i.Name == "svc-etl" && i.OwnerID != nil {
				return tx.TerminateIdentity(*i.OwnerID, now)
			}
		}
		return nil
	})
	for _, want := range []string{store.RotHandedOver, store.RotOldDisabled, store.RotVerified, store.RotOldDeleted} {
		h.step(id, want)
	}
	h.notes.mu.Lock()
	defer h.notes.mu.Unlock()
	if len(h.notes.list) != 1 || h.notes.list[0].Owner != nil {
		t.Errorf("notifications %+v: the owner has left, so there is nobody to name", h.notes.list)
	}
}

func mustOtherTenant() tenancy.ID { return tenancy.MustParse("00000000-0000-4000-8000-0000000000d4") }
