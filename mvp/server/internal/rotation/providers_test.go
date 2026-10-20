package rotation

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const (
	adapterAWSSecret = "adapterSecretAccessKey/0123456789abcdefABCDEF"
	vaultToken       = "s.vaultAdapterToken0123456789"
	ghToken          = "ghp_adapterGitHubToken0123456789"
	newIAMSecret     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEWSECRET"
)

var adapterCreds = awsCreds{AccessKeyID: "AKIAROTATORADAPTER01", SecretAccessKey: adapterAWSSecret}

func awsCredMap() map[string]string {
	return map[string]string{"access_key_id": adapterCreds.AccessKeyID, "secret_access_key": adapterCreds.SecretAccessKey}
}

// assertNoSecrets: nothing sensitive is in the audit ledger, the job rows or the database files.
func assertNoSecrets(t *testing.T, h *harness, secrets ...string) {
	t.Helper()
	text := h.auditText()
	var jobs []JobView
	h.read(func(tx *store.TenantTx, now time.Time) error {
		var err error
		jobs, err = h.svc.Jobs(tx, store.RotationJobFilter{}, now)
		return err
	})
	raw, _ := json.Marshal(jobs)
	for _, s := range secrets {
		switch {
		case strings.Contains(text, s):
			t.Errorf("the audit ledger holds %q", s)
		case strings.Contains(string(raw), s):
			t.Errorf("a job view holds %q", s)
		case h.fileHas(s):
			t.Errorf("the database files hold %q", s)
		}
	}
}

// ---------------------------------------------------------------- AWS IAM access key -> Vault KV v2

func TestIAMAccessKeyToVault_EndToEnd(t *testing.T) {
	h := newHarness(t)
	iam := newFakeIAM(t, adapterCreds)
	oldUsed := h.clock().Add(-48 * time.Hour)
	iam.addKey("svc-etl", "AKIAOLDOLDOLDOLD0001", h.clock().Add(-100*24*time.Hour), &oldUsed)
	vault := newFakeVault(t, vaultToken)
	h.putAdapter(AdapterInput{Name: "aws-prod", Type: TypeAWSIAM, Config: map[string]string{"endpoint": iam.srv.URL}, Credential: awsCredMap()})
	h.putAdapter(AdapterInput{Name: "vault-prod", Type: TypeVault, Config: map[string]string{"address": vault.srv.URL},
		Credential: map[string]string{"token": vaultToken}})
	a, v := "aws-prod", "vault-prod"
	h.putPolicy(PolicyInput{Kind: "access_key", System: "aws", MaxAgeDays: 90, GraceHours: 24, Adapter: &a, Destination: &v,
		DestPath: "kv/aws/{account}/{name}"})
	sid := h.addSecret("aws", "access_key", "AKIAETL-prod", "AKIAOLDOLDOLDOLD0001", 100*24*time.Hour)
	id := h.startRotation(sid)

	j := h.step(id, store.RotHandedOver)
	if len(vault.writes) != 1 {
		t.Fatalf("%d vault writes", len(vault.writes))
	}
	w := vault.writes[0]
	if w.Path != "kv/data/aws/svc-etl/akiaetl-prod" || w.Data["access_key_id"] != *j.NewRef ||
		w.Data["secret_access_key"] != newIAMSecret || w.Data["tessera_secret"] != "AKIAETL-prod" {
		t.Errorf("vault write %+v (new key %s)", w, *j.NewRef)
	}
	if got := iam.called(); !slices.Equal(got, []string{"CreateAccessKey svc-etl"}) {
		t.Errorf("IAM calls before the grace period: %v", got)
	}
	h.advance(24 * time.Hour)
	h.step(id, store.RotOldDisabled)
	if k := iam.find("AKIAOLDOLDOLDOLD0001"); k.Status != "Inactive" {
		t.Errorf("old key status %s after the disable step", k.Status)
	}
	j = h.step(id, store.RotVerified)
	// created 100 days before the rotation began, re-read after the 24 h grace period
	for _, want := range []string{`"verdict":"ok"`, `"old_age_days":101`, `"evidence":"age_and_last_use"`} {
		if !strings.Contains(*j.Verification, want) {
			t.Errorf("verification %s lacks %s", *j.Verification, want)
		}
	}
	h.step(id, store.RotOldDeleted)
	want := []string{
		"CreateAccessKey svc-etl",
		"UpdateAccessKey svc-etl AKIAOLDOLDOLDOLD0001 Inactive",
		"ListAccessKeys svc-etl", "GetAccessKeyLastUsed AKIAOLDOLDOLDOLD0001", // the re-read: key age and last use
		"DeleteAccessKey svc-etl AKIAOLDOLDOLDOLD0001",
		"ListAccessKeys svc-etl", // and the confirmation that it is gone
	}
	if got := iam.called(); !slices.Equal(got, want) {
		t.Errorf("IAM calls:\n got %v\nwant %v", got, want)
	}
	if s := h.secret(sid); s.ExternalID == "AKIAOLDOLDOLDOLD0001" || s.ExternalID != *j.NewRef {
		t.Errorf("inventory external id %s", s.ExternalID)
	}
	assertNoSecrets(t, h, newIAMSecret, adapterAWSSecret, vaultToken)
}

// A consumer that used the old key after it was disabled stops the rotation before the key is deleted.
func TestIAM_UseAfterDisableStopsBeforeDelete(t *testing.T) {
	h := newHarness(t)
	iam := newFakeIAM(t, adapterCreds)
	iam.addKey("svc-etl", "AKIAOLDOLDOLDOLD0002", h.clock().Add(-100*24*time.Hour), nil)
	vault := newFakeVault(t, vaultToken)
	h.putAdapter(AdapterInput{Name: "aws-prod", Type: TypeAWSIAM, Config: map[string]string{"endpoint": iam.srv.URL}, Credential: awsCredMap()})
	h.putAdapter(AdapterInput{Name: "vault-prod", Type: TypeVault, Config: map[string]string{"address": vault.srv.URL},
		Credential: map[string]string{"token": vaultToken}})
	a, v := "aws-prod", "vault-prod"
	h.putPolicy(PolicyInput{Kind: "access_key", MaxAgeDays: 90, GraceHours: 0, Adapter: &a, Destination: &v, DestPath: "kv/aws/{name}"})
	sid := h.addSecret("aws", "access_key", "AKIAETL2", "AKIAOLDOLDOLDOLD0002", 100*24*time.Hour)
	id := h.startRotation(sid)
	h.step(id, store.RotHandedOver)
	h.step(id, store.RotOldDisabled)
	h.advance(time.Hour)
	late := h.clock()
	iam.mu.Lock()
	iam.find("AKIAOLDOLDOLDOLD0002").LastUsed = iso(late) // a consumer still signs with the old key
	iam.mu.Unlock()
	j := h.step(id, store.RotFailed)
	if !strings.Contains(*j.LastError, VerdictUsedAfterDisable) {
		t.Errorf("error %s", *j.LastError)
	}
	for _, c := range iam.called() {
		if strings.HasPrefix(c, "DeleteAccessKey") {
			t.Fatalf("the old key was deleted: %v", iam.called())
		}
	}
	if iam.find("AKIAOLDOLDOLDOLD0002") == nil {
		t.Error("the old key is gone")
	}
}

func TestIAMAdapter_ErrorMapping(t *testing.T) {
	h := newHarness(t)
	iam := newFakeIAM(t, adapterCreds)
	ad := newIAM(h.http, adapterCreds, "us-east-1", iam.srv.URL, h.clock)
	tg := Target{Kind: "access_key", Account: "svc-etl", Ref: "AKIAOLDOLDOLDOLD0003"}
	ctx := context.Background()

	iam.errs["CreateAccessKey"] = [2]string{"409", "LimitExceeded"}
	_, err := ad.Create(ctx, tg)
	var e *Error
	if !asError(err, &e) || e.Code != "LimitExceeded" || e.Transient {
		t.Errorf("LimitExceeded: %v", err)
	}
	iam.errs["CreateAccessKey"] = [2]string{"400", "Throttling"}
	if _, err := ad.Create(ctx, tg); !IsTransient(err) {
		t.Errorf("Throttling must be transient: %v", err)
	}
	iam.errs["CreateAccessKey"] = [2]string{"503", "ServiceUnavailable"}
	if _, err := ad.Create(ctx, tg); !IsTransient(err) {
		t.Errorf("503 must be transient: %v", err)
	}
	iam.errs["CreateAccessKey"] = [2]string{"403", "AccessDenied"}
	if _, err := ad.Create(ctx, tg); err == nil || IsTransient(err) || strings.Contains(err.Error(), adapterAWSSecret) {
		t.Errorf("AccessDenied: %v", err)
	}
	// deleting a key that is already gone succeeds; observing a missing user reports it absent
	if err := ad.DeleteOld(ctx, tg); err != nil {
		t.Errorf("DeleteOld of a missing key: %v", err)
	}
	iam.errs["ListAccessKeys"] = [2]string{"404", "NoSuchEntity"}
	if obs, err := ad.ObserveOld(ctx, tg); err != nil || obs.Exists {
		t.Errorf("ObserveOld of a missing user: %+v, %v", obs, err)
	}
}

func TestIAMAdapter_ValidatesTargets(t *testing.T) {
	ad := &iamAdapter{}
	for name, tc := range map[string]struct {
		t  Target
		ok bool
	}{
		"valid":               {Target{Account: "svc-etl", Ref: "AKIAOLDOLDOLDOLD0001"}, true},
		"user with a slash":   {Target{Account: "svc/etl", Ref: "AKIAOLDOLDOLDOLD0001"}, false},
		"user with a space":   {Target{Account: "svc etl", Ref: "AKIAOLDOLDOLDOLD0001"}, false},
		"empty user":          {Target{Ref: "AKIAOLDOLDOLDOLD0001"}, false},
		"key id too short":    {Target{Account: "svc-etl", Ref: "AKIA"}, false},
		"key id with a hash":  {Target{Account: "svc-etl", Ref: "AKIAOLDOLDOLDOLD0001#x"}, false},
		"lower-case key id":   {Target{Account: "svc-etl", Ref: "akiaoldoldoldold0001"}, false},
		"user name injection": {Target{Account: "x&Action=DeleteUser", Ref: "AKIAOLDOLDOLDOLD0001"}, false},
	} {
		if err := ad.Validate(tc.t); (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ---------------------------------------------------------------- Vault AppRole -> Vault KV v2

func TestVaultAppRoleSecretID_EndToEnd(t *testing.T) {
	h := newHarness(t)
	vault := newFakeVault(t, vaultToken)
	vault.namespace = "team-a"
	oldAcc := "0b9d6a2c-aaaa-4bbb-8ccc-0000000000aa"
	vault.accessors["approle/etl-role#"+oldAcc] = h.clock().Add(-60 * 24 * time.Hour)
	h.putAdapter(AdapterInput{Name: "vault-prod", Type: TypeVault, Config: map[string]string{"address": vault.srv.URL, "namespace": "team-a"},
		Credential: map[string]string{"token": vaultToken}})
	vp := "vault-prod"
	h.putPolicy(PolicyInput{Kind: "approle_secret_id", MaxAgeDays: 30, GraceHours: 0, Adapter: &vp, Destination: &vp, DestPath: "kv/approles/{name}"})
	sid := h.addSecret("vault", "approle_secret_id", "etl-role-secret-id", "approle/etl-role#"+oldAcc, 60*24*time.Hour)
	id := h.startRotation(sid)

	j := h.step(id, store.RotHandedOver)
	if !strings.HasPrefix(*j.NewRef, "approle/etl-role#") || *j.NewRef == j.OldRef {
		t.Errorf("new ref %s", *j.NewRef)
	}
	if len(vault.writes) != 1 || vault.writes[0].Path != "kv/data/approles/etl-role-secret-id" ||
		vault.writes[0].Data["secret_id"] != "NEW-SECRET-ID-VALUE-0001" {
		t.Errorf("vault writes %+v", vault.writes)
	}
	h.step(id, store.RotOldDisabled) // Vault cannot disable a SecretID: the step is recorded as skipped
	j = h.step(id, store.RotVerified)
	if !strings.Contains(*j.Verification, `"evidence":"age_only"`) || !strings.Contains(*j.Verification, `"old_age_days":60`) ||
		!strings.Contains(*j.Verification, `"last_used_known":false`) {
		t.Errorf("verification %s", *j.Verification)
	}
	h.step(id, store.RotOldDeleted)
	want := []string{
		"POST /v1/auth/approle/role/etl-role/secret-id",
		"POST /v1/kv/data/approles/etl-role-secret-id",
		"POST /v1/auth/approle/role/etl-role/secret-id-accessor/lookup",
		"POST /v1/auth/approle/role/etl-role/secret-id-accessor/destroy",
		"POST /v1/auth/approle/role/etl-role/secret-id-accessor/lookup",
	}
	if got := vault.called(); !slices.Equal(got, want) {
		t.Errorf("Vault calls:\n got %v\nwant %v", got, want)
	}
	if _, still := vault.accessors["approle/etl-role#"+oldAcc]; still {
		t.Error("the old secret id accessor still exists")
	}
	assertNoSecrets(t, h, "NEW-SECRET-ID-VALUE-0001", vaultToken)
}

func TestVault_PermissionDeniedFailsWithoutLeakingTheToken(t *testing.T) {
	h := newHarness(t)
	vault := newFakeVault(t, "a-different-token-entirely")
	h.putAdapter(AdapterInput{Name: "vault-prod", Type: TypeVault, Config: map[string]string{"address": vault.srv.URL},
		Credential: map[string]string{"token": vaultToken}})
	vp := "vault-prod"
	h.putPolicy(PolicyInput{Kind: "approle_secret_id", MaxAgeDays: 30, Adapter: &vp, Destination: &vp, DestPath: "kv/x/{name}"})
	sid := h.addSecret("vault", "approle_secret_id", "etl", "approle/etl-role#0b9d6a2c-aaaa-4bbb-8ccc-0000000000aa", 60*24*time.Hour)
	id := h.startRotation(sid)
	j := h.step(id, store.RotFailed)
	if !strings.Contains(*j.LastError, "permission_denied") || strings.Contains(*j.LastError, vaultToken) {
		t.Errorf("error %q", *j.LastError)
	}
	assertNoSecrets(t, h, vaultToken)
}

func TestVaultRefAndPathValidation(t *testing.T) {
	v := &vaultAdapter{}
	for ref, ok := range map[string]bool{
		"approle/etl-role#0b9d6a2c-aaaa-4bbb-8ccc-0000000000aa":         true,
		"auth-mount/team/etl-role#0b9d6a2c-aaaa-4bbb-8ccc-0000000000aa": true,
		"etl-role#0b9d6a2c-aaaa-4bbb-8ccc-0000000000aa":                 false, // no mount
		"approle/etl-role": false, // no accessor
		"approle/../sys#0b9d6a2c-aaaa-4bbb-8ccc-0000000000aa":   false,
		"approle/etl role#0b9d6a2c-aaaa-4bbb-8ccc-0000000000aa": false,
		"approle/etl-role#short":                                false,
	} {
		if err := v.Validate(Target{Ref: ref}); (err == nil) != ok {
			t.Errorf("Validate(%q) = %v, want ok=%v", ref, err, ok)
		}
	}
	for path, ok := range map[string]bool{"kv/app/db": true, "kv/a": true, "kv": false, "kv/../sys/x": false, "kv//x": false, "kv/a b": false, "": false} {
		if err := v.ValidatePath(path); (err == nil) != ok {
			t.Errorf("ValidatePath(%q) = %v, want ok=%v", path, err, ok)
		}
	}
}

// ---------------------------------------------------------------- GitHub deploy key -> Vault KV v2

func TestGitHubDeployKeyToVault_EndToEnd(t *testing.T) {
	h := newHarness(t)
	gh := newFakeGitHub(t, ghToken)
	used := h.clock().Add(-72 * time.Hour)
	gh.keys["larkspur/payments#1001"] = &ghFakeKey{ID: 1001, Title: "ci", Created: h.clock().Add(-200 * 24 * time.Hour), ReadOnly: false, LastUsed: &used}
	vault := newFakeVault(t, vaultToken)
	h.putAdapter(AdapterInput{Name: "github-org", Type: TypeGitHub, Config: map[string]string{"api_url": gh.srv.URL}, Credential: map[string]string{"token": ghToken}})
	h.putAdapter(AdapterInput{Name: "vault-prod", Type: TypeVault, Config: map[string]string{"address": vault.srv.URL}, Credential: map[string]string{"token": vaultToken}})
	g, v := "github-org", "vault-prod"
	h.putPolicy(PolicyInput{Kind: "deploy_key", System: "github", MaxAgeDays: 180, GraceHours: 0, Adapter: &g, Destination: &v, DestPath: "kv/github/{name}"})
	sid := h.addSecret("github", "deploy_key", "payments-ci", "larkspur/payments#1001", 200*24*time.Hour)
	id := h.startRotation(sid)

	j := h.step(id, store.RotHandedOver)
	nk := gh.keys[*j.NewRef]
	if nk == nil || nk.ReadOnly || !strings.HasPrefix(nk.Public, "ssh-ed25519 ") || nk.Title != "tessera-rotated-2026-10-08" {
		t.Fatalf("new deploy key %+v: it must be read-write like the old one", nk)
	}
	if len(vault.writes) != 1 || !strings.HasPrefix(vault.writes[0].Data["private_key"], "-----BEGIN OPENSSH PRIVATE KEY-----") ||
		vault.writes[0].Data["public_key"] != nk.Public {
		t.Errorf("vault writes %+v", vault.writes)
	}
	priv := vault.writes[0].Data["private_key"]
	h.step(id, store.RotOldDisabled) // GitHub cannot disable a deploy key
	j = h.step(id, store.RotVerified)
	if !strings.Contains(*j.Verification, `"old_age_days":200`) || !strings.Contains(*j.Verification, `"evidence":"age_and_last_use"`) {
		t.Errorf("verification %s", *j.Verification)
	}
	h.step(id, store.RotOldDeleted)
	if gh.keys["larkspur/payments#1001"] != nil {
		t.Error("the old deploy key still exists")
	}
	want := []string{"GET /repos/larkspur/payments/keys/1001", "POST /repos/larkspur/payments/keys", "GET /repos/larkspur/payments/keys/1001",
		"DELETE /repos/larkspur/payments/keys/1001", "GET /repos/larkspur/payments/keys/1001"}
	if got := gh.called(); !slices.Equal(got, want) {
		t.Errorf("GitHub calls:\n got %v\nwant %v", got, want)
	}
	assertNoSecrets(t, h, priv[:60], ghToken, vaultToken)
}

func TestGitHubDeployKey_UsedAfterGracePeriodBlocksDelete(t *testing.T) {
	h := newHarness(t)
	gh := newFakeGitHub(t, ghToken)
	gh.keys["larkspur/payments#1002"] = &ghFakeKey{ID: 1002, Title: "ci", Created: h.clock().Add(-200 * 24 * time.Hour), ReadOnly: true}
	vault := newFakeVault(t, vaultToken)
	h.putAdapter(AdapterInput{Name: "github-org", Type: TypeGitHub, Config: map[string]string{"api_url": gh.srv.URL}, Credential: map[string]string{"token": ghToken}})
	h.putAdapter(AdapterInput{Name: "vault-prod", Type: TypeVault, Config: map[string]string{"address": vault.srv.URL}, Credential: map[string]string{"token": vaultToken}})
	g, v := "github-org", "vault-prod"
	h.putPolicy(PolicyInput{Kind: "deploy_key", MaxAgeDays: 180, GraceHours: 1, Adapter: &g, Destination: &v, DestPath: "kv/github/{name}"})
	sid := h.addSecret("github", "deploy_key", "payments-ci2", "larkspur/payments#1002", 200*24*time.Hour)
	id := h.startRotation(sid)
	h.step(id, store.RotHandedOver)
	h.advance(time.Hour + time.Minute)
	h.step(id, store.RotOldDisabled)
	late := h.clock().Add(time.Minute)
	gh.mu.Lock()
	gh.keys["larkspur/payments#1002"].LastUsed = &late // a CI job still clones with the old key
	gh.mu.Unlock()
	h.step(id, store.RotFailed)
	for _, c := range gh.called() {
		if strings.HasPrefix(c, "DELETE") {
			t.Fatalf("the old deploy key was deleted: %v", gh.called())
		}
	}
}

func TestGitHubRefValidation(t *testing.T) {
	g := &githubAdapter{}
	for ref, ok := range map[string]bool{
		"larkspur/payments#1001": true, "a/b.c_d-e#1": true,
		"larkspur/payments": false, "larkspur#1": false, "-bad/repo#1": false, "o/../x#1": false, "o/r#abc": false, "o/r s#1": false,
		"o/r#1/../../x": false, "o/r?x=1#1": false,
	} {
		if err := g.Validate(Target{Ref: ref}); (err == nil) != ok {
			t.Errorf("Validate(%q) = %v, want ok=%v", ref, err, ok)
		}
	}
}

func TestGitHubAdapter_ErrorMapping(t *testing.T) {
	h := newHarness(t)
	gh := newFakeGitHub(t, "another-token")
	ad := newGitHub(h.http, gh.srv.URL, ghToken, h.clock)
	_, err := ad.Create(context.Background(), Target{Ref: "larkspur/payments#1"})
	var e *Error
	if !asError(err, &e) || e.Transient || strings.Contains(err.Error(), ghToken) {
		t.Errorf("bad credentials: %v", err)
	}
	if err := ad.DisableOld(context.Background(), Target{Ref: "larkspur/payments#1"}); err != ErrUnsupported {
		t.Errorf("DisableOld = %v, want ErrUnsupported", err)
	}
}

// ---------------------------------------------------------------- Secrets Manager

func smSetup(t *testing.T, h *harness, rotation bool) *fakeSM {
	t.Helper()
	sm := newFakeSM(t, adapterCreds, "prod/app/api-key")
	sm.rotationEnabled = rotation
	sm.versions = []*smVer{{ID: "v-old-0001", Stages: []string{"AWSCURRENT"}, Created: 1.7e9, Accessed: 1.7595e9}}
	h.putAdapter(AdapterInput{Name: "sm-prod", Type: TypeAWSSM, Config: map[string]string{"endpoint": sm.srv.URL, "region": "eu-west-1"}, Credential: awsCredMap()})
	a := "sm-prod"
	h.putPolicy(PolicyInput{Kind: "api_key", MaxAgeDays: 60, GraceHours: 0, Adapter: &a})
	return sm
}

func TestSecretsManager_RotationFunction_EndToEnd(t *testing.T) {
	h := newHarness(t)
	sm := smSetup(t, h, true)
	sid := h.addSecret("aws", "api_key", "api-key-prod", "prod/app/api-key", 90*24*time.Hour)
	id := h.startRotation(sid)

	j := h.step(id, store.RotHandedOver)
	if j.OldRef != "prod/app/api-key#v-old-0001" || !strings.HasPrefix(*j.NewRef, "prod/app/api-key#") {
		t.Errorf("refs old=%s new=%s", j.OldRef, *j.NewRef)
	}
	if !slices.Contains(sm.called(), "RotateSecret prod/app/api-key") {
		t.Errorf("RotateSecret was not called: %v", sm.called())
	}
	if cur := sm.cur(); cur == nil || cur.ID == "v-old-0001" {
		t.Fatal("the new version is not AWSCURRENT")
	}
	h.step(id, store.RotOldDisabled)
	j = h.step(id, store.RotVerified)
	if !strings.Contains(*j.Verification, `"evidence":"age_and_last_use"`) || !strings.Contains(*j.Verification, `"old_active":false`) {
		t.Errorf("verification %s", *j.Verification)
	}
	h.step(id, store.RotOldDeleted)
	if s := h.secret(sid); s.ExternalID != "prod/app/api-key" {
		t.Errorf("a Secrets Manager secret keeps its name: %s", s.ExternalID)
	}
	if v := sm.versions[0]; len(v.Stages) != 0 {
		t.Errorf("the old version still has stages %v", v.Stages)
	}
}

// While the rotation function is still running the hand-over waits and resumes.
func TestSecretsManager_RotationInProgressResumes(t *testing.T) {
	h := newHarness(t)
	sm := smSetup(t, h, true)
	sid := h.addSecret("aws", "api_key", "api-key-prod", "prod/app/api-key", 90*24*time.Hour)
	id := h.startRotation(sid)
	sm.flipPolls = 1000 // AWS has not finished
	j := h.step(id, store.RotCreated)
	if j.Attempts != 1 || !strings.Contains(*j.LastError, "rotation_in_progress") {
		t.Errorf("attempts %d error %v", j.Attempts, j.LastError)
	}
	h.advance(time.Minute)
	sm.mu.Lock()
	sm.pendingFlip = 1 // the function finishes
	sm.mu.Unlock()
	h.step(id, store.RotHandedOver)
}

func TestSecretsManager_WithoutRotationFunctionWritesANewVersion(t *testing.T) {
	h := newHarness(t)
	sm := smSetup(t, h, false)
	sid := h.addSecret("aws", "api_key", "api-key-prod", "prod/app/api-key", 90*24*time.Hour)
	id := h.startRotation(sid)
	h.step(id, store.RotHandedOver)
	if !slices.Contains(sm.called(), "PutSecretValue prod/app/api-key") || slices.Contains(sm.called(), "RotateSecret prod/app/api-key") {
		t.Errorf("calls %v", sm.called())
	}
	h.step(id, store.RotOldDisabled)
	h.step(id, store.RotVerified)
	h.step(id, store.RotOldDeleted)
}

// Secrets Manager as the hand-over destination of another adapter's credential.
func TestSecretsManagerAsDestination(t *testing.T) {
	h := newHarness(t)
	iam := newFakeIAM(t, adapterCreds)
	iam.addKey("svc-etl", "AKIAOLDOLDOLDOLD0005", h.clock().Add(-100*24*time.Hour), nil)
	sm := newFakeSM(t, adapterCreds, "unrelated")
	h.putAdapter(AdapterInput{Name: "aws-prod", Type: TypeAWSIAM, Config: map[string]string{"endpoint": iam.srv.URL}, Credential: awsCredMap()})
	h.putAdapter(AdapterInput{Name: "sm-prod", Type: TypeAWSSM, Config: map[string]string{"endpoint": sm.srv.URL, "region": "eu-west-1"}, Credential: awsCredMap()})
	a, d := "aws-prod", "sm-prod"
	h.putPolicy(PolicyInput{Kind: "access_key", MaxAgeDays: 90, Adapter: &a, Destination: &d, DestPath: "tessera/{system}/{account}"})
	sid := h.addSecret("aws", "access_key", "AKIAETL5", "AKIAOLDOLDOLDOLD0005", 100*24*time.Hour)
	id := h.startRotation(sid)
	h.step(id, store.RotHandedOver)
	payload := sm.secrets["tessera/aws/svc-etl"]
	var data map[string]string
	if err := json.Unmarshal([]byte(payload), &data); err != nil || data["secret_access_key"] != newIAMSecret {
		t.Errorf("destination payload %q (%v)", payload, err)
	}
	if got := sm.called(); !slices.Equal(got, []string{"PutSecretValue tessera/aws/svc-etl", "CreateSecret <nil>"}) {
		t.Errorf("Secrets Manager calls %v", got)
	}
	// a second write finds the secret and adds a version
	h.advance(0)
	assertNoSecrets(t, h, newIAMSecret)
}

// ---------------------------------------------------------------- SSRF and environment guards

// The adapters reach providers only through a safehttp client: a production client
// refuses a loopback endpoint and nothing is sent.
func TestAdaptersUseTheSSRFGuard(t *testing.T) {
	h := newHarness(t)
	iam := newFakeIAM(t, adapterCreds)
	iam.addKey("svc-etl", "AKIAOLDOLDOLDOLD0006", h.clock().Add(-100*24*time.Hour), nil)
	prod, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	h.eng.Factory.HTTP = prod
	h.putAdapter(AdapterInput{Name: "aws-prod", Type: TypeAWSIAM, Config: map[string]string{"endpoint": iam.srv.URL}, Credential: awsCredMap()})
	h.putAdapter(AdapterInput{Name: "sim", Type: TypeFake})
	a, d := "aws-prod", "sim"
	h.putPolicy(PolicyInput{Kind: "access_key", MaxAgeDays: 90, Adapter: &a, Destination: &d, DestPath: "kv/x"})
	sid := h.addSecret("aws", "access_key", "AKIAETL6", "AKIAOLDOLDOLDOLD0006", 100*24*time.Hour)
	id := h.startRotation(sid)
	j := h.step(id, store.RotFailed)
	if !strings.Contains(*j.LastError, "destination_refused") {
		t.Errorf("error %q", *j.LastError)
	}
	if got := iam.called(); len(got) != 0 {
		t.Errorf("the provider was reached: %v", got)
	}
}

func TestSimulatedAdapterRefusedWhereNotAllowed(t *testing.T) {
	h := newHarness(t)
	h.svc.AllowFake = false
	err := h.db.InTenant(h.ctx(), h.tenant, func(tx *store.TenantTx) error {
		_, _, err := h.svc.PutAdapter(tx, AdapterInput{Name: "sim", Type: TypeFake}, "tester", h.clock())
		return err
	})
	var p *Problem
	if !asProblem(err, &p) || p.Code != "adapter_type_refused" {
		t.Errorf("PutAdapter(fake) = %v", err)
	}
	if slices.Contains(AdapterTypes(false), TypeFake) || !slices.Contains(AdapterTypes(true), TypeFake) {
		t.Error("AdapterTypes does not follow AllowFake")
	}
	// a fake row that already exists is refused by the engine's factory
	f := &Factory{AllowFake: false}
	if _, err := f.Build(&store.RotationAdapter{Name: "sim", Type: TypeFake, Config: "{}"}); err == nil {
		t.Error("the factory built a simulated adapter in an environment that refuses them")
	}
	// and a plan marks a policy that uses one as blocked
	h.svc.AllowFake = true
	fakePolicy(h, 0, nil)
	h.svc.AllowFake = false
	sid := h.addSecret("aws", "access_key", "AKIAETL7", "AKIAOLDOLDOLDOLD0007", 100*24*time.Hour)
	h.read(func(tx *store.TenantTx, now time.Time) error {
		plan, err := h.svc.Plan(tx, []int64{sid}, now)
		if err != nil || plan[0].Action != ActionBlocked || !strings.Contains(plan[0].Reason, "simulated") {
			t.Errorf("plan %+v %v", plan, err)
		}
		return nil
	})
}
