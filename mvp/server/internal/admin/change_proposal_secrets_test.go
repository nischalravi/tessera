package admin_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Proposals that carry secrets (issue #719): a secret is sealed apart from the payload, bound to the tenant, request and
// field, never shown, opened only to apply, and gone when the request ends.

const (
	hookSecret = "whsec-PLAINTEXT-signing-secret-1"
	hookURL    = "https://hooks.example.com/services/T000/B000/PLAINTEXT-URL-TOKEN"
	hecToken   = "PLAINTEXT-hec-token-0001"
	connSecret = "PLAINTEXT-connector-secret"
)

var plaintexts = []string{hookSecret, "PLAINTEXT-URL-TOKEN", hecToken, connSecret, "PLAINTEXT"}

// secretHarness is a harness whose service can apply connection proposals, with a proposer that may file them.
func secretHarness(t *testing.T) (*harness, []*store.PlatformUser, *auth.Principal) {
	h := newHarness(t)
	ad := h.admins("adm1", "adm2")
	machine := h.machine(h.user("olu", store.RoleOperator), "config.propose")
	h.grantScope(ad[0], ad[1])
	rd := readiness.NewService(template.MustDefault(), "dev")
	rd.Runner.Live.Sealer = h.sealer
	h.svc.Connections = rd
	return h, ad, machine
}

// noPlaintext fails when any secret is in the request row, its payload or sealed column, or the audit ledger.
func noPlaintext(t *testing.T, h *harness, id uuid.UUID) {
	t.Helper()
	ch := h.change(id)
	hay := []string{string(ch.Payload), string(ch.SecretEnc), ch.PayloadHash, ch.Failure}
	h.tx(func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(-1)
		for _, e := range evs {
			hay = append(hay, e.Action, string(e.Detail))
		}
		return err
	})
	for _, p := range plaintexts {
		for i, s := range hay {
			if strings.Contains(s, p) {
				t.Fatalf("%q appears in place %d: %.200s", p, i, s)
			}
		}
	}
}

func TestProposalSecrets_AlertChannel(t *testing.T) {
	h, ad, machine := secretHarness(t)
	body := `{"name":"soc-hook","kind":"webhook","target":"` + hookURL + `","min_severity":"high","signing_secret":"` + hookSecret + `"}`
	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(body))
	if err != nil {
		t.Fatal(err)
	}
	row := h.change(ch.ID)
	if len(row.SecretEnc) == 0 || !strings.Contains(string(row.Payload), `"signing_secret":"set"`) ||
		!strings.Contains(string(row.Payload), `"target_origin":"https://hooks.example.com:443"`) {
		t.Fatalf("payload %s, sealed %d bytes: want the markers and a sealed blob", row.Payload, len(row.SecretEnc))
	}
	noPlaintext(t, h, ch.ID)
	// nothing exists before approval
	h.tx(func(tx *store.TenantTx) error {
		if cs, err := tx.AlertChannels(); err != nil || len(cs) != 0 {
			t.Errorf("channels before approval = %v, %v", cs, err)
		}
		return nil
	})
	if _, err := h.svc.Approve(h.ctx, machine, ch.ID, ch.PayloadHash); err == nil {
		t.Fatal("the proposing client approved")
	}
	got, err := h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash)
	if err != nil || got.Status != store.ChangeApplied {
		t.Fatalf("approve: %v %v", got, err)
	}
	if n := len(h.change(ch.ID).SecretEnc); n != 0 {
		t.Errorf("%d sealed bytes left after the apply", n)
	}
	noPlaintext(t, h, ch.ID)
	h.tx(func(tx *store.TenantTx) error {
		cs, err := tx.AlertChannels()
		if err != nil || len(cs) != 1 {
			t.Fatalf("channels = %v, %v", cs, err)
		}
		c := cs[0]
		// the domain code sealed the secret under the channel's own AAD, and the URL is the one proposed
		plain, err := h.sealer.Open(c.SecretSealed, alerts.SecretAAD(tenantID, c.ID))
		if err != nil || string(plain) != hookSecret || c.Target != hookURL {
			t.Errorf("channel secret/target = %q %q, %v", plain, c.Target, err)
		}
		if _, err := h.sealer.Open(c.SecretSealed, alerts.SecretAAD(tenantID, uuid.NewString())); err == nil {
			t.Error("the channel's secret opens under another channel's AAD")
		}
		return nil
	})
	if id := adminResult(t, h, ch.ID); id == "" {
		t.Error("no result id for the applied channel")
	}
}

func adminResult(t *testing.T, h *harness, id uuid.UUID) string {
	t.Helper()
	var out string
	if err := h.db.ReadTenant(h.ctx, tenantID, func(tx *store.TenantTx) error {
		ch, err := tx.AdminChange(id)
		out = admin.ProposalResult(tx, ch)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProposalSecrets_SiemSinkKeepsAndReplacesToken(t *testing.T) {
	h, ad, machine := secretHarness(t)
	apply := func(id, body string) *store.AdminChange {
		t.Helper()
		ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindSiemSink, id, json.RawMessage(body))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash); err != nil {
			t.Fatal(err)
		}
		noPlaintext(t, h, ch.ID)
		return h.change(ch.ID)
	}
	sink := func() *store.SiemSink {
		var k *store.SiemSink
		h.tx(func(tx *store.TenantTx) error {
			ks, err := tx.SiemSinks()
			if err != nil || len(ks) != 1 {
				t.Fatalf("sinks = %v, %v", ks, err)
			}
			k = ks[0]
			return nil
		})
		return k
	}
	open := func(k *store.SiemSink) string {
		p, err := h.sealer.Open(k.SecretSealed, siem.SecretAAD(tenantID, k.ID))
		if err != nil {
			t.Fatal(err)
		}
		return string(p)
	}
	created := apply("", `{"name":"splunk","kind":"webhook","format":"json","flavor":"hec","target":"https://splunk.example.com:8088/services/collector","token":"`+hecToken+`"}`)
	k := sink()
	if open(k) != hecToken || created.Status != store.ChangeApplied {
		t.Fatalf("created sink token = %q, %s", open(k), created.Status)
	}
	// an update that leaves the token out keeps it
	apply(k.ID, `{"name":"splunk-prod"}`)
	if k2 := sink(); k2.Name != "splunk-prod" || open(k2) != hecToken {
		t.Errorf("after a rename: %q token %q", k2.Name, open(k2))
	}
	// one that sends a token replaces it
	apply(k.ID, `{"token":"PLAINTEXT-hec-token-0002"}`)
	if got := open(sink()); got != "PLAINTEXT-hec-token-0002" {
		t.Errorf("replaced token = %q", got)
	}
	// moving to another origin without a new token is refused by the same rule as the admin route
	_, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindSiemSink, k.ID, json.RawMessage(`{"target":"https://other.example.com/collector"}`))
	wantErr(t, err, http.StatusUnprocessableEntity, "credential_required")
}

func TestProposalSecrets_ConnectionStaysDraft(t *testing.T) {
	h, ad, machine := secretHarness(t)
	body := `{"name":"Okta prod","connector_type":"okta","config":{"org_url":"https://acme.okta.com"},"credential":{"secret":"` + connSecret + `"}}`
	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindConnection, "", json.RawMessage(body))
	if err != nil {
		t.Fatal(err)
	}
	noPlaintext(t, h, ch.ID)
	if _, err := h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	noPlaintext(t, h, ch.ID)
	h.tx(func(tx *store.TenantTx) error {
		cs, err := tx.Connections()
		if err != nil || len(cs) != 1 {
			t.Fatalf("connections = %v, %v", cs, err)
		}
		revs, err := tx.Revisions(cs[0].ID)
		if err != nil || len(revs) != 1 {
			t.Fatalf("revisions = %v, %v", revs, err)
		}
		if revs[0].SecretRef == nil || !strings.HasPrefix(*revs[0].SecretRef, "sealed:") {
			t.Errorf("secret ref = %v", revs[0].SecretRef)
		}
		// never active: activation is a separate step by a person
		_, live, pending, err := readiness.Revisions(tx, cs[0].ID)
		if err != nil || live != nil || pending == nil {
			t.Errorf("live %v, pending %v, %v: a proposal must leave the connection in draft", live, pending, err)
		}
		return nil
	})
	if adminResult(t, h, ch.ID) == "" {
		t.Error("no result id")
	}
}

// A blob opens only for the tenant, request and path it was sealed for.
func TestProposalSecrets_AADBinding(t *testing.T) {
	h, _, machine := secretHarness(t)
	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindSiemSink, "", json.RawMessage(
		`{"name":"s","kind":"webhook","format":"json","flavor":"hec","target":"https://s.example.com/c","token":"`+hecToken+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	enc := h.change(ch.ID).SecretEnc
	got, err := admin.OpenProposalSecrets(h.sealer, tenantID, ch.ID, enc, admin.KindSiemSink)
	if err != nil || got["token"] != hecToken || got["target"] == "" {
		t.Fatalf("own open = %v, %v", got, err)
	}
	other := tenancy.MustParse("00000000-0000-4000-8000-0000000000c2")
	if _, err := admin.OpenProposalSecrets(h.sealer, other, ch.ID, enc, admin.KindSiemSink); err == nil {
		t.Error("opened under another tenant")
	}
	if _, err := admin.OpenProposalSecrets(h.sealer, tenantID, uuid.New(), enc, admin.KindSiemSink); err == nil {
		t.Error("opened under another proposal")
	}
	// the blob of one field moved to another field of the same request
	var m map[string]string
	if err := json.Unmarshal(enc, &m); err != nil {
		t.Fatal(err)
	}
	m["token"], m["target"] = m["target"], m["token"]
	swapped, _ := json.Marshal(m)
	if _, err := admin.OpenProposalSecrets(h.sealer, tenantID, ch.ID, swapped, admin.KindSiemSink); err == nil {
		t.Error("opened a blob moved to another field")
	}
	wrong, _ := seal.New(seal.RandomBytes(32))
	if _, err := admin.OpenProposalSecrets(wrong, tenantID, ch.ID, enc, admin.KindSiemSink); err == nil {
		t.Error("opened under another KEK")
	}
}

// Reject, cancel, expiry and a failed apply all delete the sealed blob.
func TestProposalSecrets_EndedRequestsLoseTheirSecrets(t *testing.T) {
	h, ad, machine := secretHarness(t)
	file := func(name string) *store.AdminChange {
		ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindSiemSink, "", json.RawMessage(
			`{"name":"`+name+`","kind":"webhook","format":"json","flavor":"hec","target":"https://s.example.com/c","token":"`+hecToken+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(h.change(ch.ID).SecretEnc) == 0 {
			t.Fatal("nothing sealed")
		}
		return ch
	}
	rej, can, exp := file("a"), file("b"), file("c")
	if _, err := h.svc.Reject(h.ctx, h.as(ad[1]), rej.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Cancel(h.ctx, h.as(ad[1]), can.ID); err != nil {
		t.Fatal(err)
	}
	h.advance(admin.ApprovalWindow + 1)
	if n, err := h.svc.ExpireDue(h.ctx, tenantID); err != nil || n != 1 {
		t.Fatalf("expired %d, %v", n, err)
	}
	for name, ch := range map[string]*store.AdminChange{"rejected": rej, "cancelled": can, "expired": exp} {
		if row := h.change(ch.ID); len(row.SecretEnc) != 0 {
			t.Errorf("%s request keeps %d sealed bytes", name, len(row.SecretEnc))
		}
		noPlaintext(t, h, ch.ID)
	}
}

// A target the admin route refuses is refused at submit, and again when the request is approved: the environment may have
// changed in between.
func TestProposalSecrets_SSRFAtSubmitAndApply(t *testing.T) {
	h, ad, machine := secretHarness(t)
	for _, tc := range []struct {
		name, kind, body, code string
	}{
		{"webhook to the metadata service", admin.KindAlertChannel,
			`{"name":"m","kind":"webhook","target":"https://169.254.169.254/latest/meta-data","signing_secret":"` + hookSecret + `"}`, "invalid_target"},
		{"webhook over http", admin.KindAlertChannel,
			`{"name":"m","kind":"webhook","target":"http://hooks.example.com/x","signing_secret":"` + hookSecret + `"}`, "invalid_target"},
		{"webhook with credentials in the URL", admin.KindAlertChannel,
			`{"name":"m","kind":"webhook","target":"https://u:p@hooks.example.com/x","signing_secret":"` + hookSecret + `"}`, "invalid_target"},
		{"webhook needs its signing secret", admin.KindAlertChannel,
			`{"name":"m","kind":"webhook","target":"https://hooks.example.com/x"}`, "secret_required"},
		{"HEC to the metadata service", admin.KindSiemSink,
			`{"name":"m","kind":"webhook","format":"json","flavor":"hec","target":"https://169.254.169.254/x","token":"` + hecToken + `"}`, "invalid_target"},
		{"HEC without its token", admin.KindSiemSink,
			`{"name":"m","kind":"webhook","format":"json","flavor":"hec","target":"https://s.example.com/x"}`, "token_required"},
		{"syslog to a private address", admin.KindSiemSink,
			`{"name":"m","kind":"syslog","format":"json","target":"10.0.0.5:6514"}`, "invalid_target"},
		{"connection to the metadata service", admin.KindConnection,
			`{"name":"c","connector_type":"okta","config":{"org_url":"https://169.254.169.254"}}`, "invalid_config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.svc.SubmitProposal(h.ctx, machine, tc.kind, "", json.RawMessage(tc.body))
			wantErr(t, err, http.StatusUnprocessableEntity, tc.code)
		})
	}
	// dev allows a loopback http webhook; once the server runs as prod the same request is refused at approval, not applied
	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(
		`{"name":"local","kind":"webhook","target":"http://127.0.0.1:9/hook","signing_secret":"`+hookSecret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	h.svc.Prod = true
	_, err = h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash)
	wantErr(t, err, http.StatusUnprocessableEntity, "invalid_target")
	if got := h.change(ch.ID).Status; got != store.ChangePendingApproval {
		t.Errorf("status = %s: a refused approval must leave the request pending", got)
	}
	h.tx(func(tx *store.TenantTx) error {
		if cs, _ := tx.AlertChannels(); len(cs) != 0 {
			t.Error("the channel was created")
		}
		return nil
	})
}

// A blob that does not open ends the request as tampered; nothing is applied.
func TestProposalSecrets_TamperedBlobFails(t *testing.T) {
	h, ad, machine := secretHarness(t)
	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindSiemSink, "", json.RawMessage(
		`{"name":"s","kind":"webhook","format":"json","flavor":"hec","target":"https://s.example.com/c","token":"`+hecToken+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	// the key that sealed the blob is gone: it no longer opens
	other, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	h.svc.Sealer = other
	_, err = h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash)
	wantErr(t, err, http.StatusConflict, admin.ReasonPayloadTampered)
	if got := h.change(ch.ID).Status; got != store.ChangeFailed {
		t.Errorf("status = %s, want failed", got)
	}
	h.tx(func(tx *store.TenantTx) error {
		if ks, _ := tx.SiemSinks(); len(ks) != 0 {
			t.Error("a sink was created from a tampered request")
		}
		return nil
	})
}

// Case-variant keys must not get past the secret split: encoding/json would match "Target" to the field "target", leaving the
// URL (and its token) in the payload and letting the caller set the server-derived fields (#885 H1).
func TestProposalSecrets_CaseVariantKeysAreRefused(t *testing.T) {
	h, _, machine := secretHarness(t)
	rows := func() int {
		n := 0
		h.tx(func(tx *store.TenantTx) error { cs, err := tx.AdminChanges(); n = len(cs); return err })
		return n
	}
	before := rows()
	for _, tc := range []struct{ kind, body string }{
		{admin.KindAlertChannel, `{"name":"a","kind":"webhook","Target":"` + hookURL + `","signing_secret":"` + hookSecret + `"}`},
		{admin.KindAlertChannel, `{"name":"a","kind":"webhook","TARGET":"` + hookURL + `","signing_secret":"` + hookSecret + `"}`},
		{admin.KindAlertChannel, `{"name":"a","kind":"webhook","target":"` + hookURL + `","Target_Origin":"https://splunk.corp.example:443","signing_secret":"` + hookSecret + `"}`},
		{admin.KindAlertChannel, `{"name":"a","kind":"webhook","target":"` + hookURL + `","Signing_Secret":"` + hookSecret + `"}`},
		{admin.KindSiemSink, `{"name":"a","kind":"webhook","format":"json","flavor":"hec","Target":"` + hookURL + `","Token":"` + hecToken + `"}`},
		{admin.KindConnection, `{"name":"c","connector_type":"okta","Credential":{"secret":"` + connSecret + `"}}`},
		{admin.KindConnection, `{"name":"c","connector_type":"okta","credential":{"Secret":"` + connSecret + `"}}`},
		// the fields the server derives are never taken from a caller, even spelled exactly
		{admin.KindAlertChannel, `{"name":"a","kind":"webhook","target":"` + hookURL + `","target_origin":"https://splunk.corp.example:443","signing_secret":"` + hookSecret + `"}`},
		{admin.KindSiemSink, `{"name":"a","kind":"syslog","target":"collector:6514","target_fp":"0123456789abcdef"}`},
		{admin.KindSiemSink, `{"name":"a","kind":"syslog","target":"collector:6514","target_change":"unchanged"}`},
	} {
		_, err := h.svc.SubmitProposal(h.ctx, machine, tc.kind, "", json.RawMessage(tc.body))
		if err == nil {
			t.Errorf("accepted %s", tc.body)
			continue
		}
		for _, p := range plaintexts {
			if strings.Contains(err.Error(), p) {
				t.Errorf("the error echoes %q: %v", p, err)
			}
		}
	}
	if rows() != before {
		t.Error("a refused body left a request behind")
	}
}

// The approver sees the origin, a keyed fingerprint of the whole URL and what changed; never the path or token (#885 H2).
func TestProposalSecrets_ApproverSeesFingerprintNotURL(t *testing.T) {
	h, ad, machine := secretHarness(t)
	summary := func(id uuid.UUID) string {
		var s string
		h.tx(func(tx *store.TenantTx) error {
			ch, err := tx.AdminChange(id)
			s = admin.Summarize(tx, ch, h.clk.now())
			return err
		})
		return s
	}
	file := func(id, body string) (*store.AdminChange, string) {
		ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, id, json.RawMessage(body))
		if err != nil {
			t.Fatal(err)
		}
		return ch, summary(ch.ID)
	}
	ch, sum := file("", `{"name":"soc","kind":"webhook","target":"`+hookURL+`","signing_secret":"`+hookSecret+`"}`)
	fp, err := admin.TargetFingerprint(h.sealer, tenantID, ch.ID, hookURL)
	if err != nil || len(fp) != 16 {
		t.Fatalf("fingerprint %q, %v", fp, err)
	}
	for _, want := range []string{"https://hooks.example.com:443", "Check this URL"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary %q lacks %q", sum, want)
		}
	}
	for _, bad := range []string{"services", "PLAINTEXT", "T000"} {
		if strings.Contains(sum, bad) {
			t.Errorf("summary %q shows %q", sum, bad)
		}
	}
	// the fingerprint is keyed and bound to the tenant: another KEK or tenant gives another one
	other, _ := seal.New(seal.RandomBytes(32))
	if f2, _ := admin.TargetFingerprint(other, tenantID, ch.ID, hookURL); f2 == fp {
		t.Error("the fingerprint does not depend on the key")
	}
	if f3, _ := admin.TargetFingerprint(h.sealer, tenancy.MustParse("00000000-0000-4000-8000-0000000000c2"), ch.ID, hookURL); f3 == fp {
		t.Error("the fingerprint does not depend on the tenant")
	}
	// and to the request: the same URL in another request gives another value, so a fingerprint compares only through
	// its own request's check-target (#886)
	if f4, _ := admin.TargetFingerprint(h.sealer, tenantID, uuid.New(), hookURL); f4 == fp {
		t.Error("the fingerprint does not depend on the request")
	}
	if ch2, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(
		`{"name":"soc2","kind":"webhook","target":"`+hookURL+`","signing_secret":"`+hookSecret+`"}`)); err != nil {
		t.Fatal(err)
	} else if _, fp2 := admin.ProposalTarget(h.change(ch2.ID)); fp2 == fp {
		t.Error("the same URL filed twice shows the same fingerprint")
	}
	if o, p := admin.ProposalTarget(h.change(ch.ID)); o != "https://hooks.example.com:443" || p != fp {
		t.Errorf("ProposalTarget = %q %q", o, p)
	}
	if _, err := h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	var id string
	h.tx(func(tx *store.TenantTx) error { cs, _ := tx.AlertChannels(); id = cs[0].ID; return nil })
	// a path-only change keeps the origin: it is flagged, not hidden
	_, sum = file(id, `{"target":"https://hooks.example.com/services/T000/B000/OTHER-WORKSPACE"}`)
	if !strings.Contains(sum, "PATH CHANGED") || strings.Contains(sum, "OTHER-WORKSPACE") {
		t.Errorf("path change summary: %q", sum)
	}
	_, sum = file(id, `{"target":"`+hookURL+`"}`)
	if !strings.Contains(sum, "same URL as now") {
		t.Errorf("unchanged summary: %q", sum)
	}
	_, sum = file(id, `{"target":"https://elsewhere.example.org/x","signing_secret":"`+hookSecret+`-2"}`)
	if !strings.Contains(sum, "MOVED to another origin") {
		t.Errorf("moved summary: %q", sum)
	}
}

// A connection proposal that points a stored credential reference at an endpoint says both to the approver (#885 M2), and the
// refusal of the domain code keeps its per-field detail (#885 L5).
func TestProposalSecrets_ConnectionSummaryAndFieldErrors(t *testing.T) {
	h, _, machine := secretHarness(t)
	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindConnection, "", json.RawMessage(
		`{"name":"Okta ref","connector_type":"okta","config":{"org_url":"https://evil.example.net"},"credential":{"reference":"vault:kv/prod/okta"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var sum string
	h.tx(func(tx *store.TenantTx) error {
		c, _ := tx.AdminChange(ch.ID)
		sum = admin.Summarize(tx, c, h.clk.now())
		return nil
	})
	for _, want := range []string{"vault:kv/prod/okta", "org_url=https://evil.example.net"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary %q lacks %q", sum, want)
		}
	}
	_, err = h.svc.SubmitProposal(h.ctx, machine, admin.KindConnection, "", json.RawMessage(
		`{"name":"c2","connector_type":"okta","config":{"org_url":"https://169.254.169.254"}}`))
	if err == nil || !strings.Contains(err.Error(), "org_url") {
		t.Errorf("the refusal does not name the field: %v", err)
	}
}

// A sealed blob that names a field this kind does not seal is refused before any key is used; duplicate names are refused so
// the created object is unambiguous.
func TestProposalSecrets_BlobKeysAndDuplicateNames(t *testing.T) {
	h, ad, machine := secretHarness(t)
	enc, _ := json.Marshal(map[string]string{"": "AA==", "a|b": "AA==", "other": "AA=="})
	if _, err := admin.OpenProposalSecrets(h.sealer, tenantID, uuid.New(), enc, admin.KindSiemSink); err == nil {
		t.Error("a blob with foreign keys opened")
	}
	body := `{"name":"dup","kind":"webhook","format":"json","flavor":"hec","target":"https://s.example.com/c","token":"` + hecToken + `"}`
	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindSiemSink, "", json.RawMessage(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.SubmitProposal(h.ctx, machine, admin.KindSiemSink, "", json.RawMessage(body))
	wantErr(t, err, http.StatusConflict, "duplicate_sink")
	hook := `{"name":"dup","kind":"email","target":"a@example.com"}`
	ch, err = h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(hook))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(hook))
	wantErr(t, err, http.StatusConflict, "duplicate_channel")
}

// The approver's endpoint list is built from the decoded, typed config, so a spelling the decoder accepts cannot hide an
// endpoint and a nested host is shown; a key that is not an exact field name is refused inside config too.
func TestProposalSecrets_ConnectionEndpointsCannotBeForged(t *testing.T) {
	h, _, machine := secretHarness(t)
	for _, cfg := range []string{
		`{"Org_URL":"https://evil.example.net"}`,
		`{"ORG_URL":"https://evil.example.net"}`,
		`{"org_url":"https://acme.okta.com","Rest":{"base_url":"https://evil.example.net"}}`,
		`{"sql":{"Host":"db.evil.example","engine":"postgres","username":"u"}}`,
	} {
		_, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindConnection, "", json.RawMessage(
			`{"name":"c","connector_type":"okta","config":`+cfg+`,"credential":{"reference":"vault:kv/prod/okta"}}`))
		if err == nil || !strings.Contains(err.Error(), "case-sensitive") {
			t.Errorf("config %s: %v", cfg, err)
		}
	}
	// the endpoints field is the server's, never a caller's
	_, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindConnection, "", json.RawMessage(
		`{"name":"c","connector_type":"okta","config":{"org_url":"https://evil.example.net"},"endpoints":["org_url=https://acme.okta.com"]}`))
	if err == nil {
		t.Error("a caller set the endpoints")
	}
	summary := func(body, typ string) string {
		ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindConnection, "", json.RawMessage(body))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		var s string
		h.tx(func(tx *store.TenantTx) error {
			c, _ := tx.AdminChange(ch.ID)
			s = admin.Summarize(tx, c, h.clk.now())
			return nil
		})
		return s
	}
	sum := summary(`{"name":"DB","connector_type":"sql","system":"orders-db","config":{"sql":{"engine":"postgres","host":"db.example.org","port":5432,"database":"orders","username":"u"}},"credential":{"reference":"vault:kv/db"}}`, "sql")
	if !strings.Contains(sum, "sql.host=db.example.org:5432") {
		t.Errorf("the nested database host is not shown: %q", sum)
	}
	sum = summary(`{"name":"Okta default","connector_type":"okta","credential":{"reference":"vault:kv/okta"}}`, "okta")
	if !strings.Contains(sum, "endpoint: none named") {
		t.Errorf("an empty endpoint list is not said: %q", sum)
	}
}

// A governed type's settings.port is part of where the credential goes, so the approver's endpoint list shows it (#886).
func TestProposalSecrets_ConnectionSummaryShowsPort(t *testing.T) {
	h, _, machine := secretHarness(t)
	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindConnection, "", json.RawMessage(
		`{"name":"Unix","connector_type":"unixssh","system":"unix","config":{"settings":{"host":"ssh.example.com","port":"2222","username":"svc","host_key":"SHA256:abc"}},"credential":{"reference":"vault:kv/ssh"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var sum string
	h.tx(func(tx *store.TenantTx) error {
		c, err := tx.AdminChange(ch.ID)
		sum = admin.Summarize(tx, c, h.clk.now())
		return err
	})
	if !strings.Contains(sum, "settings.port=2222") || !strings.Contains(sum, "settings.host=ssh.example.com") {
		t.Errorf("the port is not shown: %q", sum)
	}
}

// The endpoint list is checked again when the change is applied, not only when it is approved (#886): a connection whose
// stored config moved after the approver saw the list is not sent a credential.
func TestProposalSecrets_ConnectionEndpointsRecheckedAtApply(t *testing.T) {
	h, ad, machine := secretHarness(t)
	create, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindConnection, "", json.RawMessage(
		`{"name":"Okta prod","connector_type":"okta","config":{"org_url":"https://acme.okta.com"},"credential":{"secret":"`+connSecret+`"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(h.ctx, h.as(ad[0]), create.ID, create.PayloadHash); err != nil {
		t.Fatal(err)
	}
	connID := adminResult(t, h, create.ID)
	// a credential-only update: the endpoints shown are the stored config's
	upd, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindConnection, connID, json.RawMessage(`{"credential":{"reference":"vault:kv/okta"}}`))
	if err != nil {
		t.Fatal(err)
	}
	// approved (as the store records it, with the effective time now), then the stored config moves before the apply
	h.tx(func(tx *store.TenantTx) error {
		return tx.ApproveAdminChange(upd.ID, ad[0].ID, h.clk.now(), h.clk.now())
	})
	h.tx(func(tx *store.TenantTx) error {
		_, err := h.svc.Connections.PatchConfig(tx, connID, []byte(`{"org_url":"https://evil.okta.com"}`), "adm", h.clk.now())
		return err
	})
	_, err = h.svc.Apply(h.ctx, h.as(ad[1]), upd.ID)
	wantErr(t, err, http.StatusConflict, "endpoints_changed")
	if got := h.change(upd.ID); got.Status != store.ChangeFailed {
		t.Errorf("status = %s, want failed", got.Status)
	}
}
