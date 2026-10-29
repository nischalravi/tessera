package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

const lpDenialURL = "/public/t/larkspur/lp/denials"

// lpRevoked takes a verified right-size of alice's S3 read policy through the loop to revoked: the policy now allows
// s3:GetObject on prod-pii/customers.csv only (it allowed prod-pii/*). at is when it became revoked.
func (w *awsWB) lpRevoked() (id string, at time.Time) {
	w.t.Helper()
	c := w.lpPropose()
	id = asString(c["id"])
	w.lpApprove(c)
	later := testkit.Now.Add(8 * 24 * time.Hour)
	w.lpTick(later)
	w.runAt(later)
	w.lpTick(later.Add(time.Minute))
	if st := w.lpState(id); st != "revoked" {
		w.t.Fatalf("not revoked: %s", st)
	}
	return id, later.Add(time.Minute)
}

// hook creates the receiver credential through the API and returns its secret.
func (w *awsWB) hook() string {
	w.t.Helper()
	v := w.c.json("POST", "/api/lp/denial-hook", `{}`, http.StatusCreated).(map[string]any)
	if v["url_path"] != lpDenialURL || !strings.HasPrefix(asString(v["secret"]), "lpd_") {
		w.t.Fatalf("hook = %v", v)
	}
	return asString(v["secret"])
}

// push delivers a body to the receiver as of at.
func (w *awsWB) push(secret, body string, at time.Time) *httptest.ResponseRecorder {
	w.t.Helper()
	return w.pushTo(lpDenialURL, secret, body, at)
}

func (w *awsWB) pushTo(path, secret, body string, at time.Time) *httptest.ResponseRecorder {
	w.t.Helper()
	w.srv.clock = func() time.Time { return at }
	defer func() { w.srv.clock = func() time.Time { return testkit.Now } }()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	return serve(w.srv.Handler(), req)
}

// cloudTrailDenial is an EventBridge event for a CloudTrail AccessDenied of alice (an S3 data event).
func cloudTrailDenial(eventID, errorCode, action, object string) string {
	return fmt.Sprintf(`{"version":"0","id":"eb-%s","detail-type":"AWS API Call via CloudTrail","source":"aws.s3","time":"2026-11-08T10:00:00Z",
	"detail":{"eventID":%q,"eventTime":"2026-11-08T10:00:00Z","eventSource":"s3.amazonaws.com","eventName":%q,"errorCode":%q,
	"userIdentity":{"type":"IAMUser","arn":%q},"requestParameters":{"bucketName":"prod-pii","key":%q},
	"resources":[{"type":"AWS::S3::Object","ARN":"arn:aws:s3:::prod-pii/%s"}]}}`, eventID, eventID, action, errorCode, awstest.EstateAlice, object, object)
}

// A denial of access the loop removed restores it, verified, inside the 15-minute SLO; a denial of anything else,
// a redelivery and a stranger do not.
func TestLPDenial_RestoresRevokedAccess(t *testing.T) {
	w := lpOn(t)
	id, revokedAt := w.lpRevoked()
	secret := w.hook()
	arrive := revokedAt.Add(time.Minute)

	if rec := w.push("", cloudTrailDenial("e0", "AccessDenied", "GetObject", "other.csv"), arrive); rec.Code != http.StatusUnauthorized {
		t.Errorf("no secret: %d %s", rec.Code, rec.Body)
	}
	if rec := w.push("lpd_wrong", cloudTrailDenial("e0", "AccessDenied", "GetObject", "other.csv"), arrive); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong secret: %d %s", rec.Code, rec.Body)
	}
	if w.lpState(id) != "revoked" {
		t.Fatalf("an unauthenticated event moved the revocation to %s", w.lpState(id))
	}
	// not a denial, then a denial of what the policy still allows: nothing is restored
	if rec := w.push(secret, cloudTrailDenial("e1", "ThrottlingException", "GetObject", "other.csv"), arrive); rec.Code != 202 || !strings.Contains(rec.Body.String(), "not_a_denial") {
		t.Errorf("not a denial: %d %s", rec.Code, rec.Body)
	}
	if rec := w.push(secret, cloudTrailDenial("e2", "AccessDenied", "GetObject", "customers.csv"), arrive); rec.Code != 202 || !strings.Contains(rec.Body.String(), "action_not_removed") {
		t.Errorf("a kept call: %d %s", rec.Code, rec.Body)
	}
	if rec := w.push(secret, cloudTrailDenial("e3", "AccessDenied", "PutObject", "other.csv"), arrive); rec.Code != 202 || !strings.Contains(rec.Body.String(), "action_not_removed") {
		t.Errorf("an action the policy never granted: %d %s", rec.Code, rec.Body)
	}
	if st := w.lpState(id); st != "revoked" {
		t.Fatalf("a denial of something not removed restored it: %s", st)
	}
	// the removed call: s3:GetObject on another object of the bucket
	ev := cloudTrailDenial("e4", "AccessDenied", "GetObject", "other.csv")
	if rec := w.push(secret, ev, arrive); rec.Code != 202 || !strings.Contains(rec.Body.String(), `"restored":1`) {
		t.Fatalf("the removed call: %d %s", rec.Code, rec.Body)
	}
	if st := w.lpState(id); st != "restoring" {
		t.Fatalf("after the denial: %s", st)
	}
	d := w.c.json("GET", "/api/lp/revocations/"+id, "", 200).(map[string]any)
	if d["restore_trigger"] != "denial" {
		t.Errorf("trigger = %v", d["restore_trigger"])
	}
	// a redelivery changes nothing
	if rec := w.push(secret, ev, arrive.Add(time.Second)); rec.Code != 202 || !strings.Contains(rec.Body.String(), "duplicate") {
		t.Errorf("redelivery: %d %s", rec.Code, rec.Body)
	}
	if n := len(w.ops()); n != 2 {
		t.Errorf("%d operations after a redelivery, want the revoke and one restore", n)
	}
	// the engine sends the restore and the loop's job verifies it
	w.runAt(arrive.Add(2 * time.Minute))
	w.lpTick(arrive.Add(6 * time.Minute))
	if st := w.lpState(id); st != "restored" {
		t.Fatalf("after the engine ran: %s", st)
	}
	list := w.c.json("GET", "/api/lp/denials", "", 200).(map[string]any)["items"].([]any)
	var restored map[string]any
	for _, it := range list {
		if m := it.(map[string]any); m["event_id"] == "e4" {
			restored = m
		}
	}
	if restored == nil || restored["outcome"] != "restore_requested" || restored["restore_state"] != "restored" || restored["within_slo"] != true ||
		restored["latency_seconds"] != float64(6*60) || restored["resource"] != "arn:aws:s3:::prod-pii/other.csv" {
		t.Fatalf("denial view = %v", restored)
	}
	if len(list) != 3 { // e2, e3 and e4: an event with no revoked grant behind it leaves no row
		t.Errorf("%d denial rows, want 3: %v", len(list), list)
	}
	for _, want := range []string{"lp.denial.restore_requested", "lp.denial.action_not_removed", "lp.revocation.restoring", "lp.revocation.restored", "lp.denial_hook.save"} {
		if !strings.Contains(w.audit(), want) {
			t.Errorf("audit has no %s: %s", want, w.audit())
		}
	}
	// the people who manage the loop were told
	var told int
	testkit.Read(t, w.st, func(tx *store.TenantTx) error {
		to, err := notify.Holders(tx, testkit.Now.Add(10*24*time.Hour), auth.PermLPManage)
		for _, r := range to {
			ns, err := tx.Notifications(r.UserID, false, 50)
			if err != nil {
				return err
			}
			for _, n := range ns {
				if n.Kind == notify.KindSecurityAlert && strings.Contains(n.Subject, "restored") {
					told++
				}
			}
		}
		return err
	})
	if told == 0 {
		t.Errorf("nobody was notified of the restore")
	}
}

// A pause and the operator switch stop new revocations, never a restore.
func TestLPDenial_NotBlockedByPause(t *testing.T) {
	w := lpOn(t)
	id, revokedAt := w.lpRevoked()
	secret := w.hook()
	w.c.json("POST", "/api/lp/pause", `{"reason":"test"}`, 200)
	w.srv.cfg.LPDisabled = true
	if rec := w.push(secret, cloudTrailDenial("p1", "Client.UnauthorizedOperation", "GetObject", "other.csv"), revokedAt.Add(time.Minute)); rec.Code != 202 || !strings.Contains(rec.Body.String(), `"restored":1`) {
		t.Fatalf("paused: %d %s", rec.Code, rec.Body)
	}
	if st := w.lpState(id); st != "restoring" {
		t.Errorf("paused loop: %s", st)
	}
}

// An IdP denial arrives in the normalized form; a finalized revocation is not restored by a denial.
func TestLPDenial_NormalizedAndFinal(t *testing.T) {
	w := lpOn(t)
	id, revokedAt := w.lpRevoked()
	secret := w.hook()
	bad := []string{`not json`, `{"source":"other","event_id":"x","principal":"` + awstest.EstateAlice + `","action":"s3:GetObject"}`,
		`{"source":"idp","event_id":"x y","principal":"` + awstest.EstateAlice + `","action":"s3:GetObject"}`,
		`{"source":"idp","event_id":"x","principal":"` + awstest.EstateAlice + `","action":"GetObject"}`,
		`{"source":"idp","event_id":"x","principal":"` + awstest.EstateAlice + `","action":"s3:GetObject","time":"yesterday"}`}
	for _, b := range bad {
		if rec := w.push(secret, b, revokedAt); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %s", b, rec.Code, rec.Body)
		}
	}
	// a stranger and an assumed role without an issuer name nobody with a grant
	other := `{"source":"idp","event_id":"s1","principal":"arn:aws:iam::111111111111:role/nobody","action":"s3:GetObject"}`
	if rec := w.push(secret, other, revokedAt); rec.Code != 202 || !strings.Contains(rec.Body.String(), lp.OutcomeNoRevocation) {
		t.Errorf("stranger: %d %s", rec.Code, rec.Body)
	}
	// the finalize period ends: the access comes back through a request, not a denial
	w.lpTick(revokedAt.Add(31 * 24 * time.Hour))
	if st := w.lpState(id); st != "finalized" {
		t.Fatalf("not final: %s", st)
	}
	final := fmt.Sprintf(`{"source":"idp","event_id":"f1","principal":%q,"action":"s3:GetObject","resource":"arn:aws:s3:::prod-pii/other.csv"}`, awstest.EstateAlice)
	if rec := w.push(secret, final, revokedAt.Add(32*24*time.Hour)); rec.Code != 202 || !strings.Contains(rec.Body.String(), lp.OutcomeNoRevocation) {
		t.Errorf("final: %d %s", rec.Code, rec.Body)
	}
	if st := w.lpState(id); st != "finalized" {
		t.Errorf("a denial moved a final revocation: %s", st)
	}
}

// The credential: shown once, rotation invalidates the old secret, and reading it never returns the secret.
func TestLPDenial_HookRotation(t *testing.T) {
	w := lpOn(t)
	if v := w.c.json("GET", "/api/lp/denial-hook", "", 200).(map[string]any); v["configured"] != false || v["url_path"] != lpDenialURL {
		t.Fatalf("before: %v", v)
	}
	first := w.hook()
	second := w.hook()
	if first == second {
		t.Fatal("rotation kept the secret")
	}
	v := w.c.json("GET", "/api/lp/denial-hook", "", 200).(map[string]any)
	if raw, _ := json.Marshal(v); v["configured"] != true || strings.Contains(string(raw), first) || strings.Contains(string(raw), second) {
		t.Fatalf("after: %s", raw)
	}
	body := `{"source":"idp","event_id":"r1","principal":"` + awstest.EstateAlice + `","action":"s3:GetObject"}`
	if rec := w.push(first, body, testkit.Now); rec.Code != http.StatusUnauthorized {
		t.Errorf("the old secret: %d %s", rec.Code, rec.Body)
	}
	if rec := w.push(second, body, testkit.Now); rec.Code != 202 {
		t.Errorf("the new secret: %d %s", rec.Code, rec.Body)
	}
	if rec := w.push(second, body, testkit.Now); rec.Code != 202 {
		t.Errorf("again: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(w.audit(), first) || strings.Contains(w.audit(), second) {
		t.Errorf("a secret reached the audit trail")
	}
}

func TestLPDenial_Normalize(t *testing.T) {
	const alice = "arn:aws:iam::111111111111:user/alice"
	cases := []struct {
		name, body       string
		wantAction, want string
		ignore           string
		err              bool
	}{
		{"console ec2", `{"detail":{"eventID":"a","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","errorCode":"Client.UnauthorizedOperation","userIdentity":{"arn":"` + alice + `"}}}`,
			"ec2:DescribeInstances", "", "", false},
		{"role session", `{"detail":{"eventID":"a","eventSource":"monitoring.amazonaws.com","eventName":"GetMetricData","errorCode":"AccessDenied","userIdentity":{"arn":"arn:aws:sts::111111111111:assumed-role/r/s","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::111111111111:role/r"}}}}}`,
			"cloudwatch:GetMetricData", "", "", false},
		{"success", `{"detail":{"eventID":"a","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","userIdentity":{"arn":"` + alice + `"}}}`, "", "", "not_a_denial", false},
		{"session without issuer", `{"detail":{"eventID":"a","eventSource":"ec2.amazonaws.com","eventName":"Run","errorCode":"AccessDenied","userIdentity":{"arn":"arn:aws:sts::111111111111:assumed-role/r/s"}}}`, "", "", "no_grant_holder", false},
		{"no service host", `{"detail":{"eventID":"a","eventSource":"ec2","eventName":"Run","errorCode":"AccessDenied","userIdentity":{"arn":"` + alice + `"}}}`, "", "", "", true},
		{"bad resource is unknown", `{"source":"idp","event_id":"a","principal":"` + alice + `","action":"s3:GetObject","resource":"not an arn"}`, "s3:GetObject", "", "", false},
	}
	for _, tc := range cases {
		var in lpDenialIn
		if err := json.Unmarshal([]byte(tc.body), &in); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		d, ignore, err := in.normalize()
		if (err != nil) != tc.err || ignore != tc.ignore || (tc.wantAction != "" && d.Action != tc.wantAction) || d.Resource != tc.want {
			t.Errorf("%s: %+v ignore=%q err=%v", tc.name, d, ignore, err)
		}
	}
}

func TestLPDenial_Removed(t *testing.T) {
	const prior = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","kms:Decrypt"],"Resource":"arn:aws:s3:::b/*"}]}`
	const narrowed = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/kept"}]}`
	cases := []struct {
		name, prior, doc, action, resource string
		want                               bool
	}{
		{"narrowed resource, removed object", prior, narrowed, "s3:GetObject", "arn:aws:s3:::b/other", true},
		{"narrowed resource, kept object", prior, narrowed, "s3:GetObject", "arn:aws:s3:::b/kept", false},
		{"narrowed resource, resource unknown", prior, narrowed, "s3:GetObject", "", false},
		{"action dropped, resource unknown", prior, narrowed, "s3:GetObjectVersion", "", true},
		{"wildcard removed", prior, narrowed, "s3:GetBucketLocation", "", true},
		{"never granted", prior, narrowed, "s3:PutObject", "arn:aws:s3:::b/x", false},
		{"detach leaves nothing", prior, "", "s3:GetObject", "arn:aws:s3:::b/x", true},
		{"no prior state", "", narrowed, "s3:GetObject", "", false},
		{"unparseable prior", "{", narrowed, "s3:GetObject", "", false},
		{"deny is not a grant", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`, "", "s3:GetObject", "", false},
	}
	for _, tc := range cases {
		p, _ := json.Marshal(lpPayload{Prior: tc.prior, Document: tc.doc})
		got, err := lpRemoved(&store.LPRevocation{RestorePayload: string(p)}, tc.action, tc.resource)
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
}

// A tenant's secret opens that tenant's receiver only: another slug, an unknown one, the platform and a malformed
// one all answer the same 401 as a wrong secret, and nothing is recorded.
func TestLPDenial_OtherTenantsSlug(t *testing.T) {
	w := lpOn(t)
	id, revokedAt := w.lpRevoked()
	secret := w.hook()
	body := fmt.Sprintf(`{"source":"idp","event_id":"o1","principal":%q,"action":"s3:GetObject","resource":"arn:aws:s3:::prod-pii/other.csv"}`, awstest.EstateAlice)
	want := w.pushTo(lpDenialURL, "lpd_wrong", body, revokedAt).Body.String()
	for _, slug := range []string{"globex", "no-such-tenant", "_platform", "NO_SUCH!"} {
		rec := w.pushTo("/public/t/"+slug+"/lp/denials", secret, body, revokedAt)
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "outcome") {
			t.Errorf("%s: %d %s", slug, rec.Code, rec.Body)
		}
		if rec.Code == http.StatusUnauthorized && rec.Body.String() != want {
			t.Errorf("%s answers differently from a wrong secret: %s", slug, rec.Body)
		}
	}
	if st := w.lpState(id); st != "revoked" {
		t.Errorf("another slug moved the revocation: %s", st)
	}
}
