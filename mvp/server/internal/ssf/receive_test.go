package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func TestReceive_SessionRevokedRunsTheKillSwitchOnOtherAccounts(t *testing.T) {
	r := newRig(t)
	ev, err := r.deliver("jti-a", EventSessionRevoked, issSub("alice"))
	if err != nil {
		t.Fatal(err)
	}
	// the Okta account is the transmitter's own: only the Entra account is touched. Its provider call cannot be
	// made (no outbound client), so the step fails and a retry task holds it.
	if ev.Status != store.SSFEventFailed || ev.Steps != 1 || ev.StepsFailed != 1 || ev.IdentityID == nil || *ev.IdentityID != r.alice ||
		ev.LatencyMS == nil || ev.IATLatencyMS == nil || ev.ActionedAt == nil || *ev.IATLatencyMS != 60_000 {
		t.Fatalf("event = %+v", ev)
	}
	if !strings.Contains(ev.Outcome, "1 failed (1 retry task(s) queued)") {
		t.Errorf("outcome %q", ev.Outcome)
	}
	got := r.actions()
	for _, a := range []string{"ssf.event_received", "ssf.event_actioned", "containment.run", "containment.retry_scheduled"} {
		if got[a] != 1 {
			t.Errorf("audit %s = %d: %v", a, got[a], got)
		}
	}
	d := r.auditDetail("ssf.event_actioned")
	if d["latency_ms"] == nil || d["iat_latency_ms"] != float64(60000) || d["identity"] == nil || d["event"] != "session-revoked" {
		t.Errorf("event_actioned detail %v", d)
	}
	r.read(func(c *store.TenantTx) error {
		rs, err := c.ContainmentRetriesFor(r.alice)
		if err != nil || len(rs) != 1 || rs[0].System != "entra" || rs[0].Action != "revoke_sessions" || rs[0].Trigger != "ssf" {
			t.Errorf("retries %+v %v", rs, err)
		}
		x, _ := c.SSFTransmitter(r.tr.ID)
		if x.LastEventAt == nil || x.LastError != "" {
			t.Errorf("transmitter %+v", x)
		}
		return nil
	})
	// the SET is not in the ledger
	r.read(func(c *store.TenantTx) error {
		evs, _ := c.AuditEvents(store.AuditFilter{IncludeHTTP: true})
		for _, e := range evs {
			if strings.Contains(string(e.Detail), "eyJ") {
				t.Errorf("audit event %s carries a token: %s", e.Action, e.Detail)
			}
		}
		return nil
	})
}

func TestReceive_CredentialChangeAndAccountDisabledRunGrantsToo(t *testing.T) {
	for _, event := range []string{EventCredentialChange, EventAccountDisabled} {
		r := newRig(t)
		ev, err := r.deliver("jti-"+EventName(event), event, map[string]any{"format": "email", "email": strings.ToUpper(r.aliceEmail)})
		if err != nil {
			t.Fatal(err)
		}
		// revoke_sessions and revoke_grants on the Entra account
		if ev.Steps != 2 || ev.StepsFailed != 2 || ev.Status != store.SSFEventFailed {
			t.Errorf("%s: %+v", EventName(event), ev)
		}
	}
}

func TestReceive_Statuses(t *testing.T) {
	r := newRig(t)
	cases := []struct {
		name, event string
		subject     map[string]any
		status      string
		outcome     string
	}{
		{"unknown event type", "https://example.test/event/other", issSub("alice"), store.SSFEventIgnored, "unknown event type"},
		{"unknown subject", EventSessionRevoked, issSub("nobody"), store.SSFEventUnmatched, "no okta account matches"},
		{"unknown email", EventAccountDisabled, map[string]any{"format": "email", "email": "nobody@a.example"}, store.SSFEventUnmatched, "no okta account"},
		{"unsupported format", EventSessionRevoked, map[string]any{"format": "phone_number", "phone_number": "+1"}, store.SSFEventUnmatched, "unsupported subject format"},
		{"no subject", EventSessionRevoked, nil, store.SSFEventUnmatched, "no subject"},
		{"complex without user", EventSessionRevoked, map[string]any{"format": "complex", "session": map[string]any{"format": "opaque", "id": "s"}}, store.SSFEventUnmatched, "no user"},
	}
	for i, tc := range cases {
		ev, err := r.deliver("jti-"+string(rune('a'+i)), tc.event, tc.subject)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if ev.Status != tc.status || !strings.Contains(ev.Outcome, tc.outcome) || ev.IdentityID != nil || ev.LatencyMS == nil {
			t.Errorf("%s: %+v", tc.name, ev)
		}
	}
	got := r.actions()
	if got["ssf.event_unmatched"] != 5 || got["ssf.event_ignored"] != 1 || got["ssf.event_received"] != 6 || got["containment.run"] != 0 {
		t.Errorf("audit actions %v", got)
	}
	d := r.auditDetail("ssf.event_unmatched")
	if d["reason"] == nil || d["subject"] == nil || d["transmitter_id"] != r.tr.ID {
		t.Errorf("unmatched detail %v", d)
	}
}

func TestReceive_SubjectResolution(t *testing.T) {
	r := newRig(t)
	bob := r.f.A.IDs["bob"]
	// a linked-nowhere okta account, and an email shared by two identities' accounts
	if err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(c *store.TenantTx) error {
		if _, err := c.InsertAccount(&store.Account{System: "okta", ExternalID: "orphan", Username: "orphan@a.example", Kind: "human", Status: "active"}); err != nil {
			return err
		}
		_, err := c.InsertAccount(&store.Account{System: "okta", ExternalID: "bob-2", IdentityID: &bob, Username: r.aliceEmail, Kind: "human", Status: "active"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		subject map[string]any
		status  string
		outcome string
	}{
		{"unlinked account", issSub("orphan"), store.SSFEventUnmatched, "not linked to an identity"},
		{"email of two identities' accounts", map[string]any{"format": "email", "email": r.aliceEmail}, store.SSFEventUnmatched, "ambiguous"},
		{"opaque id", map[string]any{"format": "opaque", "id": "alice"}, store.SSFEventFailed, "failed"},
		{"complex: the user is resolved", map[string]any{"format": "complex", "user": issSub("alice"),
			"session": map[string]any{"format": "opaque", "id": "sess-1"}}, store.SSFEventFailed, "failed"},
		{"another transmitter's system id does not match", issSub("alice-entra-id"), store.SSFEventUnmatched, "no okta account"},
	} {
		ev, err := r.deliver("jti-"+tc.name, EventSessionRevoked, tc.subject)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if ev.Status != tc.status || !strings.Contains(ev.Outcome, tc.outcome) {
			t.Errorf("%s: %+v", tc.name, ev)
		}
	}
	// the complex subject's label carries the session
	r.read(func(c *store.TenantTx) error {
		evs, _ := c.SSFEvents(r.tr.ID, 100)
		found := false
		for _, e := range evs {
			found = found || e.Subject == "alice (session sess-1)"
		}
		if !found {
			t.Error("the complex subject is not recorded with its session")
		}
		return nil
	})
}

func TestReceive_NoOtherAccountIsNoAction(t *testing.T) {
	r := newRig(t)
	// Bob has only his Okta account, the transmitter's own system
	ev, err := r.deliver("jti-bob", EventSessionRevoked, issSub("bob"))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != store.SSFEventNoAction || ev.Steps != 0 || ev.IdentityID == nil || ev.LatencyMS == nil ||
		!strings.Contains(ev.Outcome, "no other linked account") {
		t.Errorf("event = %+v", ev)
	}
	if got := r.actions(); got["containment.run"] != 0 || got["ssf.event_actioned"] != 1 {
		t.Errorf("actions %v", got)
	}
}

func TestReceive_Replay(t *testing.T) {
	r := newRig(t)
	raw := r.setFor("jti-once", EventSessionRevoked, issSub("alice"))
	first, err := r.deliverRaw("", raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := r.deliverRaw("", raw)
	if err != nil || again.ID != first.ID || again.Status != first.Status {
		t.Fatalf("replay = %+v, %v (first %+v)", again, err, first)
	}
	got := r.actions()
	if got["ssf.event_received"] != 1 || got["ssf.event_replayed"] != 1 || got["containment.run"] != 1 {
		t.Errorf("a replay must not run again: %v", got)
	}
	r.read(func(c *store.TenantTx) error {
		evs, _ := c.SSFEvents("", 100)
		if len(evs) != 1 {
			t.Errorf("%d event rows", len(evs))
		}
		return nil
	})
}

func TestReceive_ResumesAnUnfinishedDelivery(t *testing.T) {
	r := newRig(t)
	raw := r.setFor("jti-crash", EventSessionRevoked, issSub("bob"))
	// a crash after the event was recorded, before it was processed
	if err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(c *store.TenantTx) error {
		return c.InsertSSFEvent(&store.SSFEvent{TransmitterID: r.tr.ID, JTI: "jti-crash", Via: store.SSFPush, EventType: EventSessionRevoked,
			SubjectFormat: "iss_sub", Subject: "bob", ReceivedAt: now, IATAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	ev, err := r.deliverRaw("", raw)
	if err != nil || ev.Status != store.SSFEventNoAction {
		t.Fatalf("resumed = %+v, %v", ev, err)
	}
}

func TestReceive_Refusals(t *testing.T) {
	r := newRig(t)
	other := newSigner(t, "ES256", "k1")
	for name, tc := range map[string]struct {
		raw  string
		code string
	}{
		"bad signature":  {other.sign(t, claimsFor(nil)), ErrInvalidKey},
		"wrong audience": {r.sg.sign(t, claimsFor(func(c map[string]any) { c["aud"] = "https://elsewhere.example" })), ErrInvalidRequest},
		"alg none":       {b64(`{"alg":"none"}`) + "." + b64(mustJSON(claimsFor(nil))) + ".", ErrInvalidRequest},
		"garbage":        {"x", ErrInvalidRequest},
	} {
		ev, err := r.deliverRaw("", tc.raw)
		if ev != nil || code(err) != tc.code {
			t.Errorf("%s: %+v, %v", name, ev, err)
		}
	}
	got := r.actions()
	if got["ssf.event_rejected"] != 4 || got["ssf.event_received"] != 0 {
		t.Errorf("audit %v", got)
	}
	r.read(func(c *store.TenantTx) error {
		evs, _ := c.SSFEvents("", 10)
		x, _ := c.SSFTransmitter(r.tr.ID)
		if len(evs) != 0 || !strings.HasPrefix(x.LastError, "rejected a SET:") || x.LastEventAt != nil {
			t.Errorf("events %v, transmitter %+v", evs, x)
		}
		return nil
	})
	// the rejection carries the reason, never the token
	d, _ := json.Marshal(r.auditDetail("ssf.event_rejected"))
	if strings.Contains(string(d), "eyJ") {
		t.Errorf("rejection detail: %s", d)
	}
	// the jti a poll names must be the SET's
	_, err := r.svc.Receive(context.Background(), r.f.DB, r.f.A.ID, r.tr, store.SSFPoll, r.setFor("jti-x", EventSessionRevoked, issSub("bob")), "jti-y")
	if code(err) != ErrInvalidRequest {
		t.Errorf("mismatched jti: %v", err)
	}
	// a paused or disabled stream refuses everything
	for _, st := range []string{store.SSFPaused, store.SSFDisabled} {
		tr := *r.tr
		tr.Status = st
		_, err := r.svc.Receive(context.Background(), r.f.DB, r.f.A.ID, &tr, store.SSFPush, r.setFor("jti-p", EventSessionRevoked, issSub("bob")), "")
		if code(err) != ErrAccessDenied {
			t.Errorf("%s stream: %v", st, err)
		}
	}
}

func TestReceive_VerificationEvent(t *testing.T) {
	r := newRig(t)
	// no verification was requested: recorded, the transmitter stays unverified
	ev, err := r.deliver("jti-v0", EventVerification, nil)
	if err != nil || ev.Status != store.SSFEventIgnored || ev.Outcome != "verification event" {
		t.Fatalf("verification = %+v, %v", ev, err)
	}
	r.read(func(c *store.TenantTx) error {
		if x, _ := c.SSFTransmitter(r.tr.ID); x.VerifiedAt != nil {
			t.Error("an unsolicited verification verified the transmitter")
		}
		return nil
	})
	// a requested one: the state comes back and verifies it
	if err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(c *store.TenantTx) error {
		return c.SetSSFVerificationRequested(r.tr.ID, "state-123", now)
	}); err != nil {
		t.Fatal(err)
	}
	r.read(func(c *store.TenantTx) error { r.tr, _ = c.SSFTransmitter(r.tr.ID); return nil })
	raw := r.sg.sign(t, claimsFor(func(c map[string]any) {
		c["jti"] = "jti-v1"
		c["events"] = map[string]any{EventVerification: map[string]any{"state": "state-123"}}
	}))
	if _, err := r.deliverRaw("", raw); err != nil {
		t.Fatal(err)
	}
	r.read(func(c *store.TenantTx) error {
		x, _ := c.SSFTransmitter(r.tr.ID)
		if x.VerifiedAt == nil || x.VerificationState != "" {
			t.Errorf("transmitter %+v", x)
		}
		return nil
	})
	if d := r.auditDetail("ssf.verification_received"); d["matched_request"] != true {
		t.Errorf("audit %v", d)
	}
}

func TestReceive_KeyEndpoint(t *testing.T) {
	r := newRig(t)
	oldKey := r.sg
	calls := 0
	var served *signer = oldKey
	srv := server(t, func(w http.ResponseWriter, req *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{served.jwk}})
	})
	tr := *r.tr
	tr.JWKSInline, tr.JWKSURL = "", srv.URL
	recv := func(s *signer, jti string) error {
		_, err := r.svc.Receive(context.Background(), r.f.DB, r.f.A.ID, &tr, store.SSFPush,
			s.sign(t, claimsFor(func(c map[string]any) {
				c["jti"] = jti
				c["events"] = map[string]any{"https://example.test/e": map[string]any{}}
			})), "")
		return err
	}
	if err := recv(oldKey, "k-1"); err != nil || calls != 1 {
		t.Fatalf("first delivery: %v (%d fetches)", err, calls)
	}
	if err := recv(oldKey, "k-2"); err != nil || calls != 1 {
		t.Errorf("keys are cached: %v (%d fetches)", err, calls)
	}
	// the transmitter rotates its key: the unknown-key SET forces one refresh, but not within 30s of a fetch
	rotated := newSigner(t, "ES256", "k2")
	served = rotated
	if err := recv(rotated, "k-3"); code(err) != ErrInvalidKey || calls != 1 {
		t.Errorf("a refresh within the minimum interval: %v (%d fetches)", err, calls)
	}
	r.svc.jwksMu.Lock()
	e := r.svc.jwks[tr.ID]
	e.fetched = e.fetched.Add(-time.Minute)
	r.svc.jwks[tr.ID] = e
	r.svc.jwksMu.Unlock()
	if err := recv(rotated, "k-4"); err != nil || calls != 2 {
		t.Errorf("after the rotation: %v (%d fetches)", err, calls)
	}
	// an unreachable key endpoint is ours to retry, not a rejection
	srv.Close()
	r.svc.jwksMu.Lock()
	delete(r.svc.jwks, tr.ID)
	r.svc.jwksMu.Unlock()
	if err := recv(rotated, "k-5"); !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("unreachable keys: %v", err)
	}
}
