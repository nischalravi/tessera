package lp_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var now = storetest.Now

// fakeExec stands in for the provisioning engine: operations have the status the test gives them.
type fakeExec struct {
	status    map[string]string // op id -> status
	queued    []string
	restores  []string
	notReady  error
	cancelled []string
	sent      map[string]bool // ops that cannot be cancelled any more
}

func newExec() *fakeExec { return &fakeExec{status: map[string]string{}, sent: map[string]bool{}} }

func (f *fakeExec) Ready(*store.TenantTx, *store.LPRevocation) error { return f.notReady }
func (f *fakeExec) Enqueue(_ *store.TenantTx, _ time.Time, r *store.LPRevocation) (string, error) {
	id := "op-" + r.ID
	f.status[id] = "queued"
	f.queued = append(f.queued, r.ID)
	return id, nil
}
func (f *fakeExec) EnqueueRestore(_ *store.TenantTx, _ time.Time, r *store.LPRevocation) (string, error) {
	id := "rop-" + r.ID
	f.status[id] = "queued"
	f.restores = append(f.restores, r.ID)
	return id, nil
}
func (f *fakeExec) Cancel(_ *store.TenantTx, _ time.Time, id string) (bool, error) {
	if f.sent[id] || f.status[id] != "queued" {
		return false, nil
	}
	f.status[id] = "cancelled"
	f.cancelled = append(f.cancelled, id)
	return true, nil
}
func (f *fakeExec) OpStatus(_ *store.TenantTx, id string) (string, error) {
	st, ok := f.status[id]
	if !ok {
		return "", store.ErrNotFound
	}
	return st, nil
}

func payload() string {
	return `{"policy_arn":"p","prior":"{}","prior_sha256":"x","prior_version_id":"v1"}`
}

func cand(n int, principal, account string) *store.LPRevocation {
	p := payload()
	return &store.LPRevocation{ID: fmt.Sprintf("rev-%d", n), Kind: "aws_set_policy_version", ConnectorID: "conn", SnapshotID: "snap",
		AccountID: account, Principal: principal, PolicyARN: fmt.Sprintf("arn:aws:iam::%s:policy/P%d", account, n), UnusedDays: 120,
		Confidence: "high", Evidence: `{}`, CandidateSHA256: strings.Repeat("c", 64), RestorePayload: p, RestoreSHA256: lp.DigestPayload(p)}
}

func role(n int) string { return fmt.Sprintf("arn:aws:iam::111122223333:role/r%d", n) }

func tenant(t *testing.T, fn func(tx *store.TenantTx)) {
	t.Helper()
	f := storetest.TwoTenants(t)
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error { fn(tx); return nil }); err != nil {
		t.Fatal(err)
	}
}

func staged(t *testing.T, tx *store.TenantTx, mut func(*store.LPSettings)) *store.LPSettings {
	t.Helper()
	s := store.DefaultLPSettings()
	s.Mode, s.UpdatedBy = store.LPModeStaged, "setup"
	if mut != nil {
		mut(s)
	}
	if err := tx.PutLPSettings(s, now); err != nil {
		t.Fatal(err)
	}
	return s
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func code(err error) string {
	var e *lp.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return ""
}

func events(t *testing.T, tx *store.TenantTx, id string) []string {
	t.Helper()
	es, err := tx.LPEvents(id)
	must(t, err)
	var out []string
	for _, e := range es {
		out = append(out, e.From+">"+e.To)
	}
	slices.Sort(out) // transitions of one instant have no order of their own
	return out
}

func auditActions(t *testing.T, tx *store.TenantTx) []string {
	t.Helper()
	log, err := tx.AuditLog(-1)
	must(t, err)
	var out []string
	for _, e := range log {
		if strings.HasPrefix(e.Action, "lp.") {
			out = append(out, e.Action)
		}
	}
	return out
}

// propose and approve one candidate, then let the announce period pass.
func announced(t *testing.T, tx *store.TenantTx, ex *fakeExec, n int, principal, account string) *store.LPRevocation {
	t.Helper()
	c := cand(n, principal, account)
	must(t, lp.Propose(tx, now, "alice", c))
	rs, err := lp.Approve(tx, now, "alice", []string{c.ID}, nil, false, ex)
	must(t, err)
	return rs[0]
}

func TestCanMove(t *testing.T) {
	tests := []struct {
		from, to string
		ok       bool
	}{
		{store.LPCandidate, store.LPAnnounced, true},
		{store.LPAnnounced, store.LPRevoking, true},
		{store.LPRevoking, store.LPRevoked, true},
		{store.LPRevoked, store.LPFinalized, true},
		{store.LPRevoked, store.LPRestoring, true},
		{store.LPRestoring, store.LPRestored, true},
		{store.LPAnnounced, store.LPExempted, true},
		{store.LPRevoking, store.LPAnnounced, true},  // a pause took the queued operation back
		{store.LPCandidate, store.LPRevoking, false}, // no skipping the announcement
		{store.LPCandidate, store.LPRevoked, false},
		{store.LPAnnounced, store.LPRevoked, false},
		{store.LPFinalized, store.LPRestoring, false}, // final: an ordinary access request
		{store.LPRestored, store.LPRevoked, false},
		{store.LPExempted, store.LPAnnounced, false},
		{store.LPFailed, store.LPRevoking, false},
		{store.LPRevoking, store.LPRestoring, false},
	}
	for _, tt := range tests {
		if got := lp.CanMove(tt.from, tt.to); got != tt.ok {
			t.Errorf("CanMove(%s, %s) = %v, want %v", tt.from, tt.to, got, tt.ok)
		}
	}
	for _, s := range []string{store.LPFinalized, store.LPRestored, store.LPExempted, store.LPFailed, store.LPSuperseded} {
		if !lp.Terminal(s) {
			t.Errorf("%s should be terminal", s)
		}
	}
}

func TestPlan(t *testing.T) {
	ip := func(n int) *int { return &n }
	sp := func(s string) *string { return &s }
	bp := func(b bool) *bool { return &b }
	def := store.DefaultLPSettings()
	paused := store.DefaultLPSettings()
	paused.Mode, paused.Paused = store.LPModeStaged, true
	tests := []struct {
		name    string
		cur     *store.LPSettings
		u       lp.SettingsUpdate
		loosens bool
		code    string
	}{
		{"off to suggest is one admin", def, lp.SettingsUpdate{Mode: sp("suggest")}, false, ""},
		{"off to staged takes two", def, lp.SettingsUpdate{Mode: sp("staged")}, true, ""},
		{"staged to off is one", paused, lp.SettingsUpdate{Mode: sp("off")}, false, ""},
		{"auto is not available", def, lp.SettingsUpdate{Mode: sp("auto")}, false, "auto_not_available"},
		{"unknown mode", def, lp.SettingsUpdate{Mode: sp("yolo")}, false, "invalid_settings"},
		{"resume takes two", paused, lp.SettingsUpdate{Paused: bp(false)}, true, ""},
		{"pause is one", def, lp.SettingsUpdate{Paused: bp(true)}, false, ""},
		{"a larger cap takes two", def, lp.SettingsUpdate{CapPerRun: ip(26)}, true, ""},
		{"a smaller cap is one", def, lp.SettingsUpdate{CapPerRun: ip(5)}, false, ""},
		{"a shorter announce period takes two", def, lp.SettingsUpdate{AnnounceDays: ip(3)}, true, ""},
		{"a longer announce period is one", def, lp.SettingsUpdate{AnnounceDays: ip(14)}, false, ""},
		{"a shorter finalize period takes two", def, lp.SettingsUpdate{FinalizeDays: ip(10)}, true, ""},
		{"a lower auto threshold takes two", def, lp.SettingsUpdate{AutoMinDays: ip(30)}, true, ""},
		{"run cap above day cap", def, lp.SettingsUpdate{CapPerRun: ip(500)}, false, "invalid_settings"},
		{"cap out of range", def, lp.SettingsUpdate{CapPerDay: ip(0)}, false, "invalid_settings"},
		{"empty", def, lp.SettingsUpdate{}, false, "invalid_settings"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, loosens, err := lp.Plan(tt.cur, &tt.u)
			if code(err) != tt.code {
				t.Fatalf("Plan = %v, want code %q", err, tt.code)
			}
			if err == nil && (loosens != tt.loosens || n == nil) {
				t.Errorf("loosens = %v, want %v", loosens, tt.loosens)
			}
		})
	}
}

func TestProposeRules(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		// off: no candidates
		if err := lp.Propose(tx, now, "alice", cand(1, role(1), "111122223333")); code(err) != "mode_off" {
			t.Errorf("propose in mode off = %v", err)
		}
		staged(t, tx, nil)

		c := cand(2, role(2), "111122223333")
		must(t, lp.Propose(tx, now, "alice", c))
		if c.Eligibility != store.LPEligAuto || c.State != store.LPCandidate {
			t.Errorf("high and 120 days: %s %s", c.Eligibility, c.State)
		}
		if err := lp.Propose(tx, now, "alice", cand(2, role(2), "111122223333")); code(err) != "already_open" {
			t.Errorf("a second candidate for the grant = %v", err)
		}
		med := cand(3, role(3), "111122223333")
		med.Confidence = "medium"
		must(t, lp.Propose(tx, now, "alice", med))
		young := cand(4, role(4), "111122223333")
		young.UnusedDays = 60
		must(t, lp.Propose(tx, now, "alice", young))
		if med.Eligibility != store.LPEligItem || young.Eligibility != store.LPEligItem {
			t.Errorf("medium and short-unused are approved item by item: %s %s", med.Eligibility, young.Eligibility)
		}
		low := cand(5, role(5), "111122223333")
		low.Confidence = "low"
		if err := lp.Propose(tx, now, "alice", low); code(err) != "confidence_too_low" {
			t.Errorf("low confidence = %v", err)
		}
		bad := cand(6, role(6), "111122223333")
		bad.RestoreSHA256 = strings.Repeat("0", 64)
		if err := lp.Propose(tx, now, "alice", bad); code(err) != "payload_digest_mismatch" {
			t.Errorf("a payload that does not match its digest = %v", err)
		}
		// protected, exempted
		must(t, tx.InsertLPProtected(&store.LPProtectedRef{Kind: "principal", Ref: role(7), CreatedBy: "u", CreatedAt: now}))
		if err := lp.Propose(tx, now, "alice", cand(7, role(7), "111122223333")); code(err) != "grant_protected" {
			t.Errorf("protected principal = %v", err)
		}
		e := cand(8, role(8), "111122223333")
		must(t, tx.InsertLPExemption(&store.LPExemption{Principal: e.Principal, PolicyARN: e.PolicyARN, Source: store.LPExemptRestore,
			Until: now.AddDate(0, 0, 10), CreatedBy: "u", CreatedAt: now}))
		if err := lp.Propose(tx, now, "alice", e); code(err) != "grant_exempted" {
			t.Errorf("exempted grant = %v", err)
		}
		// an evaluator disagreement triaged as an engine bug blocks proposals
		must(t, tx.InsertAWSShadowCheck(&store.AWSShadowCheck{ID: "chk", ConnectorID: "c", SnapshotID: "s", SampleDay: "2026-10-08",
			PrincipalARN: role(9), Action: "s3:GetObject", ResourceARN: "*", TesseraOutcome: "allow", TesseraFidelity: "EXACT",
			Verdict: store.AWSShadowDisagree, CheckedAt: now}))
		must(t, tx.TriageAWSShadowCheck("chk", store.AWSTriageEngineBug, "ours", "pat", now))
		if err := lp.Propose(tx, now, "alice", cand(9, role(9), "111122223333")); code(err) != "evaluator_disagreement" {
			t.Errorf("engine bug = %v", err)
		}
		if got := auditActions(t, tx); !slices.Contains(got, "lp.revocation.candidate") {
			t.Errorf("the candidate was not audited: %v", got)
		}
	})
}

func TestApprove(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		staged(t, tx, nil)
		auto := cand(1, role(1), "111122223333")
		med := cand(2, role(2), "111122223333")
		med.Confidence = "medium"
		must(t, lp.Propose(tx, now, "alice", auto))
		must(t, lp.Propose(tx, now, "alice", med))

		if _, err := lp.Approve(tx, now, "alice", nil, nil, false, ex); code(err) != "invalid_batch" {
			t.Errorf("empty approval = %v", err)
		}
		// a medium item is never covered by a batch approval
		if _, err := lp.Approve(tx, now, "alice", []string{med.ID}, nil, false, ex); code(err) != "item_needs_own_approval" {
			t.Errorf("medium in a batch = %v", err)
		}
		if _, err := lp.Approve(tx, now, "alice", nil, []string{auto.ID}, false, ex); code(err) != "not_an_item" {
			t.Errorf("auto-eligible as an item = %v", err)
		}
		if _, err := lp.Approve(tx, now, "alice", []string{"nope"}, nil, false, ex); code(err) != "not_found" {
			t.Errorf("unknown id = %v", err)
		}
		if _, err := lp.Approve(tx, now, "alice", []string{auto.ID}, nil, true, ex); code(err) != "disabled" {
			t.Errorf("approve while disabled = %v", err)
		}
		ex.notReady = &lp.Error{Status: 409, Code: "write_back_off", Msg: "off"}
		if _, err := lp.Approve(tx, now, "alice", []string{auto.ID}, nil, false, ex); code(err) != "write_back_off" {
			t.Errorf("approve with no write target = %v", err)
		}
		ex.notReady = nil
		rs, err := lp.Approve(tx, now, "alice", []string{auto.ID}, []string{med.ID}, false, ex)
		must(t, err)
		if len(rs) != 2 || rs[0].State != store.LPAnnounced || rs[0].AnnounceUntil == nil || !rs[0].AnnounceUntil.Equal(now.AddDate(0, 0, 7)) || rs[0].ApprovedBy != "alice" {
			t.Errorf("approved = %+v", rs[0])
		}
		if _, err := lp.Approve(tx, now, "alice", []string{auto.ID}, nil, false, ex); code(err) != "not_a_candidate" {
			t.Errorf("approving twice = %v", err)
		}
		if got := events(t, tx, auto.ID); !slices.Equal(got, []string{">candidate", "candidate>announced"}) {
			t.Errorf("events = %v", got)
		}
		if got := auditActions(t, tx); !slices.Contains(got, "lp.revocation.announced") {
			t.Errorf("announcement not audited: %v", got)
		}

		// a paused loop announces nothing
		extra := cand(3, role(3), "111122223333")
		must(t, lp.Propose(tx, now, "alice", extra))
		_, err = lp.Pause(tx, now, "alice", "looks wrong", ex)
		must(t, err)
		if _, err := lp.Approve(tx, now, "alice", []string{extra.ID}, nil, false, ex); code(err) != "paused" {
			t.Errorf("approve while paused = %v", err)
		}
	})
}

func TestObject(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		staged(t, tx, nil)
		r := announced(t, tx, ex, 1, role(1), "111122223333")
		if _, err := lp.Object(tx, now, "owner", "nope", "x"); code(err) != "not_found" {
			t.Errorf("object to unknown = %v", err)
		}
		o, err := lp.Object(tx, now, "owner", r.ID, "needed for the quarterly job")
		must(t, err)
		if o.State != store.LPExempted {
			t.Errorf("state = %s", o.State)
		}
		if ex, err := tx.LPExempted(r.Principal, r.PolicyARN, now.AddDate(0, 0, 179)); err != nil || !ex {
			t.Errorf("exempt for 180 days = %v, %v", ex, err)
		}
		if ex, err := tx.LPExempted(r.Principal, r.PolicyARN, now.AddDate(0, 0, 181)); err != nil || ex {
			t.Errorf("exempt after 180 days = %v, %v", ex, err)
		}
		// an exempted grant is not proposed again
		if err := lp.Propose(tx, now, "alice", cand(1, role(1), "111122223333")); code(err) != "grant_exempted" {
			t.Errorf("propose after objection = %v", err)
		}
		if _, err := lp.Object(tx, now, "owner", r.ID, "x"); code(err) != "not_objectable" {
			t.Errorf("second objection = %v", err)
		}
	})
}

// The whole life of one revocation: announce, wait, recheck, revoke, verify, finalize; and the restore path.
func TestLifecycle(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		staged(t, tx, nil)
		r := announced(t, tx, ex, 1, role(1), "111122223333")
		ok := map[string]lp.Recheck{r.ID: {OK: true}}

		// inside the announce period nothing happens
		res, err := lp.Run(tx, now.AddDate(0, 0, 6), ex, false, ok)
		must(t, err)
		if res.Revoking != 0 || len(ex.queued) != 0 {
			t.Fatalf("revoked inside the announce period: %+v", res)
		}
		// the period is over: queued through the write target
		at := now.AddDate(0, 0, 7)
		res, err = lp.Run(tx, at, ex, false, ok)
		must(t, err)
		got, _ := tx.LPRevocation(r.ID)
		if res.Revoking != 1 || got.State != store.LPRevoking || got.OpID != "op-"+r.ID || got.ExecutedAt == nil {
			t.Fatalf("after the announce period: %+v %+v", res, got)
		}
		// not verified yet: stays revoking
		_, err = lp.Run(tx, at.Add(time.Minute), ex, false, ok)
		must(t, err)
		if got, _ = tx.LPRevocation(r.ID); got.State != store.LPRevoking {
			t.Fatalf("state = %s before verification", got.State)
		}
		ex.status[got.OpID] = "verified"
		_, err = lp.Run(tx, at.Add(2*time.Minute), ex, false, ok)
		must(t, err)
		got, _ = tx.LPRevocation(r.ID)
		if got.State != store.LPRevoked || got.RestoreUntil == nil || !got.RestoreUntil.Equal(at.Add(2*time.Minute).AddDate(0, 0, 30)) {
			t.Fatalf("revoked = %+v", got)
		}
		// 30 days with no denial: final
		res, err = lp.Run(tx, got.RestoreUntil.Add(time.Second), ex, false, nil)
		must(t, err)
		if got, _ = tx.LPRevocation(r.ID); res.Finalized != 1 || got.State != store.LPFinalized {
			t.Fatalf("finalized = %+v %+v", res, got)
		}
		if _, err := lp.Restore(tx, at, "alice", "owner", r.ID, ex); code(err) != "finalized" {
			t.Errorf("restore after finalize = %v", err)
		}
		want := []string{">candidate", "announced>revoking", "candidate>announced", "revoked>finalized", "revoking>revoked"}
		if ev := events(t, tx, r.ID); !slices.Equal(ev, want) {
			t.Errorf("events = %v, want %v", ev, want)
		}
		acts := auditActions(t, tx)
		for _, a := range []string{"lp.revocation.candidate", "lp.revocation.announced", "lp.revocation.revoking", "lp.revocation.revoked", "lp.revocation.finalized"} {
			if !slices.Contains(acts, a) {
				t.Errorf("no audit event %s in %v", a, acts)
			}
		}
	})
}

func TestRecheckSupersedes(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		staged(t, tx, nil)
		used := announced(t, tx, ex, 1, role(1), "111122223333")
		gone := announced(t, tx, ex, 2, role(2), "111122223333")
		unchecked := announced(t, tx, ex, 3, role(3), "111122223333")
		at := now.AddDate(0, 0, 8)
		res, err := lp.Run(tx, at, ex, false, map[string]lp.Recheck{
			used.ID: {Reason: "the principal used s3:GetObject since the announcement"},
			gone.ID: {OK: true}})
		must(t, err)
		if res.Superseded != 1 || res.Revoking != 1 || res.Holds["recheck_pending"] != 1 {
			t.Errorf("result = %+v", res)
		}
		u, _ := tx.LPRevocation(used.ID)
		if u.State != store.LPSuperseded || !strings.Contains(u.Reason, "used s3:GetObject") {
			t.Errorf("used = %s %q", u.State, u.Reason)
		}
		if g, _ := tx.LPRevocation(unchecked.ID); g.State != store.LPAnnounced {
			t.Errorf("an unchecked revocation moved: %s", g.State)
		}
		// a grant that became protected after the announcement is not revoked
		must(t, tx.InsertLPProtected(&store.LPProtectedRef{Kind: "principal", Ref: role(3), CreatedBy: "u", CreatedAt: now}))
		_, err = lp.Run(tx, at.Add(time.Hour), ex, false, map[string]lp.Recheck{unchecked.ID: {OK: true}})
		must(t, err)
		if g, _ := tx.LPRevocation(unchecked.ID); g.State != store.LPSuperseded || !strings.Contains(g.Reason, "protected") {
			t.Errorf("protected after announce = %s %q", g.State, g.Reason)
		}
	})
}

func TestCaps(t *testing.T) {
	t.Run("per run", func(t *testing.T) {
		tenant(t, func(tx *store.TenantTx) {
			ex := newExec()
			staged(t, tx, func(s *store.LPSettings) { s.CapPerRun = 2 })
			rc := map[string]lp.Recheck{}
			for i := 1; i <= 5; i++ {
				rc[announced(t, tx, ex, i, role(i), fmt.Sprintf("11112222333%d", i)).ID] = lp.Recheck{OK: true}
			}
			res, err := lp.Run(tx, now.AddDate(0, 0, 8), ex, false, rc)
			must(t, err)
			if res.Revoking != 2 || res.Holds["cap_per_run"] != 3 || len(ex.queued) != 2 {
				t.Fatalf("result = %+v queued %v", res, ex.queued)
			}
			// the rest are held, not dropped: still announced, and the next run (an hour on) takes the next two
			if held, _ := tx.LPRevocations(store.LPAnnounced, 0); len(held) != 3 {
				t.Errorf("held = %d, want 3 announced", len(held))
			}
			res, err = lp.Run(tx, now.AddDate(0, 0, 8).Add(time.Hour), ex, false, rc)
			must(t, err)
			if res.Revoking != 2 || len(ex.queued) != 4 {
				t.Errorf("second run = %+v", res)
			}
		})
	})
	t.Run("per day", func(t *testing.T) {
		tenant(t, func(tx *store.TenantTx) {
			ex := newExec()
			staged(t, tx, func(s *store.LPSettings) { s.CapPerRun, s.CapPerDay = 2, 3 })
			rc := map[string]lp.Recheck{}
			for i := 1; i <= 4; i++ {
				rc[announced(t, tx, ex, i, role(i), fmt.Sprintf("11112222333%d", i)).ID] = lp.Recheck{OK: true}
			}
			at := now.AddDate(0, 0, 8)
			_, err := lp.Run(tx, at, ex, false, rc)
			must(t, err)
			res, err := lp.Run(tx, at.Add(time.Hour), ex, false, rc)
			must(t, err)
			if res.Revoking != 1 || res.Holds["cap_per_day"] != 1 || len(ex.queued) != 3 {
				t.Fatalf("second run = %+v, queued %v", res, ex.queued)
			}
			// a day after the first, the window has room again
			res, err = lp.Run(tx, at.Add(25*time.Hour), ex, false, rc)
			must(t, err)
			if res.Revoking != 1 || len(ex.queued) != 4 {
				t.Errorf("next day = %+v", res)
			}
		})
	})
	t.Run("per account and per principal", func(t *testing.T) {
		tenant(t, func(tx *store.TenantTx) {
			ex := newExec()
			staged(t, tx, func(s *store.LPSettings) { s.CapPerAccount = 2 })
			rc := map[string]lp.Recheck{}
			// three roles in one account, and a fourth grant of an already revoked principal
			for i := 1; i <= 3; i++ {
				rc[announced(t, tx, ex, i, role(i), "111122223333").ID] = lp.Recheck{OK: true}
			}
			other := announced(t, tx, ex, 4, "arn:aws:iam::999988887777:role/x", "999988887777")
			rc[other.ID] = lp.Recheck{OK: true}
			same := cand(5, role(1), "111122223333") // a second policy of role 1
			must(t, lp.Propose(tx, now, "alice", same))
			rs, err := lp.Approve(tx, now, "alice", []string{same.ID}, nil, false, ex)
			must(t, err)
			rc[rs[0].ID] = lp.Recheck{OK: true}
			res, err := lp.Run(tx, now.AddDate(0, 0, 8), ex, false, rc)
			must(t, err)
			// 2 in the first account (role 1 once: its second grant waits for the principal cap), the other account is its own
			if res.Holds["cap_per_account"] != 1 || res.Holds["cap_per_principal"] != 1 || res.Revoking != 3 {
				t.Fatalf("result = %+v queued %v", res, ex.queued)
			}
			if !slices.Contains(ex.queued, other.ID) {
				t.Errorf("the other account was held by this account's cap: %v", ex.queued)
			}
		})
	})
}

func TestKillSwitch(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		staged(t, tx, nil)
		due := announced(t, tx, ex, 1, role(1), "111122223333")
		inflight := announced(t, tx, ex, 2, role(2), "111122223333")
		sent := announced(t, tx, ex, 3, role(3), "111122223333")
		at := now.AddDate(0, 0, 8)
		rc := map[string]lp.Recheck{inflight.ID: {OK: true}, sent.ID: {OK: true}}
		_, err := lp.Run(tx, at, ex, false, rc)
		must(t, err)
		ex.sent["op-"+sent.ID] = true // the engine already pushed this one

		s, err := lp.Pause(tx, at, "pat", "an owner called", ex)
		must(t, err)
		if !s.Paused || s.PausedBy != "pat" || s.PausedReason != "an owner called" {
			t.Errorf("settings = %+v", s)
		}
		// the queued operation is withdrawn and its revocation is announced again; the sent one runs to its verification
		in, _ := tx.LPRevocation(inflight.ID)
		sn, _ := tx.LPRevocation(sent.ID)
		if in.State != store.LPAnnounced || in.ExecutedAt != nil || ex.status["op-"+inflight.ID] != "cancelled" {
			t.Errorf("queued operation: %s %v %s", in.State, in.ExecutedAt, ex.status["op-"+inflight.ID])
		}
		if sn.State != store.LPRevoking {
			t.Errorf("sent operation: %s", sn.State)
		}
		// pausing twice is a no-op
		if _, err := lp.Pause(tx, at, "ivan", "again", ex); err != nil {
			t.Fatal(err)
		}
		if s, _ := tx.LPSettings(); s.PausedBy != "pat" {
			t.Errorf("a second pause replaced the first: %s", s.PausedBy)
		}
		// nothing new is executed while paused, even after the announce period and with a good recheck
		rc[due.ID] = lp.Recheck{OK: true}
		rc[inflight.ID] = lp.Recheck{OK: true}
		queued := len(ex.queued)
		res, err := lp.Run(tx, at.Add(time.Hour), ex, false, rc)
		must(t, err)
		if res.Revoking != 0 || len(ex.queued) != queued {
			t.Errorf("executed while paused: %+v", res)
		}
		// verification goes on
		ex.status["op-"+sent.ID] = "verified"
		res, err = lp.Run(tx, at.Add(2*time.Hour), ex, false, rc)
		must(t, err)
		if sn, _ = tx.LPRevocation(sent.ID); res.Revoked != 1 || sn.State != store.LPRevoked {
			t.Errorf("verification while paused: %+v %s", res, sn.State)
		}
		// the operator's switch stops executions too, without touching the settings
		ns := must2(tx.LPSettings())
		ns.Paused = false
		must(t, tx.PutLPSettings(ns, at))
		res, err = lp.Run(tx, at.Add(4*time.Hour), ex, true, rc)
		must(t, err)
		if res.Revoking != 0 {
			t.Errorf("executed with TESSERA_LP_DISABLE: %+v", res)
		}
		res, err = lp.Run(tx, at.Add(5*time.Hour), ex, false, rc)
		must(t, err)
		if res.Revoking == 0 {
			t.Errorf("did not execute once resumed: %+v", res)
		}
		// a restore is never blocked by the switch
		_, err = lp.Pause(tx, at.Add(6*time.Hour), "pat", "again", ex)
		must(t, err)
		if _, err := lp.Restore(tx, at.Add(6*time.Hour), "owner", "owner", sent.ID, ex); err != nil {
			t.Errorf("restore while paused: %v", err)
		}
		if got := auditActions(t, tx); !slices.Contains(got, "lp.paused") {
			t.Errorf("the pause was not audited: %v", got)
		}
	})
}

func must2[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestRestore(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		staged(t, tx, nil)
		r := announced(t, tx, ex, 1, role(1), "111122223333")
		if _, err := lp.Restore(tx, now, "owner", "owner", r.ID, ex); code(err) != "not_revoked" {
			t.Errorf("restore of an announced revocation = %v", err)
		}
		at := now.AddDate(0, 0, 8)
		_, err := lp.Run(tx, at, ex, false, map[string]lp.Recheck{r.ID: {OK: true}})
		must(t, err)
		ex.status["op-"+r.ID] = "verified"
		_, err = lp.Run(tx, at.Add(time.Minute), ex, false, nil)
		must(t, err)

		// a payload that does not match the digest recorded at the revoke is refused
		tampered := cand(7, role(7), "111122223333")
		tampered.State, tampered.Eligibility, tampered.CreatedBy, tampered.CreatedAt = store.LPRevoked, store.LPEligAuto, "x", at
		tampered.RestorePayload = strings.Replace(payload(), "v1", "v9", 1)
		must(t, tx.InsertLPRevocation(tampered))
		if _, err := lp.Restore(tx, at, "owner", "owner", tampered.ID, ex); code(err) != "payload_digest_mismatch" {
			t.Fatalf("tampered payload = %v", err)
		}

		got, err := lp.Restore(tx, at.Add(time.Hour), "owner", "owner", r.ID, ex)
		must(t, err)
		if got.State != store.LPRestoring || got.RestoreOpID != "rop-"+r.ID || got.RestoreTrigger != "owner" {
			t.Fatalf("restoring = %+v", got)
		}
		// asking again changes nothing
		if again, err := lp.Restore(tx, at.Add(time.Hour), "admin", "admin", r.ID, ex); err != nil || again.RestoreTrigger != "owner" || len(ex.restores) != 1 {
			t.Errorf("second restore = %+v, %v (%d queued)", again, err, len(ex.restores))
		}
		ex.status["rop-"+r.ID] = "verified"
		res, err := lp.Run(tx, at.Add(2*time.Hour), ex, false, nil)
		must(t, err)
		done, _ := tx.LPRevocation(r.ID)
		if res.Restored != 1 || done.State != store.LPRestored || done.RestoredAt == nil {
			t.Fatalf("restored = %+v %+v", res, done)
		}
		// a false positive: exempt for 180 days
		if ex, err := tx.LPExempted(r.Principal, r.PolicyARN, at.AddDate(0, 0, 179)); err != nil || !ex {
			t.Errorf("exemption after restore = %v, %v", ex, err)
		}
		if ev := events(t, tx, r.ID); !slices.Contains(ev, "revoked>restoring") || !slices.Contains(ev, "restoring>restored") {
			t.Errorf("events = %v", ev)
		}
	})
}

func TestAutoPause(t *testing.T) {
	t.Run("a failed revocation", func(t *testing.T) {
		tenant(t, func(tx *store.TenantTx) {
			ex := newExec()
			staged(t, tx, nil)
			a := announced(t, tx, ex, 1, role(1), "111122223333")
			b := announced(t, tx, ex, 2, role(2), "111122223333")
			at := now.AddDate(0, 0, 8)
			_, err := lp.Run(tx, at, ex, false, map[string]lp.Recheck{a.ID: {OK: true}})
			must(t, err)
			ex.status["op-"+a.ID] = "mismatch"
			res, err := lp.Run(tx, at.Add(time.Minute), ex, false, map[string]lp.Recheck{b.ID: {OK: true}})
			must(t, err)
			s, _ := tx.LPSettings()
			if res.Failed != 1 || !s.Paused || s.PausedBy != lp.ActorAuto || !strings.Contains(s.PausedReason, a.ID) {
				t.Fatalf("result = %+v settings = %+v", res, s)
			}
			if bb, _ := tx.LPRevocation(b.ID); bb.State != store.LPAnnounced {
				t.Errorf("another revocation was executed after the failure: %s", bb.State)
			}
		})
	})
	t.Run("three restores in one run", func(t *testing.T) {
		tenant(t, func(tx *store.TenantTx) {
			ex := newExec()
			staged(t, tx, func(s *store.LPSettings) { s.CapPerRun, s.CapPerDay = 50, 500 })
			at := now.AddDate(0, 0, 8)
			rc := map[string]lp.Recheck{}
			var ids []string
			for i := 1; i <= 4; i++ {
				id := announced(t, tx, ex, i, role(i), fmt.Sprintf("11112222333%d", i)).ID
				rc[id] = lp.Recheck{OK: true}
				ids = append(ids, id)
			}
			_, err := lp.Run(tx, at, ex, false, rc)
			must(t, err)
			for _, id := range ids {
				ex.status["op-"+id] = "verified"
			}
			_, err = lp.Run(tx, at.Add(time.Minute), ex, false, nil)
			must(t, err)
			for _, id := range ids[:3] {
				_, err := lp.Restore(tx, at.Add(2*time.Minute), "owner", "owner", id, ex)
				must(t, err)
			}
			res, err := lp.Run(tx, at.Add(3*time.Minute), ex, false, nil)
			must(t, err)
			if s, _ := tx.LPSettings(); !s.Paused || res.Paused == "" || !strings.Contains(s.PausedReason, "3 restores") {
				t.Fatalf("not paused: %+v %+v", res, s)
			}
		})
	})
	t.Run("restore rate above two percent", func(t *testing.T) {
		tenant(t, func(tx *store.TenantTx) {
			ex := newExec()
			staged(t, tx, nil)
			at := now.AddDate(0, 0, 8)
			r := announced(t, tx, ex, 1, role(1), "111122223333")
			_, err := lp.Run(tx, at, ex, false, map[string]lp.Recheck{r.ID: {OK: true}})
			must(t, err)
			ex.status["op-"+r.ID] = "verified"
			_, err = lp.Run(tx, at.Add(time.Minute), ex, false, nil)
			must(t, err)
			_, err = lp.Restore(tx, at.Add(2*time.Hour), "owner", "owner", r.ID, ex)
			must(t, err)
			res, err := lp.Run(tx, at.Add(3*time.Hour), ex, false, nil)
			must(t, err)
			if s, _ := tx.LPSettings(); !s.Paused || !strings.Contains(res.Paused, "1 of 1") {
				t.Fatalf("not paused: %+v %+v", res, s)
			}
		})
	})
	t.Run("an engine bug", func(t *testing.T) {
		tenant(t, func(tx *store.TenantTx) {
			ex := newExec()
			staged(t, tx, nil)
			must(t, tx.InsertAWSShadowCheck(&store.AWSShadowCheck{ID: "chk", ConnectorID: "c", SnapshotID: "s", SampleDay: "2026-10-08",
				PrincipalARN: role(9), Action: "s3:GetObject", ResourceARN: "*", TesseraOutcome: "allow", TesseraFidelity: "EXACT",
				Verdict: store.AWSShadowDisagree, CheckedAt: now}))
			must(t, tx.TriageAWSShadowCheck("chk", store.AWSTriageEngineBug, "ours", "pat", now))
			_, err := lp.Run(tx, now, ex, false, nil)
			must(t, err)
			if s, _ := tx.LPSettings(); !s.Paused || !strings.Contains(s.PausedReason, "engine bug") {
				t.Errorf("settings = %+v", s)
			}
		})
	})
	t.Run("a loop that is off is never auto-paused", func(t *testing.T) {
		tenant(t, func(tx *store.TenantTx) {
			must(t, tx.InsertAWSShadowCheck(&store.AWSShadowCheck{ID: "chk", ConnectorID: "c", SnapshotID: "s", SampleDay: "2026-10-08",
				PrincipalARN: role(9), Action: "s3:GetObject", ResourceARN: "*", TesseraOutcome: "allow", TesseraFidelity: "EXACT",
				Verdict: store.AWSShadowDisagree, CheckedAt: now}))
			must(t, tx.TriageAWSShadowCheck("chk", store.AWSTriageEngineBug, "ours", "pat", now))
			_, err := lp.Run(tx, now, newExec(), false, nil)
			must(t, err)
			if s, _ := tx.LPSettings(); s.Paused {
				t.Error("paused while off")
			}
		})
	})
}

func TestCandidatesExpire(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		staged(t, tx, nil)
		c := cand(1, role(1), "111122223333")
		must(t, lp.Propose(tx, now, "alice", c))
		res, err := lp.Run(tx, now.AddDate(0, 0, 31), newExec(), false, nil)
		must(t, err)
		if got, _ := tx.LPRevocation(c.ID); res.Expired != 1 || got.State != store.LPSuperseded {
			t.Errorf("expired = %+v %s", res, got.State)
		}
	})
}

func TestMoveRefusesAnIllegalTransition(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		staged(t, tx, nil)
		c := cand(1, role(1), "111122223333")
		must(t, lp.Propose(tx, now, "alice", c))
		if err := lp.Move(tx, now, c, store.LPRevoked, "x", ""); err == nil {
			t.Error("a candidate went straight to revoked")
		}
	})
}
