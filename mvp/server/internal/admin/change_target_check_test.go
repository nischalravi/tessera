package admin_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The approver's "check this URL" (issue #886): match / no-match against the keyed fingerprint of the sealed URL, for a
// different admin with a fresh step-up, bounded per request and per approver, audited without the URL.

func TestCheckTarget_RBACAndMatch(t *testing.T) {
	h, ad, machine := secretHarness(t)
	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(
		`{"name":"soc","kind":"webhook","target":"`+hookURL+`","signing_secret":"`+hookSecret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	approver := h.as(ad[1])

	res, err := h.svc.CheckTarget(h.ctx, approver, ch.ID, hookURL)
	if err != nil || !res.Match || res.AttemptsLeft != admin.MaxTargetChecksPerValue-1 {
		t.Fatalf("matching URL = %+v, %v", res, err)
	}
	// a pasted trailing newline is the same URL
	if res, err = h.svc.CheckTarget(h.ctx, approver, ch.ID, hookURL+"\n"); err != nil || !res.Match {
		t.Errorf("URL with a trailing newline = %+v, %v", res, err)
	}
	// another path, another token, another origin: no match
	for _, u := range []string{"https://hooks.example.com/services/T000/B000/OTHER", "https://evil.example.org/services/T000/B000/PLAINTEXT-URL-TOKEN"} {
		if res, err = h.svc.CheckTarget(h.ctx, approver, ch.ID, u); err != nil || res.Match {
			t.Errorf("%s = %+v, %v", u, res, err)
		}
	}
	// the answer carries nothing of the sealed value
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "PLAINTEXT") || strings.Contains(string(b), "hooks.example.com") {
		t.Errorf("result leaks: %s", b)
	}

	// who may ask
	proposer := *h.as(ad[1])
	proposer.UserID = &ch.RequestedBy
	_, err = h.svc.CheckTarget(h.ctx, &proposer, ch.ID, hookURL)
	wantErr(t, err, http.StatusForbidden, "self_check_refused")
	op := h.as(h.user("vic", store.RoleOperator))
	_, err = h.svc.CheckTarget(h.ctx, op, ch.ID, hookURL)
	wantErr(t, err, http.StatusForbidden, "forbidden")
	_, err = h.svc.CheckTarget(h.ctx, machine, ch.ID, hookURL)
	if err == nil {
		t.Error("the proposing machine client checked a URL")
	}
	_, err = h.svc.CheckTarget(h.ctx, h.asAged(ad[1], 2*time.Hour), ch.ID, hookURL)
	wantStepUp(t, err)

	// bad input is refused and does not count; a request with no sealed URL has nothing to check
	for _, u := range []string{"", "not a url", "hooks.example.com/x", strings.Repeat("a", 9000) + "://x"} {
		if _, err := h.svc.CheckTarget(h.ctx, approver, ch.ID, u); err == nil {
			t.Errorf("url %.20q was accepted", u)
		}
	}
	mail, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(`{"name":"mail","kind":"email","target":"a@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.CheckTarget(h.ctx, approver, mail.ID, "https://a.example.com/x")
	wantErr(t, err, http.StatusConflict, "no_sealed_url")
	_, err = h.svc.CheckTarget(h.ctx, approver, uuid.New(), hookURL)
	wantErr(t, err, http.StatusNotFound, "not_found")

	// once the request is decided its secrets are gone and so is the check
	if _, err := h.svc.Approve(h.ctx, approver, ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.CheckTarget(h.ctx, approver, ch.ID, hookURL)
	wantErr(t, err, http.StatusConflict, "invalid_state")
}

func TestCheckTarget_LimitsAndAudit(t *testing.T) {
	h, ad, machine := secretHarness(t)
	file := func(name, path string) *store.AdminChange {
		ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(
			`{"name":"`+name+`","kind":"webhook","target":"`+hookURL+path+`","signing_secret":"`+hookSecret+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return ch
	}
	guess := "https://hooks.example.com/services/T000/B000/GUESS-ONE"
	approver := h.as(ad[1])
	ch := file("a", "/a")
	for i := 0; i < admin.MaxTargetChecksPerValue; i++ {
		if res, err := h.svc.CheckTarget(h.ctx, approver, ch.ID, guess); err != nil || res.Match {
			t.Fatalf("try %d: %+v, %v", i, res, err)
		}
	}
	// locked for everyone, the right URL included: a lock that answered would be the oracle
	other := h.admins("adm3")[0]
	for _, p := range []*auth.Principal{approver, h.as(other)} {
		_, err := h.svc.CheckTarget(h.ctx, p, ch.ID, hookURL+"/a")
		wantErr(t, err, http.StatusTooManyRequests, admin.ReasonTargetCheckLocked)
	}
	// the lock is the value's: filing the same URL again gives no fresh tries
	again := file("a-again", "/a")
	_, err := h.svc.CheckTarget(h.ctx, h.as(other), again.ID, hookURL+"/a")
	wantErr(t, err, http.StatusTooManyRequests, admin.ReasonTargetCheckLocked)
	// another value is still open to the approver
	ch2 := file("b", "/b")
	if res, err := h.svc.CheckTarget(h.ctx, approver, ch2.ID, hookURL+"/b"); err != nil || !res.Match {
		t.Errorf("another value after a lock = %+v, %v", res, err)
	}
	// the per-approver budget runs out across values, and comes back with the window
	budget := admin.MaxTargetChecksPerApprover - admin.MaxTargetChecksPerValue - 1 // spent by the approver on a and b
	var last *store.AdminChange
	for i := 0; i < budget; i++ {
		last = file("c"+string(rune('a'+i)), "/c"+string(rune('a'+i)))
		if _, err := h.svc.CheckTarget(h.ctx, approver, last.ID, guess); err != nil {
			t.Fatalf("try %d of the budget: %v", i, err)
		}
	}
	_, err = h.svc.CheckTarget(h.ctx, approver, last.ID, guess)
	wantErr(t, err, http.StatusTooManyRequests, admin.ReasonTargetCheckRate)
	if _, err := h.svc.CheckTarget(h.ctx, h.as(other), last.ID, hookURL+"/c"+string(rune('a'+budget-1))); err != nil {
		t.Errorf("another approver is not limited by this one: %v", err)
	}
	h.advance(admin.TargetCheckWindow + time.Minute)
	if res, err := h.svc.CheckTarget(h.ctx, h.as(ad[1]), last.ID, guess); err != nil || res.Match {
		t.Errorf("after the window: %+v, %v", res, err)
	}

	// audit: one event per try, one per refusal; the submitted and the sealed URLs appear nowhere
	var checked, refused int
	h.tx(func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(-1)
		for _, e := range evs {
			d := string(e.Detail)
			for _, bad := range []string{"GUESS-ONE", "PLAINTEXT", "hooks.example.com", "T000"} {
				if strings.Contains(d, bad) {
					t.Errorf("audit %s carries %q: %s", e.Action, bad, d)
				}
			}
			switch e.Action {
			case "admin.change.target_checked":
				checked++
				if !strings.Contains(d, `"submitted_fp"`) || !strings.Contains(d, `"change_id"`) {
					t.Errorf("check event lacks the fingerprint or the request id: %s", d)
				}
			case "admin.change.target_check_refused":
				refused++
			}
		}
		return err
	})
	wantChecked := admin.MaxTargetChecksPerValue + 1 + budget + 1 + 1 // a, b, the budget, the other approver, after the window
	if checked != wantChecked || refused != 4 {
		t.Errorf("audited %d checks and %d refusals", checked, refused)
	}
}

// The tenant-wide hourly cap holds however many approvers share it.
func TestCheckTarget_TenantCap(t *testing.T) {
	h, _, machine := secretHarness(t)
	n := 0
	var last error
	for i := 0; i < admin.MaxTargetChecksPerTenant/admin.MaxTargetChecksPerApprover+2 && last == nil; i++ {
		ap := h.as(h.admins("x" + string(rune('a'+i)))[0])
		for j := 0; j < admin.MaxTargetChecksPerApprover && last == nil; j++ {
			ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(
				`{"name":"n`+string(rune('a'+i))+string(rune('a'+j))+`","kind":"webhook","target":"`+hookURL+`/`+string(rune('a'+i))+string(rune('a'+j))+`","signing_secret":"`+hookSecret+`"}`))
			if err != nil {
				t.Fatal(err)
			}
			if _, last = h.svc.CheckTarget(h.ctx, ap, ch.ID, hookURL); last == nil {
				n++
			}
		}
	}
	wantErr(t, last, http.StatusTooManyRequests, admin.ReasonTargetCheckRate)
	if n != admin.MaxTargetChecksPerTenant {
		t.Errorf("%d checks passed before the tenant cap, want %d", n, admin.MaxTargetChecksPerTenant)
	}
}

// The flag the approver is shown (same / PATH CHANGED / MOVED) is recomputed against the live object when the request is
// viewed and when it is planned, so an update filed against an object that moved meanwhile is not approved (#886).
func TestProposalTargetChange_RecomputedLive(t *testing.T) {
	h, ad, machine := secretHarness(t)
	file := func(id, body string) *store.AdminChange {
		ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, id, json.RawMessage(body))
		if err != nil {
			t.Fatal(err)
		}
		return ch
	}
	create := file("", `{"name":"soc","kind":"webhook","target":"`+hookURL+`","signing_secret":"`+hookSecret+`"}`)
	if _, err := h.svc.Approve(h.ctx, h.as(ad[0]), create.ID, create.PayloadHash); err != nil {
		t.Fatal(err)
	}
	var id string
	h.tx(func(tx *store.TenantTx) error { cs, _ := tx.AlertChannels(); id = cs[0].ID; return nil })
	same := file(id, `{"target":"`+hookURL+`"}`)
	move := file(id, `{"target":"https://hooks.example.com/services/T000/B000/OTHER"}`)
	live := func(ch *store.AdminChange) (c string) {
		h.tx(func(tx *store.TenantTx) error { c = h.svc.LiveTargetChange(tx, h.change(ch.ID)); return nil })
		return c
	}
	if got := live(same); got != "unchanged" {
		t.Fatalf("live flag = %q, want unchanged", got)
	}
	if _, err := h.svc.Approve(h.ctx, h.as(ad[1]), move.ID, move.PayloadHash); err != nil {
		t.Fatal(err)
	}
	if got := live(same); got != "path_changed" {
		t.Errorf("live flag after the object moved = %q, want path_changed", got)
	}
	_, err := h.svc.Approve(h.ctx, h.as(ad[1]), same.ID, same.PayloadHash)
	wantErr(t, err, http.StatusConflict, "target_changed")
}

// The limits hold under concurrency with no row lock: DB.InTenant serialises every writer of the tenant (a Postgres
// advisory lock; the single SQLite writer), so 20 simultaneous checks of one value let exactly 5 through. Under
// TESSERA_TEST_PG_URL this runs on Postgres.
func TestCheckTarget_ConcurrentLimit(t *testing.T) {
	h, _, machine := secretHarness(t)
	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(
		`{"name":"soc","kind":"webhook","target":"`+hookURL+`","signing_secret":"`+hookSecret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	const n = 20
	ps := make([]*auth.Principal, n)
	for i := range ps {
		ps[i] = h.as(h.admins("c" + string(rune('a'+i)))[0]) // distinct approvers: only the value's limit applies
	}
	var wg sync.WaitGroup
	var ok, locked atomic.Int32
	for _, p := range ps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.svc.CheckTarget(h.ctx, p, ch.ID, "https://hooks.example.com/guess")
			var ae *admin.Error
			switch {
			case err == nil:
				ok.Add(1)
			case errors.As(err, &ae) && ae.Code == admin.ReasonTargetCheckLocked:
				locked.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != admin.MaxTargetChecksPerValue || locked.Load() != n-admin.MaxTargetChecksPerValue {
		t.Errorf("%d checks passed and %d were locked, want %d and %d", ok.Load(), locked.Load(), admin.MaxTargetChecksPerValue, n-admin.MaxTargetChecksPerValue)
	}
}
