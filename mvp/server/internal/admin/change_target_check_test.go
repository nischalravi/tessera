package admin_test

import (
	"encoding/json"
	"net/http"
	"strings"
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
	if err != nil || !res.Match || res.AttemptsLeft != admin.MaxTargetChecksPerRequest-1 {
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
	file := func(name string) *store.AdminChange {
		ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertChannel, "", json.RawMessage(
			`{"name":"`+name+`","kind":"webhook","target":"`+hookURL+`/`+name+`","signing_secret":"`+hookSecret+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return ch
	}
	guess := "https://hooks.example.com/services/T000/B000/GUESS-ONE"
	approver := h.as(ad[1])
	ch := file("a")
	for i := 0; i < admin.MaxTargetChecksPerRequest; i++ {
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
	// the lock is the request's: another request is still open to the approver
	ch2 := file("b")
	if res, err := h.svc.CheckTarget(h.ctx, approver, ch2.ID, hookURL+"/b"); err != nil || !res.Match {
		t.Errorf("another request after a lock = %+v, %v", res, err)
	}
	// the approver's own budget runs out across requests, and comes back with the window
	budget := admin.MaxTargetChecksPerApprover - admin.MaxTargetChecksPerRequest - 1 // spent on ch and ch2 so far
	var last *store.AdminChange
	for i := 0; i < budget; i++ {
		last = file("c" + string(rune('a'+i)))
		if _, err := h.svc.CheckTarget(h.ctx, approver, last.ID, guess); err != nil {
			t.Fatalf("try %d of the budget: %v", i, err)
		}
	}
	_, err := h.svc.CheckTarget(h.ctx, approver, last.ID, guess)
	wantErr(t, err, http.StatusTooManyRequests, admin.ReasonTargetCheckRate)
	if _, err := h.svc.CheckTarget(h.ctx, h.as(other), last.ID, hookURL+"/"+"c"+string(rune('a'+budget-1))); err != nil {
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
	wantChecked := admin.MaxTargetChecksPerRequest + 1 + budget + 1 + 1 // ch, ch2, the budget, the other approver, after the window
	if checked != wantChecked || refused != 3 {
		t.Errorf("audited %d checks and %d refusals", checked, refused)
	}
	// and the stored attempts hold the fingerprint of the guess only
	h.tx(func(tx *store.TenantTx) error {
		n, err := tx.AdminChangeTargetChecks(ch.ID)
		if n != admin.MaxTargetChecksPerRequest || err != nil {
			t.Errorf("stored attempts = %d, %v", n, err)
		}
		return nil
	})
}
