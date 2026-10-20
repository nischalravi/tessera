package oauth

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func refreshForm(rt string, extra ...string) url.Values {
	v := url.Values{"grant_type": {GrantRefresh}, "client_id": {CLIClientID}, "refresh_token": {rt}}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

var viewer = []auth.Role{auth.RoleViewer}

func sessionOf(t testing.TB, h *harness, slug string, id uuid.UUID) *store.Session {
	t.Helper()
	var s *store.Session
	if err := h.db.ReadTenant(context.Background(), h.tenantID(slug), func(tx *store.TenantTx) error {
		var err error
		s, err = tx.Session(id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func sidOf(t testing.TB, access string) uuid.UUID {
	t.Helper()
	_, c := decodeJWT(t, access)
	return uuid.MustParse(c["sid"].(string))
}

// TestRefreshRotation: every refresh issues a new refresh token of the same
// family and uses up the old one.
func TestRefreshRotation(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	t0, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
	h.clock.Advance(5 * time.Minute)
	t1 := tokensOf(t, h.tokenReq(slugA, refreshForm(t0.Refresh), k))
	if t1.Refresh == t0.Refresh || t1.Access == t0.Access || !strings.HasPrefix(t1.Refresh, "trt_") || t1.Raw.str("token_type") != "DPoP" ||
		t1.Scope != t0.Scope || t1.ExpiresIn != 600 {
		t.Errorf("refreshed tokens: %s", t1.Raw.Raw)
	}
	// the new access token works for the same key
	if w := h.whoamiReq(k, t1.Access); w.Status != 200 {
		t.Errorf("whoami with the refreshed token: %d %s", w.Status, w.Raw)
	}
	old, err := h.refreshRow(slugA, hashHex(t0.Refresh))
	if err != nil || old.UsedAt == nil || old.RevokedAt != nil {
		t.Fatalf("the old token row: %+v %v", old, err)
	}
	cur, err := h.refreshRow(slugA, hashHex(t1.Refresh))
	if err != nil || cur.UsedAt != nil || cur.FamilyID != old.FamilyID || cur.ParentID == nil || *cur.ParentID != old.ID ||
		cur.DPoPJKT != jktOf(t, k) || cur.SessionID != old.SessionID {
		t.Fatalf("the new token row: %+v %v", cur, err)
	}
	// activity moves the session's idle expiry, never past its absolute expiry
	s := sessionOf(t, h, slugA, old.SessionID)
	if !s.IdleExpiresAt.Equal(h.clock.Now().Add(auth.CLIIdle)) || !s.IdleExpiresAt.Before(s.AbsoluteExpiresAt) {
		t.Errorf("session idle %v absolute %v", s.IdleExpiresAt, s.AbsoluteExpiresAt)
	}
	if evs := h.auditEvents(slugA, "oauth.refresh.rotated"); len(evs) != 1 {
		t.Errorf("%d oauth.refresh.rotated events, want 1", len(evs))
	} else if d := string(evs[0].Detail); strings.Contains(d, t0.Refresh) || strings.Contains(d, t1.Refresh) || strings.Contains(d, t1.Access) {
		t.Errorf("the event records a secret: %s", d)
	}
	// the old access token is still a valid token until it expires (the session is alive)
	if w := h.whoamiReq(k, t0.Access); w.Status != 200 {
		t.Errorf("the previous access token within its lifetime: %d %s", w.Status, w.Raw)
	}
	// but not past its expiry (10 minutes, and 30 s of leeway)
	h.clock.Advance(11 * time.Minute)
	if w := h.whoamiReq(k, t0.Access); w.Status != 401 {
		t.Errorf("an expired access token: %d %s", w.Status, w.Raw)
	}
}

// TestRefreshReuse: presenting a rotated refresh token again revokes the
// whole family and the CLI session and writes a critical audit event.
func TestRefreshReuse(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	t0, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
	h.clock.Advance(time.Minute)
	t1 := tokensOf(t, h.tokenReq(slugA, refreshForm(t0.Refresh), k))
	h.clock.Advance(time.Minute)
	t2 := tokensOf(t, h.tokenReq(slugA, refreshForm(t1.Refresh), k))
	sid := sidOf(t, t0.Access)
	if w := h.whoamiReq(k, t2.Access); w.Status != 200 {
		t.Fatalf("whoami before the reuse: %d %s", w.Status, w.Raw)
	}

	h.clock.Advance(time.Minute)
	r := h.tokenReq(slugA, refreshForm(t0.Refresh), k) // the first token again
	if r.Status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("reuse: %d %s", r.Status, r.Raw)
	}
	// the family: every token revoked, with the reason
	old, _ := h.refreshRow(slugA, hashHex(t0.Refresh))
	var family []*store.RefreshToken
	if err := h.db.ReadTenant(context.Background(), tenantAID, func(tx *store.TenantTx) error {
		var err error
		family, err = tx.RefreshTokensByFamily(old.FamilyID)
		return err
	}); err != nil || len(family) != 3 {
		t.Fatalf("family: %d tokens (%v)", len(family), err)
	}
	for _, x := range family {
		if x.RevokedAt == nil || x.RevokedReason == nil || *x.RevokedReason != auth.RevokedRTReuse {
			t.Errorf("token %s not revoked for reuse: %+v", x.ID, x)
		}
	}
	// the session
	if s := sessionOf(t, h, slugA, sid); s.Status != store.SessionRevoked || s.RevokedReason == nil || *s.RevokedReason != auth.RevokedRTReuse {
		t.Errorf("session after the reuse: %+v", s)
	}
	// the newest refresh token and the latest access token are dead
	if r := h.tokenReq(slugA, refreshForm(t2.Refresh), k); r.str("error") != "invalid_grant" {
		t.Errorf("the newest refresh token after the reuse: %d %s", r.Status, r.Raw)
	}
	if w := h.whoamiReq(k, t2.Access); w.Status != 401 || w.str("reason") != auth.FailRevoked {
		t.Errorf("the access token after the reuse: %d %s", w.Status, w.Raw)
	}
	// the critical audit event
	evs := h.auditEvents(slugA, "oauth.refresh.reuse_detected")
	if len(evs) != 1 {
		t.Fatalf("%d oauth.refresh.reuse_detected events, want 1", len(evs))
	}
	e := evs[0]
	d := string(e.Detail)
	if e.Outcome != store.OutcomeDenied || !strings.Contains(d, `"severity":"critical"`) || !strings.Contains(d, sid.String()) ||
		!strings.Contains(d, old.FamilyID.String()) || !strings.Contains(d, `"tokens_revoked":3`) ||
		!strings.Contains(d, `"session_revoked":true`) {
		t.Errorf("reuse event: %s %s", e.Outcome, d)
	}
	if strings.Contains(d, t0.Refresh) || strings.Contains(d, t1.Refresh) || strings.Contains(d, t2.Refresh) {
		t.Error("the reuse event records a refresh token")
	}
	// reuse of a token of a session that already ended revokes nothing more but is still reported
	if r := h.tokenReq(slugA, refreshForm(t1.Refresh), k); r.str("error") != "invalid_grant" {
		t.Errorf("second reuse: %d %s", r.Status, r.Raw)
	}
}

// TestRefreshOtherKey: a refresh token is bound to its DPoP key (cnf).
func TestRefreshOtherKey(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	t0, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
	other := newKey(t)
	h.clock.Advance(time.Minute)
	r := h.tokenReq(slugA, refreshForm(t0.Refresh), other)
	if r.Status != 400 || r.str("error") != "invalid_grant" || !strings.Contains(r.str("error_description"), "another key") {
		t.Fatalf("another key: %d %s", r.Status, r.Raw)
	}
	// nothing was used up or revoked: the real client carries on
	if row, err := h.refreshRow(slugA, hashHex(t0.Refresh)); err != nil || row.UsedAt != nil || row.RevokedAt != nil {
		t.Errorf("the token after another key's attempt: %+v %v", row, err)
	}
	if w := h.whoamiReq(k, t0.Access); w.Status != 200 {
		t.Errorf("the session after the attempt: %d %s", w.Status, w.Raw)
	}
	tokensOf(t, h.tokenReq(slugA, refreshForm(t0.Refresh), k))
	if evs := h.auditEvents(slugA, "oauth.dpop.invalid"); len(evs) != 1 || evs[0].Outcome != store.OutcomeDenied {
		t.Errorf("oauth.dpop.invalid events: %+v", evs)
	}
	// the access token is bound to its key as well
	if w := h.whoamiReq(other, t0.Access); w.Status != 401 || w.str("reason") != auth.FailInvalidDPoP {
		t.Errorf("an access token with another key's proof: %d %s", w.Status, w.Raw)
	}
}

// TestRefreshExpiry: the idle expiry is 12 h from the last use and the
// absolute expiry is the CLI session's (24 h, 12 h with an admin role).
func TestRefreshExpiry(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		t0, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
		h.clock.Advance(auth.CLIIdle - time.Second)
		t1 := tokensOf(t, h.tokenReq(slugA, refreshForm(t0.Refresh), k)) // just inside
		h.clock.Advance(auth.CLIIdle + time.Second)
		r := h.tokenReq(slugA, refreshForm(t1.Refresh), k)
		if r.Status != 400 || r.str("error") != "invalid_grant" {
			t.Errorf("after 12 h idle: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("absolute, ordinary user", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		tok, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
		row, _ := h.refreshRow(slugA, hashHex(tok.Refresh))
		if want := h.clock.Now().Add(24 * time.Hour); !row.AbsoluteExpiresAt.Equal(want) {
			t.Errorf("absolute expiry %v, want %v", row.AbsoluteExpiresAt, want)
		}
		for range 2 { // kept alive every 11 h: 11 h, 22 h
			h.clock.Advance(11 * time.Hour)
			tok = tokensOf(t, h.tokenReq(slugA, refreshForm(tok.Refresh), k))
		}
		// the third token's idle expiry is capped at the session's absolute expiry (24 h)
		row, _ = h.refreshRow(slugA, hashHex(tok.Refresh))
		if !row.ExpiresAt.Equal(row.AbsoluteExpiresAt) {
			t.Errorf("idle expiry %v, want it capped at the absolute expiry %v", row.ExpiresAt, row.AbsoluteExpiresAt)
		}
		h.clock.Advance(2*time.Hour + time.Second) // 24 h 1 s after sign-in, 2 h after the last use
		r := h.tokenReq(slugA, refreshForm(tok.Refresh), k)
		if r.Status != 400 || r.str("error") != "invalid_grant" {
			t.Errorf("past the absolute expiry: %d %s", r.Status, r.Raw)
		}
		if w := h.whoamiReq(k, tok.Access); w.Status != 401 {
			t.Errorf("an access token of an expired session: %d %s", w.Status, w.Raw)
		}
	})
	t.Run("absolute, admin role", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		tok, _ := h.signInCLI(slugA, "admin@a.example", []auth.Role{auth.RoleTenantAdmin}, authtest.Phr, k)
		row, _ := h.refreshRow(slugA, hashHex(tok.Refresh))
		if want := h.clock.Now().Add(12 * time.Hour); !row.AbsoluteExpiresAt.Equal(want) {
			t.Errorf("absolute expiry %v, want %v", row.AbsoluteExpiresAt, want)
		}
		h.clock.Advance(11 * time.Hour)
		tok = tokensOf(t, h.tokenReq(slugA, refreshForm(tok.Refresh), k))
		h.clock.Advance(61 * time.Minute)
		if r := h.tokenReq(slugA, refreshForm(tok.Refresh), k); r.Status != 400 || r.str("error") != "invalid_grant" {
			t.Errorf("past 12 h with an admin role: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("admin access tokens live 300 s", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		l := h.login(slugA, "admin@a.example", []auth.Role{auth.RoleTenantAdmin}, authtest.Phr)
		d := h.startDevice(slugA, nil)
		_ = d
		d2 := h.startDevice(slugA, urlValues("scope", "tessera:read tessera:admin"))
		if r := h.approve(l, d2.UserCode, "approve"); r.Status != 200 {
			t.Fatal(r.Raw)
		}
		tok := tokensOf(t, h.devicePoll(slugA, d2, k))
		if tok.ExpiresIn != 300 || tok.Scope != "tessera:read tessera:admin" {
			t.Errorf("admin-scope token: expires_in %d scope %q", tok.ExpiresIn, tok.Scope)
		}
	})
}

func urlValues(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

// TestRefreshScope: a refresh may narrow the scope, never widen it.
func TestRefreshScope(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	t0, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k) // read write
	if r := h.tokenReq(slugA, refreshForm(t0.Refresh, "scope", "tessera:read tessera:audit"), k); r.Status != 400 || r.str("error") != "invalid_scope" {
		t.Fatalf("widening: %d %s", r.Status, r.Raw)
	}
	h.clock.Advance(time.Minute)
	t1 := tokensOf(t, h.tokenReq(slugA, refreshForm(t0.Refresh, "scope", "tessera:read"), k))
	if t1.Scope != "tessera:read" {
		t.Errorf("narrowed scope = %q", t1.Scope)
	}
	if w := h.whoamiReq(k, t1.Access); w.Status != 200 || len(w.Body["scopes"].([]any)) != 1 {
		t.Errorf("whoami with the narrowed token: %d %s", w.Status, w.Raw)
	}
	// and it stays narrow
	h.clock.Advance(time.Minute)
	if t2 := tokensOf(t, h.tokenReq(slugA, refreshForm(t1.Refresh), k)); t2.Scope != "tessera:read" {
		t.Errorf("scope after another refresh = %q", t2.Scope)
	}
}

// TestRefreshRequestChecks: the DPoP proof is checked before the refresh
// token is looked at, and the request must be well formed.
func TestRefreshRequestChecks(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	t0, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
	target := h.srv.URL + "/t/" + slugA + "/oauth/token"
	post := func(form url.Values, hdr map[string]string) resp {
		return h.postForm("/t/"+slugA+"/oauth/token", form, hdr)
	}

	t.Run("no proof", func(t *testing.T) {
		if r := post(refreshForm(t0.Refresh), nil); r.Status != 400 || r.str("error") != "invalid_dpop_proof" {
			t.Errorf("%d %s", r.Status, r.Raw)
		}
	})
	t.Run("a proof for another tenant's endpoint", func(t *testing.T) {
		other := h.srv.URL + "/t/" + slugB + "/oauth/token"
		if r := post(refreshForm(t0.Refresh), map[string]string{"DPoP": h.proof(k, "POST", other, "", h.nonce())}); r.str("error") != "invalid_dpop_proof" {
			t.Errorf("%d %s", r.Status, r.Raw)
		}
	})
	t.Run("a proof for another method", func(t *testing.T) {
		if r := post(refreshForm(t0.Refresh), map[string]string{"DPoP": h.proof(k, "GET", target, "", h.nonce())}); r.str("error") != "invalid_dpop_proof" {
			t.Errorf("%d %s", r.Status, r.Raw)
		}
	})
	t.Run("a stale proof", func(t *testing.T) {
		stale := h.proofAt(k, "POST", target, "", h.nonce(), h.clock.Now().Add(-2*time.Minute))
		if r := post(refreshForm(t0.Refresh), map[string]string{"DPoP": stale}); r.str("error") != "invalid_dpop_proof" {
			t.Errorf("%d %s", r.Status, r.Raw)
		}
	})
	t.Run("a replayed proof", func(t *testing.T) {
		h.clock.Advance(time.Minute)
		hdr := map[string]string{"DPoP": h.proof(k, "POST", target, "", h.nonce())}
		first := post(refreshForm(t0.Refresh), hdr)
		if first.Status != 200 {
			t.Fatalf("first use: %d %s", first.Status, first.Raw)
		}
		second := post(refreshForm(first.str("refresh_token")), hdr)
		if second.Status != 400 || second.str("error") != "invalid_dpop_proof" || !strings.Contains(second.str("error_description"), "already used") {
			t.Errorf("replay: %d %s", second.Status, second.Raw)
		}
		t0 = tokens{Refresh: first.str("refresh_token"), Access: first.str("access_token")}
	})
	t.Run("malformed requests", func(t *testing.T) {
		for name, tc := range map[string]struct {
			form url.Values
			want string
		}{
			"no grant_type":     {url.Values{"client_id": {CLIClientID}}, "invalid_request"},
			"no client_id":      {url.Values{"grant_type": {GrantRefresh}}, "invalid_request"},
			"unknown grant":     {url.Values{"grant_type": {"password"}, "client_id": {CLIClientID}}, "unsupported_grant_type"},
			"client_credential": {url.Values{"grant_type": {"client_credentials"}, "client_id": {CLIClientID}}, "unsupported_grant_type"},
			"unknown client":    {refreshForm(t0.Refresh, "client_id", "nobody"), "invalid_client"},
			"no refresh_token":  {url.Values{"grant_type": {GrantRefresh}, "client_id": {CLIClientID}}, "invalid_request"},
			"two refresh_token": {url.Values{"grant_type": {GrantRefresh}, "client_id": {CLIClientID}, "refresh_token": {"a", "b"}}, "invalid_request"},
			"unknown token":     {refreshForm("trt_nope"), "invalid_grant"},
			"an access token":   {refreshForm(t0.Access), "invalid_grant"},
		} {
			t.Run(name, func(t *testing.T) {
				if r := h.tokenReq(slugA, tc.form, k); r.str("error") != tc.want {
					t.Errorf("%d %s, want %s", r.Status, r.Raw, tc.want)
				}
			})
		}
	})
	t.Run("a GET", func(t *testing.T) {
		if r := h.whoamiWith("x", "DPoP", nil); r.Status != 401 {
			t.Errorf("%d", r.Status)
		}
	})
}

// TestRefreshSessionEnds: a refresh token is useless once its session or user
// is gone, and revocation (RFC 7009) ends the session.
func TestRefreshSessionEnds(t *testing.T) {
	t.Run("user disabled", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		t0, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
		uid := userOf(t, t0.Access)
		h.mutateTenant(slugA, func(tx *store.TenantTx) error { return tx.DisableUser(uid, "left", h.clock.Now()) })
		if r := h.tokenReq(slugA, refreshForm(t0.Refresh), k); r.str("error") != "invalid_grant" {
			t.Errorf("refresh: %d %s", r.Status, r.Raw)
		}
		if w := h.whoamiReq(k, t0.Access); w.Status != 401 || w.str("reason") != auth.FailUserDisabled {
			t.Errorf("whoami: %d %s", w.Status, w.Raw)
		}
	})
	t.Run("session revoked by an admin or the user", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		t0, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
		h.mutateTenant(slugA, func(tx *store.TenantTx) error {
			return auth.RevokeSession(tx, sidOf(t, t0.Access), auth.RevokedAdmin, h.clock.Now())
		})
		if r := h.tokenReq(slugA, refreshForm(t0.Refresh), k); r.str("error") != "invalid_grant" {
			t.Errorf("refresh: %d %s", r.Status, r.Raw)
		}
		if w := h.whoamiReq(k, t0.Access); w.Status != 401 || w.str("reason") != auth.FailRevoked {
			t.Errorf("whoami: %d %s", w.Status, w.Raw)
		}
	})
	t.Run("revocation", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		t0, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
		revoke := func(slug string, form url.Values) resp {
			return h.postForm("/t/"+slug+"/oauth/revoke", form, nil)
		}
		// another client id, an unknown token and another tenant revoke nothing
		for name, r := range map[string]resp{
			"other client":   revoke(slugA, url.Values{"token": {t0.Refresh}, "client_id": {"nobody"}}),
			"unknown token":  revoke(slugA, url.Values{"token": {"trt_nope"}, "client_id": {CLIClientID}}),
			"other tenant":   revoke(slugB, url.Values{"token": {t0.Refresh}, "client_id": {CLIClientID}}),
			"no token field": revoke(slugA, url.Values{"client_id": {CLIClientID}}),
		} {
			if name == "no token field" {
				if r.Status != 400 {
					t.Errorf("%s: %d %s", name, r.Status, r.Raw)
				}
				continue
			}
			if r.Status != 200 {
				t.Errorf("%s: %d %s (RFC 7009 answers 200)", name, r.Status, r.Raw)
			}
		}
		if w := h.whoamiReq(k, t0.Access); w.Status != 200 {
			t.Fatalf("a no-op revocation ended the session: %d %s", w.Status, w.Raw)
		}
		if r := revoke(slugA, url.Values{"token": {t0.Refresh}, "client_id": {CLIClientID}}); r.Status != 200 {
			t.Fatalf("revoke: %d %s", r.Status, r.Raw)
		}
		if r := h.tokenReq(slugA, refreshForm(t0.Refresh), k); r.str("error") != "invalid_grant" {
			t.Errorf("refresh after revocation: %d %s", r.Status, r.Raw)
		}
		if w := h.whoamiReq(k, t0.Access); w.Status != 401 {
			t.Errorf("access token after revocation: %d %s", w.Status, w.Raw)
		}
		// tenant A: two no-ops and the revocation; the other-tenant call is tenant B's no-op
		if evs := h.auditEvents(slugA, "oauth.token.revoked"); len(evs) != 3 {
			t.Errorf("%d oauth.token.revoked events in A, want 3", len(evs))
		}
		if evs := h.auditEvents(slugB, "oauth.token.revoked"); len(evs) != 1 || evs[0].Outcome != store.OutcomeFailure {
			t.Errorf("tenant B's events: %+v", evs)
		}
	})
}

func userOf(t testing.TB, access string) uuid.UUID {
	t.Helper()
	_, c := decodeJWT(t, access)
	return uuid.MustParse(strings.TrimPrefix(c["sub"].(string), SubjectPrefix))
}

// TestRefreshCrossTenant: tenant A's refresh token and device code mean
// nothing at tenant B's endpoints.
func TestRefreshCrossTenant(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	t0, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
	if r := h.tokenReq(slugB, refreshForm(t0.Refresh), k); r.Status != 400 || r.str("error") != "invalid_grant" {
		t.Errorf("A's refresh token at B: %d %s", r.Status, r.Raw)
	}
	// and A's token is intact
	tokensOf(t, h.tokenReq(slugA, refreshForm(t0.Refresh), k))
	d := h.startDevice(slugA, nil)
	if r := h.devicePoll(slugB, d, k); r.Status != 400 || r.str("error") != "invalid_grant" {
		t.Errorf("A's device code at B: %d %s", r.Status, r.Raw)
	}
	l := h.login(slugB, "bob@b.example", viewer, authtest.Phr)
	if r := h.approve(l, d.UserCode, "approve"); r.Status != 404 {
		t.Errorf("B's user approving A's code: %d %s", r.Status, r.Raw)
	}
}
