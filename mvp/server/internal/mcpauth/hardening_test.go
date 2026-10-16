package mcpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Finding 2: the acting agent may not re-point a token at another resource.
func TestExchangeCannotRepointToAnotherResource(t *testing.T) {
	e := newEnv(t)
	tok := e.userToken(e.resA).AccessToken
	if resp, oe := e.exchange(tok, e.actorToken(actorOpts{}), e.resB, e.shared); resp != nil || oe == nil || oe.Code != "access_denied" {
		t.Fatalf("same actor, other resource = %+v, %+v", resp, oe)
	}
	if resp, oe := e.exchange(tok, e.actorToken(actorOpts{}), e.resA, e.shared); oe != nil || resp == nil {
		t.Fatalf("same actor, same resource: %+v", oe)
	}
	// a different actor (a sub-agent) is a delegation the chain records, and may name another resource
	subj := e.craftSubject(e.alice, []string{e.shared}, &Actor{Sub: SubjectOf(e.alice + 1000)}, e.resA)
	if _, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resB, e.shared); oe != nil {
		t.Errorf("sub-agent exchange to another resource: %+v", oe)
	}
}

// Finding 5: the subject token's client must still be active.
func TestExchangeChecksTheSubjectTokensClient(t *testing.T) {
	e := newEnv(t)
	const old = "https://old.example/agent.json"
	e.write(func(tx *store.TenantTx) error {
		c := &store.MCPClient{ClientID: old, Name: "Old", RedirectURIs: `["https://old.example/cb"]`, JWKS: `{"keys":[]}`,
			DocSHA256: e.client.DocSHA256, ExpiresAt: e.now.Add(time.Hour)}
		if err := tx.UpsertMCPClient(c, e.now); err != nil {
			return err
		}
		return tx.SetMCPClient(old, &e.bot, "disabled", e.now)
	})
	e.craftClient = old
	subj := e.craftSubject(e.alice, []string{e.shared}, nil, e.resA)
	resp, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared)
	if resp != nil || oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("exchange of a token whose client is disabled = %+v, %+v", resp, oe)
	}
	e.write(func(tx *store.TenantTx) error { return tx.SetMCPClient(old, &e.bot, "active", e.now) })
	if resp, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared); oe != nil || resp == nil {
		t.Fatalf("the same exchange with an active client: %+v", oe)
	}
}

// Finding 1: containment stops new tokens, not just live ones.
func TestContainedAgentGetsNoNewTokens(t *testing.T) {
	e := newEnv(t)
	approved, _ := e.authorize(e.resA.Resource, e.shared)
	pending := e.beginOnly()
	subj := e.userToken(e.resA).AccessToken
	e.write(func(tx *store.TenantTx) error {
		_, err := e.svc.RevokeIdentity(tx, e.bot, "kill switch")
		return err
	})
	if resp, oe := e.redeem(e.codeReq(approved, e.resA)); resp != nil || oe == nil {
		t.Errorf("an approved code redeemed after containment: %+v", oe)
	}
	if resp, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared); resp != nil || oe == nil {
		t.Errorf("an exchange succeeded after containment: %+v", oe)
	}
	var cl *store.MCPClient
	var req *store.MCPAuthRequest
	e.read(func(tx *store.TenantTx) error {
		var err error
		if cl, err = tx.MCPClient(e.client.ClientID); err != nil {
			return err
		}
		req, err = tx.MCPAuthRequest(pending)
		return err
	})
	if cl.Status != "disabled" || req.Status != store.MCPAuthDenied {
		t.Errorf("client %q, pending request %q", cl.Status, req.Status)
	}
	// an administrator re-enabling the client does not lift the containment
	e.write(func(tx *store.TenantTx) error { return tx.SetMCPClient(e.client.ClientID, &e.bot, "active", e.now) })
	e.client = nil
	e.read(func(tx *store.TenantTx) error {
		var err error
		e.client, err = tx.MCPClient("https://client.example/agent.json")
		return err
	})
	var oe *OAuthError
	e.write(func(tx *store.TenantTx) error {
		g, err := graphOf(tx, e)
		if err != nil {
			return err
		}
		_, _, oe, err = e.svc.BeginAuthorization(tx, g, NewAuthRequest{Client: e.client, RedirectURI: testRedirect,
			CodeChallenge: ChallengeS256(testVerif), Resource: e.resA.Resource, Scope: []string{e.shared}, UserIdentity: e.alice})
		return err
	})
	if oe == nil || oe.Code != "unauthorized_client" {
		t.Errorf("authorize for a contained agent = %+v", oe)
	}
	if evs := e.audit("mcp.tokens.revoke_identity"); len(evs) != 1 {
		t.Errorf("containment audited %d times", len(evs))
	}
}

func TestContainedUserGetsNoNewTokens(t *testing.T) {
	e := newEnv(t)
	approved, _ := e.authorize(e.resA.Resource, e.shared)
	subj := e.userToken(e.resA).AccessToken
	e.write(func(tx *store.TenantTx) error {
		_, err := e.svc.RevokeIdentity(tx, e.alice, "leaver")
		return err
	})
	if resp, oe := e.redeem(e.codeReq(approved, e.resA)); resp != nil || oe == nil {
		t.Errorf("a contained user's approved code redeemed: %+v", oe)
	}
	if resp, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared); resp != nil || oe == nil {
		t.Errorf("a contained user's token was exchanged: %+v", oe)
	}
	var oe *OAuthError
	e.write(func(tx *store.TenantTx) error {
		g, err := graphOf(tx, e)
		if err != nil {
			return err
		}
		_, _, oe, err = e.svc.BeginAuthorization(tx, g, NewAuthRequest{Client: e.client, RedirectURI: testRedirect,
			CodeChallenge: ChallengeS256(testVerif), Resource: e.resA.Resource, Scope: []string{e.shared}, UserIdentity: e.alice})
		return err
	})
	if oe == nil || oe.Code != "access_denied" {
		t.Errorf("authorize for a contained user = %+v", oe)
	}
}

// beginOnly stores a pending authorization request and returns its id.
func (e *env) beginOnly() string {
	e.t.Helper()
	var id string
	e.write(func(tx *store.TenantTx) error {
		g, err := graphOf(tx, e)
		if err != nil {
			return err
		}
		req, _, oe, err := e.svc.BeginAuthorization(tx, g, NewAuthRequest{Client: e.client, RedirectURI: testRedirect,
			CodeChallenge: ChallengeS256(testVerif), Resource: e.resA.Resource, Scope: []string{e.shared}, UserIdentity: e.alice})
		if err != nil || oe != nil {
			e.t.Fatalf("BeginAuthorization = %+v, %v", oe, err)
		}
		id = req.ID
		return nil
	})
	return id
}

// Finding 4: the actor assertion is never checked against keys older than the cache TTL.
func TestStaleClientKeysAreNotTrusted(t *testing.T) {
	e := newEnv(t)
	subj := e.userToken(e.resA).AccessToken
	e.write(func(tx *store.TenantTx) error {
		c := *e.client
		c.ExpiresAt = e.now.Add(-time.Second)
		return tx.UpsertMCPClient(&c, e.now)
	})
	resp, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared)
	if resp != nil || oe == nil || oe.Code != "invalid_client" {
		t.Fatalf("exchange with a stale client = %+v, %+v", resp, oe)
	}
}

func TestRefreshActorClient(t *testing.T) {
	e := newEnv(t)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &e.key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	fail := false
	srv, hc, hits := cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Agent Host","redirect_uris":["https://client.example/cb"],"jwks":%s}`,
			"https://"+r.Host+r.URL.Path, jwks)
	})
	url := srv.URL + "/agent.json"
	e.write(func(tx *store.TenantTx) error {
		c := &store.MCPClient{ClientID: url, Name: "Agent Host", RedirectURIs: `["https://client.example/cb"]`, JWKS: string(jwks),
			DocSHA256: e.client.DocSHA256, ExpiresAt: e.now.Add(-time.Minute)}
		if err := tx.UpsertMCPClient(c, e.now); err != nil {
			return err
		}
		return tx.SetMCPClient(url, &e.bot, "active", e.now)
	})
	e.svc.HTTP = hc
	ctx := context.Background()
	subj := e.userToken(e.resA).AccessToken

	// an unknown client never makes the server fetch anything
	if err := e.svc.RefreshActorClient(ctx, e.db.DB, e.db.Tenant, e.actorToken(actorOpts{iss: "https://nobody.example/x.json"})); err != nil || hits.Load() != 0 {
		t.Errorf("unknown client: %v after %d fetches", err, hits.Load())
	}
	// a failing refresh fails closed
	fail = true
	if err := e.svc.RefreshActorClient(ctx, e.db.DB, e.db.Tenant, e.actorToken(actorOpts{iss: url})); err == nil {
		t.Error("a failed refresh was ignored")
	}
	if resp, oe := e.exchange(subj, e.actorToken(actorOpts{iss: url}), e.resA, e.shared); resp != nil || oe == nil {
		t.Errorf("exchange after a failed refresh: %+v", oe)
	}
	// a good refresh makes the client current again, and an unchanged document keeps it active
	fail = false
	if err := e.svc.RefreshActorClient(ctx, e.db.DB, e.db.Tenant, e.actorToken(actorOpts{iss: url})); err != nil {
		t.Fatal(err)
	}
	if resp, oe := e.exchange(subj, e.actorToken(actorOpts{iss: url}), e.resA, e.shared); oe != nil || resp == nil {
		t.Errorf("exchange after a refresh: %+v", oe)
	}
	// a fresh cache is not fetched again
	n := hits.Load()
	if err := e.svc.RefreshActorClient(ctx, e.db.DB, e.db.Tenant, e.actorToken(actorOpts{iss: url})); err != nil || hits.Load() != n {
		t.Errorf("fresh cache refetched: %v, %d -> %d", err, n, hits.Load())
	}
}
