package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// proposalServer answers the token endpoint and the proposal routes; polls is the status each poll returns in turn
// (the last repeats).
func proposalServer(t *testing.T, polls []string, failure string) (*Client, *atomic.Int32) {
	t.Helper()
	var polled atomic.Int32
	var srv *httptest.Server
	mux := http.NewServeMux()
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/t/larkspur/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": srv.URL + "/t/larkspur/oauth/token"})
	})
	mux.HandleFunc("/t/larkspur/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 600})
	})
	mux.HandleFunc("POST /api/v1/proposals/alert-rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"change_id": "c-1", "status": "pending_approval", "url": srv.URL + "/admin/change-requests?id=c-1"})
	})
	mux.HandleFunc("POST /api/v1/proposals/refused", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"forbidden","message":"the client does not hold the config.propose scope"}}`))
	})
	mux.HandleFunc("GET /api/v1/proposals/c-1", func(w http.ResponseWriter, _ *http.Request) {
		n := int(polled.Add(1)) - 1
		if n >= len(polls) {
			n = len(polls) - 1
		}
		body := map[string]any{"change_id": "c-1", "status": polls[n], "url": srv.URL + "/admin/change-requests?id=c-1"}
		if failure != "" {
			body["failure"] = failure
		}
		if polls[n] == "applied" {
			body["result_id"] = "role-9"
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, err := New(Config{Endpoint: srv.URL, Tenant: "larkspur", ClientID: "tsc_x", PrivateKeyPEM: pemOf(t, key), KeyID: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	return c, &polled
}

func TestProposeAndWait(t *testing.T) {
	const fast = 5 * time.Millisecond
	for _, tc := range []struct {
		name     string
		polls    []string
		failure  string
		timeout  time.Duration
		wantErr  string // "" for applied
		timedOut bool
		polled   int32
	}{
		{"applied after two polls", []string{"pending_approval", "applied"}, "", time.Second, "", false, 2},
		{"applied at once", []string{"applied"}, "", time.Second, "", false, 1},
		{"cooling off is still waiting", []string{"cooling_off", "applied"}, "", time.Second, "", false, 2},
		{"rejected", []string{"pending_approval", "rejected"}, "", time.Second, "was rejected (change c-1)", false, 2},
		{"cancelled", []string{"cancelled"}, "", time.Second, "was cancelled", false, 1},
		{"expired", []string{"expired"}, "", time.Second, "was expired", false, 1},
		{"the applier failed", []string{"failed"}, "version_conflict: the role changed", time.Second, "version_conflict: the role changed", false, 1},
		{"nobody approves in time", []string{"pending_approval"}, "", 60 * time.Millisecond, "nobody approved it within 60ms", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, polled := proposalServer(t, tc.polls, tc.failure)
			ch, err := c.ProposeAndWait(context.Background(), "/proposals/alert-rules/signin_failures", map[string]any{"enabled": true}, tc.timeout, fast)
			if tc.wantErr == "" {
				if err != nil || ch.Status != "applied" || ch.ResultID == nil || *ch.ResultID != "role-9" {
					t.Fatalf("got %+v, %v", ch, err)
				}
			} else {
				var ce *ChangeError
				if !errors.As(err, &ce) || !strings.Contains(err.Error(), tc.wantErr) || ce.TimedOut != tc.timedOut {
					t.Fatalf("err = %v, want a ChangeError containing %q (timeout %t)", err, tc.wantErr, tc.timedOut)
				}
				// whatever the end, the error names the change and the URL a person opens
				if ce.ChangeID != "c-1" || !strings.Contains(err.Error(), "/admin/change-requests?id=c-1") {
					t.Errorf("error does not name the change and its URL: %v", err)
				}
			}
			if tc.polled > 0 && polled.Load() != tc.polled {
				t.Errorf("polled %d times, want %d", polled.Load(), tc.polled)
			}
		})
	}
}

func TestProposeAndWait_RefusalIsAnAPIError(t *testing.T) {
	c, _ := proposalServer(t, []string{"applied"}, "")
	_, err := c.ProposeAndWait(context.Background(), "/proposals/refused", map[string]any{}, time.Second, time.Millisecond)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusForbidden || !strings.Contains(err.Error(), "config.propose") {
		t.Fatalf("got %v", err)
	}
}

func TestProposeAndWait_StopsWithTheContext(t *testing.T) {
	c, _ := proposalServer(t, []string{"pending_approval"}, "")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.ProposeAndWait(ctx, "/proposals/alert-rules/signin_failures", map[string]any{}, time.Hour, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "c-1") {
		t.Fatalf("got %v", err)
	}
}
