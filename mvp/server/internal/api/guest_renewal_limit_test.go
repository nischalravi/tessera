package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
)

// renewalRequestFrom posts a renewal request as if from the given client address.
func (e *claimEnv) renewalRequestFrom(addr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/public/t/"+e.slug+"/guest/renewal-request",
		strings.NewReader(`{"token":"`+strings.Repeat("A", 43)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", claimOrigin)
	req.RemoteAddr = addr
	return serve(e.h, req)
}

// One client flooding renewal-request is limited by its own address, while
// another address is still answered; the flood leaves claim/start alone (#377).
func TestGuestLifecycleAPI_RenewalRequestRateLimits(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const flooder, other = "192.0.2.201:4000", "192.0.2.202:4000"
	var limited int
	for i := 0; i < 150; i++ {
		rec := e.renewalRequestFrom(flooder)
		switch rec.Code {
		case http.StatusTooManyRequests:
			limited++
			if !strings.Contains(rec.Body.String(), "rate_limited") || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("throttle response %v %s", rec.Header(), rec.Body)
			}
		case http.StatusAccepted:
		default:
			t.Fatalf("request %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if limited != 140 {
		t.Errorf("%d of 150 requests from one address were limited, want 140", limited)
	}
	if rec := e.renewalRequestFrom(other); rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"received"`) {
		t.Errorf("another address after the flood: %d %s", rec.Code, rec.Body)
	}
	pg := e.newPage()
	pg.ip = "192.0.2.203:4000"
	if rec := pg.start(claim.NewToken()); rec.Code == http.StatusTooManyRequests {
		t.Errorf("claim/start from another address after the flood: %d %s", rec.Code, rec.Body)
	}
}

// Many addresses together fill the renewal tenant bucket, not the one claim/start spends.
func TestGuestLifecycleAPI_RenewalTenantBucketApartFromStart(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	for i := 0; i < 130; i++ {
		e.renewalRequestFrom(fmt.Sprintf("198.51.100.%d:%d", i+1, 5000+i))
	}
	if e.srv.claimLim.renewTenant.AllowAt(ratelimit.TenantKey(e.tenant.String()), e.clk.now()) {
		t.Error("the renewal tenant bucket should be empty after 130 requests from 130 addresses")
	}
	if !e.srv.claimLim.startTenant.AllowAt(ratelimit.TenantKey(e.tenant.String()), e.clk.now()) {
		t.Error("the claim/start tenant bucket was drained by renewal requests")
	}
}
