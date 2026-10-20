package ssf

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

type pollReq struct {
	Ack               []string               `json:"ack"`
	SetErrs           map[string]*Error      `json:"setErrs"`
	ReturnImmediately bool                   `json:"returnImmediately"`
	MaxEvents         int                    `json:"maxEvents"`
	Raw               map[string]interface{} `json:"-"`
	Auth              string                 `json:"-"`
}

type pollServer struct {
	mu    sync.Mutex
	reqs  []pollReq
	reply func(n int) (int, any)
}

func (p *pollServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var body pollReq
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Errorf("poll body: %v", err)
		}
		body.Auth = req.Header.Get("Authorization")
		p.mu.Lock()
		p.reqs = append(p.reqs, body)
		n := len(p.reqs)
		p.mu.Unlock()
		status, out := p.reply(n)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	}
}

// pollRig turns the rig's transmitter into a poll stream against srv.
func (r *rig) pollRig(url string) {
	r.t.Helper()
	if err := r.inA(func(c *store.TenantTx) error {
		x, _, err := r.svc.Update(c, r.tr.ID, TransmitterInput{Name: "Okta", Issuer: testIssuer, Audience: testAudience, Delivery: "poll",
			PollURL: url, Secret: "poll-bearer-token-123456", SubjectSystem: "okta"}, "admin", now)
		r.tr = x
		return err
	}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) pending() ([]string, map[string]*Error) {
	var a []string
	var e map[string]*Error
	r.read(func(c *store.TenantTx) error {
		x, _ := c.SSFTransmitter(r.tr.ID)
		a, e = pendingOf(x)
		return nil
	})
	return a, e
}

// Poll: only the jtis whose events are committed are acknowledged; a SET that
// fails validation is reported in setErrs; both go out with the next request.
func TestPollAcknowledgesOnlyWhatItProcessed(t *testing.T) {
	r := newRig(t)
	stranger := newSigner(t, "ES256", "k1")
	good := r.setFor("good-1", EventSessionRevoked, issSub("bob"))
	unmatched := r.setFor("nobody-1", EventSessionRevoked, issSub("nobody"))
	badSig := stranger.sign(t, claimsFor(func(c map[string]any) { c["jti"] = "bad-sig" }))
	wrongKey := r.setFor("really-this", EventSessionRevoked, issSub("bob"))
	ps := &pollServer{}
	ps.reply = func(n int) (int, any) {
		if n == 1 {
			return 200, map[string]any{"sets": map[string]string{"good-1": good, "nobody-1": unmatched, "bad-sig": badSig,
				"named-differently": wrongKey}, "moreAvailable": true}
		}
		return 200, map[string]any{"sets": map[string]string{}, "moreAvailable": false}
	}
	srv := server(t, ps.handler(t))
	r.pollRig(srv.URL)

	res, err := r.svc.Poll(context.Background(), r.f.DB, r.f.A.ID, r.tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Received != 4 || res.Acked != 2 || res.Errors != 2 {
		t.Errorf("result %+v", res)
	}
	if len(ps.reqs) != 2 {
		t.Fatalf("%d requests (moreAvailable is followed once)", len(ps.reqs))
	}
	first, second := ps.reqs[0], ps.reqs[1]
	if first.Auth != "Bearer poll-bearer-token-123456" || !first.ReturnImmediately || first.MaxEvents != 25 || first.Ack == nil || len(first.Ack) != 0 || first.SetErrs != nil {
		t.Errorf("first request %+v", first)
	}
	// the second request acknowledges exactly the processed jtis (an unmatched one is processed: it is recorded),
	// and reports the invalid ones; the valid SET delivered under another name is an error too
	if len(second.Ack) != 2 || second.Ack[0] != "good-1" || second.Ack[1] != "nobody-1" {
		t.Errorf("acks %v", second.Ack)
	}
	if len(second.SetErrs) != 2 || second.SetErrs["bad-sig"].Code != ErrInvalidKey || second.SetErrs["named-differently"].Code != ErrInvalidRequest ||
		second.SetErrs["bad-sig"].Msg == "" {
		t.Errorf("setErrs %+v", second.SetErrs)
	}
	if a, e := r.pending(); len(a) != 0 || len(e) != 0 {
		t.Errorf("delivered acks and errors are forgotten: %v %v", a, e)
	}
	r.read(func(c *store.TenantTx) error {
		evs, _ := c.SSFEvents("", 10)
		x, _ := c.SSFTransmitter(r.tr.ID)
		if len(evs) != 2 || x.LastPolledAt == nil {
			t.Errorf("events %d, transmitter %+v", len(evs), x)
		}
		for _, e := range evs {
			if e.Via != store.SSFPoll {
				t.Errorf("event via %s", e.Via)
			}
		}
		return nil
	})
	if got := r.actions(); got["ssf.event_rejected"] != 2 {
		t.Errorf("audit %v", got)
	}
}

// A SET that hits an error of ours (the key endpoint is down) is not
// acknowledged, so the transmitter delivers it again.
func TestPollLeavesUnprocessedSetsUnacknowledged(t *testing.T) {
	r := newRig(t)
	good := r.setFor("later-1", EventSessionRevoked, issSub("bob"))
	ps := &pollServer{reply: func(n int) (int, any) {
		return 200, map[string]any{"sets": map[string]string{"later-1": good}, "moreAvailable": true}
	}}
	srv := server(t, ps.handler(t))
	r.pollRig(srv.URL)
	// the keys now come from an endpoint that is down
	dead := server(t, func(http.ResponseWriter, *http.Request) {})
	dead.Close()
	if err := r.inA(func(c *store.TenantTx) error {
		x, err := c.SSFTransmitter(r.tr.ID)
		if err != nil {
			return err
		}
		x.JWKSInline, x.JWKSURL = "", dead.URL
		r.tr = x
		return c.UpdateSSFTransmitter(x, now)
	}); err != nil {
		t.Fatal(err)
	}
	res, err := r.svc.Poll(context.Background(), r.f.DB, r.f.A.ID, r.tr.ID)
	if err == nil || res.Acked != 0 || res.Errors != 0 || len(ps.reqs) != 1 {
		t.Errorf("poll = %+v, %v (%d requests: no more rounds after an error)", res, err, len(ps.reqs))
	}
	if a, e := r.pending(); len(a) != 0 || len(e) != 0 {
		t.Errorf("nothing may be acknowledged or reported: %v %v", a, e)
	}
	r.read(func(c *store.TenantTx) error {
		if evs, _ := c.SSFEvents("", 10); len(evs) != 0 {
			t.Errorf("events %v", evs)
		}
		return nil
	})
}

func TestPollTransportErrors(t *testing.T) {
	r := newRig(t)
	ps := &pollServer{reply: func(n int) (int, any) {
		switch n {
		case 1:
			return 401, map[string]any{"error": "bad token"}
		case 2:
			return 200, "not an object"
		}
		return 200, map[string]any{"sets": map[string]string{}}
	}}
	srv := server(t, ps.handler(t))
	r.pollRig(srv.URL)
	// leave an ack pending: a failed poll must keep it
	if err := r.inA(func(c *store.TenantTx) error { return c.SetSSFPollState(r.tr.ID, `["keep-me"]`, `{}`, now) }); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"answered 401", "not valid JSON"} {
		if _, err := r.svc.Poll(context.Background(), r.f.DB, r.f.A.ID, r.tr.ID); err == nil || !contains(err.Error(), want) {
			t.Errorf("poll %d: %v, want %q", i, err, want)
		}
		if a, _ := r.pending(); len(a) != 1 || a[0] != "keep-me" {
			t.Errorf("a failed poll lost its acks: %v", a)
		}
		r.read(func(c *store.TenantTx) error {
			if x, _ := c.SSFTransmitter(r.tr.ID); !contains(x.LastError, "poll failed") {
				t.Errorf("last error %q", x.LastError)
			}
			return nil
		})
	}
	if _, err := r.svc.Poll(context.Background(), r.f.DB, r.f.A.ID, r.tr.ID); err != nil {
		t.Fatal(err)
	}
	if got := ps.reqs[len(ps.reqs)-1]; len(got.Ack) != 1 || got.Ack[0] != "keep-me" {
		t.Errorf("the carried ack: %+v", got)
	}
	if a, _ := r.pending(); len(a) != 0 {
		t.Errorf("a delivered ack is forgotten: %v", a)
	}
}

func TestPollAllPollsEnabledPollStreamsOnly(t *testing.T) {
	r := newRig(t) // a push stream
	ps := &pollServer{reply: func(n int) (int, any) { return 200, map[string]any{"sets": map[string]string{}} }}
	srv := server(t, ps.handler(t))
	var paused, polling string
	if err := r.inA(func(c *store.TenantTx) error {
		for _, tc := range []struct {
			name, status string
			dst          *string
		}{{"Paused poll", "paused", &paused}, {"Active poll", "enabled", &polling}} {
			x, _, err := r.svc.Create(c, TransmitterInput{Name: tc.name, Issuer: "https://" + strings.ToLower(strings.ReplaceAll(tc.name, " ", "-")) + ".example", Audience: "a", JWKSURL: "https://x/jwks",
				Delivery: "poll", PollURL: srv.URL, Secret: "poll-bearer-token-123456", SubjectSystem: "okta", Status: tc.status}, "admin", now)
			if err != nil {
				return err
			}
			*tc.dst = x.ID
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.PollAll(context.Background(), r.f.DB); err != nil {
		t.Fatal(err)
	}
	if len(ps.reqs) != 1 {
		t.Errorf("%d polls, want 1 (the enabled poll stream)", len(ps.reqs))
	}
	r.read(func(c *store.TenantTx) error {
		for id, want := range map[string]bool{paused: false, polling: true, r.tr.ID: false} {
			if x, _ := c.SSFTransmitter(id); (x.LastPolledAt != nil) != want {
				t.Errorf("%s polled=%v, want %v", x.Name, x.LastPolledAt != nil, want)
			}
		}
		return nil
	})
	if _, err := r.svc.Poll(context.Background(), r.f.DB, r.f.A.ID, r.tr.ID); err == nil {
		t.Error("polling a push stream")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
