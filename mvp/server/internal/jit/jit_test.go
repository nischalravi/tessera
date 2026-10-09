package jit_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func hasIAMStar(t *testing.T, st *store.Store, iid int64, at time.Time) (present, jitOnly bool) {
	t.Helper()
	g, err := graph.FromDB(testkit.Conn(st), at)
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range g.EffectivePermissions(iid).Values() {
		if ep.Action == "iam:*" {
			return true, ep.JITOnly()
		}
	}
	return false, false
}

func TestJITLifecycle(t *testing.T) {
	st, ids := testkit.Tiny(t)
	now := testkit.Now
	var req *store.AccessRequest
	testkit.Write(t, st, func(c *store.Conn) error {
		_, err := jit.CreateRequest(c, now, ids["alice"], ids["group:okta:eng"], jit.Hours{N: 2}, "not requestable")
		var je *jit.Error
		if !errors.As(err, &je) {
			t.Errorf("non-requestable group: err = %v, want *jit.Error", err)
		}
		req, err = jit.CreateRequest(c, now, ids["alice"], ids["group:aws:ProdAdmin"], jit.Hours{N: 2, Whole: true}, "  incident  ")
		return err
	})
	if req.Status != "pending" || req.Justification != "incident" || req.AccountID != ids["acct:okta:alice"] {
		t.Fatalf("request = %+v", req)
	}
	testkit.Write(t, st, func(c *store.Conn) error {
		r, err := jit.Approve(c, req.ID, "approver", now, now)
		if err == nil && (r.ExpiresAt == nil || !r.ExpiresAt.Equal(now.Add(2*time.Hour)) || r.EdgeID == nil) {
			t.Errorf("approved = %+v", r)
		}
		return err
	})
	if present, jitOnly := hasIAMStar(t, st, ids["alice"], now); !present || !jitOnly {
		t.Fatalf("after approve: present=%v jitOnly=%v", present, jitOnly)
	}
	for _, tc := range []struct {
		after time.Duration
		want  int
	}{{time.Hour, 0}, {3 * time.Hour, 1}, {4 * time.Hour, 0}} {
		testkit.Write(t, st, func(c *store.Conn) error {
			n, err := jit.Sweep(c, now.Add(tc.after))
			if n != tc.want {
				t.Errorf("sweep at +%v = %d, want %d", tc.after, n, tc.want)
			}
			return err
		})
	}
	got, err := testkit.Conn(st).Request(req.ID)
	if err != nil || got.Status != "expired" {
		t.Fatalf("status = %v %v", got, err)
	}
	if present, _ := hasIAMStar(t, st, ids["alice"], now.Add(3*time.Hour)); present {
		t.Error("expired grant still effective")
	}
	if n, _ := testkit.Conn(st).Count("SELECT count(*) FROM grant_edges WHERE source = 'jit'"); n != 0 {
		t.Errorf("jit edges left: %d", n)
	}
}

func TestJITRejectsStandingDuplicate(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.Conn) error {
		if _, err := c.Exec(`INSERT INTO grant_edges (src, dst, relation, source, created_at) VALUES (?, ?, 'member_of', 'connector', ?)`,
			graph.Key("account", ids["acct:okta:alice"]), graph.Key("group", ids["group:aws:ProdAdmin"]), store.T(testkit.Now)); err != nil {
			return err
		}
		_, err := jit.CreateRequest(c, testkit.Now, ids["alice"], ids["group:aws:ProdAdmin"], jit.Hours{N: 1}, "already has it")
		if err == nil || !strings.Contains(err.Error(), "standing") {
			t.Errorf("err = %v, want standing-grant error", err)
		}
		return nil
	})
}

func TestCreateRequestValidation(t *testing.T) {
	st, ids := testkit.Tiny(t)
	tests := []struct {
		name     string
		identity string
		group    string
		hours    float64
		just     string
		wantErr  string
	}{
		{"unknown identity", "nobody", "aws:ProdAdmin", 1, "x", "unknown identity or group"},
		{"unknown group", "alice", "aws:Nope", 1, "x", "unknown identity or group"},
		{"terminated identity", "dave", "aws:ProdAdmin", 1, "x", "identity is not active"},
		{"zero hours", "alice", "aws:ProdAdmin", 0, "x", "duration must be between 0 and 72 hours"},
		{"too long", "alice", "aws:ProdAdmin", 72.5, "x", "duration must be between 0 and 72 hours"},
		{"blank justification", "alice", "aws:ProdAdmin", 1, "   ", "justification is required"},
		{"no receiving account", "helper-bot", "aws:ProdAdmin", 1, "x", "identity has no active account that can receive this grant"},
		{"maximum duration", "alice", "aws:ProdAdmin", 72, "x", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iid, gid := ids[tc.identity], ids["group:"+tc.group]
			if tc.identity == "nobody" {
				iid = 99999
			}
			if tc.group == "aws:Nope" {
				gid = 99999
			}
			_ = st.Write(t.Context(), func(c *store.Conn) error {
				_, err := jit.CreateRequest(c, testkit.Now, iid, gid, jit.Hours{N: tc.hours}, tc.just)
				if tc.wantErr == "" {
					if err != nil {
						t.Errorf("unexpected error %v", err)
					}
				} else if err == nil || err.Error() != tc.wantErr {
					t.Errorf("err = %v, want %q", err, tc.wantErr)
				}
				return errors.New("rollback")
			})
		})
	}
}

func TestDecisionStateMachine(t *testing.T) {
	st, ids := testkit.Tiny(t)
	now := testkit.Now
	newReq := func() int64 {
		var id int64
		testkit.Write(t, st, func(c *store.Conn) error {
			r, err := jit.CreateRequest(c, now, ids["alice"], ids["group:aws:ProdAdmin"], jit.Hours{N: 1}, "x")
			if r != nil {
				id = r.ID
			}
			return err
		})
		return id
	}
	try := func(fn func(*store.Conn) (*store.AccessRequest, error)) error {
		var out error
		testkit.Write(t, st, func(c *store.Conn) error {
			_, out = fn(c)
			return nil
		})
		return out
	}
	denied := newReq()
	if err := try(func(c *store.Conn) (*store.AccessRequest, error) { return jit.Deny(c, denied, "x", now) }); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		fn   func(*store.Conn) (*store.AccessRequest, error)
		want string
	}{
		{"approve denied", func(c *store.Conn) (*store.AccessRequest, error) { return jit.Approve(c, denied, "x", now, now) }, "request is not pending"},
		{"deny denied", func(c *store.Conn) (*store.AccessRequest, error) { return jit.Deny(c, denied, "x", now) }, "request is not pending"},
		{"revoke denied", func(c *store.Conn) (*store.AccessRequest, error) { return jit.Revoke(c, denied, "x", now) }, "request is not active"},
		{"approve unknown", func(c *store.Conn) (*store.AccessRequest, error) { return jit.Approve(c, 999, "x", now, now) }, "request is not pending"},
	}
	for _, tc := range tests {
		if err := try(tc.fn); err == nil || err.Error() != tc.want {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	active := newReq()
	if err := try(func(c *store.Conn) (*store.AccessRequest, error) { return jit.Approve(c, active, "x", now, now) }); err != nil {
		t.Fatal(err)
	}
	if err := try(func(c *store.Conn) (*store.AccessRequest, error) { return jit.Revoke(c, active, "x", now) }); err != nil {
		t.Fatal(err)
	}
	if present, _ := hasIAMStar(t, st, ids["alice"], now); present {
		t.Error("revoked grant still effective")
	}
}

func TestHoursJSON(t *testing.T) {
	if v, ok := (jit.Hours{N: 4, Whole: true}).JSON().(int64); !ok || v != 4 {
		t.Errorf("whole = %#v", (jit.Hours{N: 4, Whole: true}).JSON())
	}
	if _, ok := (jit.Hours{N: 4}).JSON().(int64); ok {
		t.Error("non-whole hours must render as a float")
	}
}
