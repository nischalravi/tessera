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

func hasIAMStar(t *testing.T, st *testkit.DB, iid int64, at time.Time) (present, jitOnly bool) {
	t.Helper()
	g := testkit.Get(t, st, func(c *store.TenantTx) (*graph.Snapshot, error) { return graph.Build(c, at) })
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
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := jit.CreateRequest(c, now, ids["alice"], ids["group:okta:eng"], jit.Hours{N: 2}, "not requestable", store.UserRef{})
		var je *jit.Error
		if !errors.As(err, &je) {
			t.Errorf("non-requestable group: err = %v, want *jit.Error", err)
		}
		req, err = jit.CreateRequest(c, now, ids["alice"], ids["group:aws:ProdAdmin"], jit.Hours{N: 2, Whole: true}, "  incident  ", store.UserRef{})
		return err
	})
	if req.Status != "pending" || req.Justification != "incident" || req.AccountID != ids["acct:okta:alice"] {
		t.Fatalf("request = %+v", req)
	}
	testkit.Write(t, st, func(c *store.TenantTx) error {
		r, err := jit.Approve(c, req.ID, store.UserRef{Display: "approver"}, now, now)
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
		testkit.Write(t, st, func(c *store.TenantTx) error {
			n, err := jit.Sweep(c, now.Add(tc.after))
			if n != tc.want {
				t.Errorf("sweep at +%v = %d, want %d", tc.after, n, tc.want)
			}
			return err
		})
	}
	got := testkit.Get(t, st, func(c *store.TenantTx) (*store.AccessRequest, error) { return c.Request(req.ID) })
	if got.Status != "expired" {
		t.Fatalf("status = %v", got)
	}
	if present, _ := hasIAMStar(t, st, ids["alice"], now.Add(3*time.Hour)); present {
		t.Error("expired grant still effective")
	}
	edges := testkit.Get(t, st, func(c *store.TenantTx) ([]*store.GrantEdge, error) { return c.Edges() })
	for _, e := range edges {
		if e.Source == "jit" {
			t.Errorf("jit edge left: %+v", e)
		}
	}
}

func TestJITRejectsStandingDuplicate(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		if _, err := c.InsertEdge(&store.GrantEdge{Src: graph.Key("account", ids["acct:okta:alice"]),
			Dst: graph.Key("group", ids["group:aws:ProdAdmin"]), Relation: "member_of", Source: "connector",
			CreatedAt: testkit.Now}); err != nil {
			return err
		}
		_, err := jit.CreateRequest(c, testkit.Now, ids["alice"], ids["group:aws:ProdAdmin"], jit.Hours{N: 1}, "already has it", store.UserRef{})
		if err == nil || !strings.Contains(err.Error(), "standing") {
			t.Errorf("err = %v, want standing-grant error", err)
		}
		return nil
	})
}

func TestJITRejectsDuplicatePending(t *testing.T) {
	st, ids := testkit.Tiny(t)
	now := testkit.Now
	create := func() (*store.AccessRequest, error) {
		var r *store.AccessRequest
		var err error
		testkit.Write(t, st, func(c *store.TenantTx) error {
			r, err = jit.CreateRequest(c, now, ids["alice"], ids["group:aws:ProdAdmin"], jit.Hours{N: 1}, "x", store.UserRef{})
			return nil
		})
		return r, err
	}
	first, err := create()
	if err != nil {
		t.Fatal(err)
	}
	_, err = create()
	var je *jit.Error
	if !errors.As(err, &je) || je.Kind != jit.KindConflict || je.Code != jit.CodeDuplicatePending {
		t.Fatalf("second request: err = %#v, want a duplicate_pending_request conflict", err)
	}
	// once the first is decided the identity may ask again
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := jit.Deny(c, first.ID, store.UserRef{Display: "x"}, now)
		return err
	})
	if _, err := create(); err != nil {
		t.Errorf("request after a denial: %v", err)
	}
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
		{"justification at the cap", "alice", "aws:ProdAdmin", 1, strings.Repeat("é", jit.MaxJustification), ""},
		{"justification over the cap", "alice", "aws:ProdAdmin", 1, strings.Repeat("é", jit.MaxJustification+1),
			"justification must be at most 1000 characters"},
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
			_ = st.InTenant(t.Context(), st.Tenant, func(c *store.TenantTx) error {
				_, err := jit.CreateRequest(c, testkit.Now, iid, gid, jit.Hours{N: tc.hours}, tc.just, store.UserRef{})
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
		testkit.Write(t, st, func(c *store.TenantTx) error {
			r, err := jit.CreateRequest(c, now, ids["alice"], ids["group:aws:ProdAdmin"], jit.Hours{N: 1}, "x", store.UserRef{})
			if r != nil {
				id = r.ID
			}
			return err
		})
		return id
	}
	try := func(fn func(*store.TenantTx) (*store.AccessRequest, error)) error {
		var out error
		testkit.Write(t, st, func(c *store.TenantTx) error {
			_, out = fn(c)
			return nil
		})
		return out
	}
	denied := newReq()
	if err := try(func(c *store.TenantTx) (*store.AccessRequest, error) {
		return jit.Deny(c, denied, store.UserRef{Display: "x"}, now)
	}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		fn   func(*store.TenantTx) (*store.AccessRequest, error)
		want string
	}{
		{"approve denied", func(c *store.TenantTx) (*store.AccessRequest, error) {
			return jit.Approve(c, denied, store.UserRef{Display: "x"}, now, now)
		}, "request is not pending"},
		{"deny denied", func(c *store.TenantTx) (*store.AccessRequest, error) {
			return jit.Deny(c, denied, store.UserRef{Display: "x"}, now)
		}, "request is not pending"},
		{"revoke denied", func(c *store.TenantTx) (*store.AccessRequest, error) {
			return jit.Revoke(c, denied, store.UserRef{Display: "x"}, now)
		}, "request is not active"},
		{"approve unknown", func(c *store.TenantTx) (*store.AccessRequest, error) {
			return jit.Approve(c, 999, store.UserRef{Display: "x"}, now, now)
		}, "request not found"},
		{"deny unknown", func(c *store.TenantTx) (*store.AccessRequest, error) {
			return jit.Deny(c, 999, store.UserRef{Display: "x"}, now)
		}, "request not found"},
		{"revoke unknown", func(c *store.TenantTx) (*store.AccessRequest, error) {
			return jit.Revoke(c, 999, store.UserRef{Display: "x"}, now)
		}, "request not found"},
	}
	for _, tc := range tests {
		err := try(tc.fn)
		if err == nil || err.Error() != tc.want {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
			continue
		}
		wantKind := jit.KindConflict
		if tc.want == "request not found" {
			wantKind = jit.KindNotFound
		}
		var je *jit.Error
		if !errors.As(err, &je) || je.Kind != wantKind {
			t.Errorf("%s: err = %#v, want kind %d", tc.name, err, wantKind)
		}
	}
	active := newReq()
	if err := try(func(c *store.TenantTx) (*store.AccessRequest, error) {
		return jit.Approve(c, active, store.UserRef{Display: "x"}, now, now)
	}); err != nil {
		t.Fatal(err)
	}
	if err := try(func(c *store.TenantTx) (*store.AccessRequest, error) {
		return jit.Revoke(c, active, store.UserRef{Display: "x"}, now)
	}); err != nil {
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
