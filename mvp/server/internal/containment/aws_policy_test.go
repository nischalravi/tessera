package containment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The Deny policy tests (review of PR #222): what counts as a deny-all, the
// attachment check, and concurrent edits of the one shared document.

const denyAll = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"identitystore:userId":["Add user ID here"]}}}]}`

func stmt(s string) string { return `{"Version":"2012-10-17","Statement":[` + s + `]}` }

func TestDenyAllStatement(t *testing.T) {
	const cond = `"Condition":{"StringEquals":{"identitystore:userId":["Add user ID here"]}}`
	cases := []struct {
		name, policy string
		wantErr      error // nil: accepted
	}{
		{"deny-all, action list", stmt(`{"Effect":"Deny","Action":["*"],"Resource":"*",` + cond + `}`), nil},
		{"deny-all, action string", denyAll, nil},
		{"deny-all, resource list", stmt(`{"Effect":"Deny","Action":"*","Resource":["*"],` + cond + `}`), nil},
		{"deny-all, no resource, with a Sid", stmt(`{"Sid":"RevokeUser","Effect":"Deny","Action":"*",` + cond + `}`), nil},
		{"single-object statement", `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*",` + cond + `}}`, nil},
		{"restricted action", stmt(`{"Effect":"Deny","Action":["s3:GetObject"],"Resource":"*",` + cond + `}`), errNotDenyAll},
		{"two actions including *", stmt(`{"Effect":"Deny","Action":["*","s3:*"],"Resource":"*",` + cond + `}`), errNotDenyAll},
		{"no action", stmt(`{"Effect":"Deny","Resource":"*",` + cond + `}`), errNotDenyAll},
		{"restricted resource", stmt(`{"Effect":"Deny","Action":"*","Resource":"arn:aws:s3:::bucket/*",` + cond + `}`), errNotDenyAll},
		{"extra condition operator", stmt(`{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"identitystore:userId":["x"]},` +
			`"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}}`), errNotDenyAll},
		{"extra condition key", stmt(`{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"identitystore:userId":["x"],` +
			`"aws:PrincipalTag/team":["a"]}}}`), errNotDenyAll},
		{"user id under StringLike", stmt(`{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringLike":{"identitystore:userId":["x"]}}}`), errNotDenyAll},
		{"NotAction", stmt(`{"Effect":"Deny","NotAction":["iam:*"],"Resource":"*",` + cond + `}`), errNotDenyAll},
		{"NotAction next to Action", stmt(`{"Effect":"Deny","Action":"*","NotAction":["iam:*"],"Resource":"*",` + cond + `}`), errNotDenyAll},
		{"NotResource", stmt(`{"Effect":"Deny","Action":"*","NotResource":"arn:aws:s3:::x",` + cond + `}`), errNotDenyAll},
		{"two statements name the key", stmt(`{"Effect":"Deny","Action":"*","Resource":"*",` + cond + `},{"Effect":"Deny","Action":"*","Resource":"*",` + cond + `}`), errNotDenyAll},
		{"a narrow statement next to the deny-all", stmt(`{"Effect":"Deny","Action":"s3:*","Resource":"*",` + cond + `},{"Effect":"Deny","Action":"*","Resource":"*",` + cond + `}`), errNotDenyAll},
		{"no statement names the key", stmt(`{"Effect":"Deny","Action":"*","Resource":"*"}`), errNoDenyStatement},
		{"an Allow names the key", stmt(`{"Effect":"Allow","Action":"*","Resource":"*",` + cond + `}`), errNoDenyStatement},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, aerr := addUserToPolicy(tc.policy, "u-1")
			_, perr := policyHasUser(tc.policy, "u-1")
			for _, err := range []error{aerr, perr} {
				if !errors.Is(err, tc.wantErr) && !(tc.wantErr == nil && err == nil) {
					t.Errorf("err = %v, want %v", err, tc.wantErr)
				}
			}
		})
	}
}

// policyAWS is a stateful fake of the Organizations calls of the Deny policy
// (no compare-and-set, like a writer that does not pass a version): UpdatePolicy
// replaces the content, so two read-modify-writes lose an entry.
type policyAWS struct {
	srv *httptest.Server

	mu       sync.Mutex
	content  string
	targets  int
	calls    []string
	updates  int
	describe int
	// barrier: the first n DescribePolicy calls wait (up to barrierWait) until n have arrived
	barrier     int
	barrierWait time.Duration
	arrived     chan struct{}
	// afterUpdate runs under the lock after every UpdatePolicy (n is its number from 1)
	afterUpdate func(a *policyAWS, n int)
}

func newPolicyAWS(t *testing.T, content string, targets int) *policyAWS {
	t.Helper()
	a := &policyAWS{content: content, targets: targets, arrived: make(chan struct{})}
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *policyAWS) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	target := r.Header.Get("X-Amz-Target")
	op := target[strings.Index(target, ".")+1:]
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	a.mu.Lock()
	a.calls = append(a.calls, op)
	switch op {
	case "DescribeUser":
		a.mu.Unlock()
		reply(map[string]any{"UserId": in["UserId"], "UserName": "u"})
	case "ListTargetsForPolicy":
		ts := make([]map[string]string, a.targets)
		for i := range ts {
			ts[i] = map[string]string{"TargetId": "r-ab12", "Type": "ROOT"}
		}
		a.mu.Unlock()
		reply(map[string]any{"Targets": ts})
	case "DescribePolicy":
		a.describe++
		n, wait, content := a.describe, a.barrierWait, a.content
		hold := n <= a.barrier
		a.mu.Unlock()
		if hold {
			// the read is taken first, then it waits for the other worker's read
			if n == a.barrier {
				close(a.arrived)
			}
			select {
			case <-a.arrived:
			case <-time.After(wait):
			}
		}
		reply(map[string]any{"Policy": map[string]any{"Content": content}})
	case "UpdatePolicy":
		a.updates++
		a.content, _ = in["Content"].(string)
		if a.afterUpdate != nil {
			a.afterUpdate(a, a.updates)
		}
		a.mu.Unlock()
		reply(map[string]any{})
	case "ListAccountAssignmentsForPrincipal":
		a.mu.Unlock()
		reply(map[string]any{"AccountAssignments": []any{}})
	default:
		a.mu.Unlock()
		w.WriteHeader(400)
		reply(map[string]any{"__type": "UnknownOperationException"})
	}
}

func (a *policyAWS) Content() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.content
}

func (a *policyAWS) Count(op string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, c := range a.calls {
		if c == op {
			n++
		}
	}
	return n
}

func (a *policyAWS) users(t *testing.T) []string {
	t.Helper()
	u, err := policyUsers(a.Content())
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func awsItem(t *testing.T, a *policyAWS, userID string) Item {
	t.Helper()
	return Item{Action: ActionRevokeSessions, AccountID: 1, Connection: "conn-aws",
		Target: Target{System: AWSIdentityCenter, UserID: userID, Username: userID + "@x.example"},
		cred:   &Credential{BaseURL: a.srv.URL, Token: awsCredJSON(t, nil)}}
}

func runPolicy(t *testing.T, svc *Service, a *policyAWS, userID string) StepResult {
	t.Helper()
	rep := svc.Run(context.Background(), &Job{IdentityID: 7, Identity: "Alice", Trigger: "ssf", Items: []Item{awsItem(t, a, userID)}})
	if len(rep.Steps) != 1 {
		t.Fatalf("steps = %d", len(rep.Steps))
	}
	return rep.Steps[0]
}

func TestAWSDenyPolicyChecks(t *testing.T) {
	for _, tc := range []struct {
		name, policy string
		targets      int
		outcome      string
		detail       string
		updates      int
	}{
		{"deny-all, attached", denyAll, 1, OutcomeDone, "", 1},
		{"unattached policy is never verified", denyAll, 0, OutcomeFailed, "not attached to any target", 0},
		{"restricted action", stmt(`{"Effect":"Deny","Action":["s3:*"],"Resource":"*","Condition":{"StringEquals":{"identitystore:userId":["x"]}}}`),
			1, OutcomeFailed, "not a dedicated deny-all", 0},
		{"restricted resource", stmt(`{"Effect":"Deny","Action":"*","Resource":"arn:aws:s3:::b","Condition":{"StringEquals":{"identitystore:userId":["x"]}}}`),
			1, OutcomeFailed, "not a dedicated deny-all", 0},
		{"extra condition", stmt(`{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"identitystore:userId":["x"]},"Bool":{"aws:SecureTransport":"false"}}}`),
			1, OutcomeFailed, "not a dedicated deny-all", 0},
		{"NotAction", stmt(`{"Effect":"Deny","NotAction":"iam:*","Resource":"*","Condition":{"StringEquals":{"identitystore:userId":["x"]}}}`),
			1, OutcomeFailed, "not a dedicated deny-all", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := testService(t)
			a := newPolicyAWS(t, tc.policy, tc.targets)
			st := runPolicy(t, svc, a, awsUser)
			if st.Outcome != tc.outcome || !strings.Contains(st.Detail, tc.detail) || (tc.outcome == OutcomeDone) != st.Verified {
				t.Fatalf("step %+v", st)
			}
			if a.Count("UpdatePolicy") != tc.updates {
				t.Errorf("%d policy updates, want %d", a.Count("UpdatePolicy"), tc.updates)
			}
		})
	}
}

// Verify alone also refuses an unattached policy, and a policy that names the
// user in a statement that is not a deny-all.
func TestAWSVerifyRefusesWeakPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, policy string
		targets      int
		want         string
	}{
		{"unattached", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"identitystore:userId":["` + awsUser + `"]}}}]}`,
			0, "not attached"},
		{"narrow", `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"identitystore:userId":["` + awsUser + `"]}}}]}`,
			1, "not a dedicated deny-all"},
	} {
		svc, _ := testService(t)
		a := newPolicyAWS(t, tc.policy, tc.targets)
		rv, err := svc.revoker(tenancy.ID{}, AWSIdentityCenter, Credential{BaseURL: a.srv.URL, Token: awsCredJSON(t, nil)})
		if err != nil {
			t.Fatal(err)
		}
		rem, err := rv.Verify(context.Background(), Target{System: AWSIdentityCenter, UserID: awsUser}, t0, CheckSessions)
		if err == nil || !strings.Contains(err.Error(), tc.want) || rem.Sessions != 0 {
			t.Errorf("%s: Verify = %+v, %v; want error %q", tc.name, rem, err, tc.want)
		}
	}
}

// An external writer overwrites the policy right after Tessera's update: the
// read-back finds the entry missing and adds it again.
func TestAWSDenyReaddsLostEntry(t *testing.T) {
	svc, _ := testService(t)
	a := newPolicyAWS(t, denyAll, 1)
	a.afterUpdate = func(a *policyAWS, n int) {
		if n == 1 {
			a.content = denyAll // a stale copy written by someone else
		}
	}
	st := runPolicy(t, svc, a, awsUser)
	if st.Outcome != OutcomeDone || !st.Verified || !slices.Contains(a.users(t), awsUser) || a.Count("UpdatePolicy") != 2 {
		t.Fatalf("step %+v, users %v, %d updates", st, a.users(t), a.Count("UpdatePolicy"))
	}
}

// An entry that stays missing after every retry fails the step: never verified.
func TestAWSDenyFailsWhenEntryStaysMissing(t *testing.T) {
	svc, _ := testService(t)
	a := newPolicyAWS(t, denyAll, 1)
	a.afterUpdate = func(a *policyAWS, _ int) { a.content = denyAll }
	st := runPolicy(t, svc, a, awsUser)
	if st.Outcome != OutcomeFailed || st.Verified || !strings.Contains(st.Detail, "missing from the policy") {
		t.Fatalf("step %+v", st)
	}
	if a.Count("UpdatePolicy") != maxAttempts {
		t.Errorf("%d updates, want %d attempts", a.Count("UpdatePolicy"), maxAttempts)
	}
}

// Two workers want to read the policy before either writes (the fake holds the
// first two DescribePolicy reads until both have arrived, or for 400ms), and
// every UpdatePolicy succeeds without a version check. The lease makes the
// second worker wait for the first, so both deny entries survive. (Without it
// the second write would replace the first.)
func TestAWSConcurrentDenyKeepsBothEntries(t *testing.T) {
	const alice, bob = "c2a7e8f4-1031-70b2-9a64-0b5d8f6e3a11", "d3b8f9a5-2142-81c3-ab75-1c6e9a7f4b22"
	f := storetest.TwoTenants(t)
	svc, _ := testService(t)
	svc.DB = f.DB
	a := newPolicyAWS(t, denyAll, 1)
	a.barrier, a.barrierWait = 2, 400*time.Millisecond
	var wg sync.WaitGroup
	steps := make([]StepResult, 2)
	for i, u := range []string{alice, bob} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			it := awsItem(t, a, u)
			it.tenant = f.A.ID
			rep := svc.Run(context.Background(), &Job{IdentityID: 7, Identity: u, Trigger: "ssf", Items: []Item{it}})
			steps[i] = rep.Steps[0]
		}()
	}
	wg.Wait()
	for i, st := range steps {
		if st.Outcome != OutcomeDone || !st.Verified {
			t.Errorf("worker %d: %+v", i, st)
		}
	}
	got := a.users(t)
	if !slices.Contains(got, alice) || !slices.Contains(got, bob) || !slices.Contains(got, "Add user ID here") {
		t.Fatalf("policy users %v: an entry was lost", got)
	}
	if a.Count("UpdatePolicy") != 2 {
		t.Errorf("each worker writes once, got %d updates", a.Count("UpdatePolicy"))
	}
}

// The ledger merges every entry Tessera holds: a user a worker marked pending
// (its write lost, or not yet done) is put into the policy by the next worker.
func TestAWSDenyMergesHeldEntries(t *testing.T) {
	f := storetest.TwoTenants(t)
	svc, _ := testService(t)
	svc.DB = f.DB
	a := newPolicyAWS(t, denyAll, 1)
	const held = "e4c9a0b6-3253-92d4-bc86-2d7fa8b05c33"
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if err := c.MarkPolicyDenial("p-0a1b2c3d4e", held, store.DenialPending, t0); err != nil {
			return err
		}
		// an entry past the hold is forgotten
		return c.MarkPolicyDenial("p-0a1b2c3d4e", "stale-user", store.DenialActive, t0.Add(-denyHold-time.Minute))
	}); err != nil {
		t.Fatal(err)
	}
	it := awsItem(t, a, awsUser)
	it.tenant = f.A.ID
	rep := svc.Run(context.Background(), &Job{IdentityID: 7, Identity: "Alice", Trigger: "ssf", Items: []Item{it}})
	if rep.Steps[0].Outcome != OutcomeDone {
		t.Fatalf("step %+v", rep.Steps[0])
	}
	got := a.users(t)
	if !slices.Contains(got, held) || !slices.Contains(got, awsUser) || slices.Contains(got, "stale-user") {
		t.Errorf("policy users %v", got)
	}
	// the lease is released
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		ok, err := c.AcquirePolicyLease("p-0a1b2c3d4e", "someone-else", time.Now(), time.Now().Add(time.Minute))
		if err == nil && !ok {
			t.Error("the lease was not released")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// A lease another worker holds makes the step wait and then fail, not edit the policy.
func TestAWSDenyBusyLease(t *testing.T) {
	f := storetest.TwoTenants(t)
	svc, _ := testService(t)
	svc.DB = f.DB
	a := newPolicyAWS(t, denyAll, 1)
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		_, err := c.AcquirePolicyLease("p-0a1b2c3d4e", "other-worker", time.Now(), time.Now().Add(time.Minute))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	it := awsItem(t, a, awsUser)
	it.tenant = f.A.ID
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	rep := svc.Run(ctx, &Job{IdentityID: 7, Identity: "Alice", Trigger: "ssf", Items: []Item{it}})
	if st := rep.Steps[0]; st.Outcome != OutcomeFailed || st.Verified || a.Count("UpdatePolicy") != 0 {
		t.Fatalf("step %+v, %d updates", st, a.Count("UpdatePolicy"))
	}
}
