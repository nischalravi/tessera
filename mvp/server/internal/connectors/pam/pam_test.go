package pam_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam/pamfake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const user, secret = "svc-tessera", "s3cret-value"

// seed gives every vendor the same logical safe in its own terms: alice may
// read (and approve requests, where the vendor has that), ops-team may use.
func seed(vendor string) pamfake.Safe {
	s := pamfake.Safe{ID: "7", Name: "Prod-DB",
		Accounts: []pamfake.Account{{ID: "11", Name: "oracle-sys", User: "sys", Address: "db1.example.com", Platform: "Oracle", Auto: true,
			Created: t0.Add(-100 * time.Hour), Rotated: t0.Add(-10 * time.Hour)}}}
	switch vendor {
	case "cyberark":
		s.Members = []pamfake.Member{
			{Name: "alice", Type: "User", Perms: []string{"listAccounts", "viewSafeMembers", "useAccounts", "retrieveAccounts", "accessWithoutConfirmation"}},
			{Name: "ops-team", Type: "Group", Perms: []string{"listAccounts", "viewSafeMembers", "useAccounts"}}}
	case "delinea":
		s.Members = []pamfake.Member{{Name: "alice", Type: "User", Folder: "View", Secret: "Edit"},
			{Name: "ops-team", Type: "Group", Folder: "List", Secret: "List"}}
	case "beyondtrust":
		s.Members = []pamfake.Member{{Name: "ops-team", Type: "Group", Roles: []string{"Requestor"}},
			{Name: "alice", Type: "Group", Roles: []string{"Requestor", "Approver"}}}
	}
	return s
}

type rig struct {
	fake *pamfake.Fake
	srv  *connsynctest.Server
	v    pam.Vault
}

func newRig(t *testing.T, vendor string) *rig {
	t.Helper()
	fk := pamfake.New(vendor, user, secret)
	fk.Users, fk.Groups = []string{"alice", "bob"}, []string{"ops-team", "alice", "bob"}
	fk.Set(seed(vendor))
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	v, err := pam.Open(pam.Config{Vendor: vendor, BaseURL: srv.URL, Username: user, Secret: connsync.NewSecret(secret)},
		connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return &rig{fake: fk, srv: srv, v: v}
}

func edges(res *connectors.DiscoveryResult, rel string) map[string]bool {
	out := map[string]bool{}
	for _, e := range res.Edges {
		if e.Relation == rel {
			out[e.Src.ExternalID+" -> "+e.Dst.ExternalID] = true
		}
	}
	return out
}

func TestDiscoverMapsEveryVendorToTheSameGraph(t *testing.T) {
	for _, vendor := range pam.Vendors {
		t.Run(vendor, func(t *testing.T) {
			r := newRig(t, vendor)
			res, err := pam.NewConnector(r.v).Discover(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Resources) != 1 || res.Resources[0].Kind != "vault_safe" || !strings.Contains(res.Resources[0].Name, "Prod-DB") {
				t.Fatalf("resources = %+v", res.Resources)
			}
			if len(res.Groups) != 4 {
				t.Fatalf("groups = %d, want one per profile", len(res.Groups))
			}
			for _, g := range res.Groups {
				want := strings.HasSuffix(g.ExternalID, "/read") || strings.HasSuffix(g.ExternalID, "/manage")
				if g.Kind != "vault_safe_access" || g.Privileged != want || !g.Requestable {
					t.Errorf("group %+v", g)
				}
			}
			member := edges(res, "member_of")
			switch vendor {
			case pam.CyberArk:
				if !member["member:alice -> 7/read"] || !member["member:ops-team -> 7/use"] {
					t.Errorf("member_of = %v", member)
				}
				if d := edges(res, "direct_grant"); !d["member:alice -> 7:access_without_confirmation"] || len(d) != 1 {
					t.Errorf("direct_grant = %v", d)
				}
			case pam.Delinea:
				// Edit is the read profile plus adding and changing accounts
				if !member["member:alice -> 7/read"] || !member["member:ops-team -> 7/list"] {
					t.Errorf("member_of = %v", member)
				}
				d := edges(res, "direct_grant")
				for _, p := range []string{"add_accounts", "update_account_properties", "update_account_content", "rename_accounts"} {
					if !d["member:alice -> 7:"+p] {
						t.Errorf("missing direct grant %s: %v", p, d)
					}
				}
			case pam.BeyondTrust:
				if !member["member:ops-team -> 7/use"] || !member["member:alice -> 7/use"] {
					t.Errorf("member_of = %v", member)
				}
				if d := edges(res, "direct_grant"); !d["member:alice -> 7:requests_authorization_level"] {
					t.Errorf("direct_grant = %v", d)
				}
			}
			grants := edges(res, "grants")
			if !grants["7/read -> 7:retrieve_accounts"] || grants["7/use -> 7:retrieve_accounts"] {
				t.Error("a profile grants the wrong permissions")
			}
			var kinds = map[string]string{}
			for _, a := range res.Accounts {
				kinds[a.ExternalID] = a.Kind
			}
			if kinds["vaulted:7:11"] != "vaulted" || kinds["member:ops-team"] == "" {
				t.Errorf("accounts = %v", kinds)
			}
			if vendor == pam.CyberArk && kinds["member:ops-team"] != "group" {
				t.Errorf("a group member is kind %q", kinds["member:ops-team"])
			}
			if len(res.Secrets) != 1 || res.Secrets[0].Account.ExternalID != "vaulted:7:11" {
				t.Fatalf("secrets = %+v", res.Secrets)
			}
			if vendor != pam.Delinea && (res.Secrets[0].LastRotatedAt == nil || !res.Secrets[0].LastRotatedAt.Equal(t0.Add(-10*time.Hour))) {
				t.Errorf("last rotated = %v", res.Secrets[0].LastRotatedAt)
			}
			// privileged permissions are flagged
			for _, p := range res.Permissions {
				if (p.Action == "retrieve_accounts" || p.Action == "manage_safe_members") != p.Privileged && (p.Action == "retrieve_accounts" || p.Action == "list_accounts") {
					t.Errorf("permission %+v", p)
				}
			}
		})
	}
}

func TestReadFaults(t *testing.T) {
	cases := []struct {
		name   string
		faults pamfake.Faults
		check  func(t *testing.T, err error)
	}{
		{"login refused", pamfake.Faults{LoginStatus: 401}, func(t *testing.T, err error) {
			if s := connsync.Status(err); s != 401 && s != 400 {
				t.Errorf("err = %v", err)
			}
		}},
		{"server error", pamfake.Faults{ReadStatus: 500}, func(t *testing.T, err error) {
			if connsync.Status(err) != 500 || strings.Contains(err.Error(), "leaky") {
				t.Errorf("err = %v", err)
			}
		}},
		{"not json", pamfake.Faults{Malformed: true}, func(t *testing.T, err error) {
			if !errors.Is(err, connsync.ErrMalformed) {
				t.Errorf("err = %v", err)
			}
		}},
		{"throttled, then served", pamfake.Faults{Throttle: 1}, func(t *testing.T, err error) {
			if err != nil {
				t.Errorf("err = %v", err)
			}
		}},
	}
	for _, vendor := range pam.Vendors {
		for _, tc := range cases {
			t.Run(vendor+"/"+tc.name, func(t *testing.T) {
				r := newRig(t, vendor)
				r.fake.SetFaults(tc.faults)
				_, err := pam.NewConnector(r.v).Discover(context.Background())
				if tc.name != "throttled, then served" && err == nil {
					t.Fatal("no error")
				}
				if err != nil && strings.Contains(err.Error(), secret) {
					t.Error("the error carries the secret")
				}
				tc.check(t, err)
			})
		}
	}
}

func TestWrongSecretIsRefused(t *testing.T) {
	for _, vendor := range pam.Vendors {
		r := newRig(t, vendor)
		hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
		v, err := pam.Open(pam.Config{Vendor: vendor, BaseURL: r.srv.URL, Username: user, Secret: connsync.NewSecret("wrong")}, connsynctest.Runtime, hc, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Safes(context.Background()); err == nil || strings.Contains(err.Error(), "wrong") {
			t.Errorf("%s: err = %v", vendor, err)
		}
	}
}

func TestOpenRefusesBadConfig(t *testing.T) {
	hc, _ := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	rt := connsync.Runtime{Env: "prod"}
	good := pam.Config{Vendor: pam.CyberArk, BaseURL: "https://pvwa.example.com", Username: "u", Secret: connsync.NewSecret("s")}
	for name, mut := range map[string]func(*pam.Config){
		"http":       func(c *pam.Config) { c.BaseURL = "http://pvwa.example.com" },
		"a path":     func(c *pam.Config) { c.BaseURL = "https://pvwa.example.com/x" },
		"no secret":  func(c *pam.Config) { c.Secret = connsync.Secret{} },
		"no user":    func(c *pam.Config) { c.Username = "" },
		"a vendor":   func(c *pam.Config) { c.Vendor = "lastpass" },
		"a bad root": func(c *pam.Config) { c.APIRoot = "/a/../b" },
	} {
		c := good
		mut(&c)
		if _, err := pam.Open(c, rt, hc, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := pam.Open(good, rt, hc, nil); err != nil {
		t.Error(err)
	}
}

func req(kind, member, group string) target.Request {
	return target.Request{Kind: kind, Key: "k", Account: target.Account{Username: member}, Group: target.Group{ExternalID: group}}
}

func TestTargetAddAndRemoveMembership(t *testing.T) {
	ctx := context.Background()
	for _, vendor := range pam.Vendors {
		t.Run(vendor, func(t *testing.T) {
			r := newRig(t, vendor)
			tg := &pam.Target{V: r.v}
			do := func(rq target.Request) {
				t.Helper()
				if err := tg.Apply(ctx, rq); err != nil {
					t.Fatalf("Apply %s %s: %v", rq.Kind, rq.Group.ExternalID, err)
				}
				if v, err := tg.Verify(ctx, rq); err != nil || !v.OK {
					t.Fatalf("Verify %s %s: %+v, %v", rq.Kind, rq.Group.ExternalID, v, err)
				}
			}
			// bob joins at the list profile; repeating it changes nothing
			do(req(target.AddEntitlement, "bob", "7/list"))
			_, _, w1 := r.fake.Counts()
			do(req(target.AddEntitlement, "bob", "7/list"))
			if _, _, w2 := r.fake.Counts(); w2 != w1 {
				t.Errorf("a repeated add wrote again (%d -> %d)", w1, w2)
			}
			// adding a lower profile than held is already true
			do(req(target.AddEntitlement, "alice", "7/list"))
			// bob is raised (Delinea has no "use")
			high := "use"
			if vendor == pam.Delinea {
				high = "read"
			}
			do(req(target.AddEntitlement, "bob", "7/"+high))
			ms, _ := r.v.Members(ctx, pam.Safe{ID: "7", Name: "Prod-DB"})
			for _, m := range ms {
				if m.Name == "bob" && pam.TopProfile(m.Perms) != high {
					t.Errorf("bob = %+v", m)
				}
			}
			// a lower profile than he holds cannot be removed by name; the one he holds can
			if err := tg.Apply(ctx, req(target.RemoveEntitlement, "bob", "7/list")); err == nil || target.Retryable(err) {
				t.Errorf("remove below the held profile: %v", err)
			}
			do(req(target.RemoveEntitlement, "bob", "7/"+high))
			if s, _ := r.fake.SafeState("7"); len(s.Members) != 2 {
				t.Errorf("members = %+v", s.Members)
			}
			// removing someone who is not a member converges
			do(req(target.RemoveEntitlement, "bob", "7/"+high))
			// a profile above what alice holds cannot be removed by name
			err := tg.Apply(ctx, req(target.RemoveEntitlement, "alice", "7/list"))
			if vendor == pam.BeyondTrust { // alice holds use there, which is above list
				if err == nil || target.Retryable(err) {
					t.Errorf("remove below the held profile: %v", err)
				}
			}
		})
	}
}

func TestTargetUnsupportedAndBadRequests(t *testing.T) {
	ctx := context.Background()
	check := func(vendor string, rq target.Request, wantPermanent bool) {
		t.Helper()
		r := newRig(t, vendor)
		err := (&pam.Target{V: r.v}).Apply(ctx, rq)
		if err == nil || target.Retryable(err) != !wantPermanent {
			t.Errorf("%s %s %s: err = %v", vendor, rq.Kind, rq.Group.ExternalID, err)
		}
	}
	check(pam.Delinea, req(target.AddEntitlement, "bob", "7/use"), true) // no role means use
	check(pam.BeyondTrust, req(target.AddEntitlement, "ops-team", "7/read"), true)
	check(pam.BeyondTrust, req(target.AddEntitlement, "nobody", "7/list"), true) // no such group
	check(pam.Delinea, req(target.AddEntitlement, "nobody", "7/list"), true)
	for _, v := range pam.Vendors {
		check(v, req(target.AddEntitlement, "bob", "9/list"), true)   // no such safe
		check(v, req(target.AddEntitlement, "bob", "nonsense"), true) // not a safe and profile
		check(v, req(target.DisableAccount, "bob", ""), true)         // accounts are not ours to manage
		check(v, req(target.CreateAccount, "bob", ""), true)
	}
}

func TestTargetWriteFaults(t *testing.T) {
	ctx := context.Background()
	for _, vendor := range pam.Vendors {
		t.Run(vendor, func(t *testing.T) {
			r := newRig(t, vendor)
			tg := &pam.Target{V: r.v}
			rq := req(target.AddEntitlement, "bob", "7/list")
			r.fake.SetFaults(pamfake.Faults{WriteStatus: 500})
			if err := tg.Apply(ctx, rq); err == nil || !target.Retryable(err) {
				t.Errorf("a 500 on write: %v", err)
			}
			r.fake.SetFaults(pamfake.Faults{WriteStatus: 403})
			if err := tg.Apply(ctx, rq); err == nil || target.Retryable(err) {
				t.Errorf("a 403 on write: %v", err)
			}
			// a vault that accepts and drops the write: Apply succeeds, Verify says it is not there
			r.fake.SetFaults(pamfake.Faults{DropWrites: true})
			if err := tg.Apply(ctx, rq); err != nil {
				t.Fatal(err)
			}
			if v, err := tg.Verify(ctx, rq); err != nil || v.OK || v.Observed != "not a member" {
				t.Errorf("Verify after a dropped write = %+v, %v", v, err)
			}
		})
	}
}

func TestSplitGroupID(t *testing.T) {
	for in, ok := range map[string]bool{"7/read": true, "a/b/manage": true, "7/root": false, "/list": false, "list": false, "": false} {
		if _, _, got := pam.SplitGroupID(in); got != ok {
			t.Errorf("SplitGroupID(%q) = %v", in, got)
		}
	}
	if s, p, _ := pam.SplitGroupID("a/b/manage"); s != "a/b" || p != "manage" {
		t.Errorf("got %q %q", s, p)
	}
}

func TestProfiles(t *testing.T) {
	if pam.TopProfile(nil) != "" || pam.TopProfile(pam.ProfilePerms("use")) != "use" || pam.TopProfile(pam.AllPerms) != "manage" {
		t.Error("TopProfile")
	}
	if b := pam.Beyond(append(pam.ProfilePerms("use"), pam.PermNoConfirmation)); len(b) != 1 || b[0] != pam.PermNoConfirmation {
		t.Errorf("Beyond = %v", b)
	}
	_ = http.StatusOK
}

func TestFromEnvReadsASecretReference(t *testing.T) {
	r := newRig(t, pam.CyberArk)
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	env := map[string]string{"TESSERA_CYBERARK_BASE_URL": r.srv.URL, "TESSERA_CYBERARK_USER": user, "TESSERA_CYBERARK_SECRET": "env:PAMSECRET", "PAMSECRET": secret}
	c, err := pam.FromEnv(pam.CyberArk, func(k string) string { return env[k] }, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Discover(context.Background()); err != nil || len(res.Resources) != 1 || c.System() != "cyberark" {
		t.Errorf("Discover = %v, %v", res, err)
	}
	env["TESSERA_CYBERARK_SECRET"] = secret // a literal is refused
	if _, err := pam.FromEnv(pam.CyberArk, func(k string) string { return env[k] }, connsynctest.Runtime, hc, nil); err == nil {
		t.Error("a literal secret was accepted")
	}
}
