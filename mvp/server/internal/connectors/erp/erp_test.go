package erp_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/erp"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/erp/erpfake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const id, secret = "tessera-client", "s3cret-value"

func world() ([]erpfake.Role, []erpfake.User) {
	roles := []erpfake.Role{
		{ID: "Z_AP_INVOICE", Name: "Accounts payable: enter invoices", TCodes: []string{"fb60", "FK01"},
			Auth: []erpfake.Auth{{Object: "F_BKPF_BUK", Fields: map[string][]string{"ACTVT": {"02", "01"}, "BUKRS": {"1000"}}}}},
		{ID: "Z_AP_PAY", Name: "Accounts payable: release payments", TCodes: []string{"F110", "FBZ0"}},
		{ID: "Z_BASIS", Name: "Basis administration", TCodes: []string{"SU01", "SM59"},
			Auth: []erpfake.Auth{{Object: "S_TABU_DIS", Fields: map[string][]string{"ACTVT": {"02"}, "DICBERCLS": {"SS"}}}}},
		{ID: "Z_AP_ALL", Name: "Accounts payable (composite)", Children: []string{"Z_AP_INVOICE", "Z_AP_PAY", "Z_MISSING"}},
		{ID: "Z_DISPLAY", Name: "Display only", TCodes: []string{"FB03"},
			Auth: []erpfake.Auth{{Object: "S_TABU_DIS", Fields: map[string][]string{"ACTVT": {"03"}}}}},
	}
	past, future := "2026-09-01", "2027-01-01"
	users := []erpfake.User{
		{ID: "AP.CLERK", Name: "Ada Clerk", Email: "Ada.Clerk@corp.example", Roles: []erpfake.Assign{{Role: "Z_AP_INVOICE"}}},
		{ID: "AP.BOSS", Name: "Bo Boss", Email: "bo@corp.example", Roles: []erpfake.Assign{{Role: "Z_AP_ALL"}, {Role: "Z_DISPLAY", To: future}}},
		{ID: "TEMP", Name: "Tem Porary", Locked: true, Roles: []erpfake.Assign{{Role: "Z_BASIS"}}},
		{ID: "EXPIRED", Name: "Ex Pired", Email: "ex@corp.example", ValidTo: past, Roles: []erpfake.Assign{{Role: "Z_DISPLAY", To: past}, {Role: "Z_AP_PAY", From: future}}},
	}
	return roles, users
}

type rig struct {
	fake *erpfake.Fake
	srv  *connsynctest.Server
	sys  erp.System
}

func newRig(t *testing.T, system string) *rig {
	t.Helper()
	fk := erpfake.New(system, id, secret)
	r, u := world()
	fk.Set(r, u)
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	s, err := erp.Open(erp.Config{System: system, BaseURL: srv.URL, ClientID: id, ClientSecret: connsync.NewSecret(secret)},
		connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return &rig{fk, srv, s}
}

func edgeSet(res *connectors.DiscoveryResult, rel string) map[string]bool {
	out := map[string]bool{}
	for _, e := range res.Edges {
		if e.Relation == rel {
			out[e.Src.ExternalID+" -> "+e.Dst.ExternalID] = true
		}
	}
	return out
}

func TestDiscoverGivesTheSameGraphForBothSystems(t *testing.T) {
	for _, system := range erp.Systems {
		t.Run(system, func(t *testing.T) {
			r := newRig(t, system)
			res, err := erp.NewConnector(r.sys, func() time.Time { return t0 }).Discover(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Groups) != 5 || len(res.Resources) != 2 {
				t.Fatalf("groups %d, resources %d", len(res.Groups), len(res.Resources))
			}
			priv := map[string]bool{}
			for _, g := range res.Groups {
				priv[g.ExternalID] = g.Privileged
				if g.Kind != "erp_role" || !g.Requestable {
					t.Errorf("group %+v", g)
				}
			}
			if !priv["Z_BASIS"] || priv["Z_AP_INVOICE"] || priv["Z_DISPLAY"] || priv["Z_AP_ALL"] {
				t.Errorf("privileged roles = %v (only the one holding SU01, SM59 and a change on S_TABU_DIS is)", priv)
			}
			// Oracle's data-security policy has an object, a condition and actions: no other fields
			bkpf, tabu := "F_BKPF_BUK[ACTVT=01,02;BUKRS=1000]", "S_TABU_DIS[ACTVT=02;DICBERCLS=SS]"
			if system == erp.Oracle {
				bkpf, tabu = "F_BKPF_BUK[ACTVT=01,02]", "S_TABU_DIS[ACTVT=02]"
			}
			actions := map[string]bool{}
			privPerm := map[string]bool{}
			for _, p := range res.Permissions {
				actions[p.Action] = true
				privPerm[p.Action] = p.Privileged
			}
			for _, want := range []string{"FB60", "FK01", "F110", "SU01", bkpf} {
				if !actions[want] {
					t.Errorf("no permission %q in %v", want, actions)
				}
			}
			if !privPerm["SU01"] || privPerm["FB60"] || !privPerm[tabu] || privPerm["S_TABU_DIS[ACTVT=03]"] {
				t.Errorf("privileged permissions = %v", privPerm)
			}
			grants := edgeSet(res, "grants")
			if !grants["Z_AP_INVOICE -> tcode:FB60"] || !grants["Z_AP_INVOICE -> auth:"+bkpf] || grants["Z_AP_PAY -> tcode:FB60"] {
				t.Errorf("grants = %v", grants)
			}
			member := edgeSet(res, "member_of")
			// the composite includes its children (the missing one is skipped); users hold only what is active now
			for _, want := range []string{"Z_AP_ALL -> Z_AP_INVOICE", "Z_AP_ALL -> Z_AP_PAY", "AP.CLERK -> Z_AP_INVOICE", "AP.BOSS -> Z_AP_ALL", "AP.BOSS -> Z_DISPLAY", "TEMP -> Z_BASIS"} {
				if !member[want] {
					t.Errorf("missing member_of %q in %v", want, member)
				}
			}
			if member["Z_AP_ALL -> Z_MISSING"] || member["EXPIRED -> Z_DISPLAY"] || member["EXPIRED -> Z_AP_PAY"] {
				t.Errorf("member_of = %v", member)
			}
			status := map[string]string{}
			for _, a := range res.Accounts {
				status[a.ExternalID] = a.Status
				if a.ExternalID == "AP.CLERK" && (a.Identity == nil || a.Identity.Email != "ada.clerk@corp.example") {
					t.Errorf("account identity = %+v", a.Identity)
				}
			}
			if system == erp.SAP && status["EXPIRED"] != "disabled" || status["TEMP"] != "disabled" || status["AP.CLERK"] != "active" {
				t.Errorf("status = %v", status)
			}
		})
	}
}

func TestPagingReadsEveryPage(t *testing.T) {
	for _, system := range erp.Systems {
		r := newRig(t, system)
		var roles []erpfake.Role
		var users []erpfake.User
		for i := 0; i < 230; i++ {
			roles = append(roles, erpfake.Role{ID: fmt.Sprintf("R%03d", i), TCodes: []string{"FB03"}})
			users = append(users, erpfake.User{ID: fmt.Sprintf("U%03d", i), Roles: []erpfake.Assign{{Role: fmt.Sprintf("R%03d", i)}}})
		}
		r.fake.Set(roles, users)
		res, err := erp.NewConnector(r.sys, func() time.Time { return t0 }).Discover(context.Background())
		if err != nil || len(res.Groups) != 230 || len(res.Accounts) != 230 {
			t.Fatalf("%s: groups %d, accounts %d, err %v", system, len(res.Groups), len(res.Accounts), err)
		}
	}
}

func TestReadFaults(t *testing.T) {
	cases := map[string]struct {
		f     erpfake.Faults
		check func(error) bool
	}{
		"token refused": {erpfake.Faults{TokenStatus: 401}, func(e error) bool { return connsync.Status(e) == 401 }},
		"server error":  {erpfake.Faults{ReadStatus: 500}, func(e error) bool { return connsync.Status(e) == 500 && !strings.Contains(e.Error(), "leaky") }},
		"not json":      {erpfake.Faults{Malformed: true}, func(e error) bool { return errors.Is(e, connsync.ErrMalformed) }},
	}
	for _, system := range erp.Systems {
		for name, tc := range cases {
			t.Run(system+"/"+name, func(t *testing.T) {
				r := newRig(t, system)
				r.fake.SetFaults(tc.f)
				_, err := erp.NewConnector(r.sys, nil).Discover(context.Background())
				if err == nil || !tc.check(err) || strings.Contains(err.Error(), secret) {
					t.Errorf("err = %v", err)
				}
			})
		}
		t.Run(system+"/throttled", func(t *testing.T) {
			r := newRig(t, system)
			r.fake.SetFaults(erpfake.Faults{Throttle: 1})
			if _, err := erp.NewConnector(r.sys, nil).Discover(context.Background()); err != nil {
				t.Error(err)
			}
		})
		t.Run(system+"/wrong secret", func(t *testing.T) {
			r := newRig(t, system)
			hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
			s, _ := erp.Open(erp.Config{System: system, BaseURL: r.srv.URL, ClientID: id, ClientSecret: connsync.NewSecret("wrong")}, connsynctest.Runtime, hc, nil)
			if _, err := s.Roles(context.Background()); err == nil || strings.Contains(err.Error(), "wrong") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestOpenRefusesBadConfig(t *testing.T) {
	hc, _ := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	rt := connsync.Runtime{Env: "prod"}
	good := erp.Config{System: erp.SAP, BaseURL: "https://s4.example.com", ClientID: "c", ClientSecret: connsync.NewSecret("s")}
	for name, mut := range map[string]func(*erp.Config){
		"http": func(c *erp.Config) { c.BaseURL = "http://s4.example.com" }, "a path": func(c *erp.Config) { c.BaseURL = "https://s4.example.com/x" },
		"no secret": func(c *erp.Config) { c.ClientSecret = connsync.Secret{} }, "no client": func(c *erp.Config) { c.ClientID = "" },
		"a system": func(c *erp.Config) { c.System = "peoplesoft" }, "a bad root": func(c *erp.Config) { c.APIRoot = "/a/../b" },
		"a bad token path": func(c *erp.Config) { c.TokenPath = "oauth" },
	} {
		c := good
		mut(&c)
		if _, err := erp.Open(c, rt, hc, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := erp.Open(good, rt, hc, nil); err != nil {
		t.Error(err)
	}
}

func TestFromEnv(t *testing.T) {
	r := newRig(t, erp.Oracle)
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	env := map[string]string{"TESSERA_ORACLE_BASE_URL": r.srv.URL, "TESSERA_ORACLE_CLIENT_ID": id, "TESSERA_ORACLE_CLIENT_SECRET": "env:ERPSECRET", "ERPSECRET": secret}
	c, err := erp.FromEnv(erp.Oracle, func(k string) string { return env[k] }, connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Discover(context.Background()); err != nil || len(res.Groups) != 5 || c.System() != "oracle" {
		t.Errorf("Discover = %v, %v", res, err)
	}
	env["TESSERA_ORACLE_CLIENT_SECRET"] = secret
	if _, err := erp.FromEnv(erp.Oracle, func(k string) string { return env[k] }, connsynctest.Runtime, hc, nil); err == nil {
		t.Error("a literal secret was accepted")
	}
}

func req(kind, user, role string) target.Request {
	return target.Request{Kind: kind, Key: "k", Account: target.Account{Username: user}, Group: target.Group{ExternalID: role}}
}

func TestTargetAssignsAndRemovesRoles(t *testing.T) {
	ctx := context.Background()
	for _, system := range erp.Systems {
		t.Run(system, func(t *testing.T) {
			r := newRig(t, system)
			tg := &erp.Target{S: r.sys}
			do := func(rq target.Request) {
				t.Helper()
				if err := tg.Apply(ctx, rq); err != nil {
					t.Fatalf("Apply: %v", err)
				}
				if v, err := tg.Verify(ctx, rq); err != nil || !v.OK {
					t.Fatalf("Verify: %+v, %v", v, err)
				}
			}
			do(req(target.AddEntitlement, "AP.CLERK", "Z_AP_PAY"))
			if got := strings.Join(r.fake.UserRoles("AP.CLERK"), ","); got != "Z_AP_INVOICE,Z_AP_PAY" {
				t.Errorf("roles = %s", got)
			}
			_, _, w := r.fake.Counts()
			do(req(target.AddEntitlement, "AP.CLERK", "Z_AP_PAY"))
			if _, _, w2 := r.fake.Counts(); w2 != w {
				t.Error("a repeated add wrote again")
			}
			do(req(target.RemoveEntitlement, "AP.CLERK", "Z_AP_PAY"))
			do(req(target.RemoveEntitlement, "AP.CLERK", "Z_AP_PAY")) // converges
			do(req(target.RemoveEntitlement, "NOBODY", "Z_AP_PAY"))   // no such user: already gone
			permanent := []target.Request{req(target.AddEntitlement, "NOBODY", "Z_AP_PAY"), req(target.AddEntitlement, "AP.CLERK", "Z_NO_SUCH_ROLE"),
				req(target.DisableAccount, "AP.CLERK", ""), req(target.CreateAccount, "AP.CLERK", ""), req(target.AddEntitlement, "AP.CLERK", "")}
			for _, rq := range permanent {
				if err := tg.Apply(ctx, rq); err == nil || target.Retryable(err) {
					t.Errorf("%s %s %s: err = %v", rq.Kind, rq.Account.Username, rq.Group.ExternalID, err)
				}
			}
			r.fake.SetFaults(erpfake.Faults{WriteStatus: 500})
			if err := tg.Apply(ctx, req(target.AddEntitlement, "AP.CLERK", "Z_AP_PAY")); err == nil || !target.Retryable(err) {
				t.Errorf("a 500: %v", err)
			}
			r.fake.SetFaults(erpfake.Faults{WriteStatus: 403})
			if err := tg.Apply(ctx, req(target.AddEntitlement, "AP.CLERK", "Z_AP_PAY")); err == nil || target.Retryable(err) {
				t.Errorf("a 403: %v", err)
			}
			r.fake.SetFaults(erpfake.Faults{DropWrites: true})
			rq := req(target.AddEntitlement, "AP.CLERK", "Z_AP_PAY")
			if err := tg.Apply(ctx, rq); err != nil {
				t.Fatal(err)
			}
			if v, err := tg.Verify(ctx, rq); err != nil || v.OK {
				t.Errorf("a dropped write verified: %+v, %v", v, err)
			}
		})
	}
}
