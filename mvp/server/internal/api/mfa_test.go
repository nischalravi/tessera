package api

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMFAPostureReport(t *testing.T) {
	c := client{t, testServer(t, testkit.Demo(t))}
	r := c.json("GET", "/api/mfa/posture", "", 200)
	total := at(r, "summary", "totals", "total").(float64)
	if total < 10 {
		t.Fatalf("totals = %v, want the seeded people", at(r, "summary", "totals"))
	}
	idents := at(r, "identities").([]any)
	if float64(len(idents)) != total {
		t.Errorf("%d identities for a total of %v", len(idents), total)
	}
	// the classes add up to the total
	sum := 0.0
	for _, k := range []string{"phishing_resistant", "push_number_match", "push", "otp", "sms_voice", "no_mfa", "unknown"} {
		sum += at(r, "summary", "totals", k).(float64)
	}
	if sum != total {
		t.Errorf("classes sum to %v, total %v", sum, total)
	}
	if len(at(r, "summary", "by_department").([]any)) == 0 || len(at(r, "summary", "by_privileged_group").([]any)) == 0 {
		t.Error("no department or privileged-group rows")
	}
	if len(at(r, "trend").([]any)) < 30 {
		t.Errorf("trend has %d days", len(at(r, "trend").([]any)))
	}
	if len(at(r, "sources").([]any)) != 1 || at(r, "sources", 0, "system") != "okta" || at(r, "sources", 0, "status") != "ok" {
		t.Errorf("sources = %v", at(r, "sources"))
	}
	if len(at(r, "app_findings").([]any)) == 0 || len(at(r, "app_systems").([]any)) == 0 {
		t.Error("no app findings or systems seeded")
	}
	// weakest first: a person with no method is not listed after one with a passkey
	if at(idents[0], "best") == "phishing_resistant" {
		t.Errorf("first identity is the strongest: %v", idents[0])
	}

	// filters
	depts := at(r, "departments").([]any)
	dept := depts[0].(string)
	byDept := c.json("GET", "/api/mfa/posture?department="+url.QueryEscape(dept), "", 200)
	for _, i := range at(byDept, "identities").([]any) {
		if at(i, "department") != dept {
			t.Errorf("department filter leaked %v", at(i, "department"))
		}
	}
	if at(byDept, "summary", "totals", "total").(float64) >= total {
		t.Error("department filter did not narrow the totals")
	}
	priv := c.json("GET", "/api/mfa/posture?privileged=true", "", 200)
	for _, i := range at(priv, "identities").([]any) {
		if at(i, "privileged") != true {
			t.Errorf("privileged filter leaked %v", at(i, "name"))
		}
	}
	for _, f := range at(priv, "app_findings").([]any) {
		if at(f, "privileged") != true {
			t.Errorf("privileged filter leaked finding %v", f)
		}
	}
	if n := len(at(priv, "identities").([]any)); n == 0 || float64(n) >= total {
		t.Errorf("privileged identities = %d of %v", n, total)
	}
	// every department stays available for the chips when one is selected
	if len(at(byDept, "departments").([]any)) != len(depts) {
		t.Error("the department list shrank with the filter")
	}
	c.json("GET", "/api/mfa/posture?privileged=maybe", "", 422)
	c.json("GET", "/api/mfa/posture?department="+strings.Repeat("x", 201), "", 422)
}

// Tenant B's report holds none of tenant A's people, methods or sources.
func TestMFAPostureIsTenantScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.ReplaceAuthMethods("okta", []store.AuthMethod{{AccountID: tn.IDs["acct:okta:alice"], ExternalID: "k",
				Strength: "phishing_resistant", Kind: "passkey", Label: "key-" + tn.Slug, ObservedAt: storetest.Now}}); err != nil {
				return err
			}
			return c.PutAuthMethodSource(store.AuthMethodSource{System: "okta", Status: "ok", Detail: "d-" + tn.Slug, UpdatedAt: storetest.Now})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	get := func(tenant tenancy.ID) string {
		rec := serveOnce(isolationServer(t, f, tenant).Handler(), "GET", "/api/mfa/posture", "")
		if rec.Code != 200 {
			t.Fatalf("status %d: %.200s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	a, b := get(f.A.ID), get(f.B.ID)
	if !leaks(a) || !strings.Contains(a, "key-"+f.A.Slug) {
		t.Errorf("tenant A does not see its own data: %.300s", a)
	}
	if leaks(b) || strings.Contains(b, "key-"+f.A.Slug) || strings.Contains(b, "d-"+f.A.Slug) || !strings.Contains(b, "key-"+f.B.Slug) {
		t.Errorf("tenant B's report is wrong or leaks tenant A: %.300s", b)
	}
}
