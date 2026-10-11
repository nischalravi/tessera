package casclient_test

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/casclient"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const service = "http://127.0.0.1:5999/api/auth/cas/c1/callback?state=st-1"

type env struct {
	idp *devidptest.IdP
	cl  *casclient.Client
	b   *devidptest.Browser
}

func setup(t *testing.T) *env {
	t.Helper()
	idp := devidptest.Start(t, devidp.Config{})
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	cl, err := casclient.New(hc)
	if err != nil {
		t.Fatal(err)
	}
	return &env{idp: idp, cl: cl, b: idp.NewBrowser(t)}
}

// ticket signs in at /cas/login (renew, fault) and returns the ticket.
func (e *env) ticket(t *testing.T, sub string, m devidp.Method, renew bool, fault devidp.Fault) string {
	t.Helper()
	u, err := casclient.LoginURL(e.idp.CASServerURL(), service, renew)
	if err != nil {
		t.Fatal(err)
	}
	if fault != devidp.FaultNone {
		u += "&fault=" + string(fault)
	}
	cb := e.b.Authorize(t, u, sub, m, "")
	q, _ := url.ParseQuery(cb.RawQuery)
	if q.Get("state") != "st-1" || !strings.HasPrefix(q.Get("ticket"), "ST-") {
		t.Fatalf("redirect %s", cb)
	}
	return q.Get("ticket")
}

func TestLoginAndValidate(t *testing.T) {
	e := setup(t)
	start := time.Now().UTC().Add(-time.Second)
	tk := e.ticket(t, "00u-ivan-admin2", devidp.MethodHardwareKey, false, devidp.FaultNone)
	got, err := e.cl.Validate(context.Background(), e.idp.CASServerURL(), service, tk, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.User != "00u-ivan-admin2" || got.Attributes["email"][0] != "ivan.admin@larkspur.example" ||
		!slices.Contains(got.Attributes["amr"], "hwk") || got.NewLogin == nil || !*got.NewLogin ||
		got.AuthenticationDate.Before(start) || len(got.Raw) == 0 {
		t.Errorf("ticket %+v", got)
	}
	// single use, bound to the service
	if _, err := e.cl.Validate(context.Background(), e.idp.CASServerURL(), service, tk, false); casclient.ReasonOf(err) != casclient.ReasonFailure {
		t.Errorf("reused ticket: %v", err)
	}
	tk = e.ticket(t, "00u-ivan-admin2", devidp.MethodHardwareKey, false, devidp.FaultNone) // single sign-on
	if _, err := e.cl.Validate(context.Background(), e.idp.CASServerURL(), service+"x", tk, false); casclient.ReasonOf(err) != casclient.ReasonFailure {
		t.Errorf("another service: %v", err)
	}
}

// TestRenew: without renew the browser's CAS session signs in silently
// (isFromNewLogin=false); renew forces a new login, and validating with
// renew refuses a single-sign-on ticket.
func TestRenew(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.cl.Validate(ctx, e.idp.CASServerURL(), service, e.ticket(t, "00u-pat-policy", devidp.MethodPasskey, false, devidp.FaultNone), false); err != nil {
		t.Fatal(err)
	}
	sso := e.ticket(t, "ignored", devidp.MethodPassword, false, devidp.FaultNone)
	if _, err := e.cl.Validate(ctx, e.idp.CASServerURL(), service, sso, true); casclient.ReasonOf(err) != casclient.ReasonFailure {
		t.Errorf("renew validation of an SSO ticket: %v", err)
	}
	sso = e.ticket(t, "ignored", devidp.MethodPassword, false, devidp.FaultNone)
	got, err := e.cl.Validate(ctx, e.idp.CASServerURL(), service, sso, false)
	if err != nil || got.User != "00u-pat-policy" || got.NewLogin == nil || *got.NewLogin {
		t.Errorf("SSO ticket: %+v %v", got, err)
	}
	fresh := e.ticket(t, "00u-pat-policy", devidp.MethodPasskey, true, devidp.FaultNone)
	if got, err := e.cl.Validate(ctx, e.idp.CASServerURL(), service, fresh, true); err != nil || !*got.NewLogin {
		t.Errorf("renew: %+v %v", got, err)
	}
}

func TestFaultsRefused(t *testing.T) {
	want := map[devidp.Fault]string{
		devidp.FaultCASFailure: casclient.ReasonFailure, devidp.FaultCASNoUser: casclient.ReasonUser,
		devidp.FaultCASTwoUsers: casclient.ReasonUser, devidp.FaultCASCommentUser: casclient.ReasonUser,
		devidp.FaultCASProxied: casclient.ReasonProxied,
	}
	for _, f := range devidp.CASFaults() {
		if _, ok := want[f]; !ok && f != devidp.FaultCASStaleAuth && f != devidp.FaultCASTicketReuse {
			t.Errorf("CAS fault %s has no expected reason", f) // stale auth and reuse are the ACS's (api tests)
		}
	}
	for f, reason := range want {
		t.Run(string(f), func(t *testing.T) {
			e := setup(t)
			tk := e.ticket(t, "00u-vic-viewer", devidp.MethodPassword, false, f)
			if got, err := e.cl.Validate(context.Background(), e.idp.CASServerURL(), service, tk, false); casclient.ReasonOf(err) != reason {
				t.Errorf("reason %q (%v, %+v), want %q", casclient.ReasonOf(err), err, got, reason)
			}
		})
	}
	// stale auth: validates, with an old date and isFromNewLogin=false
	e := setup(t)
	got, err := e.cl.Validate(context.Background(), e.idp.CASServerURL(), service,
		e.ticket(t, "00u-vic-viewer", devidp.MethodPassword, true, devidp.FaultCASStaleAuth), true)
	if err != nil || *got.NewLogin || time.Since(got.AuthenticationDate) < time.Hour {
		t.Errorf("stale auth: %+v %v", got, err)
	}
}

func TestParse(t *testing.T) {
	ok := `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>jdoe</cas:user>` +
		`<cas:attributes><cas:email>j@x.example</cas:email><cas:authenticationDate>2026-10-11T09:30:00.123Z[UTC]</cas:authenticationDate>` +
		`</cas:attributes></cas:authenticationSuccess></cas:serviceResponse>`
	tk, err := casclient.Parse([]byte(ok))
	if err != nil || tk.User != "jdoe" || !tk.AuthenticationDate.Equal(time.Date(2026, 10, 11, 9, 30, 0, 123e6, time.UTC)) {
		t.Fatalf("%+v %v", tk, err)
	}
	for name, body := range map[string]string{
		"attribute with markup": strings.Replace(ok, "j@x.example", "j@x.example<cas:user>admin</cas:user>", 1),
		"user with whitespace":  strings.Replace(ok, ">jdoe<", "> jdoe<", 1),
		"success and failure":   strings.Replace(ok, "</cas:authenticationSuccess>", `</cas:authenticationSuccess><cas:authenticationFailure code="X"/>`, 1),
		"wrong namespace":       strings.ReplaceAll(ok, "http://www.yale.edu/tp/cas", "urn:evil"),
		"proxy granting ticket": strings.Replace(ok, "</cas:authenticationSuccess>", "<cas:proxyGrantingTicket>PGTIOU-1</cas:proxyGrantingTicket></cas:authenticationSuccess>", 1),
		"not XML":               "<<<",
		"empty":                 "",
	} {
		if tk, err := casclient.Parse([]byte(body)); err == nil {
			t.Errorf("%s: accepted %+v", name, tk)
		}
	}
	e := setup(t)
	for _, tk := range []string{"PT-123", "ST-1 2", "ST-" + strings.Repeat("a", 300), "", "ST-é"} {
		if _, err := e.cl.Validate(context.Background(), e.idp.CASServerURL(), service, tk, false); casclient.ReasonOf(err) != casclient.ReasonTicket {
			t.Errorf("ticket %q: %v", tk, err)
		}
	}
	if _, err := casclient.LoginURL("javascript:x", service, false); casclient.ReasonOf(err) != casclient.ReasonConfig {
		t.Errorf("bad server URL: %v", err)
	}
}

// FuzzParse: Parse never panics, and anything it accepts has one clean user.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>jdoe</cas:user></cas:authenticationSuccess></cas:serviceResponse>`))
	f.Add([]byte(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationFailure code="INVALID_TICKET"/></cas:serviceResponse>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		tk, err := casclient.Parse(b)
		if err == nil && (tk.User == "" || strings.ContainsAny(tk.User, "<>") || strings.TrimSpace(tk.User) != tk.User) {
			t.Fatalf("accepted user %q", tk.User)
		}
	})
}
