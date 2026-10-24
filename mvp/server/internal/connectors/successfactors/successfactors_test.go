package successfactors

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
)

func TestHostAllowlist(t *testing.T) {
	rt := connsync.Runtime{Env: config.Prod}
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"https://api4.successfactors.com", true},
		{"https://apisalesdemo8.successfactors.com", true},
		{"https://api55.sapsf.eu", true},
		{"https://api2.successfactors.eu", true},
		{"https://api10.sapsf.cn", true},
		{"https://api68sales.sapsf.com", true},
		{"https://API4.SuccessFactors.COM", true},
		{"https://successfactors.com", false}, // the apex is not an API host
		{"https://evil.example", false},       // not SuccessFactors
		{"https://successfactors.com.evil.example", false},
		{"https://notsuccessfactors.com", false}, // a suffix without the dot
		{"https://api4.successfactors.com:8443", false},
		{"https://api4.sapsf.org", false},
		{"http://api4.successfactors.com", false}, // plain http
		{"https://api4.successfactors.com/odata", false},
		{"https://user:pw@api4.successfactors.com", false},
		{"https://127.0.0.1", false}, // the loopback exception is dev only
		{"https://169.254.169.254", false},
		{"https://localhost", false},
	} {
		_, err := New(Config{BaseURL: tc.url, CompanyID: company, Username: apiUser, Password: connsync.NewSecret(password)}, rt, nil, nil)
		// hc is nil, so a host that passes stops at the client check: either way the host decides first
		hostRefused := err != nil && !strings.Contains(err.Error(), "safehttp client")
		if hostRefused == tc.ok {
			t.Errorf("%s: allowed=%v err=%v", tc.url, tc.ok, err)
		}
	}
}

func TestLoopbackOverrideIsDevOnly(t *testing.T) {
	cfg := Config{BaseURL: "https://127.0.0.1:9", CompanyID: company, Username: apiUser, Password: connsync.NewSecret(password)}
	for name, rt := range map[string]connsync.Runtime{
		"prod":                       {Env: config.Prod},
		"prod with the exception":    {Env: config.Prod, AllowLoopback: true},
		"dev without the exception":  {Env: config.Dev},
		"test environment":           {Env: config.Test, AllowLoopback: true},
		"a config Load did not make": connsync.RuntimeFromConfig(&config.Config{}),
	} {
		if _, err := New(cfg, rt, nil, nil); err == nil || strings.Contains(err.Error(), "safehttp client") {
			t.Errorf("%s: loopback host accepted (%v)", name, err)
		}
	}
	if _, err := New(cfg, connsynctest.Runtime, nil, nil); err == nil || !strings.Contains(err.Error(), "safehttp client") {
		t.Errorf("dev with the exception refused the loopback host: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	ok := Config{BaseURL: "https://api4.successfactors.com", CompanyID: company, Username: apiUser, Password: connsync.NewSecret("x")}
	rt := connsync.Runtime{Env: config.Prod}
	bundle, _ := keyBundle(t)
	for name, mut := range map[string]func(*Config){
		"unknown auth":       func(c *Config) { c.Auth = "ntlm" },
		"no company":         func(c *Config) { c.CompanyID = "" },
		"company with slash": func(c *Config) { c.CompanyID = "a/b" },
		"no user":            func(c *Config) { c.Username = "" },
		"user with colon":    func(c *Config) { c.Username = "a:b" },
		"no password":        func(c *Config) { c.Password = connsync.Secret{} },
		"saml no client":     func(c *Config) { c.Auth, c.PrivateKey = AuthSAML, connsync.NewSecret(bundle) },
		"saml no key":        func(c *Config) { c.Auth, c.ClientID = AuthSAML, clientID },
		"saml bad key":       func(c *Config) { c.Auth, c.ClientID, c.PrivateKey = AuthSAML, clientID, connsync.NewSecret("not pem") },
		"legal entity ctrl":  func(c *Config) { c.LegalEntity = "a\nb" },
		"short window":       func(c *Config) { c.EventWindow = time.Hour },
		"base with path":     func(c *Config) { c.BaseURL += "/odata/v2" },
	} {
		c := ok
		mut(&c)
		if _, err := New(c, rt, nil, nil); err == nil || strings.Contains(err.Error(), "safehttp client") {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestDiscoverBasic(t *testing.T) {
	f := newFake(t)
	c := f.connector(Config{})
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// paging: 6 users at 2 a page, with an absolute then a relative __next
	if n := f.count("User"); n != 3 {
		t.Errorf("User pages = %d, want 3", n)
	}
	for _, a := range f.auths {
		if a != f.basic {
			t.Fatalf("Authorization %q is not user@company basic", a)
		}
	}
	idents := map[string]connectors.IdentityRecord{}
	for _, i := range res.Identities {
		idents[i.ExternalID] = i
	}
	accts := map[string]connectors.AccountRecord{}
	for _, a := range res.Accounts {
		accts[a.ExternalID] = a
	}
	// Cara starts in the future: not a person yet
	if _, ok := idents["P1003"]; ok {
		t.Error("a future hire is an identity")
	}
	if _, ok := accts["1003"]; ok {
		t.Error("a future hire has an account")
	}
	// Dan has no User row: name from PerPerson, terminated from the employment end
	dan := idents["P1004"]
	if dan.Name != "Dan Departed" || dan.Status != "terminated" || dan.TerminatedAt == nil || !dan.TerminatedAt.Equal(d(2026, 10, 1)) {
		t.Errorf("terminated person: %+v", dan)
	}
	if a := accts["1004"]; a.Status != "disabled" || a.Attributes["termination_date"] != "2026-10-01" {
		t.Errorf("terminated account: %+v", a)
	}
	// Eve's end is ahead: active, with the pending end kept as an attribute
	if eve := idents["P1005"]; eve.Status != "active" || eve.TerminatedAt != nil {
		t.Errorf("future termination applied early: %+v", eve)
	}
	if accts["1005"].Attributes["termination_date"] != "2026-12-31" {
		t.Errorf("termination_date: %v", accts["1005"].Attributes)
	}
	// Finn was rehired: the latest employment is current, the 9999 end is no end
	if fn := idents["P1006"]; fn.Status != "active" || fn.HiredAt == nil || !fn.HiredAt.Equal(d(2025, 3, 1)) {
		t.Errorf("rehire: %+v", fn)
	}
	if _, has := accts["1006"].Attributes["termination_date"]; has {
		t.Error("the open end of an employment became a termination date")
	}
	// Alice: current job (the second row), manager resolved to the manager's person id
	alice := idents["P1001"]
	if alice.Department == nil || *alice.Department != "Platform" || alice.Manager == nil || alice.Manager.ExternalID != "P1005" {
		t.Errorf("alice: %+v", alice)
	}
	if alice.Email == nil || *alice.Email != "alice@acme.example" || alice.Type != "human" {
		t.Errorf("alice contact: %+v", alice)
	}
	// Bob has NO_MANAGER
	if idents["P1002"].Manager != nil {
		t.Error("NO_MANAGER became a manager")
	}
	a := accts["1001"]
	if a.System != System || a.Username != "u1001" || a.Identity == nil || a.Identity.ExternalID != "P1001" || a.Status != "active" {
		t.Errorf("alice account: %+v", a)
	}
	if a.Attributes["person_id"] != "P1001" || a.Attributes["cost_center"] != "CC-D30" || a.Attributes["hire_date"] != "2020-02-03" {
		t.Errorf("attributes: %v", a.Attributes)
	}
	// department groups and membership of active people only
	groups := map[string]string{}
	for _, g := range res.Groups {
		groups[g.ExternalID] = g.Name
		if g.Kind != "department" || g.System != System {
			t.Errorf("group %+v", g)
		}
	}
	if groups["dept:D30"] != "Platform" || groups["dept:D20"] != "Sales" {
		t.Errorf("groups: %v", groups)
	}
	for _, e := range res.Edges {
		if e.Relation != "member_of" || e.Src.ExternalID == "1004" {
			t.Errorf("edge %+v", e)
		}
	}
	// only reads were sent, and only the declared fields were asked for
	for _, m := range f.methods {
		if m != "GET" {
			t.Errorf("method %s", m)
		}
	}
	for _, q := range f.queries {
		for _, banned := range []string{"dateOfBirth", "nationalId", "salary", "compensation", "bank"} {
			if strings.Contains(q, banned) {
				t.Errorf("query asks for %s: %s", banned, q)
			}
		}
	}
}

func TestEmitIdentitiesOff(t *testing.T) {
	f := newFake(t)
	c := f.connector(Config{})
	c.cfg.EmitIdentities = false
	res, err := c.Discover(context.Background())
	if err != nil || len(res.Identities) != 0 || len(res.Accounts) == 0 {
		t.Fatalf("%v %d %d", err, len(res.Identities), len(res.Accounts))
	}
}

func TestPerPersonForbiddenStillReads(t *testing.T) {
	f := newFake(t)
	f.perPersonStatus = 403
	res, err := f.connector(Config{}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range res.Identities {
		if i.ExternalID == "P1004" && i.Name != "P1004" {
			t.Errorf("without PerPerson the name falls back to the id, got %q", i.Name)
		}
	}
}

func TestLegalEntityFilterIsEscaped(t *testing.T) {
	f := newFake(t)
	c := f.connector(Config{LegalEntity: "O'Brien Corp"})
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var job string
	for _, q := range f.queries {
		if strings.HasPrefix(q, odataRoot+"/EmpJob?") {
			job = q
		}
	}
	if !strings.Contains(job, "company eq 'O''Brien Corp'") {
		t.Errorf("filter not escaped: %s", job)
	}
	if len(res.Accounts) != 1 || res.Accounts[0].ExternalID != "1005" {
		t.Errorf("only the legal entity's people: %+v", res.Accounts)
	}
}

func TestODataStringEscaping(t *testing.T) {
	for in, want := range map[string]string{
		"plain":             "'plain'",
		"O'Brien":           "'O''Brien'",
		"'":                 "''''",
		"x' or userId ne '": "'x'' or userId ne '''",
		"a) or (1 eq 1":     "'a) or (1 eq 1'",
		"":                  "''",
		"back\\slash":       "'back\\slash'",
		"unicode é中":        "'unicode é中'",
	} {
		got, err := odataString(in)
		if err != nil || got != want {
			t.Errorf("%q -> %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{"a\nb", "a\x00b", "tab\there", "\x7f"} {
		if _, err := odataString(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// the injection attempt stays inside one literal after the query is encoded and decoded again
	lit, _ := odataString("x' or 1 eq 1 or company eq '")
	q := url.Values{"$filter": {"company eq " + lit}}
	back, _ := url.ParseQuery(encodeQuery(q))
	if got := back.Get("$filter"); got != "company eq 'x'' or 1 eq 1 or company eq '''" {
		t.Errorf("round trip: %s", got)
	}
}

func TestParseTime(t *testing.T) {
	ms := d(2026, 10, 1).UnixMilli()
	for in, want := range map[string]string{
		fmt.Sprintf("/Date(%d)/", ms):      "2026-10-01",
		fmt.Sprintf("/Date(%d+0000)/", ms): "2026-10-01",
		fmt.Sprintf("/Date(%d-0500)/", ms): "2026-10-01",
		"2026-10-01":                       "2026-10-01",
		"2026-10-01T00:00:00":              "2026-10-01",
		"2026-10-01T00:00:00Z":             "2026-10-01",
		"/Date(253402214400000)/":          "", // 9999-12-31, the open end
		"9999-12-31":                       "",
		"":                                 "",
		"garbage":                          "",
		"/Date(99999999999999999999)/":     "",
		"/Date(abc)/":                      "",
	} {
		got := parseTime(in)
		switch {
		case want == "" && got != nil:
			t.Errorf("%q -> %v, want none", in, got)
		case want != "" && (got == nil || got.Format("2006-01-02") != want):
			t.Errorf("%q -> %v, want %s", in, got, want)
		}
	}
}

func TestNextLinkLeavingTheHostIsRefused(t *testing.T) {
	f := newFake(t)
	f.crossHost = true
	_, err := f.connector(Config{}).Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "leaves the configured host") {
		t.Fatalf("err = %v", err)
	}
	for _, a := range f.auths { // the credential went nowhere else (the fake saw only its own requests)
		if a != f.basic {
			t.Errorf("auth %q", a)
		}
	}
}

func TestRejectedCredentialNeverSurfaces(t *testing.T) {
	f := newFake(t)
	f.badCreds = true
	c := f.connector(Config{})
	_, err := c.Discover(context.Background())
	if err == nil || connsync.Status(err) != 401 {
		t.Fatalf("err = %v", err)
	}
	for _, s := range []string{err.Error(), fmt.Sprintf("%v %+v %#v", c.cfg, c.cfg, c.cfg)} {
		for _, secret := range []string{password, "leaky-body", b64(apiUser + "@" + company + ":" + password)} {
			if strings.Contains(s, secret) {
				t.Errorf("%q leaks %q", s, secret)
			}
		}
	}
}

func TestSAMLBearer(t *testing.T) {
	f := newFake(t)
	bundle, cert := keyBundle(t)
	f.basic = ""
	cfg := Config{Auth: AuthSAML, ClientID: clientID, PrivateKey: connsync.NewSecret(bundle)}
	c := f.connector(cfg)
	f.basic = ""
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) == 0 {
		t.Fatal("no accounts")
	}
	if f.tokens != 1 || len(f.assertions) != 1 {
		t.Fatalf("tokens=%d assertions=%d: the token should be reused across pages and entities", f.tokens, len(f.assertions))
	}
	for _, a := range f.auths {
		if a != "Bearer tok-1" {
			t.Fatalf("Authorization %q", a)
		}
	}
	form := f.forms[0]
	if form.Get("grant_type") != samlGrant || form.Get("client_id") != clientID || form.Get("company_id") != company {
		t.Errorf("form %v", form)
	}
	raw, err := base64.StdEncoding.DecodeString(form.Get("assertion"))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	// signed: the signature verifies against the certificate and covers the assertion
	vctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	if _, err := vctx.Validate(doc.Root()); err != nil {
		t.Fatalf("signature: %v", err)
	}
	a := doc.Root()
	if a.Tag != "Assertion" || a.SelectAttrValue("Version", "") != "2.0" {
		t.Errorf("root %s", a.Tag)
	}
	if got := a.FindElement("./Subject/NameID").Text(); got != apiUser {
		t.Errorf("NameID %q", got)
	}
	if got := a.FindElement("./Issuer").Text(); got != clientID {
		t.Errorf("Issuer %q", got)
	}
	if got := a.FindElement("./Conditions/AudienceRestriction/Audience").Text(); got != "www.successfactors.com" {
		t.Errorf("Audience %q", got)
	}
	if got := a.FindElement("./Subject/SubjectConfirmation/SubjectConfirmationData").SelectAttrValue("Recipient", ""); got != c.tok.tokenURL {
		t.Errorf("Recipient %q", got)
	}
	if got := a.FindElement("./AttributeStatement/Attribute[@Name='api_key']/AttributeValue").Text(); got != clientID {
		t.Errorf("api_key %q", got)
	}
	if a.ChildElements()[1].Tag != "Signature" {
		t.Errorf("the signature is not right after the issuer: %s", a.ChildElements()[1].Tag)
	}
	nb, na := a.FindElement("./Conditions").SelectAttrValue("NotBefore", ""), a.FindElement("./Conditions").SelectAttrValue("NotOnOrAfter", "")
	if nb != "2026-10-24T08:59:00Z" || na != "2026-10-24T09:05:00Z" {
		t.Errorf("validity %s .. %s", nb, na)
	}
}

func TestSAMLTokenRefreshedAfter401(t *testing.T) {
	f := newFake(t)
	bundle, _ := keyBundle(t)
	c := f.connector(Config{Auth: AuthSAML, ClientID: clientID, PrivateKey: connsync.NewSecret(bundle)})
	f.basic = ""
	f.rejectOnce = true
	if _, err := c.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.tokens != 2 {
		t.Errorf("tokens = %d: a 401 should drop the token and sign in once more", f.tokens)
	}
}

func TestSAMLRefusedTokenEndpointNeverSurfaces(t *testing.T) {
	f := newFake(t)
	bundle, _ := keyBundle(t)
	f.badCreds = true
	c := f.connector(Config{Auth: AuthSAML, ClientID: clientID, PrivateKey: connsync.NewSecret(bundle)})
	f.basic = ""
	_, err := c.Discover(context.Background())
	if err == nil {
		t.Fatal("no error")
	}
	if strings.Contains(err.Error(), "leaky-body") || strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), "PRIVATE") {
		t.Errorf("error leaks: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", c.cfg, c.tok.signer), "PRIVATE") {
		t.Error("key printed")
	}
}

func TestKeyBundleMustMatchTheCertificate(t *testing.T) {
	a, _ := keyBundle(t)
	b, _ := keyBundle(t)
	keyA := a[:strings.Index(a, "-----BEGIN CERTIFICATE")]
	certB := b[strings.Index(b, "-----BEGIN CERTIFICATE"):]
	if _, _, err := parseKeyBundle(keyA + certB); err == nil || strings.Contains(err.Error(), "BEGIN") {
		t.Errorf("mismatched pair accepted or error leaks: %v", err)
	}
	if _, _, err := parseKeyBundle(keyA); err == nil {
		t.Error("a key without a certificate accepted")
	}
	if _, _, err := parseKeyBundle(a); err != nil {
		t.Errorf("good bundle: %v", err)
	}
}

func TestProbe(t *testing.T) {
	f := newFake(t)
	p, err := f.connector(Config{}).Probe(context.Background(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if p.Users != 4 || !slices.Contains(p.Fields, "userId") || slices.Contains(p.Fields, "__metadata") {
		t.Errorf("%+v", p)
	}
	f.users = nil
	if _, err := f.connector(Config{}).Probe(context.Background(), 4); !ErrNoRows(err) {
		t.Errorf("empty read: %v", err)
	}
	f.badCreds = true
	if _, err := f.connector(Config{}).Probe(context.Background(), 4); connsync.Status(err) != 401 {
		t.Errorf("refused: %v", err)
	}
}

func collect(t *testing.T, c *Connector) map[string]*connectors.HrisEventRecord {
	t.Helper()
	out := map[string]*connectors.HrisEventRecord{}
	var order []string
	err := c.StreamEvents(context.Background(), nil, func(e connectors.Event) error {
		r, ok := e.(*connectors.HrisEventRecord)
		if !ok {
			t.Fatalf("event %T", e)
		}
		out[r.ExternalID] = r
		order = append(order, r.ExternalID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.IsSorted(order) {
		// ordered by effective date, then id: verify the dates are non-decreasing
		for i := 1; i < len(order); i++ {
			if out[order[i]].EffectiveAt.Before(out[order[i-1]].EffectiveAt) {
				t.Errorf("events out of order: %v", order)
			}
		}
	}
	return out
}

func payloadOf(r *connectors.HrisEventRecord, k string) any {
	for _, kv := range r.Payload {
		if kv.Key == k {
			return kv.Value
		}
	}
	return nil
}

func TestEvents(t *testing.T) {
	f := newFake(t)
	evs := collect(t, f.connector(Config{}))
	want := []string{
		"sf-evt-joiner-1003-2026-11-15", // pending pre-hire
		"sf-evt-joiner-1007-2026-10-05", // started inside the window
		"sf-evt-leaver-1004-2026-10-01",
		"sf-evt-leaver-1005-2026-12-31", // pending
		"sf-evt-mover-1001-2026-10-11",
	}
	var got []string
	for id := range evs {
		got = append(got, id)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("events\n got %v\nwant %v", got, want)
	}
	pre := evs["sf-evt-joiner-1003-2026-11-15"]
	if pre.Type != "joiner" || pre.Identity != nil || !pre.EffectiveAt.Equal(d(2026, 11, 15)) || payloadOf(pre, "team") != "sales" {
		t.Errorf("pre-hire: %+v", pre)
	}
	hist := evs["sf-evt-joiner-1007-2026-10-05"]
	if hist.Identity == nil || hist.Identity.ExternalID != "P1007" || payloadOf(hist, "historical") != true {
		t.Errorf("a hire that already took effect is historical: %+v", hist)
	}
	if lv := evs["sf-evt-leaver-1004-2026-10-01"]; lv.Type != "leaver" || lv.Identity.ExternalID != "P1004" || payloadOf(lv, "last_day") != "2026-10-01" {
		t.Errorf("leaver: %+v", lv)
	}
	if lv := evs["sf-evt-leaver-1005-2026-12-31"]; !lv.EffectiveAt.Equal(d(2026, 12, 31)) {
		t.Errorf("pending leaver: %+v", lv)
	}
	mv := evs["sf-evt-mover-1001-2026-10-11"]
	if mv.Type != "mover" || payloadOf(mv, "from_team") != "engineering" || payloadOf(mv, "to_team") != "platform" ||
		payloadOf(mv, "to_manager_external_id") != "P1005" || payloadOf(mv, "from_manager_external_id") != "P1002" {
		t.Errorf("mover: %+v", mv)
	}
	if again := collect(t, f.connector(Config{})); len(again) != len(evs) {
		t.Error("a second read gave different events")
	}
}

func TestEventWindowDropsOldEvents(t *testing.T) {
	f := newFake(t)
	evs := collect(t, f.connector(Config{EventWindow: 24 * time.Hour}))
	for id := range evs {
		if strings.Contains(id, "1004") || strings.Contains(id, "1007") || strings.Contains(id, "mover") {
			t.Errorf("%s is older than the window", id)
		}
	}
}

func TestEventsStopWhenYieldFails(t *testing.T) {
	f := newFake(t)
	boom := errors.New("stop")
	n := 0
	err := f.connector(Config{}).StreamEvents(context.Background(), nil, func(connectors.Event) error { n++; return boom })
	if !errors.Is(err, boom) || n != 1 {
		t.Errorf("err=%v n=%d", err, n)
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{
		"TESSERA_SUCCESSFACTORS_BASE_URL": "https://api4.successfactors.com", "TESSERA_SUCCESSFACTORS_COMPANY_ID": company,
		"TESSERA_SUCCESSFACTORS_USER": apiUser, "TESSERA_SUCCESSFACTORS_PASSWORD": "env:PW", "PW": password,
	}
	get := func(k string) string { return env[k] }
	cfg, err := ConfigFromEnv(get)
	if err != nil || cfg.Password.Reveal() != password || !cfg.EmitIdentities || cfg.Auth != "" {
		t.Fatalf("%+v %v", cfg, err)
	}
	// a literal secret is refused, so it cannot sit in an environment file
	env["TESSERA_SUCCESSFACTORS_PASSWORD"] = password
	if _, err := ConfigFromEnv(get); err == nil || strings.Contains(err.Error(), password) {
		t.Errorf("literal secret: %v", err)
	}
	env["TESSERA_SUCCESSFACTORS_PASSWORD"] = "env:PW"
	env["TESSERA_SUCCESSFACTORS_EMIT_IDENTITIES"] = "maybe"
	if _, err := ConfigFromEnv(get); err == nil {
		t.Error("bad bool accepted")
	}
	delete(env, "TESSERA_SUCCESSFACTORS_EMIT_IDENTITIES")
	env["TESSERA_SUCCESSFACTORS_AUTH"] = AuthSAML
	if _, err := ConfigFromEnv(get); err == nil || !strings.Contains(err.Error(), "PRIVATE_KEY") {
		t.Errorf("saml without a key: %v", err)
	}
}

func TestJobReadsAskForTheEffectiveWindow(t *testing.T) {
	f := newFake(t)
	c := f.connector(Config{})
	var got []string
	if err := c.readJobs(context.Background(), d(2026, 9, 1), d(2027, 1, 1), func(j oJob) { got = append(got, string(j.UserID)+"/"+string(j.SeqNumber)) }); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, "1003/1") || !slices.Contains(got, "1001/1") {
		t.Errorf("future and past rows must come back with fromDate and toDate: %v", got)
	}
	// without the window the (fake) server answers as of today and never returns them
	got = nil
	f.jobs = f.jobs[:2]
	q := url.Values{"$filter": {"startDate le " + odataTime(d(2027, 1, 1)) + " and endDate ge " + odataTime(d(2026, 9, 1))}}
	if rows := f.applyJobFilter(q); len(rows) != 1 {
		t.Errorf("today-only default returned %d rows", len(rows))
	}
	found := false
	for _, qs := range f.queries {
		found = found || strings.Contains(qs, "fromDate=2026-09-01") && strings.Contains(qs, "toDate=2027-01-01")
	}
	if !found {
		t.Errorf("no fromDate/toDate in %v", f.queries)
	}
}

func TestSAMLNameIDIsSeparateFromTheLogin(t *testing.T) {
	f := newFake(t)
	bundle, _ := keyBundle(t)
	c := f.connector(Config{Auth: AuthSAML, ClientID: clientID, PrivateKey: connsync.NewSecret(bundle), UserID: "sfapi-0042"})
	f.basic = ""
	if _, err := c.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(f.forms[0].Get("assertion"))
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	if got := doc.Root().FindElement("./Subject/NameID").Text(); got != "sfapi-0042" {
		t.Errorf("NameID %q", got)
	}
	if b := basicHeader(Config{Username: apiUser, CompanyID: company, UserID: "x"}); !strings.Contains(b, "Basic ") {
		t.Error(b)
	}
}

func TestProbeNeverEchoesUnknownKeys(t *testing.T) {
	f := newFake(t)
	f.users[0]["leakedKeyName_SSN"] = "x"
	p, err := f.connector(Config{}).Probe(context.Background(), 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range p.Fields {
		if !strings.Contains(selUser, k) {
			t.Errorf("field %q is not one that was asked for", k)
		}
	}
}
