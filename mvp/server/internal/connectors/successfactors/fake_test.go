package successfactors

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var now0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

const (
	company  = "acme_prod"
	apiUser  = "tessera-api"
	password = "p4ss-w0rd-SECRET"
	clientID = "client-api-key-123"
)

type row = map[string]any

// msDate renders t as OData v2 does: /Date(ms)/. The open end is 9999-12-31.
func msDate(t time.Time) string { return fmt.Sprintf("/Date(%d)/", t.UnixMilli()) }

func d(y int, m time.Month, day int) time.Time { return time.Date(y, m, day, 0, 0, 0, 0, time.UTC) }

var openEnd = msDate(d(9999, 12, 31))

// fake replays a small SuccessFactors tenant: OData v2 collections with
// server-side paging (__next), basic authentication and the SAML bearer token
// endpoint. It refuses every method but GET (and POST on the token endpoint).
type fake struct {
	t   *testing.T
	srv *connsynctest.Server

	mu              sync.Mutex
	basic           string // expected Authorization for basic ("" = bearer expected)
	users           []row
	emps            []row
	jobs            []row
	people          []row
	pageSize        int
	perPersonStatus int
	queries         []string // every data query, decoded
	methods         []string
	auths           []string
	assertions      []string
	forms           []url.Values
	tokens          int
	rejectOnce      bool // answer the next data request 401
	crossHost       bool // __next points at another host
	badCreds        bool // refuse every credential with a body that must never surface
}

func newFake(t *testing.T) *fake {
	f := &fake{t: t, pageSize: 2}
	f.srv = connsynctest.New(t, http.HandlerFunc(f.serve))
	f.seed()
	return f
}

func (f *fake) seed() {
	u := func(id, name, mail, dept, status string, hire time.Time) row {
		return row{"userId": id, "username": "u" + id, "displayName": name, "email": mail, "title": "T-" + id,
			"department": dept, "status": status, "hireDate": msDate(hire), "__metadata": row{"uri": "x"}}
	}
	f.users = []row{
		u("1001", "Alice Active", "alice@acme.example", "Engineering", "active", d(2020, 2, 3)),
		u("1002", "Bob Boss", "bob@acme.example", "Engineering", "active", d(2018, 6, 1)),
		u("1003", "Cara Future", "cara@acme.example", "Sales", "active", d(2026, 11, 15)),
		u("1005", "Eve Leaving", "eve@acme.example", "Sales", "active", d(2021, 1, 4)),
		u("1006", "Finn Rehire", "finn@acme.example", "Sales", "active", d(2025, 3, 1)),
		u("1007", "Gus Recent", "gus@acme.example", "Sales", "active", d(2026, 10, 5)),
	}
	emp := func(user, person string, start time.Time, end string) row {
		return row{"userId": user, "personIdExternal": person, "startDate": msDate(start), "endDate": end}
	}
	f.emps = []row{
		emp("1001", "P1001", d(2020, 2, 3), openEnd),
		emp("1002", "P1002", d(2018, 6, 1), openEnd),
		emp("1003", "P1003", d(2026, 11, 15), openEnd),
		emp("1004", "P1004", d(2019, 5, 6), msDate(d(2026, 10, 1))),
		emp("1005", "P1005", d(2021, 1, 4), msDate(d(2026, 12, 31))),
		emp("1006", "P1006", d(2019, 1, 1), msDate(d(2022, 1, 1))),
		emp("1006", "P1006", d(2025, 3, 1), openEnd),
		emp("1007", "P1007", d(2026, 10, 5), openEnd),
	}
	job := func(user string, seq int, start time.Time, end, dept, deptName, mgr, company string) row {
		return row{"userId": user, "seqNumber": seq, "startDate": msDate(start), "endDate": end, "department": dept,
			"jobTitle": "Job-" + user, "managerId": mgr, "location": "NYC", "costCenter": "CC-" + dept, "company": company,
			"departmentNav": row{"name": deptName}}
	}
	f.jobs = []row{
		job("1001", 1, d(2024, 1, 1), msDate(d(2026, 10, 10)), "D10", "Engineering", "1002", "ACME_US"),
		job("1001", 2, d(2026, 10, 11), openEnd, "D30", "Platform", "1005", "ACME_US"),
		job("1002", 1, d(2018, 6, 1), openEnd, "D10", "Engineering", "NO_MANAGER", "ACME_US"),
		job("1003", 1, d(2026, 11, 15), openEnd, "D20", "Sales", "1005", "ACME_US"),
		job("1004", 1, d(2019, 5, 6), msDate(d(2026, 10, 1)), "D20", "Sales", "1005", "ACME_US"),
		job("1005", 1, d(2021, 1, 4), openEnd, "D20", "Sales", "1002", "O'Brien Corp"),
		job("1006", 1, d(2025, 3, 1), openEnd, "D20", "Sales", "1005", "ACME_US"),
		job("1007", 1, d(2026, 10, 5), openEnd, "D20", "Sales", "1005", "ACME_US"),
	}
	person := func(id, first, last string) row {
		return row{"personIdExternal": id, "personalInfoNav": row{"results": []row{{"firstName": first, "lastName": last}}}}
	}
	f.people = []row{person("P1004", "Dan", "Departed"), person("P1001", "Alice", "Active")}
}

func (f *fake) base() string { return f.srv.URL }

func (f *fake) connector(cfg Config) *Connector {
	f.t.Helper()
	if cfg.BaseURL == "" {
		cfg.BaseURL = f.base()
	}
	if cfg.CompanyID == "" {
		cfg.CompanyID = company
	}
	if cfg.Username == "" {
		cfg.Username = apiUser
	}
	if cfg.Auth == "" || cfg.Auth == AuthBasic {
		cfg.Password = connsync.NewSecret(password)
	}
	cfg.EmitIdentities = true
	hc, err := safehttp.NewForTest(f.t, f.srv.Options(0))
	if err != nil {
		f.t.Fatal(err)
	}
	c, err := New(cfg, connsynctest.Runtime, hc, func() time.Time { return now0 })
	if err != nil {
		f.t.Fatal(err)
	}
	f.basic = "Basic " + b64(apiUser+"@"+company+":"+password)
	return c
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, r.Method)
	if r.URL.Path == tokenPath {
		f.token(w, r)
		return
	}
	if r.Method != http.MethodGet {
		f.t.Errorf("a read-only connector sent %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	f.queries = append(f.queries, r.URL.Path+"?"+mustUnescape(r.URL.RawQuery))
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	want := f.basic
	if want == "" {
		want = "Bearer tok-" + strconv.Itoa(f.tokens)
	}
	if f.badCreds || r.Header.Get("Authorization") != want || f.rejectOnce {
		f.rejectOnce = false
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"message":{"value":"leaky-body-should-never-surface"}}}`)
		return
	}
	if r.URL.Query().Get("$format") != "json" {
		f.t.Errorf("no $format=json on %s", r.URL)
	}
	entity := strings.TrimPrefix(r.URL.Path, odataRoot+"/")
	var rows []row
	switch entity {
	case "User":
		rows = f.users
	case "EmpEmployment":
		rows = f.emps
	case "EmpJob":
		rows = f.applyJobFilter(r.URL.Query())
	case "PerPerson":
		if f.perPersonStatus != 0 {
			w.WriteHeader(f.perPersonStatus)
			return
		}
		rows = f.people
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	skip, _ := strconv.Atoi(r.URL.Query().Get("$skiptoken"))
	if top, err := strconv.Atoi(r.URL.Query().Get("$top")); err == nil && top < len(rows) {
		rows = rows[:top]
	}
	size := f.pageSize
	if r.URL.Query().Get("$top") != "" {
		size = len(rows)
	}
	end := min(skip+size, len(rows))
	d := row{"results": rows[skip:end]}
	if end < len(rows) && r.URL.Query().Get("$top") == "" {
		q := r.URL.Query()
		q.Set("$skiptoken", strconv.Itoa(end))
		switch {
		case f.crossHost:
			d["__next"] = "https://evil.example/odata/v2/" + entity + "?" + q.Encode()
		case skip == 0: // an absolute link first, then a relative one
			d["__next"] = f.base() + odataRoot + "/" + entity + "?" + q.Encode()
		default:
			d["__next"] = entity + "?" + q.Encode()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(row{"d": d})
}

var (
	leRE   = regexp.MustCompile(`startDate le datetime'([^']+)' and endDate ge datetime'([^']+)'`)
	coRE   = regexp.MustCompile(` and company eq '((?:[^']|'')*)'$`)
	isoFmt = "2006-01-02T15:04:05"
)

// applyJobFilter understands the one filter shape the connector sends.
func (f *fake) applyJobFilter(q url.Values) []row {
	filter := q.Get("$filter")
	// EmpJob is effective-dated: without fromDate and toDate only the rows in force today exist
	winFrom, winTo := now0, now0
	if q.Get("fromDate") != "" || q.Get("toDate") != "" {
		var err1, err2 error
		winFrom, err1 = time.Parse("2006-01-02", q.Get("fromDate"))
		winTo, err2 = time.Parse("2006-01-02", q.Get("toDate"))
		if err1 != nil || err2 != nil {
			f.t.Errorf("bad fromDate/toDate %v", q)
		}
	}
	m := leRE.FindStringSubmatch(filter)
	if m == nil {
		f.t.Errorf("unexpected EmpJob filter %q", filter)
		return nil
	}
	to, _ := time.Parse(isoFmt, m[1])
	from, _ := time.Parse(isoFmt, m[2])
	company := ""
	if c := coRE.FindStringSubmatch(filter); c != nil {
		company = strings.ReplaceAll(c[1], "''", "'")
	} else if strings.Contains(filter, "company") {
		f.t.Errorf("a company filter that is not an escaped literal: %q", filter)
	}
	var out []row
	for _, j := range f.jobs {
		s, e := parseTime(j["startDate"].(string)), parseTime(j["endDate"].(string))
		if s.After(to) || e != nil && e.Before(from) {
			continue
		}
		if s.After(winTo.Add(24*time.Hour-time.Second)) || e != nil && e.Before(winFrom) {
			continue
		}
		if company != "" && j["company"] != company {
			continue
		}
		out = append(out, j)
	}
	return out
}

func (f *fake) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.forms = append(f.forms, r.PostForm)
	f.assertions = append(f.assertions, r.PostForm.Get("assertion"))
	if f.badCreds || r.PostForm.Get("grant_type") != samlGrant || r.PostForm.Get("client_id") != clientID || r.PostForm.Get("company_id") != company {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"leaky-body-should-never-surface"}`)
		return
	}
	f.tokens++
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"Bearer","expires_in":3600}`, f.tokens)
}

func (f *fake) count(entity string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, q := range f.queries {
		if strings.HasPrefix(q, odataRoot+"/"+entity+"?") {
			n++
		}
	}
	return n
}

func mustUnescape(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func mustPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// keyBundle returns a PEM bundle (RSA key and a self-signed certificate) and
// the certificate.
func keyBundle(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "tessera-sf-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	k := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)})
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(k) + string(c), cert
}
