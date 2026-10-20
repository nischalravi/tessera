package rotation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
)

// Provider stand-ins for the protocol tests. Their responses are rendered
// from the recorded response shapes in testdata/, and they check what the
// adapters send: SigV4 signatures, tokens, paths and bodies.

func fixture(t testing.TB, name string, data any) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- fixed test fixtures
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New(name).Parse(string(raw))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, data); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b.Bytes()
}

// plainFixture reads a fixture with {{TOKEN}} placeholders (not Go templates).
func plainFixture(t testing.TB, name string, repl map[string]string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- fixed test fixtures
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for k, v := range repl {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return []byte(s)
}

func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// ---------------------------------------------------------------- IAM

type iamKey struct {
	ID       string
	Status   string
	Created  string
	created  time.Time
	LastUsed string
}

type fakeIAM struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	keys   map[string][]*iamKey
	calls  []string // "Action key=value ..." in order
	creds  awsCreds
	region string
	nextID int
	// errors maps an Action to an error response {status, code}
	errs map[string][2]string
}

func newFakeIAM(t *testing.T, creds awsCreds) *fakeIAM {
	f := &fakeIAM{t: t, keys: map[string][]*iamKey{}, creds: creds, region: "us-east-1", errs: map[string][2]string{}}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIAM) addKey(user, id string, created time.Time, lastUsed *time.Time) {
	k := &iamKey{ID: id, Status: "Active", Created: iso(created), created: created}
	if lastUsed != nil {
		k.LastUsed = iso(*lastUsed)
	}
	f.keys[user] = append(f.keys[user], k)
}

func (f *fakeIAM) find(id string) *iamKey {
	for _, ks := range f.keys {
		for _, k := range ks {
			if k.ID == id {
				return k
			}
		}
	}
	return nil
}

func (f *fakeIAM) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeIAM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	// recompute the SigV4 signature of what arrived
	stamp, err := time.Parse(amzDate, r.Header.Get("X-Amz-Date"))
	if err != nil {
		http.Error(w, "bad date", 400)
		return
	}
	check, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), nil)
	check.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	signV4(check, body, f.creds, f.region, "iam", stamp)
	if got, want := r.Header.Get("Authorization"), check.Header.Get("Authorization"); got != want {
		f.t.Errorf("IAM request signature mismatch:\n got %s\nwant %s", got, want)
		http.Error(w, "SignatureDoesNotMatch", 403)
		return
	}
	form, _ := url.ParseQuery(string(body))
	action, user := form.Get("Action"), form.Get("UserName")
	f.calls = append(f.calls, strings.Join(strings.Fields(action+" "+user+" "+form.Get("AccessKeyId")+" "+form.Get("Status")), " "))
	if e, ok := f.errs[action]; ok {
		w.WriteHeader(atoi(e[0]))
		_, _ = w.Write(fixture(f.t, "aws/iam_error.xml.tmpl", map[string]string{"Code": e[1], "Message": "simulated " + e[1]}))
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	switch action {
	case "CreateAccessKey":
		f.nextID++
		id := fmt.Sprintf("AKIANEWKEYEXAMPLE%04d", f.nextID)
		k := &iamKey{ID: id, Status: "Active", Created: iso(time.Now()), created: time.Now()}
		f.keys[user] = append(f.keys[user], k)
		_, _ = w.Write(fixture(f.t, "aws/iam_create_access_key.xml.tmpl", map[string]string{"User": user, "ID": id,
			"Secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEWSECRET", "Created": k.Created}))
	case "ListAccessKeys":
		_, _ = w.Write(fixture(f.t, "aws/iam_list_access_keys.xml.tmpl", map[string]any{"User": user, "Keys": f.keys[user]}))
	case "GetAccessKeyLastUsed":
		k := f.find(form.Get("AccessKeyId"))
		if k == nil {
			w.WriteHeader(404)
			_, _ = w.Write(fixture(f.t, "aws/iam_error.xml.tmpl", map[string]string{"Code": "NoSuchEntity", "Message": "not found"}))
			return
		}
		_, _ = w.Write(fixture(f.t, "aws/iam_get_access_key_last_used.xml.tmpl", map[string]string{"User": user, "LastUsed": k.LastUsed}))
	case "UpdateAccessKey":
		if k := f.find(form.Get("AccessKeyId")); k != nil {
			k.Status = form.Get("Status")
		}
		_, _ = w.Write(fixture(f.t, "aws/iam_empty.xml.tmpl", map[string]string{"Action": action}))
	case "DeleteAccessKey":
		id := form.Get("AccessKeyId")
		ks := f.keys[user]
		i := slices.IndexFunc(ks, func(k *iamKey) bool { return k.ID == id })
		if i < 0 {
			w.WriteHeader(404)
			_, _ = w.Write(fixture(f.t, "aws/iam_error.xml.tmpl", map[string]string{"Code": "NoSuchEntity", "Message": "The Access Key with id " + id + " cannot be found."}))
			return
		}
		f.keys[user] = slices.Delete(ks, i, i+1)
		_, _ = w.Write(fixture(f.t, "aws/iam_empty.xml.tmpl", map[string]string{"Action": action}))
	default:
		http.Error(w, "unknown action", 400)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// ---------------------------------------------------------------- Vault

type vaultWrite struct {
	Path string
	Data map[string]string
}

type fakeVault struct {
	t         *testing.T
	srv       *httptest.Server
	mu        sync.Mutex
	token     string
	namespace string
	accessors map[string]time.Time // role path + "#" + accessor -> created
	writes    []vaultWrite
	calls     []string
	nextID    int
	failKV    bool
}

func newFakeVault(t *testing.T, token string) *fakeVault {
	f := &fakeVault{t: t, token: token, accessors: map[string]time.Time{}}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVault) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Vault-Token") != f.token {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}
	if f.namespace != "" && r.Header.Get("X-Vault-Namespace") != f.namespace {
		f.t.Errorf("namespace header %q, want %q", r.Header.Get("X-Vault-Namespace"), f.namespace)
	}
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	var body map[string]any
	raw, _ := io.ReadAll(r.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &body)
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasPrefix(p, "auth/") && strings.HasSuffix(p, "/secret-id"):
		role := strings.Replace(strings.TrimPrefix(strings.TrimSuffix(p, "/secret-id"), "auth/"), "/role/", "/", 1)
		f.nextID++
		acc := fmt.Sprintf("0b9d6a2c-aaaa-4bbb-8ccc-%012d", f.nextID)
		f.accessors[role+"#"+acc] = time.Now()
		_, _ = w.Write(plainFixture(f.t, "vault/approle_secret_id.json", map[string]string{"ACCESSOR": acc}))
	case strings.HasSuffix(p, "/secret-id-accessor/lookup"), strings.HasSuffix(p, "/secret-id-accessor/destroy"):
		role := strings.Replace(strings.TrimPrefix(p[:strings.Index(p, "/secret-id-accessor")], "auth/"), "/role/", "/", 1)
		acc, _ := body["secret_id_accessor"].(string)
		key := role + "#" + acc
		created, ok := f.accessors[key]
		if !ok {
			w.WriteHeader(400)
			_, _ = w.Write(plainFixture(f.t, "vault/accessor_not_found.json", map[string]string{"ACCESSOR": acc}))
			return
		}
		if strings.HasSuffix(p, "/destroy") {
			delete(f.accessors, key)
			w.WriteHeader(204)
			return
		}
		_, _ = w.Write(plainFixture(f.t, "vault/accessor_lookup.json", map[string]string{"ACCESSOR": acc, "CREATED": iso(created)}))
	case strings.Contains(p, "/data/"):
		if f.failKV {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"errors":["internal error"]}`))
			return
		}
		data := map[string]string{}
		if d, ok := body["data"].(map[string]any); ok {
			for k, v := range d {
				data[k], _ = v.(string)
			}
		}
		f.writes = append(f.writes, vaultWrite{Path: p, Data: data})
		_, _ = w.Write(plainFixture(f.t, "vault/kv_write.json", nil))
	default:
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"errors":[]}`))
	}
}

// ---------------------------------------------------------------- GitHub

type ghFakeKey struct {
	ID       int
	Title    string
	Created  time.Time
	ReadOnly bool
	LastUsed *time.Time
	Public   string
}

type fakeGitHub struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	token  string
	keys   map[string]*ghFakeKey // "owner/repo#id"
	calls  []string
	nextID int
}

func newFakeGitHub(t *testing.T, token string) *fakeGitHub {
	f := &fakeGitHub{t: t, token: token, keys: map[string]*ghFakeKey{}, nextID: 5000}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeGitHub) keyJSON(k *ghFakeKey) []byte {
	last := "null"
	if k.LastUsed != nil {
		last = `"` + iso(*k.LastUsed) + `"`
	}
	return plainFixture(f.t, "github/deploy_key.json", map[string]string{"ID": fmt.Sprint(k.ID), "TITLE": k.Title,
		"CREATED": iso(k.Created), "READONLY": fmt.Sprint(k.ReadOnly), "LASTUSED": last})
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token || r.Header.Get("X-GitHub-Api-Version") == "" {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
		return
	}
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // repos owner repo keys [id]
	if len(parts) < 4 || parts[0] != "repos" || parts[3] != "keys" {
		w.WriteHeader(404)
		_, _ = w.Write(plainFixture(f.t, "github/not_found.json", nil))
		return
	}
	repo := parts[1] + "/" + parts[2]
	switch {
	case r.Method == http.MethodPost && len(parts) == 4:
		var in struct {
			Title    string `json:"title"`
			Key      string `json:"key"`
			ReadOnly bool   `json:"read_only"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if !strings.HasPrefix(in.Key, "ssh-ed25519 ") || in.Title == "" {
			w.WriteHeader(422)
			_, _ = w.Write([]byte(`{"message":"Validation Failed"}`))
			return
		}
		f.nextID++
		k := &ghFakeKey{ID: f.nextID, Title: in.Title, Created: time.Now(), ReadOnly: in.ReadOnly, Public: in.Key}
		f.keys[fmt.Sprintf("%s#%d", repo, k.ID)] = k
		w.WriteHeader(201)
		_, _ = w.Write(f.keyJSON(k))
	case r.Method == http.MethodGet && len(parts) == 5, r.Method == http.MethodDelete && len(parts) == 5:
		ref := repo + "#" + parts[4]
		k := f.keys[ref]
		if k == nil {
			w.WriteHeader(404)
			_, _ = w.Write(plainFixture(f.t, "github/not_found.json", nil))
			return
		}
		if r.Method == http.MethodDelete {
			delete(f.keys, ref)
			w.WriteHeader(204)
			return
		}
		_, _ = w.Write(f.keyJSON(k))
	default:
		w.WriteHeader(404)
	}
}

// ---------------------------------------------------------------- Secrets Manager

type smVer struct {
	ID       string
	Stages   []string
	Created  float64
	Accessed float64
}

type fakeSM struct {
	t               *testing.T
	srv             *httptest.Server
	mu              sync.Mutex
	creds           awsCreds
	region          string
	name            string
	rotationEnabled bool
	versions        []*smVer
	calls           []string
	secrets         map[string]string // destination secrets written: name -> payload
	flipPolls       int               // RotateSecret: DescribeSecret/ListSecretVersionIds polls before AWSCURRENT moves (default 2)
	pendingFlip     int
	pendingToken    string
}

func newFakeSM(t *testing.T, creds awsCreds, name string) *fakeSM {
	f := &fakeSM{t: t, creds: creds, region: "eu-west-1", name: name, secrets: map[string]string{}}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSM) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeSM) cur() *smVer {
	for _, v := range f.versions {
		if slices.Contains(v.Stages, "AWSCURRENT") {
			return v
		}
	}
	return nil
}

func removeStage(v *smVer, s string) {
	v.Stages = slices.DeleteFunc(v.Stages, func(x string) bool { return x == s })
}

// promote makes the version current and the former current AWSPREVIOUS.
func (f *fakeSM) promote(id string) {
	var prev *smVer
	for _, v := range f.versions {
		if v.ID == id {
			continue
		}
		if slices.Contains(v.Stages, "AWSPREVIOUS") {
			removeStage(v, "AWSPREVIOUS")
		}
		if slices.Contains(v.Stages, "AWSCURRENT") {
			prev = v
		}
	}
	if prev != nil {
		removeStage(prev, "AWSCURRENT")
		prev.Stages = append(prev.Stages, "AWSPREVIOUS")
	}
	for _, v := range f.versions {
		if v.ID == id {
			v.Stages = append(removeAll(v.Stages, "AWSPENDING"), "AWSCURRENT")
		}
	}
}

func removeAll(s []string, x string) []string {
	return slices.DeleteFunc(s, func(y string) bool { return y == x })
}

func (f *fakeSM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	stamp, err := time.Parse(amzDate, r.Header.Get("X-Amz-Date"))
	if err != nil {
		http.Error(w, "bad date", 400)
		return
	}
	check, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), nil)
	check.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	check.Header.Set("X-Amz-Target", r.Header.Get("X-Amz-Target"))
	signV4(check, body, f.creds, f.region, "secretsmanager", stamp)
	if got, want := r.Header.Get("Authorization"), check.Header.Get("Authorization"); got != want {
		f.t.Errorf("Secrets Manager signature mismatch:\n got %s\nwant %s", got, want)
		w.WriteHeader(403)
		return
	}
	action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "secretsmanager.")
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	f.calls = append(f.calls, action+" "+fmt.Sprint(in["SecretId"]))
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	fail := func(status int, typ, msg string) {
		w.WriteHeader(status)
		_, _ = w.Write(fixture(f.t, "aws/sm_error.json.tmpl", map[string]string{"Type": typ, "Message": msg}))
	}
	switch action {
	case "DescribeSecret", "ListSecretVersionIds":
		if f.pendingToken != "" {
			f.pendingFlip--
			if f.pendingFlip <= 0 {
				f.promote(f.pendingToken)
				f.pendingToken = ""
			}
		}
		if id, _ := in["SecretId"].(string); id != f.name {
			fail(400, "com.amazonaws.secretsmanager#ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
			return
		}
		var vs []smVer
		for _, v := range f.versions {
			if action == "ListSecretVersionIds" && len(v.Stages) == 0 && in["IncludeDeprecated"] != true {
				continue
			}
			vs = append(vs, *v)
		}
		data := map[string]any{"Name": f.name, "RotationEnabled": f.rotationEnabled, "Versions": vs}
		tmpl := "aws/sm_describe_secret.json.tmpl"
		if action == "ListSecretVersionIds" {
			tmpl = "aws/sm_list_versions.json.tmpl"
		}
		_, _ = w.Write(fixture(f.t, tmpl, data))
	case "RotateSecret":
		tok, _ := in["ClientRequestToken"].(string)
		f.versions = append(f.versions, &smVer{ID: tok, Stages: []string{"AWSPENDING"}, Created: 1.7604e9})
		f.pendingToken, f.pendingFlip = tok, max(f.flipPolls, 1)
		if f.flipPolls == 0 {
			f.pendingFlip = 2
		}
		_, _ = w.Write(fixture(f.t, "aws/sm_version_result.json.tmpl", map[string]string{"Name": f.name, "VersionID": tok}))
	case "PutSecretValue":
		id, _ := in["SecretId"].(string)
		tok, _ := in["ClientRequestToken"].(string)
		if id == f.name {
			f.versions = append(f.versions, &smVer{ID: tok, Created: 1.7604e9})
			f.promote(tok)
		} else if _, ok := f.secrets[id]; ok {
			f.secrets[id], _ = in["SecretString"].(string)
		} else {
			fail(400, "com.amazonaws.secretsmanager#ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
			return
		}
		_, _ = w.Write(fixture(f.t, "aws/sm_version_result.json.tmpl", map[string]string{"Name": id, "VersionID": tok}))
	case "CreateSecret":
		name, _ := in["Name"].(string)
		f.secrets[name], _ = in["SecretString"].(string)
		_, _ = w.Write(fixture(f.t, "aws/sm_version_result.json.tmpl", map[string]string{"Name": name, "VersionID": "v-created"}))
	case "UpdateSecretVersionStage":
		stage, _ := in["VersionStage"].(string)
		from, _ := in["RemoveFromVersionId"].(string)
		for _, v := range f.versions {
			if v.ID == from {
				removeStage(v, stage)
			}
		}
		_, _ = w.Write(fixture(f.t, "aws/sm_version_result.json.tmpl", map[string]string{"Name": f.name, "VersionID": from}))
	default:
		fail(400, "InvalidRequestException", "unknown action "+action)
	}
}

func newSealer(t testing.TB) *seal.Sealer {
	s, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
