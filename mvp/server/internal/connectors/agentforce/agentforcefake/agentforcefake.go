// Package agentforcefake is an in-process Salesforce org with Agentforce objects (issue #562), for tests: the
// JWT bearer token endpoint (the assertion's issuer and subject are checked) and a bearer-checked SOQL
// query endpoint that answers the fixed queries of the connector, with paging. Every answer is a stored value.
package agentforcefake

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Token is the access token the fake issues.
const Token = "00Dxx0000001gPL!agentforce-access-token" // #nosec G101 -- a fixed test token of an in-process fake, not a credential

// Credential returns a connection credential (JSON) for the consumer key and user, with a fresh RSA key.
func Credential(clientID, username string) string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	b, _ := json.Marshal(map[string]string{"client_id": clientID, "username": username,
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(k)}))})
	return string(b)
}

func mustPKCS8(k *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	return der
}

type cursor struct {
	q    string
	skip int
}

// Bot is one BotDefinition.
type Bot struct{ ID, Dev, Label, Type, User, Owner, Creator, Created string }

// Function is one GenAiFunctionDefinition.
type Function struct{ ID, Dev, Target, TargetType string }

// Fake is one org.
type Fake struct {
	// PageSize is the records per page (0: all in one); Deny makes the API answer 403; RefuseToken makes the
	// token endpoint answer 400; NoGenAi makes the GenAi objects unknown (400 INVALID_TYPE).
	PageSize                   int
	Deny, RefuseToken, NoGenAi bool
	// Description is served on bots, so a test can prove the connector does not keep it.
	Description string

	client, user string
	mu           sync.Mutex
	bots         []Bot
	users        map[string]string // user id -> e-mail address
	planners     map[string]string // planner id -> developer name
	funcs        []Function
	links        [][2]string // planner id, function id
	queries      []string
	cursors      map[string]cursor
	writes       int
}

// New returns a fake.
func New(client, user string, users map[string]string, bots []Bot, planners map[string]string, funcs []Function, links [][2]string) *Fake {
	return &Fake{client: client, user: user, users: users, bots: bots, planners: planners, funcs: funcs, links: links}
}

// Queries are the SOQL texts received.
func (f *Fake) Queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

// Writes counts requests other than GET and the token POST.
func (f *Fake) Writes() int { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/services/oauth2/token" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		parts := strings.Split(r.PostForm.Get("assertion"), ".")
		var c struct{ Iss, Sub string }
		if len(parts) == 3 {
			b, _ := base64.RawURLEncoding.DecodeString(parts[1])
			_ = json.Unmarshal(b, &c)
		}
		if f.RefuseToken || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || c.Iss != f.client || c.Sub != f.user {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": Token, "token_type": "Bearer", "instance_url": "https://evil.example"})
		return
	}
	if r.Method != http.MethodGet {
		f.mu.Lock()
		f.writes++
		f.mu.Unlock()
		http.Error(w, `[{"errorCode":"METHOD_NOT_ALLOWED"}]`, http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+Token {
		http.Error(w, `[{"errorCode":"INVALID_SESSION_ID"}]`, http.StatusUnauthorized)
		return
	}
	if f.Deny {
		http.Error(w, `[{"errorCode":"INSUFFICIENT_ACCESS"}]`, http.StatusForbidden)
		return
	}
	switch {
	case r.URL.Path == "/services/data/v61.0/query":
		f.query(w, r.URL.Query().Get("q"), 0)
	case strings.HasPrefix(r.URL.Path, "/services/data/v61.0/query/01g"):
		f.mu.Lock()
		cur, ok := f.cursors[strings.TrimPrefix(r.URL.Path, "/services/data/v61.0/query/")]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		f.query(w, cur.q, cur.skip)
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) query(w http.ResponseWriter, q string, skip int) {
	f.mu.Lock()
	if skip == 0 {
		f.queries = append(f.queries, q)
	}
	f.mu.Unlock()
	var rows []map[string]any
	switch {
	case strings.Contains(q, "FROM BotDefinition"):
		for _, b := range f.bots {
			rows = append(rows, map[string]any{"Id": b.ID, "DeveloperName": b.Dev, "MasterLabel": b.Label, "Type": b.Type, "BotUserId": b.User,
				"OwnerId": b.Owner, "CreatedById": b.Creator, "CreatedDate": b.Created, "Description": f.Description})
		}
		if strings.Contains(q, "LIMIT 10") {
			rows = rows[:min(10, len(rows))]
		}
	case strings.Contains(q, "FROM User WHERE Id IN ("):
		in := q[strings.Index(q, "IN (")+4:]
		asked := strings.Split(strings.TrimSuffix(in, ")"), ",")
		ids := make([]string, 0, len(f.users))
		for id := range f.users {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids { // the stored id is answered, never the text of the query
			if slices.Contains(asked, "'"+id+"'") {
				rows = append(rows, map[string]any{"Id": id, "Email": f.users[id]})
			}
		}
	case strings.Contains(q, "GenAi") && f.NoGenAi:
		http.Error(w, `[{"errorCode":"INVALID_TYPE"}]`, http.StatusBadRequest)
		return
	case strings.Contains(q, "FROM GenAiPlannerDefinition"):
		// a fixed order, as Salesforce keeps across the pages of one query: ranging over the map would
		// reorder every page and could repeat or skip a planner (issue #628)
		ids := make([]string, 0, len(f.planners))
		for id := range f.planners {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			rows = append(rows, map[string]any{"Id": id, "DeveloperName": f.planners[id]})
		}
	case strings.Contains(q, "FROM GenAiFunctionDefinition"):
		for _, x := range f.funcs {
			rows = append(rows, map[string]any{"Id": x.ID, "DeveloperName": x.Dev, "InvocationTarget": x.Target, "InvocationTargetType": x.TargetType})
		}
	case strings.Contains(q, "FROM GenAiPlannerFunctionDef"):
		for _, l := range f.links {
			rows = append(rows, map[string]any{"PlannerId": l[0], "FunctionId": l[1]})
		}
	default:
		http.Error(w, `[{"errorCode":"MALFORMED_QUERY"}]`, http.StatusBadRequest)
		return
	}
	size := f.PageSize
	if size <= 0 {
		size = len(rows)
	}
	end := min(skip+size, len(rows))
	if skip > len(rows) {
		skip = len(rows)
	}
	body := map[string]any{"totalSize": len(rows), "done": end >= len(rows), "records": append([]map[string]any{}, rows[skip:end]...)}
	if end < len(rows) {
		f.mu.Lock()
		if f.cursors == nil {
			f.cursors = map[string]cursor{}
		}
		id := "01gxx000000" + itoaN(len(f.cursors)) + "-2000"
		f.cursors[id] = cursor{q, end}
		f.mu.Unlock()
		body["nextRecordsUrl"] = "/services/data/v61.0/query/" + id
	}
	_ = json.NewEncoder(w).Encode(body)
}

func itoaN(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
