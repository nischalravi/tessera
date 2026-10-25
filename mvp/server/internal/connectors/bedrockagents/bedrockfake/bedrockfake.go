// Package bedrockfake is an in-process bedrock-agent API (issue #562) for tests: ListAgents, GetAgent,
// ListAgentActionGroups, GetAgentActionGroup, ListAgentKnowledgeBases and ListTagsForResource with paging,
// SigV4 verification (the fake signs the request it received again and compares), and the faults the API
// shows: a refused signature, an access-denied answer, throttling, server errors, an agent deleted mid-read
// and an answer that is not JSON.
//
// It serves reads only: any other operation is a 405. Every answer is a stored value or a fixed body:
// nothing a request carried is echoed.
package bedrockfake

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
)

// Group is an action group.
type Group struct {
	ID, Name, State, Lambda, Signature string
	Functions                          []string
}

// KB is an agent's knowledge base association.
type KB struct{ ID, State string }

// Agent is one agent.
type Agent struct {
	ID, Name, ARN, Status, Description, Role, Model string
	Created                                         float64 // epoch seconds
	Tags                                            map[string]string
	Groups                                          []Group
	KBs                                             []KB
}

// Faults to inject.
type Faults struct {
	Throttle  int  // answer this many requests with 429 ThrottlingException
	Deny      bool // answer every request 403 AccessDeniedException
	ServerErr int  // answer this many requests 500
	NotJSON   bool
	Gone      string // GetAgent of this id answers 404
}

// Fake is one account and region.
type Fake struct {
	AccessKey, Secret, Token, Region string
	PageSize                         int

	mu     sync.Mutex
	agents []Agent
	faults Faults
	ops    map[string]int
	writes int
	bad    int
}

// New returns a fake that accepts one key pair (and session token, when not empty).
func New(accessKey, secret, token, region string, agents ...Agent) *Fake {
	return &Fake{AccessKey: accessKey, Secret: secret, Token: token, Region: region, agents: agents, ops: map[string]int{}}
}

// SetFaults replaces the injected faults.
func (f *Fake) SetFaults(x Faults) { f.mu.Lock(); f.faults = x; f.mu.Unlock() }

// Ops returns how many times each operation was served.
func (f *Fake) Ops() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for k, v := range f.ops {
		out[k] = v
	}
	return out
}

// Writes is how many requests asked for an operation that is not one of the served reads.
func (f *Fake) Writes() int { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }

// BadSignatures is how many requests failed signature verification.
func (f *Fake) BadSignatures() int { f.mu.Lock(); defer f.mu.Unlock(); return f.bad }

func deny(w http.ResponseWriter, status int, code string) {
	w.Header().Set("X-Amzn-Errortype", code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"message":"error"}`))
}

// verify signs the received request again and compares the Authorization header.
func (f *Fake) verify(r *http.Request, body []byte) bool {
	auth := r.Header.Get("Authorization")
	_, rest, ok := strings.Cut(auth, "Credential=")
	if !ok {
		return false
	}
	scope, _, _ := strings.Cut(rest, ",")
	parts := strings.Split(scope, "/")
	if len(parts) != 5 || parts[0] != f.AccessKey || parts[2] != f.Region || parts[3] != "bedrock" {
		return false
	}
	now, err := time.Parse(sigv4.TimeLayout, r.Header.Get("X-Amz-Date"))
	if err != nil {
		return false
	}
	if f.Token != "" && r.Header.Get("X-Amz-Security-Token") != f.Token {
		return false
	}
	u := url.URL{Scheme: "https", Host: r.Host, Path: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery}
	again, err := http.NewRequest(r.Method, u.String(), nil)
	if err != nil {
		return false
	}
	for k, vs := range r.Header {
		l := strings.ToLower(k)
		if l == "content-type" || l == "content-md5" || (strings.HasPrefix(l, "x-amz-") && l != "x-amz-date" && l != "x-amz-security-token") {
			again.Header[k] = vs
		}
	}
	c := sigv4.Credentials{AccessKeyID: f.AccessKey, SecretAccessKey: f.Secret, SessionToken: f.Token}
	if err := sigv4.Sign(again, body, c, f.Region, "bedrock", now); err != nil {
		return false
	}
	return again.Header.Get("Authorization") == auth
}

// ServeHTTP implements http.Handler.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.verify(r, body) {
		f.bad++
		deny(w, http.StatusForbidden, "InvalidSignatureException")
		return
	}
	if f.faults.Deny {
		deny(w, http.StatusForbidden, "AccessDeniedException")
		return
	}
	if f.faults.Throttle > 0 {
		f.faults.Throttle--
		deny(w, http.StatusTooManyRequests, "ThrottlingException")
		return
	}
	if f.faults.ServerErr > 0 {
		f.faults.ServerErr--
		deny(w, http.StatusInternalServerError, "InternalServerException")
		return
	}
	// the decoded path: AWS ARNs are one segment on the wire
	segs := strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/")
	for i, s := range segs {
		if d, err := url.PathUnescape(s); err == nil {
			segs[i] = d
		}
	}
	op, out := f.route(r.Method, segs, body)
	switch {
	case op == "":
		f.writes++ // an operation the fake does not serve: none of them is a read the connector needs
		deny(w, http.StatusMethodNotAllowed, "UnknownOperationException")
	case out == nil:
		deny(w, http.StatusNotFound, "ResourceNotFoundException")
	default:
		f.ops[op]++
		w.Header().Set("Content-Type", "application/json")
		if f.faults.NotJSON {
			_, _ = w.Write([]byte("<html>not json</html>"))
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}

func (f *Fake) find(id string) *Agent {
	for i := range f.agents {
		if f.agents[i].ID == id {
			return &f.agents[i]
		}
	}
	return nil
}

// page returns the slice bounds of the page the body's nextToken asks for and the next token.
func (f *Fake) page(body []byte, n int) (int, int, string) {
	var req struct {
		Next string `json:"nextToken"`
	}
	_ = json.Unmarshal(body, &req)
	start := 0
	if req.Next != "" {
		start, _ = strconv.Atoi(strings.TrimPrefix(req.Next, "t"))
	}
	if start < 0 || start > n {
		start = n
	}
	end := n
	if f.PageSize > 0 && start+f.PageSize < n {
		end = start + f.PageSize
	}
	next := ""
	if end < n {
		next = fmt.Sprintf("t%d", end)
	}
	return start, end, next
}

func withNext(m map[string]any, next string) map[string]any {
	if next != "" {
		m["nextToken"] = next
	}
	return m
}

func (f *Fake) route(method string, s []string, body []byte) (string, any) {
	switch {
	case method == http.MethodPost && len(s) == 1 && s[0] == "agents":
		a, b, next := f.page(body, len(f.agents))
		list := []map[string]any{}
		for _, x := range f.agents[a:b] {
			list = append(list, map[string]any{"agentId": x.ID, "agentName": x.Name, "agentStatus": x.Status})
		}
		return "ListAgents", withNext(map[string]any{"agentSummaries": list}, next)
	case method == http.MethodGet && len(s) == 2 && s[0] == "agents":
		x := f.find(s[1])
		if x == nil || f.faults.Gone == s[1] {
			return "GetAgent", nil
		}
		return "GetAgent", map[string]any{"agent": map[string]any{"agentId": x.ID, "agentName": x.Name, "agentArn": x.ARN, "agentStatus": x.Status,
			"description": x.Description, "agentResourceRoleArn": x.Role, "foundationModel": x.Model, "createdAt": x.Created}}
	case method == http.MethodGet && len(s) == 2 && s[0] == "tags":
		for _, x := range f.agents {
			if x.ARN == s[1] {
				return "ListTagsForResource", map[string]any{"tags": x.Tags}
			}
		}
		return "ListTagsForResource", nil
	case method == http.MethodPost && len(s) == 5 && s[0] == "agents" && s[2] == "agentversions" && s[3] == "DRAFT" && s[4] == "actiongroups":
		x := f.find(s[1])
		if x == nil {
			return "ListAgentActionGroups", nil
		}
		a, b, next := f.page(body, len(x.Groups))
		list := []map[string]any{}
		for _, g := range x.Groups[a:b] {
			list = append(list, map[string]any{"actionGroupId": g.ID, "actionGroupName": g.Name, "actionGroupState": g.State})
		}
		return "ListAgentActionGroups", withNext(map[string]any{"actionGroupSummaries": list}, next)
	case method == http.MethodGet && len(s) == 6 && s[0] == "agents" && s[2] == "agentversions" && s[3] == "DRAFT" && s[4] == "actiongroups":
		x := f.find(s[1])
		if x == nil {
			return "GetAgentActionGroup", nil
		}
		for _, g := range x.Groups {
			if g.ID == s[5] {
				grp := map[string]any{"actionGroupId": g.ID, "actionGroupName": g.Name, "actionGroupState": g.State}
				if g.Lambda != "" {
					grp["actionGroupExecutor"] = map[string]any{"lambda": g.Lambda}
				} else {
					grp["actionGroupExecutor"] = map[string]any{"customControl": "RETURN_CONTROL"}
				}
				if g.Signature != "" {
					grp["parentActionGroupSignature"] = g.Signature
				}
				fns := []map[string]any{}
				for _, n := range g.Functions {
					fns = append(fns, map[string]any{"name": n, "description": "free text the connector must not keep"})
				}
				grp["functionSchema"] = map[string]any{"functions": fns}
				return "GetAgentActionGroup", map[string]any{"agentActionGroup": grp}
			}
		}
		return "GetAgentActionGroup", nil
	case method == http.MethodPost && len(s) == 5 && s[0] == "agents" && s[2] == "agentversions" && s[3] == "DRAFT" && s[4] == "knowledgebases":
		x := f.find(s[1])
		if x == nil {
			return "ListAgentKnowledgeBases", nil
		}
		a, b, next := f.page(body, len(x.KBs))
		list := []map[string]any{}
		for _, k := range x.KBs[a:b] {
			list = append(list, map[string]any{"knowledgeBaseId": k.ID, "knowledgeBaseState": k.State})
		}
		return "ListAgentKnowledgeBases", withNext(map[string]any{"agentKnowledgeBaseSummaries": list}, next)
	}
	return "", nil
}
