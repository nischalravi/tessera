// Package mcpserver inventories a Model Context Protocol server (issue #562): the tools it exposes and how it is
// reached, as a non-human identity linked to its owner. It is read-only: it sends initialize, the initialized
// notification and tools/list over the Streamable HTTP transport, and never calls a tool.
//
// Mapping onto Tessera's model:
//
//	server  -> identity mcp:<slug> (type service) owned by the configured owner, account kind service
//	tool    -> resource (kind mcp_tool) and permission "call" on it, a direct_grant from the server's account;
//	           privileged when the tool says it is destructive (annotations.destructiveHint) or, with no
//	           annotation, its name says it runs commands or deletes
//	server  -> an mcp_server finding (the existing MCP findings view), with the auth mode seen
//
// The auth mode is observed, not configured: with a credential set, the connector also sends initialize with no
// credential. A server that answers it accepts anonymous callers, which is tagged "anonymous_access" on every
// tool and reported as the auth_mode attribute of the account (anonymous or required).
//
// Tool descriptions and input schemas are never stored: they are free text written by the server's operator and
// a known prompt-injection carrier. Only the tool name and the hints are kept.
package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

const (
	protocolVersion = "2025-06-18"
	maxPages        = 50
	maxTools        = 2000
)

var (
	toolRE   = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
	headerRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	ownerRE  = regexp.MustCompile(`^[^@\s/]{1,200}@[A-Za-z0-9.-]{1,253}$`)
	nameRE   = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,128}$`)
)

// ErrCredential: the server refused the credential (401 or 403 with it).
var ErrCredential = errors.New("mcpserver: the credential was refused")

// Config configures one MCP server.
type Config struct {
	// URL is the server's MCP endpoint (https://tools.acme.example/mcp).
	URL string
	// Name is the display name; empty takes the name the server reports, then its host.
	Name string
	// Owner is the e-mail address of the person accountable for the server. MCP carries no owner.
	Owner string
	// AuthHeader is the header the credential is sent in. Empty: "Authorization: Bearer <credential>".
	AuthHeader string
	// Secret is the bearer token or API key.
	Secret connsync.Secret
}

// Client speaks MCP to one server.
type Client struct {
	api *connsync.Client
	u   *url.URL
	cfg Config
}

// Open validates cfg and returns the client. hc must be the server's shared safehttp client: it refuses
// private, loopback and link-local addresses at connect time, which is the host check of a customer-hosted URL.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client) (*Client, error) {
	if hc == nil {
		return nil, errors.New("mcpserver: an internal/safehttp client is required")
	}
	u, err := connsync.ParseBaseURL(cfg.URL, rt)
	if err != nil {
		return nil, fmt.Errorf("mcpserver: URL: %w", err)
	}
	if cfg.Secret.Empty() {
		return nil, errors.New("mcpserver: a credential is required")
	}
	if cfg.AuthHeader != "" && (!headerRE.MatchString(cfg.AuthHeader) || strings.EqualFold(cfg.AuthHeader, "host") || strings.EqualFold(cfg.AuthHeader, "content-type") ||
		strings.EqualFold(cfg.AuthHeader, "accept") || strings.EqualFold(cfg.AuthHeader, "content-length")) {
		return nil, errors.New("mcpserver: the credential header is not a usable header name")
	}
	if cfg.Owner != "" && !ownerRE.MatchString(cfg.Owner) {
		return nil, errors.New("mcpserver: the owner is an e-mail address")
	}
	if cfg.Name != "" && !nameRE.MatchString(cfg.Name) {
		return nil, errors.New("mcpserver: the name is 1 to 128 printable characters")
	}
	api := &connsync.Client{HC: hc, Header: http.Header{"User-Agent": {"tessera-connector/mcp"}}}
	return &Client{api: api, u: u, cfg: cfg}, nil
}

// Host is the server's host name.
func (c *Client) Host() string { return strings.ToLower(c.u.Hostname()) }

// Path is the endpoint path ("/mcp").
func (c *Client) Path() string {
	if c.u.Path == "" {
		return "/"
	}
	return c.u.Path
}

// Mode names how the client authenticates, for a prober.
func (c *Client) Mode() string {
	if c.cfg.AuthHeader != "" {
		return "api_key_header"
	}
	return "bearer_token"
}

// Identity names the credential holder for a prober: the endpoint host.
func (c *Client) Identity() string { return c.Host() }

// Tool is one tool a server exposes. Descriptions and schemas are not kept.
type Tool struct {
	Name string
	// ReadOnly and Destructive are the server's annotations; nil when it gave none.
	ReadOnly, Destructive *bool
}

// Info is what a read found.
type Info struct {
	// ServerName and ServerVersion are what the server reports about itself (clipped, printable).
	ServerName, ServerVersion string
	ProtocolVersion           string
	Tools                     []Tool
	// Anonymous is true when the server answered initialize with no credential (the check is made on every
	// read).
	Anonymous bool
}

type rpcReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int   `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResp struct {
	ID     *json.Number    `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code int `json:"code"`
	} `json:"error"`
}

// call posts one JSON-RPC message and returns the response with the matching id. A notification (id nil)
// has no answer. withCred says whether the credential is sent.
func (c *Client) call(ctx context.Context, session string, withCred bool, id *int, method string, params any) (json.RawMessage, http.Header, error) {
	body, err := json.Marshal(rpcReq{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return nil, nil, errors.New("mcpserver: cannot encode the request")
	}
	hdr := http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json, text/event-stream"}}
	if session != "" {
		hdr.Set("Mcp-Session-Id", session)
		hdr.Set("MCP-Protocol-Version", protocolVersion)
	}
	if withCred {
		if c.cfg.AuthHeader != "" {
			hdr.Set(c.cfg.AuthHeader, c.cfg.Secret.Reveal())
		} else {
			hdr.Set("Authorization", "Bearer "+c.cfg.Secret.Reveal())
		}
	}
	resp, err := c.api.Do(ctx, http.MethodPost, c.u.String(), hdr, body)
	if err != nil {
		if s := connsync.Status(err); withCred && (s == http.StatusUnauthorized || s == http.StatusForbidden) {
			return nil, nil, fmt.Errorf("%w: %w", ErrCredential, err)
		}
		return nil, nil, err
	}
	if id == nil {
		return nil, resp.Header, nil
	}
	msg, err := answer(resp, *id)
	return msg, resp.Header, err
}

// answer extracts the JSON-RPC response with the id from a JSON or event-stream body.
func answer(resp *connsync.Response, id int) (json.RawMessage, error) {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	var candidates [][]byte
	if strings.HasPrefix(ct, "text/event-stream") {
		sc := bufio.NewScanner(bytes.NewReader(resp.Body))
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		var data []byte
		flush := func() {
			if len(data) > 0 {
				candidates = append(candidates, data)
				data = nil
			}
		}
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				flush()
			case strings.HasPrefix(line, "data:"):
				if len(data) > 0 {
					data = append(data, '\n')
				}
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")...)
			}
		}
		flush()
	} else {
		candidates = [][]byte{resp.Body}
	}
	for _, cand := range candidates {
		var r rpcResp
		if connsync.DecodeJSON(cand, &r) != nil || r.ID == nil || r.ID.String() != fmt.Sprint(id) {
			continue
		}
		if r.Error != nil {
			return nil, fmt.Errorf("mcpserver: the server answered a request with a JSON-RPC error (code %d)", r.Error.Code)
		}
		return r.Result, nil
	}
	return nil, fmt.Errorf("%w: no JSON-RPC answer to the request", connsync.ErrMalformed)
}

func clip(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			break
		}
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// initialize opens a session and returns the server's self description.
func (c *Client) initialize(ctx context.Context, withCred bool) (info Info, session string, err error) {
	one := 1
	res, hdr, err := c.call(ctx, "", withCred, &one, "initialize", map[string]any{
		"protocolVersion": protocolVersion, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "tessera", "version": "1"}})
	if err != nil {
		return info, "", err
	}
	var r struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := connsync.DecodeJSON(res, &r); err != nil {
		return info, "", err
	}
	info.ServerName, info.ServerVersion, info.ProtocolVersion = clip(r.ServerInfo.Name, 128), clip(r.ServerInfo.Version, 64), clip(r.ProtocolVersion, 32)
	session = hdr.Get("Mcp-Session-Id")
	if len(session) > 256 || strings.ContainsAny(session, "\r\n") {
		session = ""
	}
	return info, session, nil
}

// Read opens a session, lists every tool and checks whether the server also answers without a credential.
func (c *Client) Read(ctx context.Context) (Info, error) {
	info, session, err := c.initialize(ctx, true)
	if err != nil {
		return info, err
	}
	if _, _, err := c.call(ctx, session, true, nil, "notifications/initialized", nil); err != nil {
		return info, err
	}
	cursor := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			return info, errors.New("mcpserver: the server lists more tool pages than the connector reads")
		}
		id := page + 2
		var params any
		if cursor != "" {
			params = map[string]string{"cursor": cursor}
		}
		res, _, err := c.call(ctx, session, true, &id, "tools/list", params)
		if err != nil {
			return info, err
		}
		var tl struct {
			Tools []struct {
				Name        string `json:"name"`
				Annotations struct {
					ReadOnly    *bool `json:"readOnlyHint"`
					Destructive *bool `json:"destructiveHint"`
				} `json:"annotations"`
			} `json:"tools"`
			Next string `json:"nextCursor"`
		}
		if err := connsync.DecodeJSON(res, &tl); err != nil {
			return info, err
		}
		for _, t := range tl.Tools {
			if len(info.Tools) >= maxTools {
				return info, errors.New("mcpserver: the server exposes more tools than the connector reads")
			}
			if toolRE.MatchString(t.Name) {
				info.Tools = append(info.Tools, Tool{Name: t.Name, ReadOnly: t.Annotations.ReadOnly, Destructive: t.Annotations.Destructive})
			}
		}
		if tl.Next == "" || len(tl.Next) > 2048 {
			break
		}
		cursor = tl.Next
	}
	info.Anonymous = c.anonymous(ctx)
	return info, nil
}

// anonymous reports whether initialize is answered without a credential. Any failure counts as "not
// anonymous": the check proves access, never its absence.
func (c *Client) anonymous(ctx context.Context) bool {
	_, _, err := c.initialize(ctx, false)
	return err == nil
}

// Probe is a bounded read for readiness: one initialize and the first tools page.
func (c *Client) Probe(ctx context.Context) (Info, error) {
	info, session, err := c.initialize(ctx, true)
	if err != nil {
		return info, err
	}
	if _, _, err := c.call(ctx, session, true, nil, "notifications/initialized", nil); err != nil {
		return info, err
	}
	id := 2
	res, _, err := c.call(ctx, session, true, &id, "tools/list", nil)
	if err != nil {
		return info, err
	}
	var tl struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := connsync.DecodeJSON(res, &tl); err != nil {
		return info, err
	}
	for _, t := range tl.Tools {
		if toolRE.MatchString(t.Name) {
			info.Tools = append(info.Tools, Tool{Name: t.Name})
		}
	}
	info.Anonymous = c.anonymous(ctx)
	return info, nil
}

// Format prints the client without its credential (every verb): fmt cannot call the redacting methods of
// unexported fields, so a bare %+v would show the token.
func (c *Client) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "mcpserver.Client{"+c.Host()+"}")
}
