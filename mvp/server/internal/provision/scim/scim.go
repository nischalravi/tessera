// Package scim is a SCIM 2.0 client (RFC 7643, RFC 7644) for provisioning
// accounts and group memberships, and for re-reading them to verify.
//
// Two dialects are supported. "standard" follows the RFCs. "entra" speaks the
// way Microsoft Entra ID's provisioning service does: PATCH operation names
// are capitalised ("Add", "Replace", "Remove") and booleans travel as the
// strings "True" and "False". Reads accept either form from any dialect,
// because servers answer with strings whatever they were sent.
package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Dialects.
const (
	Standard = "standard"
	Entra    = "entra"
)

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	pageSize    = 100
	maxPages    = 200 // 20,000 members; a larger group is reported, not walked forever
	maxBody     = 512 << 10
)

// Client talks to one SCIM service. HTTP must be an internal/safehttp client.
type Client struct {
	HTTP    *http.Client
	BaseURL string // the service root, e.g. https://example.com/scim/v2
	Token   string // bearer token; empty sends none
	Dialect string
	// Header is added to every request (the dev fake target reads its fault
	// mode from one).
	Header http.Header
}

// flexBool reads a SCIM boolean sent as a JSON boolean or, as Entra and some
// others do, as a string ("True", "false", ...).
type flexBool bool

func (b *flexBool) UnmarshalJSON(raw []byte) error {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	switch strings.ToLower(s) {
	case "true":
		*b = true
	case "false", "null", "":
		*b = false
	default:
		return fmt.Errorf("scim: %q is not a boolean", s)
	}
	return nil
}

type user struct {
	ID          string   `json:"id"`
	UserName    string   `json:"userName"`
	ExternalID  string   `json:"externalId"`
	DisplayName string   `json:"displayName"`
	Active      flexBool `json:"active"`
	Emails      []struct {
		Value   string   `json:"value"`
		Primary flexBool `json:"primary"`
	} `json:"emails"`
}

type member struct {
	Value string `json:"value"`
}

type group struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	ExternalID  string   `json:"externalId"`
	Members     []member `json:"members"`
}

type listPage struct {
	TotalResults int               `json:"totalResults"`
	ItemsPerPage int               `json:"itemsPerPage"`
	StartIndex   int               `json:"startIndex"`
	Resources    []json.RawMessage `json:"Resources"`
}

// ---------------------------------------------------------------- transport

func (c *Client) url(path string, q url.Values) string {
	u := strings.TrimRight(c.BaseURL, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// do sends one request and returns the status and body. A transport failure
// is a retryable *target.Error.
func (c *Client) do(ctx context.Context, method, op, path string, q url.Values, key string, body any) (int, []byte, error) {
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path, q), rd)
	if err != nil {
		return 0, nil, target.Permanent("%s: bad target URL: %v", op, err)
	}
	for k, v := range c.Header {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "application/scim+json, application/json")
	if k, ok := ctx.Value(opKey{}).(string); ok {
		req.Header.Set("X-Tessera-Operation", k)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if key != "" && method != http.MethodGet {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, target.Transport(op, err)
	}
	defer resp.Body.Close()
	b, err := target.ReadBody(resp, maxBody)
	if err != nil {
		return 0, nil, target.Transport(op, err)
	}
	return resp.StatusCode, b, nil
}

func detail(b []byte) string {
	var e struct {
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(b, &e)
	return e.Detail
}

var safeFilter = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// list runs a filtered GET on a collection and returns every match across
// pages (startIndex is 1-based, per RFC 7644 3.4.2).
func (c *Client) list(ctx context.Context, op, path, filter string) ([]json.RawMessage, int, error) {
	var out []json.RawMessage
	for start := 1; ; {
		q := url.Values{"filter": {filter}, "startIndex": {strconv.Itoa(start)}, "count": {strconv.Itoa(pageSize)}}
		st, b, err := c.do(ctx, http.MethodGet, op, path, q, "", nil)
		if err != nil {
			return nil, 0, err
		}
		if st != http.StatusOK {
			return nil, st, target.Fail(op, st, detail(b))
		}
		var p listPage
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, st, target.Permanent("%s: unreadable list response: %v", op, err)
		}
		out = append(out, p.Resources...)
		n := len(p.Resources)
		start += n
		if n == 0 || start > p.TotalResults || start > maxPages*pageSize {
			return out, st, nil
		}
	}
}

func (c *Client) findUser(ctx context.Context, username string) (*user, error) {
	rs, _, err := c.list(ctx, "find user", "/Users", `userName eq "`+safeFilter.Replace(username)+`"`)
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		var u user
		if err := json.Unmarshal(r, &u); err != nil {
			return nil, target.Permanent("find user: unreadable user: %v", err)
		}
		if strings.EqualFold(u.UserName, username) {
			return &u, nil
		}
	}
	return nil, nil
}

// findGroup finds a group by external id, then by display name. A server that
// rejects the externalId filter (400) falls through to the name.
func (c *Client) findGroup(ctx context.Context, g target.Group) (*group, error) {
	try := func(filter string) (*group, error) {
		rs, st, err := c.list(ctx, "find group", "/Groups", filter)
		if err != nil {
			var te *target.Error
			if st == http.StatusBadRequest && asTarget(err, &te) {
				return nil, nil
			}
			return nil, err
		}
		if len(rs) == 0 {
			return nil, nil
		}
		var out group
		if err := json.Unmarshal(rs[0], &out); err != nil {
			return nil, target.Permanent("find group: unreadable group: %v", err)
		}
		return &out, nil
	}
	if g.ExternalID != "" {
		if out, err := try(`externalId eq "` + safeFilter.Replace(g.ExternalID) + `"`); err != nil || out != nil {
			return out, err
		}
	}
	if g.Name != "" {
		return try(`displayName eq "` + safeFilter.Replace(g.Name) + `"`)
	}
	return nil, nil
}

func asTarget(err error, out **target.Error) bool {
	te, ok := err.(*target.Error)
	if ok {
		*out = te
	}
	return ok
}

// isMember walks a group's members a page at a time, so a group larger than
// one response still answers correctly. The walk stops at the first page that
// adds nobody new: an empty page, or the repeat a server that ignores paging
// sends.
func (c *Client) isMember(ctx context.Context, groupID, userID string) (bool, error) {
	seen := map[string]bool{}
	for start, pages := 1, 0; pages < maxPages; pages++ {
		q := url.Values{"attributes": {"members"}, "startIndex": {strconv.Itoa(start)}, "count": {strconv.Itoa(pageSize)}}
		st, b, err := c.do(ctx, http.MethodGet, "read group", "/Groups/"+url.PathEscape(groupID), q, "", nil)
		if err != nil {
			return false, err
		}
		if st == http.StatusNotFound {
			return false, nil
		}
		if st != http.StatusOK {
			return false, target.Fail("read group", st, detail(b))
		}
		var g group
		if err := json.Unmarshal(b, &g); err != nil {
			return false, target.Permanent("read group: unreadable group: %v", err)
		}
		fresh := 0
		for _, m := range g.Members {
			if m.Value == userID {
				return true, nil
			}
			if !seen[m.Value] {
				seen[m.Value] = true
				fresh++
			}
		}
		// A server may cap a page below the count asked for, so only an
		// empty page (or one that repeats members, a server that ignores
		// paging) ends the walk.
		if fresh == 0 {
			return false, nil
		}
		start += len(g.Members)
	}
	return false, target.Permanent("read group: more than %d members; cannot verify membership", maxPages*pageSize)
}

// ---------------------------------------------------------------- patch

func (c *Client) opName(op string) string {
	if c.Dialect == Entra {
		return strings.ToUpper(op[:1]) + op[1:]
	}
	return op
}

// boolValue renders a boolean the way the dialect sends it.
func (c *Client) boolValue(b bool) any {
	if c.Dialect == Entra {
		if b {
			return "True"
		}
		return "False"
	}
	return b
}

func (c *Client) patch(ctx context.Context, op, path, id, key string, ops ...map[string]any) error {
	body := map[string]any{"schemas": []string{schemaPatch}, "Operations": ops}
	st, b, err := c.do(ctx, http.MethodPatch, op, path+"/"+url.PathEscape(id), nil, key, body)
	if err != nil {
		return err
	}
	switch st {
	case http.StatusOK, http.StatusNoContent:
		return nil
	}
	return target.Fail(op, st, detail(b))
}

var attrRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.:\[\]" =-]{0,79}$`)

// ---------------------------------------------------------------- Apply

// opKey carries the operation kind to the transport, which names it in the
// X-Tessera-Operation header (informational: the target's own logs show why).
type opKey struct{}

// Apply sends the change.
func (c *Client) Apply(ctx context.Context, r target.Request) error {
	ctx = context.WithValue(ctx, opKey{}, r.Kind)
	switch r.Kind {
	case target.CreateAccount:
		return c.create(ctx, r)
	case target.UpdateAccount:
		return c.update(ctx, r)
	case target.DisableAccount:
		u, err := c.findUser(ctx, r.Account.Username)
		if err != nil {
			return err
		}
		if u == nil {
			return target.Permanent("disable account: %s does not exist in the target", r.Account.Username)
		}
		if !bool(u.Active) {
			return nil
		}
		return c.patch(ctx, "disable account", "/Users", u.ID, r.Key,
			map[string]any{"op": c.opName("replace"), "path": "active", "value": c.boolValue(false)})
	case target.DeleteAccount:
		u, err := c.findUser(ctx, r.Account.Username)
		if err != nil || u == nil {
			return err
		}
		st, b, err := c.do(ctx, http.MethodDelete, "delete account", "/Users/"+url.PathEscape(u.ID), nil, r.Key, nil)
		if err != nil {
			return err
		}
		if st == http.StatusNoContent || st == http.StatusOK || st == http.StatusNotFound {
			return nil
		}
		return target.Fail("delete account", st, detail(b))
	case target.AddEntitlement, target.RemoveEntitlement:
		return c.membership(ctx, r)
	}
	return target.Permanent("unsupported operation %q", r.Kind)
}

func (c *Client) create(ctx context.Context, r target.Request) error {
	a := r.Account
	if u, err := c.findUser(ctx, a.Username); err != nil || u != nil {
		return err
	}
	body := map[string]any{"schemas": []string{schemaUser}, "userName": a.Username, "active": c.boolValue(true)}
	if a.ExternalID != "" {
		body["externalId"] = a.ExternalID
	}
	if a.DisplayName != "" {
		body["displayName"] = a.DisplayName
	}
	if a.Email != "" {
		body["emails"] = []map[string]any{{"value": a.Email, "type": "work", "primary": c.boolValue(true)}}
	}
	st, b, err := c.do(ctx, http.MethodPost, "create account", "/Users", nil, r.Key, body)
	if err != nil {
		return err
	}
	// 409: it appeared between the read and the write (another run of this
	// operation); the change is in place.
	if st == http.StatusCreated || st == http.StatusOK || st == http.StatusConflict {
		return nil
	}
	return target.Fail("create account", st, detail(b))
}

func (c *Client) update(ctx context.Context, r target.Request) error {
	u, err := c.findUser(ctx, r.Account.Username)
	if err != nil {
		return err
	}
	if u == nil {
		return target.Permanent("update account: %s does not exist in the target", r.Account.Username)
	}
	var ops []map[string]any
	for _, path := range sortedKeys(r.Account.Attrs) {
		if !attrRE.MatchString(path) {
			return target.Permanent("update account: %q is not a valid attribute path", path)
		}
		ops = append(ops, map[string]any{"op": c.opName("replace"), "path": path, "value": r.Account.Attrs[path]})
	}
	if len(ops) == 0 {
		return nil
	}
	return c.patch(ctx, "update account", "/Users", u.ID, r.Key, ops...)
}

func (c *Client) membership(ctx context.Context, r target.Request) error {
	add := r.Kind == target.AddEntitlement
	u, err := c.findUser(ctx, r.Account.Username)
	if err != nil {
		return err
	}
	g, err := c.findGroup(ctx, r.Group)
	if err != nil {
		return err
	}
	switch {
	case add && u == nil:
		return target.Permanent("add entitlement: %s does not exist in the target", r.Account.Username)
	case add && g == nil:
		return target.Permanent("add entitlement: group %q does not exist in the target", r.Group.Name)
	case !add && (u == nil || g == nil):
		return nil // nothing to remove
	}
	in, err := c.isMember(ctx, g.ID, u.ID)
	if err != nil || in == add {
		return err
	}
	if add {
		return c.patch(ctx, "add entitlement", "/Groups", g.ID, r.Key,
			map[string]any{"op": c.opName("add"), "path": "members", "value": []member{{Value: u.ID}}})
	}
	return c.removeMember(ctx, g.ID, u.ID, r.Key)
}

// removeMember takes a user out of a group. PATCH filter paths interoperate
// poorly across servers, so the standard dialect tries the RFC 7644 filter
// path first and, if the server refuses it (400 or 501), the value-list form
// (a "remove" on members naming the member). The entra dialect sends the
// value-list form, as Entra's own provisioning client does.
func (c *Client) removeMember(ctx context.Context, groupID, userID, key string) error {
	byValue := map[string]any{"op": c.opName("remove"), "path": "members", "value": []member{{Value: userID}}}
	if c.Dialect == Entra {
		return c.patch(ctx, "remove entitlement", "/Groups", groupID, key, byValue)
	}
	byFilter := map[string]any{"op": c.opName("remove"), "path": `members[value eq "` + safeFilter.Replace(userID) + `"]`}
	err := c.patch(ctx, "remove entitlement", "/Groups", groupID, key, byFilter)
	var te *target.Error
	if asTarget(err, &te) && (te.Status == http.StatusBadRequest || te.Status == http.StatusNotImplemented) {
		return c.patch(ctx, "remove entitlement", "/Groups", groupID, key, byValue)
	}
	return err
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// insertion sort: attribute maps are tiny
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ---------------------------------------------------------------- Verify

// Verify re-reads the target.
func (c *Client) Verify(ctx context.Context, r target.Request) (target.Verdict, error) {
	ctx = context.WithValue(ctx, opKey{}, "verify:"+r.Kind)
	u, err := c.findUser(ctx, r.Account.Username)
	if err != nil {
		return target.Verdict{}, err
	}
	switch r.Kind {
	case target.CreateAccount:
		return verdict(u != nil, "account exists", present(u != nil, "account exists", "account missing")), nil
	case target.DeleteAccount:
		return verdict(u == nil, "account absent", present(u != nil, "account still exists", "account absent")), nil
	case target.DisableAccount:
		if u == nil {
			return verdict(true, "account disabled or absent", "account absent"), nil
		}
		return verdict(!bool(u.Active), "account disabled", "active="+strconv.FormatBool(bool(u.Active))), nil
	case target.UpdateAccount:
		if u == nil {
			return verdict(false, "account updated", "account missing"), nil
		}
		return c.verifyUpdate(ctx, u, r)
	case target.AddEntitlement, target.RemoveEntitlement:
		add := r.Kind == target.AddEntitlement
		want := "not a member of " + groupLabel(r.Group)
		if add {
			want = "member of " + groupLabel(r.Group)
		}
		g, err := c.findGroup(ctx, r.Group)
		if err != nil {
			return target.Verdict{}, err
		}
		in := false
		if u != nil && g != nil {
			if in, err = c.isMember(ctx, g.ID, u.ID); err != nil {
				return target.Verdict{}, err
			}
		}
		got := "not a member of " + groupLabel(r.Group)
		if in {
			got = "member of " + groupLabel(r.Group)
		}
		return verdict(in == add, want, got), nil
	}
	return target.Verdict{}, target.Permanent("unsupported operation %q", r.Kind)
}

func (c *Client) verifyUpdate(ctx context.Context, u *user, r target.Request) (target.Verdict, error) {
	// Re-read the whole resource: the list result may be a projection.
	st, b, err := c.do(ctx, http.MethodGet, "read user", "/Users/"+url.PathEscape(u.ID), nil, "", nil)
	if err != nil {
		return target.Verdict{}, err
	}
	if st != http.StatusOK {
		return target.Verdict{}, target.Fail("read user", st, detail(b))
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return target.Verdict{}, target.Permanent("read user: unreadable user: %v", err)
	}
	for _, path := range sortedKeys(r.Account.Attrs) {
		want := r.Account.Attrs[path]
		if got := fmt.Sprint(raw[path]); raw[path] == nil || got != want {
			return verdict(false, path+"="+want, path+"="+got), nil
		}
	}
	return verdict(true, "attributes updated", "attributes updated"), nil
}

func groupLabel(g target.Group) string {
	if g.Name != "" {
		return g.Name
	}
	return g.ExternalID
}

func present(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func verdict(ok bool, want, got string) target.Verdict {
	return target.Verdict{OK: ok, Expected: want, Observed: got}
}
