// Package okta is a native connector for the Okta Users and Groups APIs
// (/api/v1). It is used where SCIM is not enough or not available: Okta's own
// group membership endpoints are the source of truth for who is in a group.
//
// Auth is an API token (SSWS). Collections are paged with Link headers
// (rel="next"); every next link must stay on the configured origin.
package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

const (
	pageLimit = 200
	maxPages  = 100
	maxBody   = 512 << 10
)

// Client talks to one Okta org. HTTP must be an internal/safehttp client.
type Client struct {
	HTTP    *http.Client
	BaseURL string // https://example.okta.com
	Token   string
}

type oktaUser struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Profile struct {
		Login     string `json:"login"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"profile"`
}

type oktaGroup struct {
	ID      string `json:"id"`
	Profile struct {
		Name string `json:"name"`
	} `json:"profile"`
}

func (c *Client) origin() *url.URL {
	u, _ := url.Parse(c.BaseURL)
	return u
}

func (c *Client) req(ctx context.Context, method, op, rawURL, key string, body any) (*http.Response, []byte, error) {
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return nil, nil, target.Permanent("%s: bad target URL: %v", op, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "SSWS "+c.Token)
	}
	if key != "" && method != http.MethodGet {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, target.Transport(op, err)
	}
	defer resp.Body.Close()
	b, err := target.ReadBody(resp, maxBody)
	if err != nil {
		return nil, nil, target.Transport(op, err)
	}
	return resp, b, nil
}

func (c *Client) api(path string, q url.Values) string {
	u := strings.TrimRight(c.BaseURL, "/") + "/api/v1" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

func errSummary(b []byte) string {
	var e struct {
		Summary string `json:"errorSummary"`
	}
	_ = json.Unmarshal(b, &e)
	return e.Summary
}

var nextRE = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// nextLink returns the rel="next" URL of a response, which must stay on the
// org's origin (a next link is data from the network, not a trusted URL).
func (c *Client) nextLink(resp *http.Response) (string, bool, error) {
	for _, h := range resp.Header.Values("Link") {
		if m := nextRE.FindStringSubmatch(h); m != nil {
			u, err := url.Parse(m[1])
			o := c.origin()
			if err != nil || o == nil || u.Scheme != o.Scheme || u.Host != o.Host {
				return "", false, target.Permanent("paging link leaves the Okta org: %q", m[1])
			}
			return u.String(), true, nil
		}
	}
	return "", false, nil
}

// getAll pages through a collection, calling each for every page's raw array.
func (c *Client) getAll(ctx context.Context, op, first string, each func([]json.RawMessage) (stop bool)) error {
	next := first
	for page := 0; next != "" && page < maxPages; page++ {
		resp, b, err := c.req(ctx, http.MethodGet, op, next, "", nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return target.Fail(op, resp.StatusCode, errSummary(b))
		}
		var items []json.RawMessage
		if err := json.Unmarshal(b, &items); err != nil {
			return target.Permanent("%s: unreadable list response: %v", op, err)
		}
		if each(items) {
			return nil
		}
		link, ok, err := c.nextLink(resp)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		next = link
	}
	if next != "" {
		return target.Permanent("%s: more than %d pages; stopping", op, maxPages)
	}
	return nil
}

var safeSearch = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func (c *Client) findUser(ctx context.Context, login string) (*oktaUser, error) {
	q := url.Values{"search": {`profile.login eq "` + safeSearch.Replace(login) + `"`}, "limit": {"2"}}
	var found *oktaUser
	err := c.getAll(ctx, "find user", c.api("/users", q), func(items []json.RawMessage) bool {
		for _, it := range items {
			var u oktaUser
			if json.Unmarshal(it, &u) == nil && strings.EqualFold(u.Profile.Login, login) {
				found = &u
				return true
			}
		}
		return false
	})
	return found, err
}

// findGroup resolves a group by Okta id, then by exact name.
func (c *Client) findGroup(ctx context.Context, g target.Group) (*oktaGroup, error) {
	if g.ExternalID != "" {
		resp, b, err := c.req(ctx, http.MethodGet, "find group", c.api("/groups/"+url.PathEscape(g.ExternalID), nil), "", nil)
		if err != nil {
			return nil, err
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var out oktaGroup
			if err := json.Unmarshal(b, &out); err != nil {
				return nil, target.Permanent("find group: unreadable group: %v", err)
			}
			return &out, nil
		case http.StatusNotFound:
		default:
			return nil, target.Fail("find group", resp.StatusCode, errSummary(b))
		}
	}
	name := g.Name
	if name == "" {
		name = g.ExternalID
	}
	if name == "" {
		return nil, nil
	}
	var found *oktaGroup
	q := url.Values{"q": {name}, "limit": {strconv.Itoa(pageLimit)}}
	err := c.getAll(ctx, "find group", c.api("/groups", q), func(items []json.RawMessage) bool {
		for _, it := range items {
			var gr oktaGroup
			if json.Unmarshal(it, &gr) == nil && strings.EqualFold(gr.Profile.Name, name) {
				found = &gr
				return true
			}
		}
		return false
	})
	return found, err
}

func (c *Client) isMember(ctx context.Context, groupID, userID string) (bool, error) {
	in := false
	q := url.Values{"limit": {strconv.Itoa(pageLimit)}}
	err := c.getAll(ctx, "read group members", c.api("/groups/"+url.PathEscape(groupID)+"/users", q), func(items []json.RawMessage) bool {
		for _, it := range items {
			var u oktaUser
			if json.Unmarshal(it, &u) == nil && u.ID == userID {
				in = true
				return true
			}
		}
		return false
	})
	return in, err
}

func disabled(status string) bool { return status == "DEPROVISIONED" || status == "SUSPENDED" }

func splitName(a target.Account) (first, last string) {
	n := strings.Fields(a.DisplayName)
	switch len(n) {
	case 0:
		return a.Username, "-"
	case 1:
		return n[0], "-"
	}
	return n[0], strings.Join(n[1:], " ")
}

// Apply sends the change.
func (c *Client) Apply(ctx context.Context, r target.Request) error {
	switch r.Kind {
	case target.CreateAccount:
		if u, err := c.findUser(ctx, r.Account.Username); err != nil || u != nil {
			return err
		}
		first, last := splitName(r.Account)
		email := r.Account.Email
		if email == "" {
			email = r.Account.Username
		}
		body := map[string]any{"profile": map[string]string{"login": r.Account.Username, "email": email,
			"firstName": first, "lastName": last}}
		resp, b, err := c.req(ctx, http.MethodPost, "create account", c.api("/users", url.Values{"activate": {"true"}}), r.Key, body)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		return target.Fail("create account", resp.StatusCode, errSummary(b))
	case target.UpdateAccount:
		u, err := c.findUser(ctx, r.Account.Username)
		if err != nil {
			return err
		}
		if u == nil {
			return target.Permanent("update account: %s does not exist in the target", r.Account.Username)
		}
		profile := map[string]string{}
		for k, v := range r.Account.Attrs {
			if !profileAttr.MatchString(k) {
				return target.Permanent("update account: %q is not a valid profile attribute", k)
			}
			profile[k] = v
		}
		if len(profile) == 0 {
			return nil
		}
		resp, b, err := c.req(ctx, http.MethodPost, "update account", c.api("/users/"+url.PathEscape(u.ID), nil), r.Key,
			map[string]any{"profile": profile})
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		return target.Fail("update account", resp.StatusCode, errSummary(b))
	case target.DisableAccount, target.DeleteAccount:
		u, err := c.findUser(ctx, r.Account.Username)
		if err != nil {
			return err
		}
		if u == nil {
			if r.Kind == target.DeleteAccount {
				return nil
			}
			return target.Permanent("disable account: %s does not exist in the target", r.Account.Username)
		}
		if !disabled(u.Status) {
			if err := c.post204(ctx, "deactivate account", c.api("/users/"+url.PathEscape(u.ID)+"/lifecycle/deactivate", nil), r.Key); err != nil {
				return err
			}
		}
		if r.Kind == target.DeleteAccount {
			// Okta deletes a deprovisioned user permanently.
			resp, b, err := c.req(ctx, http.MethodDelete, "delete account", c.api("/users/"+url.PathEscape(u.ID), nil), r.Key, nil)
			if err != nil {
				return err
			}
			if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
				return target.Fail("delete account", resp.StatusCode, errSummary(b))
			}
		}
		return nil
	case target.AddEntitlement, target.RemoveEntitlement:
		return c.membership(ctx, r)
	}
	return target.Permanent("unsupported operation %q", r.Kind)
}

// profileAttr are the profile attributes an update may change (the ones
// Verify can read back).
var profileAttr = regexp.MustCompile(`^(email|firstName|lastName)$`)

func (c *Client) post204(ctx context.Context, op, rawURL, key string) error {
	resp, b, err := c.req(ctx, http.MethodPost, op, rawURL, key, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return target.Fail(op, resp.StatusCode, errSummary(b))
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
		return nil
	}
	in, err := c.isMember(ctx, g.ID, u.ID)
	if err != nil || in == add {
		return err
	}
	method, op := http.MethodDelete, "remove entitlement"
	if add {
		method, op = http.MethodPut, "add entitlement"
	}
	resp, b, err := c.req(ctx, method, op, c.api("/groups/"+url.PathEscape(g.ID)+"/users/"+url.PathEscape(u.ID), nil), r.Key, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	return target.Fail(op, resp.StatusCode, errSummary(b))
}

// Verify re-reads the target.
func (c *Client) Verify(ctx context.Context, r target.Request) (target.Verdict, error) {
	u, err := c.findUser(ctx, r.Account.Username)
	if err != nil {
		return target.Verdict{}, err
	}
	status := "absent"
	if u != nil {
		status = u.Status
	}
	switch r.Kind {
	case target.CreateAccount:
		return v(u != nil, "account exists", "account "+strings.ToLower(status)), nil
	case target.DeleteAccount:
		return v(u == nil, "account absent", "account "+strings.ToLower(status)), nil
	case target.DisableAccount:
		return v(u == nil || disabled(u.Status), "account deprovisioned or suspended", "status="+status), nil
	case target.UpdateAccount:
		if u == nil {
			return v(false, "account updated", "account absent"), nil
		}
		for _, k := range sortedKeys(r.Account.Attrs) {
			if got := profileValue(u, k); got != r.Account.Attrs[k] {
				return v(false, k+"="+r.Account.Attrs[k], k+"="+got), nil
			}
		}
		return v(true, "profile updated", "profile updated"), nil
	case target.AddEntitlement, target.RemoveEntitlement:
		add := r.Kind == target.AddEntitlement
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
		label := r.Group.Name
		if label == "" {
			label = r.Group.ExternalID
		}
		want, got := "not a member of "+label, "not a member of "+label
		if add {
			want = "member of " + label
		}
		if in {
			got = "member of " + label
		}
		return v(in == add, want, got), nil
	}
	return target.Verdict{}, target.Permanent("unsupported operation %q", r.Kind)
}

func profileValue(u *oktaUser, k string) string {
	switch k {
	case "email":
		return u.Profile.Email
	case "firstName":
		return u.Profile.FirstName
	case "lastName":
		return u.Profile.LastName
	case "login":
		return u.Profile.Login
	}
	return ""
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func v(ok bool, want, got string) target.Verdict {
	return target.Verdict{OK: ok, Expected: want, Observed: got}
}
