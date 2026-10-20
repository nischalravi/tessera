package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// The SCIM 2.0 target (RFC 7643, RFC 7644) is a generic client with profiles
// for the services whose SCIM differs from the RFCs in ways that matter here:
//
//	generic              the RFCs: lower-case PATCH ops, members filter paths
//	aws_identity_center  AWS IAM Identity Center: remove takes a values list, 100 per page
//	github_emu           GitHub Enterprise Managed Users: capitalised PATCH ops, externalId
//	                     required on create, members excluded from list responses
//
// Group membership is read from the group resource and changed with PATCH
// (add and remove on "members"); member references are SCIM user ids (the
// account's external id by default). The profiles follow the services'
// documentation and have not been exercised against the live services.

type scimCfg struct {
	BaseURL  string `json:"base_url"`
	Profile  string `json:"profile"`
	PageSize int    `json:"page_size"`
}

type scimProfile struct {
	title         bool // PATCH ops are "Add" / "Remove"
	listMembers   bool // the list response carries members
	excludeParam  bool // list with excludedAttributes=members
	needExternal  bool // create needs externalId
	removeByValue bool // remove is {op, path: members, value: [...]}
	maxPage       int
}

var scimProfiles = map[string]scimProfile{
	"generic":             {listMembers: true, maxPage: 200},
	"aws_identity_center": {removeByValue: true, maxPage: 100},
	"github_emu":          {title: true, excludeParam: true, needExternal: true, maxPage: 100},
}

func parseSCIMConfig(c *Compiled) (scimCfg, error) {
	cfg := scimCfg{Profile: "generic"}
	if err := strictJSON(c.Target, &cfg); err != nil {
		return cfg, cfgErr("target: %v", err)
	}
	p, ok := scimProfiles[cfg.Profile]
	if !ok {
		return cfg, cfgErr("target.profile must be generic, aws_identity_center or github_emu")
	}
	if _, err := httpURL("target.base_url", cfg.BaseURL, false); err != nil {
		return cfg, err
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = min(100, p.maxPage)
	}
	if cfg.PageSize < 1 || cfg.PageSize > p.maxPage {
		return cfg, cfgErr("target.page_size must be from 1 to %d for the %s profile", p.maxPage, cfg.Profile)
	}
	for k := range c.Attrs {
		if k != "externalId" {
			return cfg, cfgErr("attrs: a SCIM group has only the attribute externalId, not %q", k)
		}
	}
	if p.needExternal && c.Attrs["externalId"] == "" {
		return cfg, cfgErr(`attrs.externalId is required for the %s profile (for example "{{.ID}}")`, cfg.Profile)
	}
	return cfg, nil
}

type scimTarget struct {
	cfg   scimCfg
	prof  scimProfile
	base  string
	token string
	http  *http.Client
}

func openSCIM(spec TargetSpec) (Provisioner, error) {
	cfg, err := parseSCIMConfig(spec.Common)
	if err != nil {
		return nil, err
	}
	if spec.Secret["token"] == "" {
		return nil, cfgErr("secret.token is required")
	}
	if spec.Deps.HTTP == nil {
		return nil, errors.New("no outbound HTTP client is configured")
	}
	return &scimTarget{cfg: cfg, prof: scimProfiles[cfg.Profile], base: strings.TrimRight(cfg.BaseURL, "/"), token: spec.Secret["token"],
		// the stored base URL may name a port (https://scim.example.com:9443); no other host gets one
		http: safehttp.WithConfiguredPorts(spec.Deps.HTTP, cfg.BaseURL)}, nil
}

func (t *scimTarget) Capabilities() Capabilities {
	return Capabilities{Groups: true, Memberships: true, Incremental: true, MaxBatch: 20, Readable: true, ChangeTokens: true}
}

func (t *scimTarget) Close() error { return nil }

const (
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimMemberChunk = 100
)

type scimMember struct {
	Value string `json:"value"`
}

type scimGroup struct {
	ID          string       `json:"id"`
	DisplayName string       `json:"displayName"`
	ExternalID  string       `json:"externalId"`
	Members     []scimMember `json:"members"`
	Meta        struct {
		Version      string `json:"version"`
		LastModified string `json:"lastModified"`
	} `json:"meta"`
}

type scimList struct {
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	Resources    []scimGroup `json:"Resources"`
}

func (t *scimTarget) do(ctx context.Context, method, path string, q url.Values, body any) (int, []byte, error) {
	u := t.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	var req *http.Request
	var err error
	if rd != nil {
		req, err = ctxReq(ctx, method, u, rd)
	} else {
		req, err = ctxReq(ctx, method, u, nil)
	}
	if err != nil {
		return 0, nil, errors.New("invalid URL")
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("Accept", "application/scim+json, application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	return doHTTP(t.http, req)
}

func (t *scimTarget) toGroup(g scimGroup) *TargetGroup {
	tg := &TargetGroup{Ref: TargetRef{Name: g.DisplayName, ID: g.ID}, Token: scimToken(g)}
	if g.ExternalID != "" {
		tg.Attrs = map[string][]string{"externalId": {g.ExternalID}}
	}
	for _, m := range g.Members {
		tg.Members = append(tg.Members, m.Value)
	}
	return tg
}

func scimToken(g scimGroup) string {
	if g.Meta.Version != "" {
		return g.Meta.Version
	}
	return g.Meta.LastModified
}

// list pages through /Groups. attrs, when set, is the attributes parameter.
func (t *scimTarget) list(ctx context.Context, filter string, attrs string) ([]scimGroup, error) {
	var out []scimGroup
	for start := 1; ; {
		q := url.Values{"startIndex": {strconv.Itoa(start)}, "count": {strconv.Itoa(t.cfg.PageSize)}}
		if filter != "" {
			q.Set("filter", filter)
		}
		if attrs != "" {
			q.Set("attributes", attrs)
		}
		if t.prof.excludeParam {
			q.Set("excludedAttributes", "members")
		}
		status, body, err := t.do(ctx, http.MethodGet, "/Groups", q, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, statusErr("list groups", status)
		}
		var l scimList
		if err := json.Unmarshal(body, &l); err != nil {
			return nil, errors.New("list groups: the response is not a SCIM ListResponse")
		}
		out = append(out, l.Resources...)
		start += len(l.Resources)
		if len(l.Resources) == 0 || (l.TotalResults > 0 && start > l.TotalResults) || len(out) > 1_000_000 {
			return out, nil
		}
	}
}

// withMembers fills in the members a list response left out.
func (t *scimTarget) withMembers(ctx context.Context, g scimGroup) (scimGroup, error) {
	if t.prof.listMembers && g.Members != nil {
		return g, nil
	}
	got, found, err := t.get(ctx, g.ID)
	if err != nil || !found {
		return g, err
	}
	return got, nil
}

func (t *scimTarget) get(ctx context.Context, id string) (scimGroup, bool, error) {
	var g scimGroup
	status, body, err := t.do(ctx, http.MethodGet, "/Groups/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return g, false, err
	}
	switch status {
	case http.StatusOK:
		if err := json.Unmarshal(body, &g); err != nil {
			return g, false, errors.New("get group: the response is not a SCIM Group")
		}
		return g, true, nil
	case http.StatusNotFound:
		return g, false, nil
	}
	return g, false, statusErr("get group", status)
}

func (t *scimTarget) ReadAll(ctx context.Context, _ Scope) (TargetState, error) {
	st := NewState()
	gs, err := t.list(ctx, "", "")
	if err != nil {
		return st, err
	}
	for _, g := range gs {
		if g, err = t.withMembers(ctx, g); err != nil {
			return st, err
		}
		st.Groups[Key(g.DisplayName)] = t.toGroup(g)
	}
	return st, nil
}

// scimFilterValue quotes a string for a SCIM filter (RFC 7644 §3.4.2.2).
func scimFilterValue(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func (t *scimTarget) Read(ctx context.Context, refs []TargetRef) (TargetState, error) {
	st := NewState()
	for _, r := range refs {
		var g scimGroup
		found := false
		if r.ID != "" {
			var err error
			if g, found, err = t.get(ctx, r.ID); err != nil {
				return st, err
			}
			found = found && Key(g.DisplayName) == Key(r.Name)
		}
		if !found {
			gs, err := t.list(ctx, "displayName eq "+scimFilterValue(r.Name), "")
			if err != nil {
				return st, err
			}
			for _, c := range gs {
				if Key(c.DisplayName) == Key(r.Name) {
					if g, err = t.withMembers(ctx, c); err != nil {
						return st, err
					}
					found = true
					break
				}
			}
		}
		if found {
			st.Groups[Key(r.Name)] = t.toGroup(g)
		}
	}
	return st, nil
}

// Tokens implements TokenReader: the version (or last-modified time) of every group.
func (t *scimTarget) Tokens(ctx context.Context, _ Scope) (map[string]string, error) {
	gs, err := t.list(ctx, "", "id,displayName,meta")
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(gs))
	for _, g := range gs {
		out[Key(g.DisplayName)] = scimToken(g)
	}
	return out, nil
}

func (t *scimTarget) op(name string) string {
	if t.prof.title {
		return strings.ToUpper(name[:1]) + name[1:]
	}
	return name
}

func members(ids []string) []scimMember {
	out := make([]scimMember, len(ids))
	for i, id := range ids {
		out[i] = scimMember{Value: id}
	}
	return out
}

func (t *scimTarget) Apply(ctx context.Context, ops []Op) ([]OpResult, error) {
	out := make([]OpResult, len(ops))
	for i, op := range ops {
		out[i] = OpResult{ID: op.ID, Ref: op.Ref}
		ref, err := t.apply(ctx, op)
		if ref.ID != "" {
			out[i].Ref = ref
		}
		out[i].Err = err
	}
	return out, nil
}

func (t *scimTarget) apply(ctx context.Context, op Op) (TargetRef, error) {
	ref := op.Ref
	switch op.Kind {
	case OpCreate:
		body := map[string]any{"schemas": []string{scimGroupSchema}, "displayName": op.Ref.Name}
		if v := op.Attrs["externalId"]; len(v) > 0 {
			body["externalId"] = v[0]
		} else if t.prof.needExternal {
			return ref, errors.New("the profile needs an externalId and the group has none")
		}
		first := op.Add[:min(len(op.Add), scimMemberChunk)]
		if len(first) > 0 {
			body["members"] = members(first)
		}
		status, resp, err := t.do(ctx, http.MethodPost, "/Groups", nil, body)
		if err != nil {
			return ref, err
		}
		if status != http.StatusCreated && status != http.StatusOK {
			return ref, statusErr("create group", status)
		}
		var g scimGroup
		if err := json.Unmarshal(resp, &g); err != nil || g.ID == "" {
			return ref, errors.New("create group: the response has no id")
		}
		ref.ID = g.ID
		if rest := op.Add[len(first):]; len(rest) > 0 {
			return ref, t.patchMembers(ctx, ref.ID, rest, nil)
		}
		return ref, nil
	case OpUpdate:
		id, err := t.idOf(ctx, op.Ref)
		if err != nil {
			return ref, err
		}
		var ops []map[string]any
		if v := op.Attrs["externalId"]; len(v) > 0 {
			ops = append(ops, map[string]any{"op": t.op("replace"), "path": "externalId", "value": v[0]})
		}
		if len(ops) == 0 {
			return ref, nil
		}
		return ref, t.patch(ctx, id, ops)
	case OpMembers:
		id, err := t.idOf(ctx, op.Ref)
		if err != nil {
			return ref, err
		}
		return ref, t.patchMembers(ctx, id, op.Add, op.Remove)
	case OpDelete:
		id, err := t.idOf(ctx, op.Ref)
		if errors.Is(err, errScimGone) {
			return ref, nil
		}
		if err != nil {
			return ref, err
		}
		status, _, err := t.do(ctx, http.MethodDelete, "/Groups/"+url.PathEscape(id), nil, nil)
		if err != nil {
			return ref, err
		}
		if status != http.StatusNoContent && status != http.StatusOK && status != http.StatusNotFound {
			return ref, statusErr("delete group", status)
		}
		return ref, nil
	}
	return ref, fmt.Errorf("unknown op %q", op.Kind)
}

var errScimGone = errors.New("the group no longer exists on the target")

// idOf returns the target id of a group, looking it up by name when unknown.
func (t *scimTarget) idOf(ctx context.Context, r TargetRef) (string, error) {
	if r.ID != "" {
		return r.ID, nil
	}
	gs, err := t.list(ctx, "displayName eq "+scimFilterValue(r.Name), "id,displayName")
	if err != nil {
		return "", err
	}
	for _, g := range gs {
		if Key(g.DisplayName) == Key(r.Name) {
			return g.ID, nil
		}
	}
	return "", errScimGone
}

func (t *scimTarget) patch(ctx context.Context, id string, ops []map[string]any) error {
	status, _, err := t.do(ctx, http.MethodPatch, "/Groups/"+url.PathEscape(id), nil,
		map[string]any{"schemas": []string{scimPatchSchema}, "Operations": ops})
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return statusErr("patch group", status)
	}
	return nil
}

// patchMembers adds and removes members in requests of at most scimMemberChunk
// changes each. Adds go first, so a group is never emptied on the way.
func (t *scimTarget) patchMembers(ctx context.Context, id string, add, remove []string) error {
	for chunk := range slices.Chunk(add, scimMemberChunk) {
		if err := t.patch(ctx, id, []map[string]any{{"op": t.op("add"), "path": "members", "value": members(chunk)}}); err != nil {
			return err
		}
	}
	for chunk := range slices.Chunk(remove, scimMemberChunk) {
		var ops []map[string]any
		if t.prof.removeByValue {
			ops = []map[string]any{{"op": t.op("remove"), "path": "members", "value": members(chunk)}}
		} else {
			for _, m := range chunk {
				ops = append(ops, map[string]any{"op": t.op("remove"), "path": "members[value eq " + scimFilterValue(m) + "]"})
			}
		}
		if err := t.patch(ctx, id, ops); err != nil {
			return err
		}
	}
	return nil
}
