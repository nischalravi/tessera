package restgen

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Target is the REST system as a provisioning target (target.Connector). Every
// change reads first, so a repeated request converges, and Verify re-reads.
type Target struct {
	spec *Spec
	c    *Client
	um   *mapper
}

// NewTarget returns the provisioning target for a Spec with write operations.
// hc must come from internal/safehttp.
func NewTarget(spec *Spec, sec Secrets, rt connsync.Runtime, hc *http.Client) (*Target, error) {
	if errs := spec.Validate(rt); len(errs) > 0 {
		return nil, errs
	}
	if spec.Writes == nil {
		return nil, errors.New("restgen: the config has no write operations")
	}
	c, err := NewClient(spec, sec, rt, hc)
	if err != nil {
		return nil, err
	}
	t := &Target{spec: spec, c: c}
	if spec.Users != nil {
		if t.um, err = newMapper(spec.Users); err != nil {
			return nil, err
		}
	}
	return t, nil
}

var _ target.Connector = (*Target)(nil)

// vars are the template variables of a request.
func vars(r target.Request) Vars {
	v := Vars{}
	set := func(k, val string) {
		if val != "" {
			v[k] = val
		}
	}
	set(varUsername, r.Account.Username)
	set(varExternalID, r.Account.ExternalID)
	set(varEmail, r.Account.Email)
	set(varDisplayName, r.Account.DisplayName)
	set(varGroupID, r.Group.ExternalID)
	set(varGroupName, r.Group.Name)
	for k, val := range r.Account.Attrs {
		if attrRE.MatchString(k) {
			v["attr."+k] = val
		}
	}
	return v
}

// opFor returns the operation a request kind needs.
func (t *Target) opFor(kind string) (*Operation, string) {
	w := t.spec.Writes
	switch kind {
	case target.CreateAccount:
		return w.Create, "create"
	case target.UpdateAccount:
		return w.Update, "update"
	case target.DisableAccount:
		return w.Disable, "disable"
	case target.DeleteAccount:
		return w.Delete, "delete"
	case target.AddEntitlement:
		return w.AddMember, "add_member"
	case target.RemoveEntitlement:
		return w.RemoveMember, "remove_member"
	}
	return nil, kind
}

// Apply sends the change, after reading the target to see whether it is
// already made.
func (t *Target) Apply(ctx context.Context, r target.Request) error {
	op, name := t.opFor(r.Kind)
	if op == nil {
		return target.Permanent("%s: this REST target has no %s operation configured", name, name)
	}
	v := vars(r)
	switch r.Kind {
	case target.CreateAccount:
		if r.Account.Username == "" {
			return target.Permanent("create: the change has no username")
		}
		_, found, err := t.lookup(ctx, "create", v)
		if err != nil || found {
			return err // nil when the account is already there
		}
	case target.UpdateAccount, target.DisableAccount, target.DeleteAccount:
		u, found, err := t.lookup(ctx, name, v)
		if err != nil {
			return err
		}
		switch {
		case !found && r.Kind == target.DeleteAccount:
			return nil
		case !found:
			return target.Permanent("%s: the account does not exist in the target", name)
		case r.Kind == target.DisableAccount && !u.active:
			return nil
		case r.Kind == target.UpdateAccount && len(r.Account.Attrs) > 0:
			if bad, compared := t.attrMismatch(u, r.Account.Attrs); bad == "" && compared == len(r.Account.Attrs) {
				return nil // every attribute is already as wanted
			}
		}
		if v[varExternalID] == "" {
			v[varExternalID] = u.id
		}
	case target.AddEntitlement, target.RemoveEntitlement:
		if r.Group.ExternalID == "" && r.Group.Name == "" {
			return target.Permanent("%s: the change names no group", name)
		}
		if err := t.resolveUser(ctx, name, v); err != nil {
			return err
		}
		member, err := t.isMember(ctx, name, v)
		if err != nil || member == (r.Kind == target.AddEntitlement) {
			return err // already as wanted
		}
	}
	return t.send(ctx, name, op, v, r.Key)
}

// Verify re-reads the target and reports whether the change is visible.
func (t *Target) Verify(ctx context.Context, r target.Request) (target.Verdict, error) {
	v := vars(r)
	switch r.Kind {
	case target.CreateAccount, target.UpdateAccount, target.DisableAccount, target.DeleteAccount:
		u, found, err := t.lookup(ctx, "verify", v)
		if err != nil {
			return target.Verdict{}, err
		}
		switch r.Kind {
		case target.CreateAccount:
			return verdict(found, "the account exists", "the account is not there"), nil
		case target.DeleteAccount:
			return verdict(!found, "the account is gone", "the account still exists"), nil
		case target.DisableAccount:
			return verdict(found && !u.active, "the account is disabled", "the account is not disabled"), nil
		default:
			if !found {
				return target.Verdict{Expected: "the account has the new attributes", Observed: "the account is not there"}, nil
			}
			if bad, _ := t.attrMismatch(u, r.Account.Attrs); bad != "" {
				return target.Verdict{Expected: "the account has the new attributes", Observed: bad + " differs"}, nil
			}
			return target.Verdict{OK: true, Expected: "the account has the new attributes", Observed: "the account has the new attributes"}, nil
		}
	case target.AddEntitlement, target.RemoveEntitlement:
		if err := t.resolveUser(ctx, "verify", v); err != nil {
			return target.Verdict{}, err
		}
		member, err := t.isMember(ctx, "verify", v)
		if err != nil {
			return target.Verdict{}, err
		}
		want := r.Kind == target.AddEntitlement
		exp, obs := "the account is a member", "the account is not a member"
		if !want {
			exp = "the account is not a member"
		}
		if member {
			obs = "the account is a member"
		}
		return target.Verdict{OK: member == want, Expected: exp, Observed: obs}, nil
	}
	return target.Verdict{}, target.Permanent("verify: unknown operation %q", r.Kind)
}

func verdict(ok bool, expected, observed string) target.Verdict {
	v := target.Verdict{OK: ok, Expected: expected, Observed: observed}
	if ok {
		v.Observed = expected
	}
	return v
}

// attrMismatch names the first updated attribute whose mapped value in the
// target differs, and says how many attributes could be compared at all: only
// those the users mapping reads back are.
func (t *Target) attrMismatch(u user, attrs map[string]string) (string, int) {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	compared := 0
	for _, k := range keys {
		var got string
		switch k {
		case "email":
			got = u.email
		case "display_name", "displayName":
			got = u.name
		case "department":
			got = u.dept
		case "title":
			got = u.title
		default:
			var ok bool
			if got, ok = u.attrs[k]; !ok {
				continue
			}
		}
		compared++
		if got != attrs[k] {
			return k, compared
		}
	}
	return "", compared
}

// resolveUser fills in external_id from the target when the change has only a username.
func (t *Target) resolveUser(ctx context.Context, op string, v Vars) error {
	if v[varExternalID] != "" || !pathUses(t.spec.Writes, varExternalID) {
		return nil
	}
	u, found, err := t.lookup(ctx, op, v)
	if err != nil {
		return err
	}
	if !found {
		return target.Permanent("%s: the account does not exist in the target", op)
	}
	v[varExternalID] = u.id
	return nil
}

// pathUses reports whether any membership operation's path or query needs the variable.
func pathUses(w *Writes, name string) bool {
	for _, op := range []*Operation{w.AddMember, w.RemoveMember, w.IsMember} {
		if op != nil && strings.Contains(op.Path, "{"+name+"}") {
			return true
		}
	}
	return false
}

// lookup reads one user. found is false on 404.
func (t *Target) lookup(ctx context.Context, what string, v Vars) (user, bool, error) {
	op := t.spec.Writes.Lookup
	if op == nil {
		return user{}, false, target.Permanent("%s: this REST target has no lookup operation configured", what)
	}
	resp, err := t.exec(ctx, "lookup", op, v, "")
	if err != nil {
		return user{}, false, err
	}
	if resp.Status == http.StatusNotFound {
		return user{}, false, nil
	}
	if !accepted(op, resp) {
		return user{}, false, fail("lookup", resp)
	}
	doc, err := resp.JSON()
	if err != nil {
		return user{}, false, target.Permanent("lookup: %v", err)
	}
	ip, _ := optionalPath(op.RecordPath)
	items := selectItems(ip, doc)
	if len(items) != 1 {
		// a search endpoint may answer several fuzzy matches or none: never guess which one is meant
		// (an absent account is a 404)
		return user{}, false, target.Permanent("lookup: the answer holds %d records, expected exactly one (answer 404 when the account is absent)", len(items))
	}
	u, ok := t.um.mapUser(items[0])
	if !ok {
		return user{}, false, target.Permanent("lookup: the answer has no id or username under the users mapping")
	}
	// the record must be the one asked for: ids compare exactly, user names as the SCIM and Okta targets do
	if want := v[varExternalID]; want != "" {
		if u.id != want {
			return user{}, false, target.Permanent("lookup: the answer is a different account than the one asked for")
		}
	} else if want := v[varUsername]; want == "" || !strings.EqualFold(u.username, want) {
		return user{}, false, target.Permanent("lookup: the answer is a different account than the one asked for")
	}
	return u, true, nil
}

func (t *Target) isMember(ctx context.Context, what string, v Vars) (bool, error) {
	op := t.spec.Writes.IsMember
	if op == nil {
		return false, target.Permanent("%s: this REST target has no is_member operation configured", what)
	}
	resp, err := t.exec(ctx, "is_member", op, v, "")
	if err != nil {
		return false, err
	}
	if resp.Status == http.StatusNotFound {
		return false, nil
	}
	if !accepted(op, resp) {
		return false, fail("is_member", resp)
	}
	return true, nil
}

// DryRunHeader marks the empty answer a dry run gives a held-back write
// (provision.DryRun). Such an answer counts as accepted whatever the
// operation expects, so the steps after the write still show.
const DryRunHeader = "X-Tessera-Dry-Run"

func accepted(op *Operation, r *Response) bool {
	status := r.Status
	if status == http.StatusNoContent && r.Header.Get(DryRunHeader) != "" {
		return true
	}
	if len(op.Expect) > 0 {
		return slices.Contains(op.Expect, status)
	}
	return status >= 200 && status <= 299
}

// send runs a write operation and judges its status.
func (t *Target) send(ctx context.Context, name string, op *Operation, v Vars, key string) error {
	resp, err := t.exec(ctx, name, op, v, key)
	if err != nil {
		return err
	}
	if !accepted(op, resp) {
		return fail(name, resp)
	}
	return nil
}

func fail(op string, r *Response) error {
	e := target.Fail(op, r.Status, errorDetail(r.Body))
	if r.RetryAfter > 0 {
		e.Msg += fmt.Sprintf(" (asked to wait %ds)", int(r.RetryAfter.Seconds()))
	}
	return e
}

// exec renders and sends one operation.
func (t *Target) exec(ctx context.Context, name string, op *Operation, v Vars, key string) (*Response, error) {
	rq, err := t.render(op, v)
	if err != nil {
		return nil, target.Permanent("%s: %v", name, err)
	}
	rq.key = key
	resp, err := t.c.do(ctx, rq)
	if err != nil {
		if tooLarge(err) {
			return nil, target.Permanent("%s: %v", name, err)
		}
		var se *StatusError
		if errors.As(err, &se) {
			return nil, target.Fail(name, se.Status, se.Detail)
		}
		return nil, target.Transport(name, err)
	}
	return resp, nil
}

func (t *Target) render(op *Operation, v Vars) (request, error) {
	p, err := expandPath(op.Path, v)
	if err != nil {
		return request{}, err
	}
	u, err := buildURL(t.c.base, p, expandQuery(op.Query, v))
	if err != nil {
		return request{}, err
	}
	body, err := expandBody(op.Body, v)
	if err != nil {
		return request{}, err
	}
	return request{method: op.Method, u: u, body: body}, nil
}

// Planned is one request a change would send.
type Planned struct {
	// Step is the operation ("lookup", "create", "add_member").
	Step   string `json:"step"`
	Method string `json:"method"`
	URL    string `json:"url"`
	// Body is the rendered JSON body.
	Body string `json:"body,omitempty"`
	// Auth says how the request authenticates; the credential itself is never shown.
	Auth string `json:"auth"`
	// Write is true for a request that changes the target. Conditional: it is sent only if the read
	// before it does not show the change already made.
	Write       bool `json:"write"`
	Conditional bool `json:"conditional,omitempty"`
}

// Plan shows the exact requests Apply would send for r, in order, without
// sending any and without fetching a token or touching the network. A request
// whose template needs a value the change lacks is an error naming it.
func (t *Target) Plan(r target.Request) ([]Planned, error) {
	op, name := t.opFor(r.Kind)
	if op == nil {
		return nil, fmt.Errorf("%s: this REST target has no %s operation configured", name, name)
	}
	v := vars(r)
	var out []Planned
	add := func(step string, o *Operation, write, cond bool) error {
		rq, err := t.render(o, v)
		if err != nil {
			return fmt.Errorf("%s: %v", step, err)
		}
		pl := Planned{Step: step, Method: rq.method, URL: t.redact(rq.u), Body: string(rq.body), Auth: t.authNote(), Write: write, Conditional: cond}
		out = append(out, pl)
		return nil
	}
	w := t.spec.Writes
	switch r.Kind {
	case target.CreateAccount, target.UpdateAccount, target.DisableAccount, target.DeleteAccount:
		if w.Lookup != nil {
			if err := add("lookup", w.Lookup, false, false); err != nil && r.Kind == target.CreateAccount {
				return nil, err
			}
		}
	case target.AddEntitlement, target.RemoveEntitlement:
		if w.IsMember != nil {
			if err := add("is_member", w.IsMember, false, false); err != nil {
				return nil, err
			}
		}
	}
	if err := add(name, op, true, true); err != nil {
		return nil, err
	}
	return out, nil
}

func (t *Target) authNote() string {
	a := t.spec.Auth
	switch a.Type {
	case AuthAPIKey:
		return "api_key in " + a.In + " " + a.Name
	case AuthBasic:
		return "basic as " + a.Username
	case AuthOAuth2:
		return "oauth2 bearer token from " + safeHost(a.TokenURL)
	}
	return "bearer token"
}

func safeHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(invalid URL)"
	}
	return u.Host
}

// redact is the URL as it would be sent, with an API key in the query shown as ***.
func (t *Target) redact(u *url.URL) string {
	a := t.spec.Auth
	if a.Type != AuthAPIKey || a.In != "query" {
		return u.String()
	}
	cp := *u
	q := queryOf(&cp)
	q.Set(a.Name, "***")
	cp.RawQuery = q.Encode()
	return cp.String()
}
