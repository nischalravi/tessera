package servicenow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// System is the connector's system name.
const System = "servicenow"

// Group kinds.
const (
	KindGroup = "servicenow_group"
	KindRole  = "servicenow_role"
)

// Tables the connector reads.
const (
	tUser    = "sys_user"
	tGroup   = "sys_user_group"
	tMember  = "sys_user_grmember"
	tHasRole = "sys_user_has_role"
	tRole    = "sys_user_role"
)

// privilegedRoles are the roles that are privileged by name: admin reaches everything, security_admin is the
// elevated role that edits access control. Any other role flagged "elevated privilege" is privileged too.
var privilegedRoles = map[string]bool{"admin": true, "security_admin": true}

func jsonBody(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, errors.New("servicenow: cannot encode the request")
	}
	return b, nil
}

// Connector is the read connector (connectors.Connector).
type Connector struct {
	c   *Client
	now func() time.Time
}

// NewConnector wraps a client; now decides which expiring role assignments still hold.
func NewConnector(c *Client, now func() time.Time) *Connector {
	if now == nil {
		now = time.Now
	}
	return &Connector{c, now}
}

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "ServiceNow" }
func (*Connector) TypeName() string    { return "ServiceNowConnector" }

// StreamEvents: no usage is read here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// ConfigFromEnv reads TESSERA_SERVICENOW_*:
//
//	TESSERA_SERVICENOW_BASE_URL    https://acme.service-now.com
//	TESSERA_SERVICENOW_AUTH        basic (default) or oauth
//	TESSERA_SERVICENOW_USERNAME    the integration user (basic)
//	TESSERA_SERVICENOW_CLIENT_ID   the OAuth client id (oauth)
//	TESSERA_SERVICENOW_SECRET      reference to the password or client secret: file:/abs/path or env:NAME
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_SERVICENOW_"
	secret, err := connsync.ResolveSecret(getenv(p+"SECRET"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "SECRET: " + err.Error())
	}
	mode := strings.TrimSpace(getenv(p + "AUTH"))
	user := strings.TrimSpace(getenv(p + "USERNAME"))
	if mode == AuthOAuth {
		user = strings.TrimSpace(getenv(p + "CLIENT_ID"))
	}
	return Config{BaseURL: getenv(p + "BASE_URL"), AuthMode: mode, Username: user, Secret: secret}, nil
}

// FromEnv builds the read connector from TESSERA_SERVICENOW_* (ConfigFromEnv).
func FromEnv(getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	c, err := Open(cfg, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(c, now), nil
}

// ProbeResult is what one bounded read found.
type ProbeResult struct {
	Users, Groups, Roles, Assignments int
}

// Probe reads one page of each table, for the readiness checks: it proves the credential, the table access
// and the shape of the answers, and keeps counts only.
func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	var r ProbeResult
	for _, t := range []struct {
		table  string
		fields []string
		n      *int
	}{{tUser, []string{"sys_id"}, &r.Users}, {tGroup, []string{"sys_id"}, &r.Groups}, {tRole, []string{"sys_id"}, &r.Roles}, {tHasRole, []string{"sys_id"}, &r.Assignments}} {
		rs, err := c.probeRows(ctx, t.table, t.fields)
		if err != nil {
			return r, err
		}
		*t.n = rs
	}
	return r, nil
}

func (c *Client) probeRows(ctx context.Context, table string, fields []string) (int, error) {
	n := 0
	errStop := errors.New("stop")
	err := c.each(ctx, table, "ORDERBYsys_id", fields, func(record) error {
		if n++; n >= 100 {
			return errStop
		}
		return nil
	})
	if errors.Is(err, errStop) {
		err = nil
	}
	return n, err
}

// Discover reads every user, group and role, and who holds them.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	read := func(what, table string, fields ...string) ([]record, error) {
		rs, err := c.c.rows(ctx, table, "ORDERBYsys_id", fields)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		return rs, nil
	}
	users, err := read("users", tUser, "sys_id", "user_name", "email", "name", "first_name", "last_name", "active", "locked_out",
		"employee_number", "title", "last_login_time", "sys_created_on", "web_service_access_only")
	if err != nil {
		return nil, err
	}
	groups, err := read("groups", tGroup, "sys_id", "name", "description", "active")
	if err != nil {
		return nil, err
	}
	roles, err := read("roles", tRole, "sys_id", "name", "description", "elevated_privilege")
	if err != nil {
		return nil, err
	}
	members, err := read("group members", tMember, "user", "group")
	if err != nil {
		return nil, err
	}
	held, err := read("role assignments", tHasRole, "user", "role", "state", "inherited", "expires")
	if err != nil {
		return nil, err
	}

	res := &connectors.DiscoveryResult{}
	ref := func(id string) connectors.Ref { return connectors.Ref{Kind: "group", System: System, ExternalID: id} }
	groupIDs, roleIDs, userIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, g := range groups {
		id := g.str("sys_id")
		groupIDs[id] = true
		rec := connectors.GroupRecord{System: System, ExternalID: id, Name: g.str("name"), Kind: KindGroup, Requestable: true}
		if d := g.str("description"); d != "" {
			rec.Description = &d
		}
		res.Groups = append(res.Groups, rec)
	}
	for _, r := range roles {
		id := r.str("sys_id")
		roleIDs[id] = true
		rec := connectors.GroupRecord{System: System, ExternalID: id, Name: r.str("name"), Kind: KindRole, Requestable: true,
			Privileged: privilegedRoles[r.str("name")] || r.flag("elevated_privilege")}
		if d := r.str("description"); d != "" {
			rec.Description = &d
		}
		res.Groups = append(res.Groups, rec)
	}

	for _, u := range users {
		id := u.str("sys_id")
		userIDs[id] = true
		status := "active"
		if !u.flag("active") || u.flag("locked_out") {
			status = "disabled"
		}
		kind := "user"
		if u.flag("web_service_access_only") {
			kind = "service"
		}
		acct := connectors.AccountRecord{System: System, ExternalID: id, Username: u.str("user_name"), Kind: kind, Status: status,
			CreatedAt: u.time("sys_created_on"), LastLoginAt: u.time("last_login_time"),
			Attributes: map[string]string{"sys_id": id, "user_name": u.str("user_name"), "email": u.str("email"), "employee_number": u.str("employee_number"),
				"title": u.str("title"), "active": fmt.Sprint(u.flag("active")), "locked_out": fmt.Sprint(u.flag("locked_out"))}}
		if e := strings.ToLower(strings.TrimSpace(u.str("email"))); e != "" {
			acct.Identity = &connectors.IdentityRef{Email: e}
		}
		res.Accounts = append(res.Accounts, acct)
	}

	seen := map[string]bool{}
	edge := func(user, group string) {
		if k := user + ">" + group; !seen[k] {
			seen[k] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: System, ExternalID: user}, Dst: ref(group), Relation: "member_of"})
		}
	}
	for _, m := range members {
		if u, g := m.str("user"), m.str("group"); userIDs[u] && groupIDs[g] {
			edge(u, g)
		}
	}
	now := c.now()
	for _, h := range held {
		u, r := h.str("user"), h.str("role")
		if !userIDs[u] || !roleIDs[r] {
			continue
		}
		if st := strings.ToLower(h.str("state")); st == "inactive" || st == "suspended" {
			continue
		}
		if exp := h.time("expires"); exp != nil && !exp.After(now) {
			continue
		}
		edge(u, r)
	}
	return res, nil
}
