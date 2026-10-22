package erp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Open builds the system of cfg. hc is the server's safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (System, error) {
	if now == nil {
		now = time.Now
	}
	if cfg.ClientID == "" || len(cfg.ClientID) > 256 || cfg.ClientSecret.Empty() {
		return nil, errors.New("erp: a client id and secret are required")
	}
	base, err := connsync.ParseBaseURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("erp: base URL: %w", err)
	}
	if base.Path != "" {
		return nil, errors.New("erp: the base URL is a host without a path")
	}
	for _, p := range []string{cfg.APIRoot, cfg.TokenPath} {
		if p != "" && (!strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.Contains(p, "//") || len(p) > 200) {
			return nil, errors.New("erp: paths must be absolute")
		}
	}
	root, token := cfg.APIRoot, cfg.TokenPath
	switch cfg.System {
	case SAP:
		root, token = orStr(root, DefaultSAPRoot), orStr(token, "/oauth/token")
	case Oracle:
		root, token = orStr(root, DefaultOracleRoot), orStr(token, "/oauth2/v1/token")
	default:
		return nil, fmt.Errorf("erp: unknown system %q", cfg.System)
	}
	s, err := newSession(cfg, base, root, token, hc, now)
	if err != nil {
		return nil, err
	}
	if cfg.System == SAP {
		return &sap{s}, nil
	}
	return &oracle{s}, nil
}

func orStr(v, d string) string {
	if v != "" {
		return v
	}
	return d
}

// Connector is the read connector of an ERP (connectors.Connector).
type Connector struct {
	sys Sys
	now func() time.Time
}

// Sys is what the connector needs of a system (System without the writes).
type Sys interface {
	Vendor() string
	Roles(ctx context.Context) ([]Role, error)
	Users(ctx context.Context) ([]User, error)
}

// NewConnector wraps a system; now decides which time-bound assignments hold.
func NewConnector(s Sys, now func() time.Time) *Connector {
	if now == nil {
		now = time.Now
	}
	return &Connector{s, now}
}

func (c *Connector) System() string { return c.sys.Vendor() }
func (c *Connector) DisplayName() string {
	return map[string]string{SAP: "SAP", Oracle: "Oracle Fusion Applications"}[c.sys.Vendor()]
}
func (c *Connector) TypeName() string { return "ERPConnector" }

// StreamEvents: an ERP reports no usage here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

func tcodePerm(t string) string { return "tcode:" + strings.ToUpper(t) }

// Discover reads every role and user.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	sys := c.sys.Vendor()
	roles, err := c.sys.Roles(ctx)
	if err != nil {
		return nil, fmt.Errorf("roles: %w", err)
	}
	users, err := c.sys.Users(ctx)
	if err != nil {
		return nil, fmt.Errorf("users: %w", err)
	}
	res := &connectors.DiscoveryResult{}
	res.Resources = []connectors.ResourceRecord{
		{System: sys, ExternalID: ResTransactions, Name: c.DisplayName() + " transactions", Kind: "erp_transactions", Tags: []string{"erp", sys}},
		{System: sys, ExternalID: ResAuthorizations, Name: c.DisplayName() + " authorizations", Kind: "erp_authorizations", Tags: []string{"erp", sys}},
	}
	known := map[string]bool{}
	perm := func(id, action, resource string, priv bool) {
		if !known[id] {
			known[id] = true
			res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: sys, ExternalID: id, Action: action, ResourceExternalID: resource, Privileged: priv})
		}
	}
	roleIDs := map[string]bool{}
	for _, r := range roles {
		roleIDs[r.ID] = true
	}
	for _, r := range roles {
		desc := r.Description
		g := connectors.GroupRecord{System: sys, ExternalID: r.ID, Name: r.Name, Kind: "erp_role", Privileged: r.Privileged(), Requestable: true}
		if desc != "" {
			g.Description = &desc
		}
		res.Groups = append(res.Groups, g)
		ref := connectors.Ref{Kind: "group", System: sys, ExternalID: r.ID}
		for _, t := range r.TCodes {
			perm(tcodePerm(t), strings.ToUpper(t), ResTransactions, IsCriticalTCode(t))
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: ref, Dst: connectors.Ref{Kind: "perm", System: sys, ExternalID: tcodePerm(t)}, Relation: "grants"})
		}
		for _, a := range r.AuthObjects {
			act := a.Action()
			perm("auth:"+act, act, ResAuthorizations, IsPrivilegedAuth(a))
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: ref, Dst: connectors.Ref{Kind: "perm", System: sys, ExternalID: "auth:" + act}, Relation: "grants"})
		}
		for _, ch := range r.Children {
			if roleIDs[ch] {
				res.Edges = append(res.Edges, connectors.EdgeRecord{Src: ref, Dst: connectors.Ref{Kind: "group", System: sys, ExternalID: ch}, Relation: "member_of"})
			}
		}
	}
	now := c.now()
	for _, u := range users {
		status := "active"
		if u.Locked || (u.ValidTo != nil && !u.ValidTo.After(now)) {
			status = "disabled"
		}
		name := u.Name
		if name == "" {
			name = u.ID
		}
		acct := connectors.AccountRecord{System: sys, ExternalID: u.ID, Username: u.ID, Kind: "user", Status: status, LastLoginAt: u.LastLogon}
		if u.Email != "" {
			acct.Identity = &connectors.IdentityRef{Email: strings.ToLower(u.Email)}
		}
		res.Accounts = append(res.Accounts, acct)
		for _, a := range u.Roles {
			if a.Active(now) && roleIDs[a.Role] {
				res.Edges = append(res.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: sys, ExternalID: u.ID},
					Dst: connectors.Ref{Kind: "group", System: sys, ExternalID: a.Role}, Relation: "member_of"})
			}
		}
	}
	return res, nil
}
