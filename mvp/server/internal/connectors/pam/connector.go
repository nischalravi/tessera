package pam

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Open builds the vault of cfg. hc is the server's safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (Vault, error) {
	if now == nil {
		now = time.Now
	}
	if cfg.Username == "" || len(cfg.Username) > 256 || cfg.Secret.Empty() {
		return nil, errors.New("pam: a user and a secret are required")
	}
	base, err := connsync.ParseBaseURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("pam: base URL: %w", err)
	}
	if base.Path != "" {
		return nil, errors.New("pam: the base URL is a host without a path")
	}
	if cfg.APIRoot != "" && (!strings.HasPrefix(cfg.APIRoot, "/") || strings.Contains(cfg.APIRoot, "..") || strings.Contains(cfg.APIRoot, "//") || len(cfg.APIRoot) > 200) {
		return nil, errors.New("pam: the API root must be an absolute path")
	}
	switch cfg.Vendor {
	case CyberArk:
		return newCyberArk(cfg, base, hc, now)
	case Delinea:
		return newDelinea(cfg, base, hc, now)
	case BeyondTrust:
		return newBeyondTrust(cfg, base, hc, now)
	}
	return nil, fmt.Errorf("pam: unknown vendor %q", cfg.Vendor)
}

// Connector is the read connector of a vault (connectors.Connector).
type Connector struct {
	v Vault
}

// NewConnector wraps a vault.
func NewConnector(v Vault) *Connector { return &Connector{v} }

func (c *Connector) System() string { return c.v.Vendor() }
func (c *Connector) DisplayName() string {
	return map[string]string{CyberArk: "CyberArk", Delinea: "Delinea Secret Server", BeyondTrust: "BeyondTrust Password Safe"}[c.v.Vendor()]
}
func (c *Connector) TypeName() string { return "PAMConnector" }

// StreamEvents: a vault reports no usage here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// GroupID is the entitlement id of a safe at a profile.
func GroupID(safeID, profile string) string { return safeID + "/" + profile }

// SplitGroupID is GroupID's inverse.
func SplitGroupID(id string) (safeID, profile string, ok bool) {
	i := strings.LastIndexByte(id, '/')
	if i <= 0 || !ValidProfile(id[i+1:]) {
		return "", "", false
	}
	return id[:i], id[i+1:], true
}

func memberKind(t string) string {
	switch t {
	case MemberGroup, MemberRole:
		return t
	}
	return "user"
}

// Discover reads every safe, its accounts and its members.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	sys := c.v.Vendor()
	safes, err := c.v.Safes(ctx)
	if err != nil {
		return nil, err
	}
	res := &connectors.DiscoveryResult{}
	seenAcct := map[string]bool{}
	addAcct := func(a connectors.AccountRecord) {
		if !seenAcct[a.ExternalID] {
			seenAcct[a.ExternalID] = true
			res.Accounts = append(res.Accounts, a)
		}
	}
	for _, s := range safes {
		res.Resources = append(res.Resources, connectors.ResourceRecord{System: sys, ExternalID: s.ID, Name: s.Name, Kind: "vault_safe",
			Tags: []string{"pam", sys}})
		for _, p := range AllPerms {
			res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: sys, ExternalID: s.ID + ":" + p, Action: p,
				ResourceExternalID: s.ID, Privileged: IsPrivilegedPerm(p)})
		}
		for _, pr := range Profiles {
			desc := "Safe " + s.Name + " at the " + pr + " profile"
			res.Groups = append(res.Groups, connectors.GroupRecord{System: sys, ExternalID: GroupID(s.ID, pr), Name: s.Name + " / " + pr,
				Kind: "vault_safe_access", Privileged: pr == ProfileRead || pr == ProfileManage, Requestable: true, Description: &desc})
			for _, p := range profilePerms[pr] {
				res.Edges = append(res.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "group", System: sys, ExternalID: GroupID(s.ID, pr)},
					Dst: connectors.Ref{Kind: "perm", System: sys, ExternalID: s.ID + ":" + p}, Relation: "grants"})
			}
		}
		members, err := c.v.Members(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("members of safe %s: %w", s.Name, err)
		}
		for _, m := range members {
			ref := connectors.Ref{Kind: "account", System: sys, ExternalID: "member:" + m.Name}
			addAcct(connectors.AccountRecord{System: sys, ExternalID: ref.ExternalID, Username: m.Name, Kind: memberKind(m.Type), Status: "active"})
			if top := TopProfile(m.Perms); top != "" {
				res.Edges = append(res.Edges, connectors.EdgeRecord{Src: ref,
					Dst: connectors.Ref{Kind: "group", System: sys, ExternalID: GroupID(s.ID, top)}, Relation: "member_of"})
			}
			for _, p := range Beyond(m.Perms) {
				res.Edges = append(res.Edges, connectors.EdgeRecord{Src: ref,
					Dst: connectors.Ref{Kind: "perm", System: sys, ExternalID: s.ID + ":" + p}, Relation: "direct_grant"})
			}
		}
		accts, err := c.v.Accounts(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("accounts of safe %s: %w", s.Name, err)
		}
		for _, a := range accts {
			id := "vaulted:" + s.ID + ":" + a.ID
			addAcct(connectors.AccountRecord{System: sys, ExternalID: id, Username: a.Username, Kind: "vaulted", Status: "active", CreatedAt: a.CreatedAt,
				Attributes: map[string]string{"safe": s.Name, "address": a.Address, "platform": a.Platform}})
			created := time.Time{}
			if a.CreatedAt != nil {
				created = *a.CreatedAt
			}
			res.Secrets = append(res.Secrets, connectors.SecretRecord{System: sys, ExternalID: id + ":secret", Account: connectors.Ref{Kind: "account", System: sys, ExternalID: id},
				Kind: "password", Name: a.Name, CreatedAt: created, LastRotatedAt: a.LastRotatedAt})
		}
	}
	sort.SliceStable(res.Accounts, func(i, j int) bool { return res.Accounts[i].ExternalID < res.Accounts[j].ExternalID })
	return res, nil
}
