package loaders

import (
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	ldapdir "github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// The ldap_simple and ldap_group_list sources read people and groups from an
// LDAP directory or Active Directory (design §9.1: paged search, LDAPS or
// StartTLS only, scope and filter validated). The connection is the read-only
// reader of internal/connectors/ldap over safedial: ports 389 (StartTLS
// required) and 636 only, TLS 1.2 or later, blocked addresses refused, and a
// bind password sent only on a connection that is secure. In production a
// directory on a private address is not reachable from the server; the dev
// allowlist (TESSERA_SAFEDIAL_ALLOW) is refused there by the configuration.

// MaxLDAPEntries bounds the entries one search returns: more is an error.
const MaxLDAPEntries = 1_000_000

// DirectorySpec is what an opener needs to connect.
type DirectorySpec struct {
	Host     string
	Port     int
	BindDN   string
	Password []byte
	// CAPEM verifies a private CA's server certificate.
	CAPEM string
}

// DirectoryReader is the read side of a directory connection.
type DirectoryReader interface {
	Search(ctx context.Context, base string, scope ldapdir.Scope, filter string, attrs []string, page, max int) ([]ldapdir.Entry, error)
	Close()
}

// DirectoryOpener opens a bound directory connection.
type DirectoryOpener func(ctx context.Context, spec DirectorySpec) (DirectoryReader, error)

// NewDirectoryOpener returns the opener for production: safedial with the
// server's environment and its dev allowlist.
func NewDirectoryOpener(env string, allow []safedial.AllowEntry) DirectoryOpener {
	return func(ctx context.Context, spec DirectorySpec) (DirectoryReader, error) {
		var roots *x509.CertPool
		if spec.CAPEM != "" {
			var err error
			if roots, err = ldapdir.CAPool(spec.CAPEM); err != nil {
				return nil, err
			}
		}
		if env == "" {
			env = config.Prod
		}
		d, err := safedial.New(safedial.Options{Env: env, Allow: allow, RootCAs: roots})
		if err != nil {
			return nil, err
		}
		return ldapdir.OpenReader(ctx, ldapdir.ReadConfig{Host: spec.Host, Port: spec.Port, BindDN: spec.BindDN,
			Password: ldapdir.Secret(spec.Password), Dialer: d})
	}
}

type ldapSource struct{ noChanges }

// ldapFail is a failed read of the directory. The cause is named by kind, not
// by the library's text, which may carry server messages.
func ldapFail(err error) error {
	switch {
	case errors.Is(err, ldapdir.ErrBindRefused):
		return conflict("source_auth_failed", "the directory refused the bind: check bind_dn and the password")
	case errors.Is(err, ldapdir.ErrTooManyEntries):
		return conflict("source_too_large", "the search returns more than %d entries: narrow base_dn or filter", MaxLDAPEntries)
	case errors.Is(err, safedial.ErrNoTLS):
		return conflict("source_tls_required", "the directory does not offer TLS (LDAPS or StartTLS), so nothing was sent")
	case errors.Is(err, safedial.ErrBlockedAddress), errors.Is(err, safedial.ErrPort), errors.Is(err, safedial.ErrHost):
		return conflict("source_address_refused", "the directory's address is not allowed from this server")
	case errors.Is(err, safedial.ErrHandshake):
		return conflict("source_tls_failed", "the directory's certificate could not be verified (add its CA as ca_pem)")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return conflict("source_timeout", "reading the directory took too long")
	}
	return conflict("source_fetch_failed", "reading the directory failed")
}

func (c *LDAPConfig) scope() ldapdir.Scope {
	if c.Scope == "one" {
		return ldapdir.ScopeOne
	}
	return ldapdir.ScopeSub
}

func (c *LDAPConfig) page() int {
	if c.PageSize > 0 {
		return c.PageSize
	}
	return 500
}

func (c *LDAPConfig) source() string {
	switch {
	case c.SubjectSource != "":
		return c.SubjectSource
	case strings.EqualFold(c.SubjectAttr, "mail"):
		return "email"
	}
	return "identity"
}

func (s ldapSource) Full(ctx context.Context, job LoaderJob) ([]LoadedGroup, error) {
	var cfg LDAPConfig
	if err := decodeConfig(job, &cfg); err != nil {
		return nil, err
	}
	if job.Env.Directory == nil {
		return nil, conflict("source_unavailable", "LDAP sources are not available on this server")
	}
	if len(job.Secret) == 0 {
		return nil, conflict("source_auth_missing", "the loader has no bind password")
	}
	ep, err := ParseLDAPURL(cfg.URL)
	if err != nil {
		return nil, invalid("invalid_config", "config: %v", err)
	}
	r, err := job.Env.Directory(ctx, DirectorySpec{Host: ep.Host, Port: ep.Port, BindDN: cfg.BindDN, Password: job.Secret, CAPEM: cfg.CAPEM})
	if err != nil {
		return nil, ldapFail(err)
	}
	defer r.Close()
	if job.Loader.Type == TypeLDAPSimple {
		return s.simple(ctx, job, &cfg, r)
	}
	return s.groupList(ctx, job, &cfg, r)
}

// simple: every entry the filter selects is a member of one group.
func (s ldapSource) simple(ctx context.Context, job LoaderJob, cfg *LDAPConfig, r DirectoryReader) ([]LoadedGroup, error) {
	es, err := r.Search(ctx, cfg.BaseDN, cfg.scope(), cfg.Filter, []string{cfg.SubjectAttr}, cfg.page(), MaxLDAPEntries)
	if err != nil {
		return nil, ldapFail(err)
	}
	job.Stats.Rows = len(es)
	g := LoadedGroup{Name: cfg.Group}
	seen := map[string]bool{}
	for _, e := range es {
		v := strings.TrimSpace(e.First(cfg.SubjectAttr))
		if v == "" {
			// an entry the filter selects but that cannot be named: listed, never skipped
			g.Members = append(g.Members, SubjectRef{Source: "ldap_dn", Identifier: e.DN})
			continue
		}
		if !seen[v] {
			seen[v] = true
			g.Members = append(g.Members, SubjectRef{Source: cfg.source(), Identifier: v})
		}
	}
	return []LoadedGroup{g}, nil
}

// groupList: every group entry the filter selects, with its members.
func (s ldapSource) groupList(ctx context.Context, job LoaderJob, cfg *LDAPConfig, r DirectoryReader) ([]LoadedGroup, error) {
	nameAttr, memberAttr := cfg.GroupNameAttr, cfg.MemberAttr
	if nameAttr == "" {
		nameAttr = "cn"
	}
	if memberAttr == "" {
		memberAttr = "member"
	}
	attrs := []string{nameAttr, memberAttr}
	if cfg.DisplayAttr != "" {
		attrs = append(attrs, cfg.DisplayAttr)
	}
	es, err := r.Search(ctx, cfg.BaseDN, cfg.scope(), cfg.Filter, attrs, cfg.page(), MaxLDAPEntries)
	if err != nil {
		return nil, ldapFail(err)
	}
	var out []LoadedGroup
	used := map[string]bool{}
	source := cfg.source()
	for _, e := range es {
		name := strings.TrimSpace(e.First(nameAttr))
		if name == "" {
			name = e.DN
		}
		ext := cfg.NamePrefix + sanitizeExt(name)
		if used[strings.ToLower(ext)] {
			ext += "_" + sanitizeExt(e.DN)
		}
		used[strings.ToLower(ext)] = true
		lg := LoadedGroup{Name: ext, DisplayName: strings.TrimSpace(e.First(cfg.DisplayAttr))}
		values, err := s.members(ctx, r, cfg, e, memberAttr)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, v := range values {
			id := v
			if cfg.MemberRDN != "" {
				rv, ok := ldapdir.RDNValue(v, cfg.MemberRDN)
				if !ok {
					// a member that is not that kind of DN (a nested group's, a service entry): listed
					lg.Members = append(lg.Members, SubjectRef{Source: "ldap_dn", Identifier: v})
					continue
				}
				id = rv
			}
			if id = strings.TrimSpace(id); id != "" && !seen[id] {
				seen[id] = true
				lg.Members = append(lg.Members, SubjectRef{Source: source, Identifier: id})
			}
		}
		job.Stats.Rows += len(lg.Members)
		out = append(out, lg)
	}
	return out, nil
}

// members returns every value of the member attribute. Active Directory
// returns at most 1,500 values at a time and names the window in the attribute
// ("member;range=0-1499"): the following windows are read by asking for
// "member;range=1500-*" until the server answers "*" as the end.
func (s ldapSource) members(ctx context.Context, r DirectoryReader, cfg *LDAPConfig, e ldapdir.Entry, attr string) ([]string, error) {
	prefix := strings.ToLower(attr) + ";range="
	var vals []string
	next := ""
	collect := func(en ldapdir.Entry) {
		for name, v := range en.Attrs {
			switch {
			case name == strings.ToLower(attr):
				vals = append(vals, v...)
			case strings.HasPrefix(name, prefix):
				vals = append(vals, v...)
				next = ""
				if _, hi, ok := strings.Cut(strings.TrimPrefix(name, prefix), "-"); ok && hi != "*" {
					if n, err := strconv.Atoi(hi); err == nil {
						next = strconv.Itoa(n + 1)
					}
				}
			}
		}
	}
	collect(e)
	for rounds := 0; next != ""; rounds++ {
		if rounds > 10_000 {
			return nil, conflict("source_too_large", "a group has too many members to read")
		}
		got, err := r.Search(ctx, e.DN, ldapdir.ScopeBase, "(objectClass=*)", []string{attr + ";range=" + next + "-*"}, 1, 1)
		if err != nil {
			return nil, ldapFail(err)
		}
		if len(got) == 0 {
			break
		}
		next = ""
		collect(got[0])
	}
	slices.Sort(vals) // a stable order whatever the server's
	return slices.Compact(vals), nil
}
