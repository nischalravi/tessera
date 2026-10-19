package transport

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Actions in a plan.
const (
	Add       = "add"
	Change    = "change"
	Remove    = "remove"
	Unchanged = "unchanged"
	Manual    = "manual" // differs, but is not applied by an import
)

// Item is one planned change.
type Item struct {
	Section string   `json:"section"` // connections | overlays | identity_providers
	Name    string   `json:"name"`
	Action  string   `json:"action"`
	Fields  []string `json:"fields,omitempty"` // what differs, for a change
	Notes   []string `json:"notes,omitempty"`
}

// Plan is what applying a bundle would do.
type Plan struct {
	Hash      string   `json:"hash"`
	Signer    string   `json:"signer"`
	SignerKID string   `json:"signer_kid"`
	Source    Source   `json:"source"`
	Exported  string   `json:"exported_at"`
	Items     []Item   `json:"items"`
	Refusals  []string `json:"refusals"` // non-empty: the bundle cannot be applied here
	Counts    Counts   `json:"counts"`
	// Digest and DigestPrune bind an apply to this plan (without and with
	// prune): the bundle, the destination tenant and environment, the
	// current state of what the plan touches, the proposed operations and
	// the prune mode. Apply recomputes the digest in its own transaction and
	// refuses with 409 stale_plan when it differs.
	Digest      string `json:"digest"`
	DigestPrune string `json:"digest_prune"`

	state []string // the destination state the plan was made against (digest input)
}

// digest hashes everything the reviewed plan depends on.
func (p *Plan) digest(tenant string, target Target, prune bool) string {
	state := append([]string(nil), p.state...)
	sort.Strings(state)
	raw, _ := json.Marshal(struct {
		V      int      `json:"v"`
		Tenant string   `json:"tenant"`
		Prod   bool     `json:"prod"`
		Prune  bool     `json:"prune"`
		Bundle string   `json:"bundle"`
		Items  []Item   `json:"items"`
		State  []string `json:"state"`
	}{1, tenant, target.Prod, prune, p.Hash, p.Items, state})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// Counts summarize a plan.
type Counts struct {
	Add       int `json:"add"`
	Change    int `json:"change"`
	Remove    int `json:"remove"`
	Unchanged int `json:"unchanged"`
	Manual    int `json:"manual"`
}

// Target is where a bundle is applied.
type Target struct {
	Prod bool // a production server: dev-only values are refused
}

// MakePlan compares a verified bundle with the tenant's configuration.
func MakePlan(tx *store.TenantTx, rd *readiness.Service, v *Verified, target Target, now time.Time) (*Plan, error) {
	b := v.Bundle
	p := &Plan{Hash: v.Hash, Signer: v.Signer.Label, SignerKID: v.Signer.KID, Source: b.Source,
		Exported: b.ExportedAt.UTC().Format(time.RFC3339), Items: []Item{}, Refusals: []string{}}
	p.Refusals = append(p.Refusals, secretFree(b)...)
	if target.Prod {
		p.Refusals = append(p.Refusals, devOnly(b)...)
	}
	if err := planConnections(tx, rd, b, p, now); err != nil {
		return nil, err
	}
	if err := planOverlays(tx, rd, b, p); err != nil {
		return nil, err
	}
	if err := planIdPs(tx, b, p); err != nil {
		return nil, err
	}
	for _, it := range p.Items {
		switch it.Action {
		case Add:
			p.Counts.Add++
		case Change:
			p.Counts.Change++
		case Remove:
			p.Counts.Remove++
		case Manual:
			p.Counts.Manual++
		default:
			p.Counts.Unchanged++
		}
	}
	p.Digest = p.digest(tx.Tenant().String(), target, false)
	p.DigestPrune = p.digest(tx.Tenant().String(), target, true)
	return p, nil
}

// devOnly lists values a production server must not take: dev-only URLs
// (config.DevOnlyURL) anywhere in a connection or sign-in connection, and
// the dev mock IdP.
func devOnly(b *Bundle) []string {
	var out []string
	for _, c := range b.Connections {
		var v any
		if json.Unmarshal(c.Config, &v) == nil {
			for _, s := range stringsIn(v) {
				if loopback(s) {
					out = append(out, fmt.Sprintf("connection %q points at %s, a localhost address, which a production server does not accept", c.Name, s))
				}
			}
		}
	}
	for _, i := range b.IdentityProviders {
		if i.Profile == "dev_mock" {
			out = append(out, fmt.Sprintf("sign-in connection %q is the dev mock IdP", i.Name))
		}
		for _, u := range []*string{i.Issuer, i.DiscoveryURL, i.IdPSSOURL, i.MetadataURL} {
			if u != nil {
				if why := config.DevOnlyURL(*u); why != "" {
					out = append(out, fmt.Sprintf("sign-in connection %q points at %s (%s)", i.Name, *u, why))
				}
			}
		}
	}
	return out
}

// loopback reports a URL or bare host[:port] that names this machine.
// Private addresses are fine for connections: directories usually live on
// internal networks.
func loopback(s string) bool {
	s = strings.TrimSpace(s)
	host := s
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && (a.Unmap().IsLoopback() || a.IsUnspecified())
}

func stringsIn(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, stringsIn(e)...)
		}
		return out
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []string
		for _, k := range keys {
			out = append(out, stringsIn(x[k])...)
		}
		return out
	}
	return nil
}

func jsonEq(a, b json.RawMessage) bool {
	return bytes.Equal(compactRaw(a, "null"), compactRaw(b, "null"))
}

func strEq(a, b *string) bool {
	return (a == nil || *a == "") == (b == nil || *b == "") && (a == nil || b == nil || *a == *b)
}

// changedKeys lists the top-level config keys whose values differ.
func changedKeys(a, b json.RawMessage) []string {
	var ma, mb map[string]json.RawMessage
	_ = json.Unmarshal(a, &ma)
	_ = json.Unmarshal(b, &mb)
	seen := map[string]bool{}
	var out []string
	for k, va := range ma {
		seen[k] = true
		if vb, ok := mb[k]; !ok || !jsonEq(va, vb) {
			out = append(out, "config."+k)
		}
	}
	for k := range mb {
		if !seen[k] {
			out = append(out, "config."+k)
		}
	}
	sort.Strings(out)
	return out
}

type liveConn struct {
	conn *store.Connection
	cfg  json.RawMessage
	cred Credential
	rev  string // the current revision: id, config hash and credential reference
}

func liveConnections(tx *store.TenantTx, rd *readiness.Service, now time.Time) (map[string]liveConn, error) {
	conns, err := tx.Connections()
	if err != nil {
		return nil, err
	}
	out := map[string]liveConn{}
	for _, c := range conns {
		if c.RetiredAt != nil {
			continue
		}
		cur, err := rd.Current(tx, c.ID, now)
		if err != nil {
			return nil, err
		}
		lc := liveConn{conn: c, cfg: compactJSON(cur.Rev.Config), cred: Credential{Kind: "none"}}
		lc.rev = cur.Rev.ID + ":" + cur.Rev.ConfigHash
		if r := cur.Rev.SecretRef; r != nil {
			lc.rev += ":" + shortHash(*r)
		}
		if r := cur.Rev.SecretRef; r != nil && *r != "" {
			if len(*r) > 7 && (*r)[:7] == "sealed:" {
				lc.cred = Credential{Kind: "sealed"}
			} else {
				lc.cred = Credential{Kind: "reference", Reference: *r}
			}
		}
		out[c.Name] = lc
	}
	return out, nil
}

func planConnections(tx *store.TenantTx, rd *readiness.Service, b *Bundle, p *Plan, now time.Time) error {
	live, err := liveConnections(tx, rd, now)
	if err != nil {
		return err
	}
	all, err := tx.Connections()
	if err != nil {
		return err
	}
	// Names and systems are unique across all connections, retired ones too.
	takenName, takenSystem := map[string]*store.Connection{}, map[string]*store.Connection{}
	for _, c := range all {
		takenName[c.Name] = c
		takenSystem[c.System] = c
		p.state = append(p.state, fmt.Sprintf("connection|%s|%s|%s|%t", c.ID, c.Name, c.System, c.RetiredAt != nil))
	}
	for n, l := range live {
		p.state = append(p.state, "revision|"+n+"|"+l.rev)
	}
	inBundle := map[string]bool{}
	for _, c := range b.Connections {
		inBundle[c.Name] = true
		it := Item{Section: "connections", Name: c.Name}
		l, ok := live[c.Name]
		switch {
		case !ok && takenName[c.Name] != nil:
			it.Action = Manual
			it.Notes = append(it.Notes, "a retired connection here has this name: rename one of them")
		case !ok && takenSystem[c.System] != nil:
			it.Action = Manual
			it.Notes = append(it.Notes, fmt.Sprintf("connection %q here already covers system %q", takenSystem[c.System].Name, c.System))
		case ok && l.conn.System != c.System:
			it.Action = Manual
			it.Notes = append(it.Notes, fmt.Sprintf("this connection covers system %q here, %q in the bundle", l.conn.System, c.System))
		case !ok:
			it.Action = Add
			it.Notes = append(it.Notes, "created as a draft: validate and dry-run it here before activating")
		case l.conn.ConnectorType != c.ConnectorType:
			it.Action = Manual
			it.Notes = append(it.Notes, fmt.Sprintf("a %s connection here has this name; the bundle has a %s one", l.conn.ConnectorType, c.ConnectorType))
		default:
			it.Fields = changedKeys(l.cfg, c.Config)
			if c.Credential.Kind == "reference" && l.cred.Reference != c.Credential.Reference {
				it.Fields = append(it.Fields, "credential")
			}
			it.Action = Unchanged
			if len(it.Fields) > 0 {
				it.Action = Change
				it.Notes = append(it.Notes, "a config change makes a new draft revision; the active one keeps running until it is re-validated")
			}
		}
		if c.Credential.Kind == "sealed" && (!ok || l.cred.Kind == "none") {
			it.Notes = append(it.Notes, "the credential is not in the bundle: set it here")
		}
		p.Items = append(p.Items, it)
	}
	names := make([]string, 0, len(live))
	for n := range live {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if !inBundle[n] {
			p.Items = append(p.Items, Item{Section: "connections", Name: n, Action: Remove,
				Notes: []string{"retired only when the import is applied with prune"}})
		}
	}
	return nil
}

func planOverlays(tx *store.TenantTx, rd *readiness.Service, b *Bundle, p *Plan) error {
	for _, o := range b.Overlays {
		it := Item{Section: "overlays", Name: o.TemplateID}
		if _, ok := rd.Templates.Get(o.TemplateID); !ok {
			it.Action = Manual
			it.Notes = append(it.Notes, "this Tessera has no such readiness template")
			p.Items = append(p.Items, it)
			continue
		}
		cur, err := tx.LatestOverlay(o.TemplateID)
		if err != nil {
			return err
		}
		if cur == nil {
			p.state = append(p.state, "overlay|"+o.TemplateID+"|none")
		} else {
			p.state = append(p.state, fmt.Sprintf("overlay|%s|%d|%s", o.TemplateID, cur.Version, shortHash(cur.Body)))
		}
		switch {
		case cur == nil:
			it.Action = Add
		case jsonOrTextEq(cur.Body, o.Body):
			it.Action = Unchanged
		default:
			it.Action = Change
			it.Fields = []string{"body"}
		}
		p.Items = append(p.Items, it)
	}
	return nil
}

func jsonOrTextEq(a, b string) bool {
	var va, vb any
	if json.Unmarshal([]byte(a), &va) == nil && json.Unmarshal([]byte(b), &vb) == nil {
		return jsonEq(json.RawMessage(a), json.RawMessage(b))
	}
	return a == b
}

func planIdPs(tx *store.TenantTx, b *Bundle, p *Plan) error {
	idps, err := tx.IdPConnections()
	if err != nil {
		return err
	}
	byName := map[string]*store.IdPConnection{}
	for _, c := range idps {
		byName[c.Name] = c
		p.state = append(p.state, "idp|"+c.ID.String()+"|"+c.Name)
	}
	for _, i := range b.IdentityProviders {
		it := Item{Section: "identity_providers", Name: i.Name}
		cur, ok := byName[i.Name]
		if !ok {
			it.Action = Add
			it.Notes = append(it.Notes, "added as pending: it signs nobody in until an admin activates it")
			if i.NeedsSecret {
				it.Notes = append(it.Notes, "set its client secret here")
			}
		} else {
			it.Fields = idpDiff(idpOf(cur), i)
			it.Action = Unchanged
			if len(it.Fields) > 0 {
				it.Action = Manual
				it.Notes = append(it.Notes, "sign-in trust is not changed by an import: make the change through an admin change request")
			}
		}
		p.Items = append(p.Items, it)
	}
	return nil
}

func idpDiff(a, b IdP) []string {
	var out []string
	add := func(name string, same bool) {
		if !same {
			out = append(out, name)
		}
	}
	add("protocol", a.Protocol == b.Protocol)
	add("profile", a.Profile == b.Profile)
	add("verified_domains", jsonEq(a.VerifiedDomains, b.VerifiedDomains))
	add("issuer", strEq(a.Issuer, b.Issuer))
	add("discovery_url", strEq(a.DiscoveryURL, b.DiscoveryURL))
	add("client_id", strEq(a.ClientID, b.ClientID))
	add("client_auth_method", strEq(a.ClientAuthMethod, b.ClientAuthMethod))
	add("scopes", jsonEq(a.Scopes, b.Scopes))
	add("id_token_algs", jsonEq(a.IDTokenAlgs, b.IDTokenAlgs))
	add("step_up_request", jsonEq(a.StepUpRequest, b.StepUpRequest))
	add("idp_entity_id", strEq(a.IdPEntityID, b.IdPEntityID))
	add("idp_sso_url", strEq(a.IdPSSOURL, b.IdPSSOURL))
	add("idp_signing_certs", jsonEq(a.IdPSigningCerts, b.IdPSigningCerts))
	add("metadata_url", strEq(a.MetadataURL, b.MetadataURL))
	add("pin_certs", a.PinCerts == b.PinCerts)
	add("subject_source", a.SubjectSource == b.SubjectSource)
	add("attribute_map", jsonEq(a.AttributeMap, b.AttributeMap))
	add("authn_mapping", jsonEq(a.AuthnMapping, b.AuthnMapping))
	add("assume_phishing_resistant", a.AssumePhishingResistant == b.AssumePhishingResistant)
	add("groups_claim", strEq(a.GroupsClaim, b.GroupsClaim))
	add("group_role_mapping", jsonEq(a.GroupRoleMapping, b.GroupRoleMapping))
	add("jit_provisioning", a.JITProvisioning == b.JITProvisioning)
	add("default_role", a.DefaultRole == b.DefaultRole)
	return out
}

// ------------------------------------------------------------------- apply

// Applied is the outcome of an apply.
type Applied struct {
	ImportID string `json:"import_id"`
	Plan     *Plan  `json:"plan"`
}

// Apply plans a verified bundle again and makes the changes, all in tx.
// Removals happen only with prune. It refuses a bundle whose plan has
// refusals.
func Apply(tx *store.TenantTx, rd *readiness.Service, v *Verified, target Target, prune bool, digest string, actor string, actorUser *string, now time.Time) (*Applied, error) {
	p, err := MakePlan(tx, rd, v, target, now)
	if err != nil {
		return nil, err
	}
	// The digest the admin reviewed must still describe this tenant, this
	// prune choice and these operations: checked before anything is written.
	want := p.Digest
	if prune {
		want = p.DigestPrune
	}
	if digest == "" || subtle.ConstantTimeCompare([]byte(digest), []byte(want)) != 1 {
		return nil, refuse(409, "stale_plan", "the configuration here or the prune choice changed since the preview; plan the import again and review it")
	}
	if len(p.Refusals) > 0 {
		return nil, refuse(422, "bundle_refused", "this bundle cannot be applied here: %s", p.Refusals[0])
	}
	b := v.Bundle
	live, err := liveConnections(tx, rd, now)
	if err != nil {
		return nil, err
	}
	byName := map[string]Connection{}
	for _, c := range b.Connections {
		byName[c.Name] = c
	}
	for _, it := range p.Items {
		switch it.Section {
		case "connections":
			if err := applyConnection(tx, rd, it, byName[it.Name], live[it.Name], prune, actor, now); err != nil {
				return nil, fmt.Errorf("connection %q: %w", it.Name, err)
			}
		case "overlays":
			if it.Action != Add && it.Action != Change {
				continue
			}
			for _, o := range b.Overlays {
				if o.TemplateID == it.Name {
					if _, err := rd.PutOverlay(tx, o.TemplateID, []byte(o.Body), actor, now); err != nil {
						return nil, fmt.Errorf("overlay %q: %w", it.Name, err)
					}
				}
			}
		case "identity_providers":
			if it.Action != Add {
				continue
			}
			for _, i := range b.IdentityProviders {
				if i.Name == it.Name {
					if err := tx.InsertIdPConnection(newIdP(tx, i, now)); err != nil {
						return nil, fmt.Errorf("sign-in connection %q: %w", it.Name, err)
					}
				}
			}
		}
	}
	summary, _ := json.Marshal(p.Counts)
	imp := &store.ConfigImport{ID: uuid.NewString(), BundleHash: v.Hash, SignerKID: v.Signer.KID,
		Source: fmt.Sprintf("%s (%s)", b.Source.Tenant, b.Source.Env), ExportedAt: b.ExportedAt, Summary: string(summary),
		AppliedBy: actorUser, AppliedAt: now}
	if err := tx.InsertConfigImport(imp); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actor, "config.import.applied", ojson.Object{{Key: "import_id", Value: imp.ID},
		{Key: "bundle_hash", Value: v.Hash}, {Key: "signer_kid", Value: v.Signer.KID}, {Key: "signer", Value: v.Signer.Label},
		{Key: "source_tenant", Value: b.Source.Tenant}, {Key: "source_env", Value: b.Source.Env},
		{Key: "added", Value: p.Counts.Add}, {Key: "changed", Value: p.Counts.Change},
		{Key: "removed", Value: map[bool]int{true: p.Counts.Remove, false: 0}[prune]}, {Key: "manual", Value: p.Counts.Manual},
		{Key: "prune", Value: prune}}); err != nil {
		return nil, err
	}
	return &Applied{ImportID: imp.ID, Plan: p}, nil
}

func applyConnection(tx *store.TenantTx, rd *readiness.Service, it Item, c Connection, l liveConn, prune bool, actor string, now time.Time) error {
	switch it.Action {
	case Add:
		bun, err := rd.Create(tx, readiness.CreateInput{Name: c.Name, ConnectorType: c.ConnectorType, System: c.System, Role: c.Role,
			Config: c.Config}, actor, now)
		if err != nil {
			return err
		}
		return applyRef(tx, rd, bun.Conn.ID, c, actor, now)
	case Change:
		if len(changedKeys(l.cfg, c.Config)) > 0 {
			if _, err := rd.PatchConfig(tx, l.conn.ID, replacePatch(l.cfg, c.Config), actor, now); err != nil {
				return err
			}
		}
		return applyRef(tx, rd, l.conn.ID, c, actor, now)
	case Remove:
		if prune {
			return rd.Retire(tx, l.conn.ID, actor, now)
		}
	}
	return nil
}

// replacePatch is a merge patch that turns config from into to: keys only
// in from are set to null, which removes them.
func replacePatch(from, to json.RawMessage) []byte {
	var mf, mt map[string]json.RawMessage
	_ = json.Unmarshal(from, &mf)
	_ = json.Unmarshal(to, &mt)
	if mt == nil {
		mt = map[string]json.RawMessage{}
	}
	for k := range mf {
		if _, ok := mt[k]; !ok {
			mt[k] = json.RawMessage("null")
		}
	}
	out, _ := json.Marshal(mt)
	return out
}

// applyRef sets an external credential reference that differs. Owners
// travel in the config.
func applyRef(tx *store.TenantTx, rd *readiness.Service, connID string, c Connection, actor string, now time.Time) error {
	if c.Credential.Kind != "reference" || c.Credential.Reference == "" {
		return nil
	}
	cur, err := rd.Current(tx, connID, now)
	if err != nil {
		return err
	}
	if cur.Rev.SecretRef != nil && *cur.Rev.SecretRef == c.Credential.Reference {
		return nil
	}
	_, err = rd.SetCredential(tx, connID, readiness.CredentialInput{Reference: c.Credential.Reference}, actor, now)
	return err
}

func newIdP(tx *store.TenantTx, i IdP, now time.Time) *store.IdPConnection {
	return &store.IdPConnection{ID: uuid.New(), TenantID: tx.Tenant(), Name: i.Name, Protocol: i.Protocol, Profile: i.Profile, Status: "pending",
		VerifiedDomains: i.VerifiedDomains, Issuer: i.Issuer, DiscoveryURL: i.DiscoveryURL, ClientID: i.ClientID,
		ClientAuthMethod: i.ClientAuthMethod, Scopes: i.Scopes, IDTokenAlgs: i.IDTokenAlgs, StepUpRequest: i.StepUpRequest,
		IdPEntityID: i.IdPEntityID, IdPSSOURL: i.IdPSSOURL, IdPSigningCerts: i.IdPSigningCerts, MetadataURL: i.MetadataURL,
		PinCerts: i.PinCerts, SubjectSource: i.SubjectSource, AttributeMap: i.AttributeMap, AuthnMapping: i.AuthnMapping,
		AssumePhishingResistant: i.AssumePhishingResistant, GroupsClaim: i.GroupsClaim, GroupRoleMapping: i.GroupRoleMapping,
		JITProvisioning: i.JITProvisioning, DefaultRole: i.DefaultRole, CreatedAt: now, UpdatedAt: now}
}
