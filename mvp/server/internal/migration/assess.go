// Package migration assesses bounded offline exports. It has no database or
// network access; imported history and proposals never become live decisions.
package migration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/policy"
)

const (
	MaxBytes       = 8 << 20
	MaxRecords     = 20000
	MaxDepth       = 32
	MaxTokens      = 200000
	MaxValueBytes  = 8192
	AdapterVersion = "assessment-v1"
)

// Options identifies the assessment namespace. Tenant is an operator-supplied
// label, not an authenticated tenant or an automatic identity correlation.
type Options struct{ Tenant, Product, Instance, Format string }

type Identity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Account struct {
	ID             string   `json:"id"`
	IdentityID     string   `json:"identity_id"`
	Application    string   `json:"application"`
	NativeIdentity string   `json:"native_identity"`
	EntitlementIDs []string `json:"entitlement_ids"`
}
type Entitlement struct {
	ID          string `json:"id"`
	Application string `json:"application"`
	Attribute   string `json:"attribute"`
	Value       string `json:"value"`
	OwnerID     string `json:"owner_id,omitempty"`
}
type Role struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	OwnerID        string   `json:"owner_id,omitempty"`
	EntitlementIDs []string `json:"entitlement_ids"`
}
type SoD struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	ActionsA []string `json:"actions_a"`
	ActionsB []string `json:"actions_b"`
}

// Certification is source evidence only; no Tessera review IDs or approvals.
type Certification struct {
	ID            string `json:"id"`
	IdentityID    string `json:"identity_id"`
	EntitlementID string `json:"entitlement_id"`
	Decision      string `json:"decision"`
	DecidedAt     string `json:"decided_at"`
}

// Unsupported carries logic only on input. Reports retain its digest, not text.
type Unsupported struct {
	ObjectID string `json:"object_id"`
	Kind     string `json:"kind"`
	Content  string `json:"content"`
}

// Pack is Tessera's interchange contract, NOT a native ISC/Saviynt export format.
type Pack struct {
	SchemaVersion  int             `json:"schema_version"`
	ProductVersion string          `json:"product_version"`
	CapturedAt     string          `json:"captured_at"`
	Complete       bool            `json:"complete"`
	Identities     []Identity      `json:"identities"`
	Accounts       []Account       `json:"accounts"`
	Entitlements   []Entitlement   `json:"entitlements"`
	Roles          []Role          `json:"roles"`
	SoD            []SoD           `json:"sod"`
	Certifications []Certification `json:"certifications"`
	Unsupported    []Unsupported   `json:"unsupported"`
}
type Diagnostic struct {
	Code     string `json:"code"`
	Object   string `json:"object"`
	Field    string `json:"field"`
	Digest   string `json:"content_sha256,omitempty"`
	Blocking bool   `json:"blocking"`
}
type RoleProposal struct {
	SourceRef string `json:"source_ref"`
	Role      Role   `json:"role"`
	Status    string `json:"status"`
}
type SoDProposal struct {
	SourceRef  string         `json:"source_ref"`
	Definition map[string]any `json:"definition"`
	Status     string         `json:"status"`
}
type Report struct {
	SchemaVersion    int            `json:"schema_version"`
	AdapterVersion   string         `json:"adapter_version"`
	Tenant           string         `json:"tenant_label"`
	Product          string         `json:"source_product"`
	Instance         string         `json:"source_instance"`
	Format           string         `json:"format"`
	Digest           string         `json:"content_sha256"`
	Coverage         string         `json:"compatibility"`
	ComparisonStatus string         `json:"comparison_status"`
	Snapshot         Pack           `json:"snapshot"`
	Diagnostics      []Diagnostic   `json:"diagnostics"`
	RoleProposals    []RoleProposal `json:"role_proposals"`
	SoDProposals     []SoDProposal  `json:"sod_proposals"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (r *Report) ref(kind, id string) string {
	parts := []string{r.Tenant, r.Product, r.Instance, kind, id}
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// informational codes describe the report itself; they never block a migration.
var informational = map[string]bool{"provisional_source_id": true}

func (r *Report) diagnostic(code, kind, id, field, hash string) {
	r.Diagnostics = append(r.Diagnostics, Diagnostic{code, r.ref(kind, id), field, hash, !informational[code]})
}

func Assess(o Options, input io.Reader) (*Report, error) {
	for _, v := range []string{o.Tenant, o.Instance} {
		if strings.TrimSpace(v) == "" || len(v) > 256 {
			return nil, errors.New("migration: tenant and instance must be nonempty labels of at most 256 bytes")
		}
	}
	if o.Product != "sailpoint-iiq" && o.Product != "sailpoint-isc" && o.Product != "saviynt" {
		return nil, errors.New("migration: unsupported product")
	}
	if o.Format != "normalized-json" && !(o.Format == "iiq-xml" && o.Product == "sailpoint-iiq") {
		return nil, errors.New("migration: unsupported format/product combination")
	}
	b, err := io.ReadAll(io.LimitReader(input, MaxBytes+1))
	if err != nil {
		return nil, errors.New("migration: cannot read input")
	}
	if len(b) > MaxBytes {
		return nil, errors.New("migration: input exceeds 8 MiB")
	}
	r := &Report{SchemaVersion: 1, AdapterVersion: AdapterVersion, Tenant: o.Tenant, Product: o.Product, Instance: o.Instance, Format: o.Format, Digest: digest(b), Coverage: "synthetic-fixture-tested; native vendor compatibility unverified", ComparisonStatus: "not_performed", Diagnostics: []Diagnostic{}, RoleProposals: []RoleProposal{}, SoDProposals: []SoDProposal{}}
	if o.Format == "normalized-json" {
		if err := validateJSON(b); err != nil {
			return nil, err
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err := d.Decode(&r.Snapshot); err != nil {
			return nil, errors.New("migration: JSON does not match interchange schema")
		}
		if r.Snapshot.SchemaVersion != 1 {
			return nil, errors.New("migration: unsupported schema_version")
		}
	} else if err := parseXML(b, r); err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Token preflight rejects duplicate keys (encoding/json otherwise takes the
// last value), deep nesting and oversized values before typed decoding.
func validateJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	tokens := 0
	var walk func(int) error
	walk = func(depth int) error {
		if depth > MaxDepth {
			return errors.New("migration: JSON nesting limit")
		}
		tokens++
		if tokens > MaxTokens {
			return errors.New("migration: JSON token limit")
		}
		t, err := d.Token()
		if err != nil {
			return errors.New("migration: invalid JSON")
		}
		if s, ok := t.(string); ok && len(s) > MaxValueBytes {
			return errors.New("migration: JSON value limit")
		}
		if delim, ok := t.(json.Delim); ok {
			if delim != '{' && delim != '[' {
				return errors.New("migration: invalid JSON delimiter")
			}
			keys := map[string]bool{}
			for d.More() {
				if delim == '{' {
					key, err := d.Token()
					if err != nil {
						return errors.New("migration: invalid JSON key")
					}
					k, ok := key.(string)
					if !ok || len(k) > MaxValueBytes || keys[k] {
						return errors.New("migration: duplicate or invalid JSON key")
					}
					keys[k] = true
					tokens++
					if tokens > MaxTokens {
						return errors.New("migration: JSON token limit")
					}
				}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
				return errors.New("migration: invalid JSON container")
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("migration: trailing JSON data")
	}
	return nil
}

func (r *Report) validate() error {
	p := &r.Snapshot
	if len(p.Identities)+len(p.Accounts)+len(p.Entitlements)+len(p.Roles)+len(p.SoD)+len(p.Certifications)+len(p.Unsupported) > MaxRecords {
		return errors.New("migration: record limit")
	}
	sets := map[string]map[string]bool{}
	add := func(kind, id string) error {
		if strings.TrimSpace(id) == "" {
			return errors.New("migration: missing object ID")
		}
		if sets[kind] == nil {
			sets[kind] = map[string]bool{}
		}
		if sets[kind][id] {
			return errors.New("migration: duplicate object ID")
		}
		sets[kind][id] = true
		return nil
	}
	for _, x := range p.Identities {
		if err := add("identity", x.ID); err != nil {
			return err
		}
	}
	for _, x := range p.Accounts {
		if err := add("account", x.ID); err != nil {
			return err
		}
	}
	for _, x := range p.Entitlements {
		if err := add("entitlement", x.ID); err != nil {
			return err
		}
	}
	for _, x := range p.Roles {
		if err := add("role", x.ID); err != nil {
			return err
		}
	}
	for _, x := range p.SoD {
		if err := add("sod", x.ID); err != nil {
			return err
		}
	}
	for _, x := range p.Certifications {
		if err := add("certification", x.ID); err != nil {
			return err
		}
	}
	check := func(kind, id, field, target, ref string, required bool) {
		if ref == "" && !required {
			return
		}
		if !sets[target][ref] {
			r.diagnostic("unresolved_reference", kind, id, field, "")
		}
	}
	for _, x := range p.Accounts {
		check("account", x.ID, "identity_id", "identity", x.IdentityID, true)
		for _, id := range x.EntitlementIDs {
			check("account", x.ID, "entitlement_ids", "entitlement", id, true)
		}
	}
	for _, x := range p.Entitlements {
		check("entitlement", x.ID, "owner_id", "identity", x.OwnerID, false)
	}
	for _, x := range p.Roles {
		check("role", x.ID, "owner_id", "identity", x.OwnerID, false)
		for _, id := range x.EntitlementIDs {
			check("role", x.ID, "entitlement_ids", "entitlement", id, true)
		}
		r.RoleProposals = append(r.RoleProposals, RoleProposal{r.ref("role", x.ID), x, "draft_business_role; destination validation pending"})
	}
	for _, x := range p.SoD {
		valid := len(x.ActionsA) > 0 && len(x.ActionsB) > 0
		for _, action := range append(append([]string{}, x.ActionsA...), x.ActionsB...) {
			if strings.TrimSpace(action) == "" {
				valid = false
			}
		}
		if !valid {
			r.diagnostic("invalid_sod_actions", "sod", x.ID, "actions_a/actions_b", "")
			continue
		}
		definition := map[string]any{"id": r.ref("sod", x.ID), "name": x.Name, "type": "separation_of_duties", "severity": "high", "enabled": false, "conflict": map[string]any{"a": x.ActionsA, "b": x.ActionsB}}
		if _, err := policy.Parse(definition, "migration proposal"); err != nil {
			// One definition the engine rejects must not hide the rest of the report.
			r.diagnostic("sod_proposal_invalid", "sod", x.ID, "definition", "")
			continue
		}
		r.SoDProposals = append(r.SoDProposals, SoDProposal{r.ref("sod", x.ID), definition, "draft_disabled"})
	}
	for _, x := range p.Certifications {
		check("certification", x.ID, "identity_id", "identity", x.IdentityID, true)
		check("certification", x.ID, "entitlement_id", "entitlement", x.EntitlementID, true)
		if x.Decision != "approve" && x.Decision != "revoke" {
			r.diagnostic("unsupported_certification_decision", "certification", x.ID, "decision", "")
		}
		if _, err := time.Parse(time.RFC3339, x.DecidedAt); err != nil {
			r.diagnostic("invalid_timestamp", "certification", x.ID, "decided_at", "")
		}
	}
	for _, x := range p.Unsupported {
		r.diagnostic("unsupported_logic", "unsupported", x.ObjectID, x.Kind, digest([]byte(x.Content)))
	}
	p.Unsupported = nil // never echo raw vendor code or credentials
	if _, err := time.Parse(time.RFC3339, p.CapturedAt); err != nil {
		r.diagnostic("capture_time_unverified", "snapshot", "", "captured_at", "")
	}
	if !p.Complete {
		r.diagnostic("incomplete_source", "snapshot", "", "complete", "")
	}
	sort.Slice(r.Diagnostics, func(i, j int) bool {
		a, b := r.Diagnostics[i], r.Diagnostics[j]
		return a.Object+a.Field+a.Code+a.Digest < b.Object+b.Field+b.Code+b.Digest
	})
	return nil
}

// WriteReport does not persist or activate anything. The caller controls output
// storage; reports contain identity metadata and must be treated as sensitive.
func WriteReport(w io.Writer, r *Report) error {
	if r == nil {
		return fmt.Errorf("migration: missing report")
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}
