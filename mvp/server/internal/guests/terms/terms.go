// Package terms is the guest terms of use (guest accounts design §7.4, issue
// #73): versioned documents with the SHA-256 of their text, assigned to guest
// populations and access bundles; the acceptance ledger; the check that a
// person has accepted what applies to them; and the re-acceptance of a new
// version with a grace period. It also records the attribute-release consent
// of a federated sign-in (consent.go).
//
// Acceptance in a claim happens before a credential is bound (the claim
// refuses to start or complete the credential step while a document is
// outstanding). After the claim, a new version of a document must be accepted
// within the document's grace period; after it, the person's access is blocked
// until they accept (the API's authorize step asks Blocked).
package terms

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Error is a refused change; Code is stable for API clients.
type Error = requests.Error

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Limits on what an administrator may publish.
const (
	MaxTitle       = 200
	MaxBody        = 100_000
	DefaultGrace   = 14
	MaxGraceDays   = 365
	ScopePopPrefix = "population:"
	ScopeBundle    = "bundle:"
)

var keyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Populations a document may be assigned to.
var Populations = []string{store.PopVisitor, store.PopContractor, store.PopVolunteer, store.PopPartner}

// Hash is the SHA-256 (hex) of a document's rendered text.
func Hash(body string) string { return seal.SHA256Hex([]byte(body)) }

// Input is a new version of a document.
type Input struct {
	Key       string
	Title     string
	Body      string
	GraceDays *int // nil: DefaultGrace
}

func audited(tx *store.TenantTx, now time.Time, action, targetType, targetID string, detail ojson.Object, opts ...audit.Option) error {
	opts = append([]audit.Option{audit.At(now), audit.Target(targetType, targetID)}, opts...)
	_, err := audit.Record(tx.Context(), tx, action, detail, opts...)
	return err
}

// Publish records a new version of the document Input.Key (the first version
// when the key is new). The version is the next number, the hash is of the
// body as given, and publishing a body identical to the current version is
// refused. The new version is in force at once; people who accepted an earlier
// one have the document's grace period to accept it.
func Publish(tx *store.TenantTx, createdBy string, in Input, now time.Time) (*store.TermsDocument, error) {
	in.Key, in.Title = strings.TrimSpace(in.Key), strings.TrimSpace(in.Title)
	grace := DefaultGrace
	if in.GraceDays != nil {
		grace = *in.GraceDays
	}
	switch {
	case !keyRE.MatchString(in.Key):
		return nil, refuse(422, "invalid_key", "the key is lower-case letters, digits and hyphens, up to 64")
	case in.Title == "" || len(in.Title) > MaxTitle:
		return nil, refuse(422, "invalid_title", "the title is required, up to %d characters", MaxTitle)
	case strings.TrimSpace(in.Body) == "" || len(in.Body) > MaxBody:
		return nil, refuse(422, "invalid_body", "the text is required, up to %d bytes", MaxBody)
	case grace < 0 || grace > MaxGraceDays:
		return nil, refuse(422, "invalid_grace", "the grace period is 0 to %d days", MaxGraceDays)
	}
	all, err := tx.TermsDocuments()
	if err != nil {
		return nil, err
	}
	version := 1
	hash := Hash(in.Body)
	for _, d := range all {
		if d.Key == in.Key && d.Version >= version {
			version = d.Version + 1
			if d.TextSHA256 == hash {
				return nil, refuse(409, "unchanged", "that text is already version %d", d.Version)
			}
		}
	}
	d := &store.TermsDocument{ID: uuid.NewString(), Key: in.Key, Version: version, Title: in.Title, Body: in.Body, TextSHA256: hash,
		GraceDays: grace, CreatedBy: createdBy, CreatedAt: now}
	if err := tx.InsertTermsDocument(d); err != nil {
		return nil, err
	}
	return d, audited(tx, now, "terms.publish", "terms_document", d.ID, ojson.Object{{Key: "document_id", Value: d.ID},
		{Key: "key", Value: d.Key}, {Key: "version", Value: d.Version}, {Key: "text_sha256", Value: d.TextSHA256},
		{Key: "grace_days", Value: d.GraceDays}})
}

// Latest returns the version in force of each document key.
func Latest(tx *store.TenantTx) (map[string]*store.TermsDocument, error) {
	all, err := tx.TermsDocuments()
	if err != nil {
		return nil, err
	}
	out := map[string]*store.TermsDocument{}
	for _, d := range all {
		if cur, ok := out[d.Key]; !ok || d.Version > cur.Version {
			out[d.Key] = d
		}
	}
	return out, nil
}

// Assign sets the populations and bundles (group ids of catalog items) the
// document applies to, replacing what it applied to before.
func Assign(tx *store.TenantTx, key string, populations []string, bundles []int64, now time.Time) error {
	latest, err := Latest(tx)
	if err != nil {
		return err
	}
	if _, ok := latest[key]; !ok {
		return store.ErrNotFound
	}
	var rows []*store.TermsAssignment
	seen := map[string]bool{}
	for _, p := range populations {
		pop := p
		if !slices.Contains(Populations, pop) {
			return refuse(422, "invalid_population", "%q is not a guest population", pop)
		}
		if scope := ScopePopPrefix + pop; !seen[scope] {
			seen[scope] = true
			rows = append(rows, &store.TermsAssignment{ID: uuid.NewString(), Key: key, Scope: scope, Population: &pop, CreatedAt: now})
		}
	}
	for _, g := range bundles {
		gid := g
		if _, err := tx.Group(gid); errors.Is(err, store.ErrNotFound) {
			return refuse(422, "invalid_bundle", "group %d is not known", gid)
		} else if err != nil {
			return err
		}
		if scope := ScopeBundle + strconv.FormatInt(gid, 10); !seen[scope] {
			seen[scope] = true
			rows = append(rows, &store.TermsAssignment{ID: uuid.NewString(), Key: key, Scope: scope, GroupID: &gid, CreatedAt: now})
		}
	}
	// an assignment that stays keeps its date: the grace period of a document
	// newly assigned to someone runs from the day it was first assigned
	old, err := tx.TermsAssignments()
	if err != nil {
		return err
	}
	for _, o := range old {
		if o.Key != key {
			continue
		}
		for _, r := range rows {
			if r.Scope == o.Scope {
				r.CreatedAt = o.CreatedAt
			}
		}
	}
	if err := tx.ReplaceTermsAssignments(key, rows); err != nil {
		return err
	}
	scopes := make([]string, 0, len(rows))
	for _, r := range rows {
		scopes = append(scopes, r.Scope)
	}
	return audited(tx, now, "terms.assign", "terms_document", key, ojson.Object{{Key: "key", Value: key}, {Key: "scopes", Value: scopes}})
}

// States of a requirement.
const (
	StateAccepted = "accepted" // the version in force was accepted
	StateGrace    = "grace"    // not yet, and access continues until DueBy
	StateBlocked  = "blocked"  // not accepted and DueBy has passed
)

// Requirement is one document that applies to a person and where it stands.
type Requirement struct {
	Doc   *store.TermsDocument
	State string
	// DueBy is when access stops if the version in force is still not
	// accepted: its publication plus the grace period (for a document first
	// assigned later, the assignment plus the grace period).
	DueBy time.Time
	// Prior is true when the person accepted an earlier version.
	Prior bool
}

// Outstanding reports whether the person still has to accept this version.
func (r Requirement) Outstanding() bool { return r.State != StateAccepted }

type bundleRef struct {
	GroupID int64 `json:"group_id"`
}

// scopesOf are the assignment scopes that apply to a person: the populations
// and bundles of the sponsorships they hold.
func scopesOf(tx *store.TenantTx, identityID int64) (map[string]bool, error) {
	all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: identityID})
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, s := range all {
		if !s.Live() {
			continue
		}
		out[ScopePopPrefix+s.Population] = true
		var items []bundleRef
		if s.AccessBundle != "" && json.Unmarshal([]byte(s.AccessBundle), &items) == nil {
			for _, it := range items {
				out[ScopeBundle+strconv.FormatInt(it.GroupID, 10)] = true
			}
		}
	}
	return out, nil
}

// Required lists the documents that apply to a person, each at the version in
// force, with where it stands at now. The list is empty for a person nothing
// is assigned to, and for a tenant with no terms (a single cheap query).
func Required(tx *store.TenantTx, identityID int64, now time.Time) ([]Requirement, error) {
	has, err := tx.HasTermsDocuments()
	if err != nil || !has {
		return nil, err
	}
	scopes, err := scopesOf(tx, identityID)
	if err != nil || len(scopes) == 0 {
		return nil, err
	}
	assigns, err := tx.TermsAssignments()
	if err != nil {
		return nil, err
	}
	assigned := map[string]time.Time{} // key -> first assignment that applies
	for _, a := range assigns {
		if !scopes[a.Scope] {
			continue
		}
		if at, ok := assigned[a.Key]; !ok || a.CreatedAt.Before(at) {
			assigned[a.Key] = a.CreatedAt
		}
	}
	if len(assigned) == 0 {
		return nil, nil
	}
	latest, err := Latest(tx)
	if err != nil {
		return nil, err
	}
	accs, err := tx.TermsAcceptancesFor(identityID)
	if err != nil {
		return nil, err
	}
	accepted, prior := map[string]bool{}, map[string]bool{}
	for _, a := range accs {
		accepted[a.DocumentID] = true
		prior[a.Key] = true
	}
	var out []Requirement
	for key, since := range assigned {
		d, ok := latest[key]
		if !ok {
			continue
		}
		start := d.CreatedAt
		if since.After(start) {
			start = since
		}
		r := Requirement{Doc: d, Prior: prior[key], DueBy: start.Add(time.Duration(d.GraceDays) * 24 * time.Hour)}
		switch {
		case accepted[d.ID]:
			r.State = StateAccepted
		case now.Before(r.DueBy):
			r.State = StateGrace
		default:
			r.State = StateBlocked
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Requirement) int { return strings.Compare(a.Doc.Key, b.Doc.Key) })
	return out, nil
}

// Outstanding returns the requirements not yet accepted.
func Outstanding(reqs []Requirement) []Requirement {
	var out []Requirement
	for _, r := range reqs {
		if r.Outstanding() {
			out = append(out, r)
		}
	}
	return out
}

// IsBlocked reports whether any requirement is past its grace period.
func IsBlocked(reqs []Requirement) bool {
	for _, r := range reqs {
		if r.State == StateBlocked {
			return true
		}
	}
	return false
}

// Blocked reports whether a person's access is stopped until they accept: a
// document that applies to them, whose version in force they have not accepted,
// and whose grace period has passed.
func Blocked(tx *store.TenantTx, identityID int64, now time.Time) (bool, error) {
	reqs, err := Required(tx, identityID, now)
	return IsBlocked(reqs), err
}

// Accepting says who accepts, where, and from what.
type Accepting struct {
	IdentityID  int64
	Context     string  // store.TermsContext*
	SessionHash *string // the claim session, in a claim or recovery
	IPHash      string  // keyed hashes of the client address and user agent
	UAHash      string
}

// Shown is a document as the person saw it: its id and the hash of its text.
type Shown struct {
	DocumentID string `json:"id"`
	SHA256     string `json:"sha256"`
}

// Accept records the acceptance of the listed documents. Each must be a version
// in force that applies to the person and not yet accepted, and the hash must
// be the hash of the text in force, so a person only ever accepts the text they
// were shown; anything else refuses the whole request and writes nothing. Each
// acceptance is a row in terms_acceptances and an audit event, in the caller's
// transaction. It returns the acceptances written.
func Accept(tx *store.TenantTx, who Accepting, shown []Shown, now time.Time) ([]*store.TermsAcceptance, error) {
	if len(shown) == 0 || len(shown) > 50 {
		return nil, refuse(422, "invalid_documents", "name the documents being accepted")
	}
	reqs, err := Required(tx, who.IdentityID, now)
	if err != nil {
		return nil, err
	}
	byID := map[string]Requirement{}
	for _, r := range reqs {
		if r.Outstanding() {
			byID[r.Doc.ID] = r
		}
	}
	var rows []*store.TermsAcceptance
	seen := map[string]bool{}
	for _, s := range shown {
		r, ok := byID[s.DocumentID]
		if !ok {
			return nil, refuse(409, "terms_changed", "a document is not one you need to accept; reload and read the current text")
		}
		if !seal.Equal([]byte(r.Doc.TextSHA256), []byte(strings.ToLower(strings.TrimSpace(s.SHA256)))) {
			return nil, refuse(409, "terms_changed", "the text changed; reload and read the current text")
		}
		if seen[s.DocumentID] {
			continue
		}
		seen[s.DocumentID] = true
		rows = append(rows, &store.TermsAcceptance{ID: uuid.NewString(), IdentityID: who.IdentityID, DocumentID: r.Doc.ID, Key: r.Doc.Key,
			Version: r.Doc.Version, TextSHA256: r.Doc.TextSHA256, Context: who.Context, SessionHash: who.SessionHash,
			IPHash: who.IPHash, UAHash: who.UAHash, AcceptedAt: now})
	}
	var written []*store.TermsAcceptance
	for _, a := range rows {
		fresh, err := tx.InsertTermsAcceptance(a)
		if err != nil {
			return nil, err
		}
		if !fresh {
			continue
		}
		written = append(written, a)
		if err := audited(tx, now, "terms.accept", "identity", strconv.FormatInt(a.IdentityID, 10), ojson.Object{
			{Key: "identity_id", Value: a.IdentityID}, {Key: "document_id", Value: a.DocumentID}, {Key: "key", Value: a.Key},
			{Key: "version", Value: a.Version}, {Key: "text_sha256", Value: a.TextSHA256}, {Key: "context", Value: a.Context},
			{Key: "ip_hash", Value: a.IPHash}, {Key: "ua_hash", Value: a.UAHash}}); err != nil {
			return nil, err
		}
	}
	return written, nil
}
