package reviews

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/gowebpki/jcs"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Frozen, provably complete review populations (issue #110).
//
// At launch the campaign snapshots every grant in scope (not only the risky
// ones that become review items) into review_population_rows, with a hash over
// the rows. The hash is the "tessera-review-population-v1" algorithm:
//
//	line(row) = RFC 8785 (JCS) form of the JSON object
//	            {ordinal, edge_id, identity_id, identity_ref, account_ref,
//	             system, entitlement, edge_src, edge_dst, in_scope_reason,
//	             disposition}
//	hash      = lower-hex SHA-256 of  "tessera-review-population-v1" 0x00
//	            || line(row 1) "\n" line(row 2) "\n" ... line(row n)
//
// with rows in ascending ordinal (ordinals are 1..n, assigned in ascending
// edge_id). There is no trailing newline; an empty population hashes the
// domain and the 0x00 byte. Strings are UTF-8, numbers are integers. The same
// text is in mvp/README.md and a golden vector is in
// testdata/golden/review_population_v1.json.

// Population hash, rules and settings.
const (
	HashDomain = "tessera-review-population-v1"
	// RulesVersion names the exception-only rule set that built the population.
	RulesVersion = "exception-only-v1"
	// RuleAutoCertify is the id of the rule that auto-certifies a grant with no
	// exception signal; RuleVersion is its version.
	RuleAutoCertify = "exception_only.no_exception_signals"
	RuleVersion     = 1
	// SettingQASamplePct is the tenant setting for the share of auto-decisions
	// sent to human QA.
	SettingQASamplePct = "qa_sample_pct"
	DefaultQASamplePct = 5
	// InScope is why every row is in the population: a standing grant of an
	// active account.
	InScope = "standing_grant"

	DispositionReview = "review"
	DispositionAuto   = "auto_certified"
)

// PopulationHash returns the population hash of rows (see the format above).
// Rows are hashed in ascending Ordinal, whatever order they are given in.
func PopulationHash(rows []*store.PopulationRow) (string, error) {
	sorted := append([]*store.PopulationRow(nil), rows...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Ordinal < sorted[j].Ordinal })
	h := sha256.New()
	h.Write([]byte(HashDomain))
	h.Write([]byte{0})
	for i, r := range sorted {
		line, err := rowLine(r)
		if err != nil {
			return "", err
		}
		if i > 0 {
			h.Write([]byte{'\n'})
		}
		h.Write(line)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func rowLine(r *store.PopulationRow) ([]byte, error) {
	raw, err := ojson.Marshal(ojson.Object{{Key: "ordinal", Value: r.Ordinal}, {Key: "edge_id", Value: r.EdgeID},
		{Key: "identity_id", Value: r.IdentityID}, {Key: "identity_ref", Value: r.IdentityRef},
		{Key: "account_ref", Value: r.AccountRef}, {Key: "system", Value: r.System},
		{Key: "entitlement", Value: r.Entitlement}, {Key: "edge_src", Value: r.EdgeSrc}, {Key: "edge_dst", Value: r.EdgeDst},
		{Key: "in_scope_reason", Value: r.InScopeReason}, {Key: "disposition", Value: r.Disposition}})
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

// SelectQASample picks the auto-decisions (by edge id) that go to human QA:
// ceil(pct% of n), at least 1 when n > 0 and pct > 0, at most n. The order is
// by SHA-256(populationHash ":" edgeID) ascending (then edge id), so the same
// frozen population and percentage always select the same grants, and an
// auditor can re-derive the sample.
func SelectQASample(populationHash string, edgeIDs []int64, pct int) map[int64]bool {
	out := map[int64]bool{}
	n := len(edgeIDs)
	if n == 0 || pct <= 0 {
		return out
	}
	k := (n*pct + 99) / 100
	k = max(1, min(k, n))
	type scored struct {
		edge  int64
		score string
	}
	s := make([]scored, n)
	for i, e := range edgeIDs {
		sum := sha256.Sum256([]byte(populationHash + ":" + strconv.FormatInt(e, 10)))
		s[i] = scored{e, hex.EncodeToString(sum[:])}
	}
	sort.Slice(s, func(i, j int) bool {
		if s[i].score != s[j].score {
			return s[i].score < s[j].score
		}
		return s[i].edge < s[j].edge
	})
	for _, x := range s[:k] {
		out[x.edge] = true
	}
	return out
}

// QASamplePct reads the tenant's qa_sample_pct setting (default 5).
func QASamplePct(c *store.TenantTx) (int, error) {
	v, ok, err := c.TenantSetting(SettingQASamplePct)
	if err != nil {
		return 0, err
	}
	if !ok {
		return DefaultQASamplePct, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 100 {
		return 0, fmt.Errorf("reviews: stored %s %q is not 0-100", SettingQASamplePct, v)
	}
	return n, nil
}

// SetQASamplePct changes the setting (0 disables sampling) and audits it.
func SetQASamplePct(c *store.TenantTx, now time.Time, pct int, by store.UserRef) error {
	if pct < 0 || pct > 100 {
		return &Error{"qa_sample_pct must be between 0 and 100"}
	}
	if err := c.SetTenantSetting(SettingQASamplePct, strconv.Itoa(pct), now); err != nil {
		return err
	}
	return c.Audit(now, by.Display, "review.qa_sample_pct_changed", ojson.Object{{Key: "qa_sample_pct", Value: pct}})
}

// freezer collects the population while a campaign is generated.
type freezer struct {
	rows  []*store.PopulationRow
	rules map[int64]ojson.Object // edge id -> the rule that auto-certified it
	ident map[int64]int64        // edge id -> identity id
}

func newFreezer() *freezer {
	return &freezer{rules: map[int64]ojson.Object{}, ident: map[int64]int64{}}
}

// record adds one in-scope grant. rule is nil for a grant that becomes a
// review item.
func (f *freezer) record(ident *store.Identity, g *graph.Snapshot, ag graph.AccountGrant, rule ojson.Object) {
	edge := *ag.Edge.EdgeID
	acct := g.Node(ag.Acct)
	disp := DispositionReview
	if rule != nil {
		disp = DispositionAuto
		f.rules[edge] = rule
		f.ident[edge] = ident.ID
	}
	f.rows = append(f.rows, &store.PopulationRow{EdgeID: edge, IdentityID: ident.ID, IdentityRef: ident.ExternalID,
		AccountRef: acct.Label, System: acct.System, Entitlement: g.Label(ag.Dst), EdgeSrc: ag.Acct, EdgeDst: ag.Dst,
		InScopeReason: InScope, Disposition: disp})
}

// autoRule is the evidence recorded for an auto-certified grant: the rule, its
// version and the inputs that matched (no exception signal fired).
func autoRule(now time.Time, unusedDays, perms, used int, last *time.Time, privileged bool, ident *store.Identity) ojson.Object {
	var days any
	if last != nil {
		days = timeutil.Days(now, *last)
	}
	return ojson.Object{{Key: "id", Value: RuleAutoCertify}, {Key: "version", Value: RuleVersion},
		{Key: "inputs", Value: ojson.Object{{Key: "unused_days_threshold", Value: unusedDays},
			{Key: "last_used", Value: timeutil.ISOPtr(last)}, {Key: "days_since_used", Value: days},
			{Key: "permissions", Value: perms}, {Key: "permissions_used", Value: used},
			{Key: "privileged", Value: privileged}, {Key: "policy_violation", Value: false},
			{Key: "identity_status", Value: ident.Status}, {Key: "identity_type", Value: ident.Type}}}}
}

// lastSync is when the tenant's connectors last synced: the newest
// connectors.sync audit event. Tessera keeps no per-system sync clock, so every
// system of the population carries this time (null when no sync is recorded).
func lastSync(c *store.TenantTx) (*time.Time, error) {
	evs, err := c.AuditEvents(store.AuditFilter{Action: "connectors.sync", Limit: 1})
	if err != nil || len(evs) == 0 {
		return nil, err
	}
	t := evs[0].OccurredAt
	return &t, nil
}

// freeze writes the population, its auto-decisions (with the QA sample) and the
// review.population_frozen audit event, in the launch transaction.
func (f *freezer) freeze(c *store.TenantTx, now time.Time, campID int64, unusedDays int, qaReviewer *int64) (string, error) {
	sort.Slice(f.rows, func(i, j int) bool { return f.rows[i].EdgeID < f.rows[j].EdgeID })
	counts := map[string]int{}
	var autoEdges []int64
	for i, r := range f.rows {
		r.CampaignID, r.Ordinal = campID, i+1
		counts[r.System]++
		if r.Disposition == DispositionAuto {
			autoEdges = append(autoEdges, r.EdgeID)
		}
	}
	hash, err := PopulationHash(f.rows)
	if err != nil {
		return "", err
	}
	pct, err := QASamplePct(c)
	if err != nil {
		return "", err
	}
	sync, err := lastSync(c)
	if err != nil {
		return "", err
	}
	systems := make([]string, 0, len(counts))
	for s := range counts {
		systems = append(systems, s)
	}
	sort.Strings(systems)
	countObj, syncObj := ojson.Object{}, ojson.Object{}
	for _, s := range systems {
		countObj = append(countObj, ojson.KV{Key: s, Value: counts[s]})
		syncObj = append(syncObj, ojson.KV{Key: s, Value: timeutil.ISOPtr(sync)})
	}
	scope := ojson.Object{{Key: "grants", Value: "standing (non-JIT) grant edges of active accounts with effective permissions"},
		{Key: "identities", Value: "all, including terminated"}, {Key: "unused_days", Value: unusedDays},
		{Key: "rules_version", Value: RulesVersion}}
	enc := func(v ojson.Object) ([]byte, error) { return ojson.Marshal(v) }
	cj, err := enc(countObj)
	if err != nil {
		return "", err
	}
	sj, err := enc(syncObj)
	if err != nil {
		return "", err
	}
	scj, err := enc(scope)
	if err != nil {
		return "", err
	}
	if err := c.InsertReviewPopulation(&store.ReviewPopulation{CampaignID: campID, CreatedAt: now, PopulationHash: hash,
		ItemCount: len(f.rows), SystemCounts: cj, SourceSyncs: sj, Scope: scj, RulesVersion: RulesVersion,
		QASamplePct: pct}, f.rows); err != nil {
		return "", err
	}
	sample := SelectQASample(hash, autoEdges, pct)
	for _, r := range f.rows {
		if r.Disposition != DispositionAuto {
			continue
		}
		rule, err := ojson.Marshal(f.rules[r.EdgeID])
		if err != nil {
			return "", err
		}
		ad := &store.AutoDecision{CampaignID: campID, Ordinal: r.Ordinal, EdgeID: r.EdgeID, IdentityID: r.IdentityID,
			Rule: rule, QASample: sample[r.EdgeID]}
		if ad.QASample {
			ad.QAReviewerID = qaReviewer
		}
		if err := c.InsertAutoDecision(ad); err != nil {
			return "", err
		}
	}
	return hash, c.Audit(now, "system", "review.population_frozen", ojson.Object{{Key: "campaign_id", Value: campID},
		{Key: "population_hash", Value: hash}, {Key: "items", Value: len(f.rows)}, {Key: "systems", Value: countObj},
		{Key: "auto_certified", Value: len(autoEdges)}, {Key: "qa_sampled", Value: len(sample)},
		{Key: "qa_sample_pct", Value: pct}})
}

// QADecide records a human QA decision on a sampled auto-decision. revoke
// overturns the auto-keep: it removes the grant like a review revoke does, and
// both outcomes are audited.
func QADecide(c *store.TenantTx, now time.Time, id int64, decision string, by store.UserRef, comment *string) (*store.AutoDecision, error) {
	if decision != "keep" && decision != "revoke" {
		return nil, &Error{"decision must be keep or revoke"}
	}
	ad, err := c.AutoDecision(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Error{"unknown QA item"}
	}
	if err != nil {
		return nil, err
	}
	if !ad.QASample {
		return nil, &Error{"item was not sampled for QA"}
	}
	if ad.QADecision != nil {
		return nil, &Error{"QA decision already recorded"}
	}
	rows, err := c.PopulationRows(ad.CampaignID)
	if err != nil {
		return nil, err
	}
	var row *store.PopulationRow
	for _, r := range rows {
		if r.Ordinal == ad.Ordinal {
			row = r
		}
	}
	if row == nil {
		return nil, fmt.Errorf("reviews: population row %d of campaign %d is missing", ad.Ordinal, ad.CampaignID)
	}
	if err := c.QADecideAutoDecision(id, decision, comment, now, by); err != nil {
		return nil, err
	}
	ad.QADecision, ad.QAComment, ad.QADecidedAt, ad.Overturned = &decision, comment, &now, decision == "revoke"
	action := "review.qa_confirmed"
	if decision == "revoke" {
		action = "review.qa_overturned"
		if e, err := c.EdgeBetween(row.EdgeSrc, row.EdgeDst); err == nil {
			if err := c.RevokeEdge(e.ID, now, "review_qa"); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	var rule any
	if v, err := ojson.Decode(ad.Rule); err == nil {
		if o, ok := v.(ojson.Object); ok {
			rule, _ = o.Get("id")
		}
	}
	err = c.Audit(now, by.Display, action, ojson.Object{{Key: "campaign_id", Value: ad.CampaignID},
		{Key: "qa_item_id", Value: ad.ID}, {Key: "grant", Value: row.IdentityRef + " → " + row.Entitlement},
		{Key: "rule", Value: rule}})
	return ad, err
}
