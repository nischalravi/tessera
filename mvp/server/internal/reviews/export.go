package reviews

import (
	"encoding/csv"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// ErrNoPopulation is returned for a campaign launched before populations were
// frozen.
var ErrNoPopulation = &Error{"campaign has no frozen population"}

// Revocation verification statuses of an exported decision.
const (
	VerifyNotApplicable = "not_applicable" // the grant was kept
	VerifyVerified      = "verified_removed"
	VerifyPending       = "pending" // revoked, but the grant edge is still in the graph
)

// Export is the auditor export of a campaign: the frozen population with its
// hash (stored and recomputed from the stored rows) and every decision.
type Export struct {
	Campaign     *store.ReviewCampaign
	Population   *store.ReviewPopulation
	Rows         []*store.PopulationRow
	Recomputed   string
	Decisions    []Decision // same order as Rows
	QA           QACounts
	ExportedAt   time.Time
	systemCounts ojson.Object
	sourceSyncs  ojson.Object
}

// HashMatch reports whether the stored hash equals the one recomputed from the
// stored rows.
func (e *Export) HashMatch() bool { return e.Recomputed == e.Population.PopulationHash }

// QACounts summarise the sampled QA of a campaign's auto-decisions.
type QACounts struct {
	AutoCertified, Sampled, Decided, Overturned int
}

// Decision is the outcome for one grant of the population.
type Decision struct {
	Row          *store.PopulationRow
	Decision     string // keep | revoke | auto_certified | open
	Source       string // reviewer | rule | qa_overturn | qa_confirmed
	Reviewer     string // assigned reviewer (name), "" when none
	DecidedBy    string // platform user id of the decider, "" when none
	DecidedAt    *time.Time
	Reason       string // reviewer's comment, or the exception reasons for an open item
	Reasons      []string
	Rule         string // JSON of the rule that auto-certified it, "" otherwise
	QASample     bool
	QADecision   string
	QAReviewer   string
	QADecidedAt  *time.Time
	Verification string
}

// BuildExport assembles the export of a campaign (ErrNoPopulation when it has
// none). It reads only; the caller audits the export.
func BuildExport(c *store.TenantTx, campaignID int64, now time.Time) (*Export, error) {
	cmp, err := c.Campaign(campaignID)
	if err != nil {
		return nil, err
	}
	pop, err := c.ReviewPopulation(campaignID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoPopulation
	}
	if err != nil {
		return nil, err
	}
	rows, err := c.PopulationRows(campaignID)
	if err != nil {
		return nil, err
	}
	recomputed, err := PopulationHash(rows)
	if err != nil {
		return nil, err
	}
	items, err := c.CampaignItems(campaignID)
	if err != nil {
		return nil, err
	}
	autos, err := c.AutoDecisions(campaignID)
	if err != nil {
		return nil, err
	}
	people, _, err := c.IdentityMap()
	if err != nil {
		return nil, err
	}
	name := func(id *int64) string {
		if id == nil || people[*id] == nil {
			return ""
		}
		return people[*id].Name
	}
	itemByEdge := map[int64]*store.ReviewItem{}
	for _, it := range items {
		if it.EdgeID != nil {
			itemByEdge[*it.EdgeID] = it
		}
	}
	autoByOrdinal := map[int]*store.AutoDecision{}
	for _, a := range autos {
		autoByOrdinal[a.Ordinal] = a
	}
	e := &Export{Campaign: cmp, Population: pop, Rows: rows, Recomputed: recomputed, ExportedAt: now}
	if e.systemCounts, err = decodeObject(pop.SystemCounts); err != nil {
		return nil, err
	}
	if e.sourceSyncs, err = decodeObject(pop.SourceSyncs); err != nil {
		return nil, err
	}
	for _, r := range rows {
		d := Decision{Row: r, Decision: "open", Verification: VerifyNotApplicable}
		revoked := false
		switch it, a := itemByEdge[r.EdgeID], autoByOrdinal[r.Ordinal]; {
		case r.Disposition == DispositionAuto && a != nil:
			e.QA.AutoCertified++
			d.Decision, d.Source, d.DecidedAt, d.Rule = "auto_certified", "rule", &pop.CreatedAt, string(a.Rule)
			d.QASample = a.QASample
			if a.QASample {
				e.QA.Sampled++
				d.QAReviewer = name(a.QAReviewerID)
			}
			if a.QADecision != nil {
				e.QA.Decided++
				d.QADecision, d.QADecidedAt, d.Reason = *a.QADecision, a.QADecidedAt, deref(a.QAComment)
				if a.QADecidedByUser != nil {
					d.DecidedBy = a.QADecidedByUser.String()
				}
				d.Source = "qa_confirmed"
				if a.Overturned {
					e.QA.Overturned++
					d.Decision, d.Source, d.DecidedAt, revoked = "revoke", "qa_overturn", a.QADecidedAt, true
				}
			}
		case it != nil:
			d.Source, d.Reviewer, d.Reasons, d.Reason = "reviewer", name(it.ReviewerID), it.Reasons, deref(it.Comment)
			if it.Decision != nil && *it.Decision != "" {
				d.Decision, d.DecidedAt = *it.Decision, it.DecidedAt
				revoked = *it.Decision == "revoke"
				if it.DecidedByUserID != nil {
					d.DecidedBy = it.DecidedByUserID.String()
				}
			}
		}
		if revoked {
			d.Verification = VerifyPending
			if _, err := c.EdgeBetween(r.EdgeSrc, r.EdgeDst); errors.Is(err, store.ErrNotFound) {
				d.Verification = VerifyVerified
			} else if err != nil {
				return nil, err
			}
		}
		e.Decisions = append(e.Decisions, d)
	}
	return e, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func decodeObject(raw []byte) (ojson.Object, error) {
	v, err := ojson.Decode(raw)
	if err != nil {
		return nil, err
	}
	o, _ := v.(ojson.Object)
	return o, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// JSON is the export as an ordered JSON document: a population section (rows,
// hash, counts, sync timestamps) and a decisions section.
func (e *Export) JSON() (ojson.Object, error) {
	rows := []ojson.Object{}
	for _, r := range e.Rows {
		rows = append(rows, ojson.Object{{Key: "ordinal", Value: r.Ordinal}, {Key: "edge_id", Value: r.EdgeID},
			{Key: "identity_id", Value: r.IdentityID}, {Key: "identity_ref", Value: r.IdentityRef},
			{Key: "account_ref", Value: r.AccountRef}, {Key: "system", Value: r.System},
			{Key: "entitlement", Value: r.Entitlement}, {Key: "edge_src", Value: r.EdgeSrc}, {Key: "edge_dst", Value: r.EdgeDst},
			{Key: "in_scope_reason", Value: r.InScopeReason}, {Key: "disposition", Value: r.Disposition}})
	}
	scope, err := decodeObject(e.Population.Scope)
	if err != nil {
		return nil, err
	}
	decisions := []ojson.Object{}
	for _, d := range e.Decisions {
		var rule any
		if d.Rule != "" {
			if rule, err = ojson.Decode([]byte(d.Rule)); err != nil {
				return nil, err
			}
		}
		reasons := d.Reasons
		if reasons == nil {
			reasons = []string{}
		}
		decisions = append(decisions, ojson.Object{{Key: "ordinal", Value: d.Row.Ordinal}, {Key: "edge_id", Value: d.Row.EdgeID},
			{Key: "identity", Value: d.Row.IdentityRef}, {Key: "account", Value: d.Row.AccountRef},
			{Key: "system", Value: d.Row.System}, {Key: "entitlement", Value: d.Row.Entitlement},
			{Key: "decision", Value: d.Decision}, {Key: "decision_source", Value: d.Source},
			{Key: "reviewer", Value: nullable(d.Reviewer)}, {Key: "decided_by_user_id", Value: nullable(d.DecidedBy)},
			{Key: "decided_at", Value: timeutil.ISOPtr(d.DecidedAt)}, {Key: "reason", Value: nullable(d.Reason)},
			{Key: "exception_reasons", Value: reasons}, {Key: "rule", Value: rule}, {Key: "qa_sample", Value: d.QASample},
			{Key: "qa_reviewer", Value: nullable(d.QAReviewer)}, {Key: "qa_decision", Value: nullable(d.QADecision)},
			{Key: "qa_decided_at", Value: timeutil.ISOPtr(d.QADecidedAt)},
			{Key: "revocation_verification", Value: d.Verification}})
	}
	p := e.Population
	return ojson.Object{{Key: "format_version", Value: 1},
		{Key: "exported_at", Value: timeutil.ISO(e.ExportedAt)},
		{Key: "campaign", Value: ojson.Object{{Key: "id", Value: e.Campaign.ID}, {Key: "name", Value: e.Campaign.Name},
			{Key: "status", Value: e.Campaign.Status}, {Key: "created_at", Value: timeutil.ISO(e.Campaign.CreatedAt)},
			{Key: "unused_days", Value: e.Campaign.UnusedDays}}},
		{Key: "population", Value: ojson.Object{{Key: "hash_algorithm", Value: HashDomain},
			{Key: "stored_hash", Value: p.PopulationHash}, {Key: "recomputed_hash", Value: e.Recomputed},
			{Key: "hash_match", Value: e.HashMatch()}, {Key: "frozen_at", Value: timeutil.ISO(p.CreatedAt)},
			{Key: "item_count", Value: p.ItemCount}, {Key: "system_counts", Value: e.systemCounts},
			{Key: "source_syncs", Value: e.sourceSyncs}, {Key: "scope", Value: scope},
			{Key: "rules_version", Value: p.RulesVersion}, {Key: "qa_sample_pct", Value: p.QASamplePct},
			{Key: "rows", Value: rows}}},
		{Key: "decisions", Value: decisions},
		{Key: "qa", Value: qaObject(e.QA)}}, nil
}

func qaObject(q QACounts) ojson.Object {
	return ojson.Object{{Key: "auto_certified", Value: q.AutoCertified}, {Key: "sampled", Value: q.Sampled},
		{Key: "decided", Value: q.Decided}, {Key: "overturned", Value: q.Overturned}}
}

// csvColumns is the header of the CSV export: one line per grant of the
// population with its decision. The hash columns repeat on every line so a
// line is self-describing.
var csvColumns = []string{"ordinal", "edge_id", "identity", "account", "system", "entitlement", "in_scope_reason",
	"disposition", "decision", "decision_source", "reviewer", "decided_by_user_id", "decided_at", "reason",
	"exception_reasons", "rule", "qa_sample", "qa_reviewer", "qa_decision", "qa_decided_at", "revocation_verification",
	"source_sync", "population_hash", "recomputed_hash", "hash_match", "frozen_at"}

// WriteCSV writes the export as CSV (RFC 4180). Text cells that start with a
// spreadsheet formula character are prefixed with an apostrophe.
func (e *Export) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvColumns); err != nil {
		return err
	}
	syncs := map[string]string{}
	for _, kv := range e.sourceSyncs {
		if s, ok := kv.Value.(string); ok {
			syncs[kv.Key] = s
		}
	}
	for _, d := range e.Decisions {
		r := d.Row
		rec := []string{strconv.Itoa(r.Ordinal), strconv.FormatInt(r.EdgeID, 10), r.IdentityRef, r.AccountRef, r.System,
			r.Entitlement, r.InScopeReason, r.Disposition, d.Decision, d.Source, d.Reviewer, d.DecidedBy,
			isoOrEmpty(d.DecidedAt), d.Reason, strings.Join(d.Reasons, ";"), d.Rule, strconv.FormatBool(d.QASample),
			d.QAReviewer, d.QADecision, isoOrEmpty(d.QADecidedAt), d.Verification, syncs[r.System],
			e.Population.PopulationHash, e.Recomputed, strconv.FormatBool(e.HashMatch()), timeutil.ISO(e.Population.CreatedAt)}
		for i := range rec {
			rec[i] = csvSafe(rec[i])
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func isoOrEmpty(t *time.Time) string {
	if t == nil {
		return ""
	}
	return timeutil.ISO(*t)
}

// csvSafe defuses spreadsheet formula injection (CWE-1236).
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// PopulationView is the summary the UI shows in the campaign panel: hash,
// counts, freeze time, integrity and the QA queue.
func PopulationView(c *store.TenantTx, campaignID int64, now time.Time) (ojson.Object, error) {
	e, err := BuildExport(c, campaignID, now)
	if err != nil {
		return nil, err
	}
	autos, err := c.AutoDecisions(campaignID)
	if err != nil {
		return nil, err
	}
	byOrdinal := map[int]*Decision{}
	for i := range e.Decisions {
		byOrdinal[e.Decisions[i].Row.Ordinal] = &e.Decisions[i]
	}
	queue := []ojson.Object{}
	for _, a := range autos {
		if !a.QASample {
			continue
		}
		d := byOrdinal[a.Ordinal]
		rule, err := ojson.Decode(a.Rule)
		if err != nil {
			return nil, err
		}
		queue = append(queue, ojson.Object{{Key: "id", Value: a.ID}, {Key: "identity", Value: d.Row.IdentityRef},
			{Key: "grant", Value: d.Row.AccountRef + " → " + d.Row.Entitlement}, {Key: "system", Value: d.Row.System},
			{Key: "rule", Value: rule}, {Key: "qa_reviewer", Value: nullable(d.QAReviewer)},
			{Key: "qa_decision", Value: nullable(d.QADecision)}, {Key: "overturned", Value: a.Overturned}})
	}
	p := e.Population
	return ojson.Object{{Key: "campaign_id", Value: campaignID}, {Key: "population_hash", Value: p.PopulationHash},
		{Key: "recomputed_hash", Value: e.Recomputed}, {Key: "hash_match", Value: e.HashMatch()},
		{Key: "hash_algorithm", Value: HashDomain}, {Key: "frozen_at", Value: timeutil.ISO(p.CreatedAt)},
		{Key: "item_count", Value: p.ItemCount}, {Key: "system_counts", Value: e.systemCounts},
		{Key: "source_syncs", Value: e.sourceSyncs}, {Key: "rules_version", Value: p.RulesVersion},
		{Key: "qa_sample_pct", Value: p.QASamplePct}, {Key: "qa", Value: qaObject(e.QA)}, {Key: "qa_queue", Value: queue}}, nil
}
