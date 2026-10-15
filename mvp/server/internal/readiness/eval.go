package readiness

import (
	"fmt"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Item statuses (§3.2).
const (
	StatusPending       = "pending"
	StatusPass          = "pass"
	StatusFail          = "fail"
	StatusBlocked       = "blocked"
	StatusStale         = "stale"
	StatusSkipped       = "skipped"
	StatusNotApplicable = "not_applicable"
)

// DefaultLiveTTL is how long live evidence stays fresh before activation (§3.3).
const DefaultLiveTTL = 24 * time.Hour

// RunInfo is a validation or dry-run check run.
type RunInfo struct {
	ID, Kind, Status, ConfigHash string
	Simulated                    bool
	StartedAt                    time.Time
	FinishedAt                   *time.Time
}

// ResultInfo is one check result for one item.
type ResultInfo struct {
	ItemID, CheckID, Status, Message string
	Observed                         map[string]any
	ItemHash                         string
	Simulated                        bool
	DurationMS                       int
}

// FindingInfo is the part of a reconciliation finding a gate reads.
type FindingInfo struct {
	ID, Code, Variant, Title, Severity, Status string
	Count                                      int
}

type resultKey struct{ item, check string }

// Evidence is everything the gate reads for one revision.
type Evidence struct {
	Attestations map[string]*store.Attestation
	// LiveAttestations stand in for live checks the system reported unsupported.
	LiveAttestations map[string]*store.LiveAttestation
	Skips            map[string]*store.Skip
	LiveRun          *RunInfo
	Live             map[resultKey]*ResultInfo
	DataRun          *RunInfo
	Data             map[resultKey]*ResultInfo
	Findings         []FindingInfo
	TenantTypes      map[string]bool // template ids of the tenant's other connections
}

// Part is the evaluation of one verification of an item.
type Part struct {
	Kind      template.VerifyKind `json:"kind"`
	Check     string              `json:"check,omitempty"`
	Status    string              `json:"status"`
	Reason    string              `json:"reason,omitempty"`
	Simulated bool                `json:"simulated,omitempty"`
	RunID     string              `json:"run_id,omitempty"`
	Observed  map[string]any      `json:"observed,omitempty"`
	Message   string              `json:"message,omitempty"`
	// Unsupported marks a fresh live result the system could not answer. When
	// the verification declares on_unsupported, an attestation may stand in.
	Unsupported bool `json:"unsupported,omitempty"`
}

// ItemEval is the evaluated state of one checklist item.
type ItemEval struct {
	template.Item
	Applicable bool     `json:"applicable"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason,omitempty"`
	BlockedBy  []string `json:"blocked_by,omitempty"`
	// LiveBlockedBy are dependencies that stop the item's live checks from
	// running: like BlockedBy, but data checks (which need a dry run, which
	// needs validation) are ignored.
	LiveBlockedBy []string               `json:"live_blocked_by,omitempty"`
	Parts         []Part                 `json:"parts"`
	Attestation   *store.Attestation     `json:"-"`
	Skip          *store.Skip            `json:"-"`
	LiveAttest    *store.LiveAttestation `json:"-"`
	ItemHash      string                 `json:"-"`
	own           string                 // status before dependencies and skips
	ownReason     string
}

// Evaluation is a whole checklist.
type Evaluation struct {
	Items []*ItemEval
	byID  map[string]*ItemEval
}

// Item returns an item by id.
func (e *Evaluation) Item(id string) (*ItemEval, bool) {
	it, ok := e.byID[id]
	return it, ok
}

// statusRank orders part statuses when combining: the worst one wins.
var statusRank = map[string]int{StatusPass: 0, StatusPending: 1, StatusStale: 2, StatusBlocked: 3, StatusFail: 4}

func worst(a, b string) string {
	if statusRank[b] > statusRank[a] {
		return b
	}
	return a
}

// applies evaluates the closed applies_when vocabulary.
func applies(aw *template.AppliesWhen, cfg ConnConfig, role string, tenantTypes map[string]bool) (bool, string) {
	if aw == nil {
		return true, ""
	}
	mode := cfg.WriteMode
	if mode == "" {
		mode = "off"
	}
	if len(aw.WriteMode) > 0 && !slices.Contains(aw.WriteMode, mode) {
		return false, fmt.Sprintf("applies only when write_mode is %v (it is %s)", aw.WriteMode, mode)
	}
	if len(aw.Role) > 0 && !slices.Contains(aw.Role, role) {
		return false, fmt.Sprintf("does not apply to an %s connection", role)
	}
	if len(aw.TenantHasConnectionType) > 0 && !slices.ContainsFunc(aw.TenantHasConnectionType, func(t string) bool { return tenantTypes[t] }) {
		return false, fmt.Sprintf("applies only when the tenant has a %v connection", aw.TenantHasConnectionType)
	}
	switch aw.ConfigFlag {
	case "hybrid":
		if !cfg.Hybrid {
			return false, "applies only when hybrid is set"
		}
	case "use_dirsync":
		if !cfg.UseDirSync {
			return false, "applies only when use_dirsync is set"
		}
	}
	return true, ""
}

// Evaluate computes every item's status from the evidence (§3.2–3.4).
func (b *Bundle) Evaluate(now time.Time, liveTTL time.Duration) (*Evaluation, error) {
	ev := b.Evidence
	out := &Evaluation{byID: map[string]*ItemEval{}}
	for _, it := range b.Template.Items {
		ie := &ItemEval{Item: it}
		ie.Applicable, ie.Reason = applies(it.AppliesWhen, b.Config, b.Conn.Role, ev.TenantTypes)
		h, err := b.Hash.ItemHash(it.ConfigFields)
		if err != nil {
			return nil, err
		}
		ie.ItemHash = h
		if !ie.Applicable {
			ie.Status, ie.own = StatusNotApplicable, StatusNotApplicable
		} else {
			ie.own = StatusPass
			for _, v := range it.Verify {
				p := b.evalPart(ie, v, now, liveTTL)
				ie.Parts = append(ie.Parts, p)
				if worst(ie.own, p.Status) != ie.own {
					ie.own, ie.ownReason = p.Status, p.Reason
				}
			}
		}
		ie.Attestation, ie.Skip, ie.LiveAttest = ev.Attestations[it.ID], ev.Skips[it.ID], ev.LiveAttestations[it.ID]
		out.Items = append(out.Items, ie)
		out.byID[it.ID] = ie
	}
	// Dependencies: an item is blocked until every applicable dependency
	// passes (or was skipped as an accepted gap). Root blockers are listed.
	state := map[string]int{}
	var resolve func(ie *ItemEval)
	resolve = func(ie *ItemEval) {
		if state[ie.ID] == 2 || !ie.Applicable {
			return
		}
		if state[ie.ID] == 1 { // cycle (only possible through overlay items): treat as blocked
			ie.Status, ie.Reason = StatusBlocked, "dependency cycle"
			return
		}
		state[ie.ID] = 1
		ie.Status, ie.Reason = ie.own, ie.ownReason
		for _, d := range ie.DependsOn {
			dep, ok := out.byID[d]
			if !ok || !dep.Applicable {
				continue
			}
			resolve(dep)
			if dep.Status != StatusPass && dep.Status != StatusSkipped {
				if dep.Status == StatusBlocked {
					ie.BlockedBy = append(ie.BlockedBy, dep.BlockedBy...)
				} else {
					ie.BlockedBy = append(ie.BlockedBy, d)
				}
			}
		}
		if len(ie.BlockedBy) > 0 {
			slices.Sort(ie.BlockedBy)
			ie.BlockedBy = slices.Compact(ie.BlockedBy)
			ie.Status = StatusBlocked
			ie.Reason = "blocked by " + joinIDs(ie.BlockedBy)
		}
		if ie.Skip != nil && ie.Level == template.Recommended && ie.Status != StatusPass {
			if ie.Skip.ReviewBy.After(now) {
				ie.Status = StatusSkipped
				ie.Reason = "skipped: " + ie.Skip.Reason
			} else {
				ie.Reason = fmt.Sprintf("skip expired on %s; pass it or skip it again", ie.Skip.ReviewBy.Format("2006-01-02"))
			}
		}
		state[ie.ID] = 2
	}
	for _, ie := range out.Items {
		resolve(ie)
	}
	memo := map[string]bool{}
	for _, ie := range out.Items {
		if !ie.Applicable {
			continue
		}
		for _, d := range ie.DependsOn {
			if !out.liveOK(d, memo, map[string]bool{}) {
				ie.LiveBlockedBy = append(ie.LiveBlockedBy, d)
			}
		}
	}
	return out, nil
}

// liveOK reports whether an item is satisfied for the live phase: not
// applicable, skipped, or its attestation and live parts pass and so do
// its dependencies.
func (e *Evaluation) liveOK(id string, memo, visiting map[string]bool) bool {
	if v, ok := memo[id]; ok {
		return v
	}
	ie, ok := e.byID[id]
	if !ok || !ie.Applicable || ie.Status == StatusSkipped || ie.Status == StatusPass {
		return true
	}
	if visiting[id] {
		return false
	}
	visiting[id] = true
	okAll := true
	for _, p := range ie.Parts {
		if p.Kind != template.Data && p.Status != StatusPass {
			okAll = false
		}
	}
	for _, d := range ie.DependsOn {
		if okAll && !e.liveOK(d, memo, visiting) {
			okAll = false
		}
	}
	memo[id] = okAll
	return okAll
}

func joinIDs(ids []string) string {
	s := ""
	for i, id := range ids {
		if i > 0 {
			s += ", "
		}
		s += id
	}
	return s
}

func (b *Bundle) evalPart(ie *ItemEval, v template.Verify, now time.Time, liveTTL time.Duration) Part {
	p := Part{Kind: v.Kind, Check: v.Check}
	ev := b.Evidence
	switch v.Kind {
	case template.Attestation:
		a := ev.Attestations[ie.ID]
		switch {
		case a == nil:
			p.Status, p.Reason = StatusPending, "attest with a note"
		case a.ItemHash != ie.ItemHash:
			p.Status, p.Reason = StatusStale, "configuration changed since it was attested"
		default:
			p.Status = StatusPass
			p.Message = fmt.Sprintf("attested by %s on %s", a.ActorID, a.AttestedAt.Format("2006-01-02"))
		}
	case template.Live, template.Data:
		run, results, what := ev.LiveRun, ev.Live, "run validation"
		if v.Kind == template.Data {
			run, results, what = ev.DataRun, ev.Data, "run a dry run"
		}
		r := results[resultKey{ie.ID, v.Check}]
		if run == nil || r == nil {
			p.Status, p.Reason = StatusPending, what
			return p
		}
		p.RunID, p.Simulated, p.Observed, p.Message = run.ID, r.Simulated, r.Observed, r.Message
		switch {
		case r.ItemHash != ie.ItemHash:
			p.Status, p.Reason = StatusStale, "configuration changed since this evidence was collected; "+what
		case v.Kind == template.Live && run.FinishedAt != nil && now.Sub(*run.FinishedAt) > liveTTL:
			p.Status, p.Reason = StatusStale, fmt.Sprintf("live evidence older than %s", fmtTTL(liveTTL))
		case r.Simulated && !IsDemoType(b.Conn.ConnectorType):
			p.Status, p.Reason = StatusPending, "a simulated result cannot satisfy a gate for a real connector type"
		case v.Kind == template.Live && unsupportedResult(r):
			p.Unsupported = true
			p.Status, p.Reason = StatusPending, r.Message
			if v.OnUnsupported == template.Attestation {
				p.Status, p.Reason = b.evalLiveAttestation(ie, now, liveTTL, &p)
			}
		default:
			switch r.Status {
			case "pass", "warn":
				p.Status = StatusPass
			case "fail", "error":
				p.Status, p.Reason = StatusFail, r.Message
			case "blocked":
				p.Status, p.Reason = StatusBlocked, r.Message
			default:
				p.Status, p.Reason = StatusPending, r.Message
			}
		}
	}
	return p
}

// unsupportedResult reports whether a live result is the system saying it
// cannot answer the check (skipped, observed.unsupported). A fail or an error
// is never unsupported, so it can never be attested away.
func unsupportedResult(r *ResultInfo) bool {
	u, _ := r.Observed["unsupported"].(bool)
	return r.Status == "skipped" && u
}

// liveAttestationFresh reports whether a live attestation holds for the item:
// bound to the fields the item depends on, and not older than the live TTL.
// The binding is the per-item hash (the item's config_fields: for the LDAP
// items the bind DN, trusted CA and port among them), not the whole
// ConfigHash, which an unrelated edit would invalidate. The stored
// ConfigHash is kept for the audit trail only.
func liveAttestationFresh(a *store.LiveAttestation, itemHash string, now time.Time, ttl time.Duration) (ok bool, reason string) {
	switch {
	case a == nil:
		return false, ""
	case a.ItemHash != itemHash:
		return false, "configuration changed since it was attested; attest again"
	case now.Sub(a.AttestedAt) > ttl:
		return false, fmt.Sprintf("attestation older than %s; attest again", fmtTTL(ttl))
	}
	return true, ""
}

// evalLiveAttestation judges the attestation that stands in for an
// unsupported live check.
func (b *Bundle) evalLiveAttestation(ie *ItemEval, now time.Time, ttl time.Duration, p *Part) (status, reason string) {
	a := b.Evidence.LiveAttestations[ie.ID]
	if a == nil {
		return StatusPending, "the system cannot answer this check; attest instead"
	}
	if ok, why := liveAttestationFresh(a, ie.ItemHash, now, ttl); !ok {
		return StatusStale, why
	}
	p.Message = fmt.Sprintf("attested by %s on %s (live check unsupported)", a.Attester, a.AttestedAt.Format("2006-01-02"))
	return StatusPass, ""
}

func fmtTTL(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	return d.String()
}

// partsOf returns the statuses of an item's parts of one kind, and whether it has any.
func (ie *ItemEval) partsOf(k template.VerifyKind) (status, reason string, has bool) {
	status = StatusPass
	for _, p := range ie.Parts {
		if p.Kind != k {
			continue
		}
		has = true
		if worst(status, p.Status) != status {
			status, reason = p.Status, p.Reason
		}
	}
	return status, reason, has
}

// Progress counts passing applicable items per level.
type Progress struct {
	Pass    int `json:"pass"`
	Total   int `json:"total"`
	Skipped int `json:"skipped"`
}

// Progress tallies the evaluation by level.
func (e *Evaluation) Progress() map[string]*Progress {
	out := map[string]*Progress{"required": {}, "recommended": {}, "optional": {}}
	for _, it := range e.Items {
		if !it.Applicable {
			continue
		}
		p := out[string(it.Level)]
		p.Total++
		switch it.Status {
		case StatusPass:
			p.Pass++
		case StatusSkipped:
			p.Skipped++
		}
	}
	return out
}
