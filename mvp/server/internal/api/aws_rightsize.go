package api

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	awsq "github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
	"github.com/nischalravi/tessera/mvp/server/internal/leastpriv"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// POST /api/aws/principals/{arn}/right-size (issue #659, LP-3; design
// least-privilege-loop §4, §4.1): a verified right-size of one customer-managed
// policy for one principal.
//
//	{"policy_arn": "arn:aws:iam::111111111111:policy/S3Read",
//	 "unused_days": 60, "connector": "", "snapshot": "", "profile": "default"}
//
// The candidate is the policy with its Allow statements replaced by the calls
// the principal used in the window (the snapshot's own connector's usage, as
// for the unused-access findings), its Deny statements kept. The evaluator then
// re-evaluates it: the answer is "verified" only if every used call stays
// allowed at EXACT fidelity, the candidate gives nothing new and everything it
// removes rests on an EXACT, unconditional allow. It is "review" when only the
// removed side is inexact, and "refused" otherwise (a used call breaks or is
// not EXACT, something is added, nothing is removed). The answer carries the
// candidate document and the evaluator's diff.
//
// "auto_eligible" is the design's §4 gate for this change: verified, the policy
// attached to this principal only, and high confidence in every removed
// permission. It is advice: this route reads, and changes nothing in AWS. It is
// a POST because of its body; like the rotation plan it is recorded as an
// answer, not a mutation.

const (
	awsRSMaxUsedCalls = 2000 // used calls one right-size verifies
	awsRSMaxAssessed  = 5000 // removed actions whose confidence is assessed
	awsRSMaxChanges   = 50   // diff changes returned; the rest are counted
)

func (s *Server) registerAWSRightSizeRoutes() {
	s.handle(http.MethodPost, "/api/aws/principals/{arn}/right-size", read, need(auth.PermGraphRead), s.rd(s.awsRightSize)).answersRead = true
}

type awsRightSizeIn struct {
	PolicyARN  string `json:"policy_arn"`
	UnusedDays int    `json:"unused_days"`
	Connector  string `json:"connector"`
	Snapshot   string `json:"snapshot"`
	Profile    string `json:"profile"`
}

type awsRightSizeView struct {
	Principal  string         `json:"principal"`
	Snapshot   awsSnapshotRef `json:"snapshot"`
	Connector  string         `json:"connector"`
	PolicyARN  string         `json:"policy_arn"`
	UnusedDays int            `json:"unused_days"`
	// Verdict is verified, review or refused (leastpriv.Judge); Reasons say why.
	Verdict string   `json:"verdict"`
	Reasons []string `json:"reasons"`
	// AutoEligible: verified, the policy is this principal's alone, and every
	// removed permission is rated high. Only then may a later stage act on it.
	AutoEligible bool `json:"auto_eligible"`
	// Exclusive: every attachment of the policy is to this principal.
	Exclusive  bool                    `json:"exclusive"`
	Confidence leastpriv.Confidence    `json:"confidence"`
	Used       []leastpriv.UsedCall    `json:"used_calls"`
	Skipped    []awsRSSkipped          `json:"skipped_calls"`
	Check      *leastpriv.Verification `json:"verification"`
	// Document is the candidate policy document ("" when none could be built).
	Document string `json:"document"`
	// DocumentSHA256 is target.DocDigest of Document: what a reviewer approves and the apply route checks (issue #660).
	DocumentSHA256 string     `json:"document_sha256"`
	Diff           *awsRSDiff `json:"diff"`
}

// awsRSSkipped is a used call left out of the candidate because it is not
// allowed now (stale or foreign usage): the change cannot break it.
type awsRSSkipped struct {
	leastpriv.UsedCall
	Why string `json:"why"`
}

type awsRSDiff struct {
	Summary        awsDiffSummary  `json:"summary"`
	Changes        []awsDiffChange `json:"changes"`
	OmittedChanges int             `json:"omitted_changes"`
}

func rsRefusal(code, msg string) error {
	return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: code, Msg: msg}
}

func (s *Server) awsRightSize(r *http.Request, p *params) (int, any, error) {
	arn, err := awsName("principal", p.path["arn"], true)
	if err != nil {
		return 0, nil, err
	}
	var in awsRightSizeIn
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if err := in.check(); err != nil {
		return 0, nil, err
	}
	res, err := s.rightSize(r, arn, in)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, res.view, nil
}

// check validates the input of a right-size and fills its defaults.
func (in *awsRightSizeIn) check() (err error) {
	if in.PolicyARN, err = awsName("policy_arn", in.PolicyARN, true); err != nil {
		return err
	}
	if in.Connector, err = awsName("connector", in.Connector, false); err != nil {
		return err
	}
	if in.UnusedDays == 0 {
		in.UnusedDays = awsLPDefaultDays
	}
	if in.UnusedDays < 1 || in.UnusedDays > awsLPMaxDays {
		return badRequest("invalid_unused_days", "unused_days must be 1 to "+strconv.Itoa(awsLPMaxDays))
	}
	return nil
}

// rsResult is a computed right-size: the view the route answers with, and what applying it needs.
type rsResult struct {
	view *awsRightSizeView
	// doc is the policy as the snapshot has it: its default version and verbatim document are the prior state.
	doc *model.PolicyDoc
}

// rightSize computes the verified right-size of one policy for one principal (see the route's comment). It
// reads; the apply route uses the same computation, so what is applied is what was verified.
func (s *Server) rightSize(r *http.Request, arn string, in awsRightSizeIn) (*rsResult, error) {
	ctx := r.Context()
	tx := store.TxFrom(ctx)
	ac, err := s.awsContext(tx, in.Snapshot)
	if err != nil {
		return nil, err
	}
	connector, err := awsLPConnector(ac, in.Connector)
	if err != nil {
		return nil, err
	}
	if connector == "" {
		return nil, rsRefusal("no_usage_evidence", "the snapshot has no connector, so there is no usage to right-size from")
	}
	snap := ac.eng.snap
	if snap.Principals[arn] == nil {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "principal_not_found", Msg: "no such principal in the snapshot"}
	}
	doc, exclusive, err := rsPolicy(snap, in.PolicyARN, arn)
	if err != nil {
		return nil, err
	}
	bq, _, err := s.awsQuerier(ac, in.Profile)
	if err != nil {
		return nil, err
	}

	now := s.clock()
	today := now.UTC().Truncate(24 * time.Hour)
	since := today.AddDate(0, 0, -(in.UnusedDays - 1)).Format("2006-01-02")
	rows, err := tx.AWSUsage(connector, arn, since, 0)
	if err != nil {
		return nil, err
	}
	states, err := tx.AWSUsageStates(connector)
	if err != nil {
		return nil, err
	}
	gaps, err := tx.AWSUsageGaps(connector, 0)
	if err != nil {
		return nil, err
	}
	used := leastpriv.UsedCallsFromUsage(rows)
	if len(used) > awsRSMaxUsedCalls {
		return nil, rsRefusal("too_many_calls", "the principal used more distinct calls than one right-size verifies: narrow unused_days")
	}

	view := &awsRightSizeView{Principal: arn, Snapshot: snapshotRef(ac.hdr), Connector: connector, PolicyARN: in.PolicyARN,
		UnusedDays: in.UnusedDays, Exclusive: exclusive, Reasons: []string{}, Used: []leastpriv.UsedCall{}, Skipped: []awsRSSkipped{},
		Confidence: leastpriv.Confidence{Level: leastpriv.ConfUnknown, Reasons: []string{}}}
	res := &rsResult{view: view, doc: doc}
	refuse := func(reasons ...string) (*rsResult, error) {
		view.Verdict, view.Reasons = leastpriv.VerdictRefused, reasons
		return res, nil
	}

	// A used call the principal is not allowed now cannot be broken by a narrowing: it is left out. A conditional
	// one would lose its condition in the candidate, which no verification of the used set would notice: refused.
	for _, u := range used {
		d, err := bq.Can(ctx, arn, u.Action, u.Resource)
		switch {
		case errors.Is(err, eval.ErrInvalidRequest):
			view.Skipped = append(view.Skipped, awsRSSkipped{u, "the call cannot be evaluated"})
		case err != nil:
			return nil, awsEvalErr(err)
		case d.Outcome == authz.Conditional:
			return refuse(u.Action + " on " + u.Resource + " is allowed only under a condition now, which the candidate would drop")
		case d.Outcome != authz.Allow:
			view.Skipped = append(view.Skipped, awsRSSkipped{u, "not allowed now"})
		default:
			view.Used = append(view.Used, u)
		}
	}
	candidate, err := leastpriv.RightSizeDocument(doc.RawJSON, view.Used)
	if err != nil {
		if errors.Is(err, leastpriv.ErrRightSize) {
			return refuse(strings.TrimPrefix(err.Error(), leastpriv.ErrRightSize.Error()+": "))
		}
		return nil, err
	}
	view.Document, view.DocumentSHA256 = candidate, target.DocDigest(candidate)

	head, err := snapshot.Apply(snap, []snapshot.PolicyChange{{Op: snapshot.OpPutPolicyVersion, TargetARN: in.PolicyARN, Document: &candidate}},
		snapshot.ApplyOptions{FetchedAt: now, MultivaluedKey: ac.cat.MultivaluedKey})
	if err != nil {
		return nil, err
	}
	hix, err := ac.eng.ix.Refine(head, ac.cat.indexConfig(head))
	if err != nil {
		return nil, err
	}
	opts, _, err := awsOptions(in.Profile, now)
	if err != nil {
		return nil, err
	}
	hq, err := awsq.New(hix, ac.eng.memo, opts)
	if err != nil {
		return nil, badRequest("invalid_profile", err.Error())
	}
	v, err := leastpriv.VerifyAWS(ctx, bq, hq, arn, view.Used)
	if err != nil {
		return nil, awsEvalErr(err)
	}
	view.Check = v
	view.Verdict, view.Reasons = leastpriv.Judge(v)

	dres, err := awsq.Diff(ctx, bq, hq, awsq.DiffOptions{MaxExpand: awsRSMaxAssessed})
	if err != nil {
		return nil, awsEvalErr(err)
	}
	view.Diff = rsDiffView(ac.eng, dres)
	view.Confidence = rsConfidence(now, in.UnusedDays, arn, ac, rows, states, gaps, dres)
	view.AutoEligible = view.Verdict == leastpriv.VerdictVerified && exclusive && view.Confidence.Level == leastpriv.ConfHigh
	return res, nil
}

// rsPolicy finds the customer-managed policy in the snapshot and says whether
// the principal is the only one it is attached to.
func rsPolicy(snap *model.Snapshot, policyARN, principal string) (*model.PolicyDoc, bool, error) {
	var doc *model.PolicyDoc
	for _, d := range snap.Policies {
		if d.Kind == model.PolicyIdentity && d.SourceARN == policyARN {
			doc = d
			break
		}
	}
	if doc == nil {
		return nil, false, &readiness.Error{Status: http.StatusNotFound, Code: "policy_not_found", Msg: "no such managed policy in the snapshot"}
	}
	if doc.AWSManaged {
		return nil, false, rsRefusal("policy_not_customer_managed", "an AWS-managed policy cannot be changed: detach it instead")
	}
	if doc.Unparseable != "" {
		return nil, false, rsRefusal("policy_unreadable", "the policy document could not be read, so it cannot be right-sized")
	}
	if strings.Contains(policyARN, "#") {
		return nil, false, rsRefusal("policy_not_managed", "only a customer-managed policy has versions to replace; an inline policy is changed by put")
	}
	exclusive, attached := true, false
	for _, a := range snap.Attachments {
		if a.PolicyID != doc.ID {
			continue
		}
		attached = true
		if a.TargetARN != principal {
			exclusive = false
		}
	}
	return doc, exclusive && attached, nil
}

func rsDiffView(e *awsEngine, res *awsq.DiffResult) *awsRSDiff {
	out := &awsRSDiff{Changes: []awsDiffChange{}}
	out.Summary.Groups, out.Summary.Recomputed, out.Summary.Global = res.Groups, res.Recomputed, res.Global
	affected := map[string]bool{}
	for i := range res.Changes {
		c := &res.Changes[i]
		switch c.Kind {
		case awsq.Gained:
			out.Summary.Gained++
		case awsq.Lost:
			out.Summary.Lost++
		case awsq.ConditionalChanged:
			out.Summary.ConditionalChanged++
		case awsq.FidelityChanged:
			out.Summary.FidelityChanged++
		}
		for _, pa := range c.Principals {
			affected[pa] = true
		}
		if i >= awsRSMaxChanges {
			out.OmittedChanges++
			continue
		}
		out.Changes = append(out.Changes, awsDiffChange{Principals: c.Principals, Actions: c.Actions, Resources: c.Resources,
			ActionCount: c.ActionCount, ResourceCount: c.ResourceCount, Kind: c.Kind.String(), Before: cellViewOf(c.Before, nil),
			After: cellViewOf(c.After, nil), Trace: []string{}, Gap: changeHasGap(e, c)})
	}
	out.Summary.PrincipalsAffected = len(affected)
	return out
}

// rsConfidence rates the removal as the least trusted of the permissions the
// principal loses: each removed action is assessed as unused in the window,
// except that a service-level usage row (Access Advisor) counts as use. A list
// of removed actions cut short is rated unknown.
func rsConfidence(now time.Time, days int, arn string, ac *awsCtx, rows []*store.AWSUsageDay, states []*store.AWSUsageState,
	gaps []*store.AWSUsageGap, res *awsq.DiffResult) leastpriv.Confidence {
	serviceUsed := map[string]bool{}
	var active []string
	seenDay := map[string]bool{}
	for _, u := range rows {
		if svc, ok := strings.CutSuffix(strings.ToLower(u.Action), ":*"); ok {
			serviceUsed[svc] = true
		}
		if !seenDay[u.Day] {
			seenDay[u.Day] = true
			active = append(active, u.Day)
		}
	}
	var created *time.Time
	if pr := ac.eng.snap.Principals[arn]; pr != nil && pr.CreateDate != "" {
		if t, err := time.Parse(time.RFC3339, pr.CreateDate); err == nil {
			created = &t
		}
	}
	facts := leastpriv.PrincipalFacts{ARN: arn, Created: created, ActiveDays: active}
	ev := leastpriv.AWSEvidence{States: states, Gaps: gaps}
	actions := map[string]bool{}
	var out []leastpriv.Confidence
	for i := range res.Changes {
		c := &res.Changes[i]
		if c.Kind != awsq.Lost || !slices.Contains(c.Principals, arn) {
			continue
		}
		if len(c.Actions) < c.ActionCount {
			out = append(out, leastpriv.Confidence{Level: leastpriv.ConfUnknown, Reasons: []string{"too many removed actions to assess one by one"}})
		}
		for _, a := range c.Actions {
			actions[a] = true
		}
	}
	if len(actions) > awsRSMaxAssessed {
		return leastpriv.Confidence{Level: leastpriv.ConfUnknown, Reasons: []string{"too many removed actions to assess one by one"}}
	}
	for a := range actions {
		svc, _, _ := strings.Cut(strings.ToLower(a), ":")
		out = append(out, leastpriv.Assess(now, days, a, serviceUsed[svc], ev, facts))
	}
	return leastpriv.LowestConfidence(out)
}
