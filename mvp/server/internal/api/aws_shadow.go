package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The production shadow agreement (issue #641, EP-6; docs/design/differentiators-plan.md
// section 1). A tenant that opts in has up to K of the evaluator's decisions a
// day compared with iam:SimulatePrincipalPolicy in the customer account, called
// with the connector's own reader role:
//
//	GET  /api/aws/shadow                      the opt-in, today's quota and the agreement metric
//	PUT  /api/aws/shadow {enabled, daily_k}   opt in or out (K is 1 to 200; default 20)
//	GET  /api/aws/shadow/checks               the comparisons, newest first (?verdict=, ?triage=, ?limit=)
//	GET  /api/aws/shadow/checks/{id}          one comparison with its triage records
//	POST /api/aws/shadow/checks/{id}/triage   {status, note}: a person's verdict on a disagreement
//
// A job of the durable queue (kind aws_shadow, hourly) does the sampling. It is
// rate-limited three ways: at most K comparisons a UTC day per tenant (the rows
// are the counter, so a restart cannot spend a day twice), at most
// awsShadowPerRun in one run, and a pause between simulator calls; three calls
// in a row that fail end the run (a reader role that lacks the permission
// should not be asked again and again).
//
// What is sampled: decisions of the newest snapshot of each connector that the
// evaluator calls allow or deny with exact fidelity, and that no collection
// finding reaches, asked with no context keys (the "bare" profile). The
// simulator is asked the same, so a decision it can only give with a context
// key is "inconclusive", and is kept out of the rate. Half of a run's samples
// are permissions the evaluator says a principal has; the other half are
// denials, asked of a principal about permissions that others of the run have,
// so a permission the evaluator wrongly withholds can be found too. A
// disagreement (allow against deny) is the finding: it is open until a person
// triages it. Explicit and implicit deny are one answer here.
//
// Listing needs connections.read; opting in needs connections.manage with a
// fresh sign-in (the job calls AWS in the customer's account); triage needs
// connections.manage. The agreement metric is also on Deployment health.
func (s *Server) registerAWSShadowRoutes() {
	s.handle(http.MethodGet, "/api/aws/shadow", read, need(auth.PermConnectionsRead), s.rd(s.getAWSShadow))
	s.handle(http.MethodPut, "/api/aws/shadow", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.putAWSShadow))
	s.handle(http.MethodGet, "/api/aws/shadow/checks", read, need(auth.PermConnectionsRead), s.rd(s.listAWSShadowChecks))
	s.handle(http.MethodGet, "/api/aws/shadow/checks/{id}", read, need(auth.PermConnectionsRead), s.rd(s.getAWSShadowCheck))
	s.handle(http.MethodPost, "/api/aws/shadow/checks/{id}/triage", write, need(auth.PermConnectionsManage), s.rd(s.triageAWSShadowCheck))
}

const (
	awsShadowActor = "aws.shadow"
	// awsShadowEvery is the job's interval; the daily quota is what limits the work.
	awsShadowEvery = time.Hour
	// awsShadowPerRun bounds the comparisons of one run.
	awsShadowPerRun = 50
	// awsShadowMaxPrincipals bounds the principals one run looks at.
	awsShadowMaxPrincipals = 10
	// awsShadowMaxFailures is the number of simulator calls in a row that may fail before the run stops.
	awsShadowMaxFailures = 3
	awsShadowNoteMax     = 500
)

// awsShadowGap is the pause between two simulator calls (a variable so a test can remove it).
var awsShadowGap = 250 * time.Millisecond

// ---------------------------------------------------------------- the API

type awsShadowView struct {
	Enabled   bool                       `json:"enabled"`
	DailyK    int                        `json:"daily_k"`
	UpdatedBy string                     `json:"updated_by"`
	UpdatedAt *string                    `json:"updated_at"`
	Today     awsShadowToday             `json:"today"`
	Agreement *readiness.ShadowAgreement `json:"agreement"`
}

type awsShadowToday struct {
	Day       string `json:"day"`
	Sampled   int    `json:"sampled"`
	Remaining int    `json:"remaining"`
}

func awsShadowDay(t time.Time) string { return t.UTC().Format("2006-01-02") }

func (s *Server) awsShadowViewOf(c *store.TenantTx, now time.Time) (*awsShadowView, error) {
	set, err := c.AWSShadowSettings()
	if err != nil {
		return nil, err
	}
	day := awsShadowDay(now)
	used, err := c.AWSShadowSampledOn(day)
	if err != nil {
		return nil, err
	}
	ag, err := readiness.ShadowAgreementOf(c, now)
	if err != nil {
		return nil, err
	}
	v := &awsShadowView{Enabled: set.Enabled, DailyK: set.DailyK, UpdatedBy: set.UpdatedBy, Agreement: ag,
		Today: awsShadowToday{Day: day, Sampled: used, Remaining: max(0, set.DailyK-used)}}
	if set.UpdatedBy != "" {
		t := store.RT(set.UpdatedAt)
		v.UpdatedAt = &t
	}
	return v, nil
}

func (s *Server) getAWSShadow(r *http.Request, _ *params) (int, any, error) {
	v, err := s.awsShadowViewOf(store.TxFrom(r.Context()), s.clock())
	return http.StatusOK, v, err
}

func (s *Server) putAWSShadow(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Enabled bool `json:"enabled"`
		DailyK  *int `json:"daily_k"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.DailyK != nil && (*in.DailyK < 1 || *in.DailyK > store.AWSShadowMaxK) {
		return 0, nil, badRequest("invalid_daily_k", fmt.Sprintf("daily_k must be 1 to %d", store.AWSShadowMaxK))
	}
	var out *awsShadowView
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		cur, err := c.AWSShadowSettings()
		if err != nil {
			return err
		}
		next := &store.AWSShadowSettings{Enabled: in.Enabled, DailyK: cur.DailyK, UpdatedBy: actor(r)}
		if in.DailyK != nil {
			next.DailyK = *in.DailyK
		}
		if err := c.PutAWSShadowSettings(next, now); err != nil {
			return err
		}
		if err := c.Audit(now, actor(r), "aws.shadow.settings", ojson.Object{{Key: "enabled", Value: next.Enabled},
			{Key: "daily_k", Value: next.DailyK}}); err != nil {
			return err
		}
		out, err = s.awsShadowViewOf(c, now)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

type awsShadowCheckView struct {
	ID              string `json:"id"`
	ConnectorID     string `json:"connector_id"`
	SnapshotID      string `json:"snapshot_id"`
	PrincipalARN    string `json:"principal_arn"`
	Action          string `json:"action"`
	ResourceARN     string `json:"resource_arn"`
	TesseraOutcome  string `json:"tessera_outcome"`
	TesseraFidelity string `json:"tessera_fidelity"`
	ExplanationID   string `json:"explanation_id"`
	AWSDecision     string `json:"aws_decision"`
	Verdict         string `json:"verdict"`
	Detail          string `json:"detail"`
	CheckedAt       string `json:"checked_at"`
	TriageStatus    string `json:"triage_status"`
}

func awsShadowCheckViewOf(c *store.AWSShadowCheck) awsShadowCheckView {
	return awsShadowCheckView{ID: c.ID, ConnectorID: c.ConnectorID, SnapshotID: c.SnapshotID, PrincipalARN: c.PrincipalARN,
		Action: c.Action, ResourceARN: c.ResourceARN, TesseraOutcome: c.TesseraOutcome, TesseraFidelity: c.TesseraFidelity,
		ExplanationID: c.ExplanationID, AWSDecision: c.AWSDecision, Verdict: c.Verdict, Detail: c.Detail,
		CheckedAt: store.RT(c.CheckedAt), TriageStatus: c.TriageStatus}
}

type awsShadowTriageView struct {
	Status    string `json:"status"`
	Note      string `json:"note"`
	Actor     string `json:"actor"`
	CreatedAt string `json:"created_at"`
}

var (
	awsShadowVerdicts = []string{store.AWSShadowAgree, store.AWSShadowDisagree, store.AWSShadowInconclusive, store.AWSShadowError}
	awsShadowTriages  = []string{store.AWSTriageNone, store.AWSTriageOpen, store.AWSTriageInvestigating, store.AWSTriageEngineBug,
		store.AWSTriageExpected, store.AWSTriageResolved}
	// awsShadowSettable are the states a person may set (not "none", which is an agreement's)
	awsShadowSettable = []string{store.AWSTriageOpen, store.AWSTriageInvestigating, store.AWSTriageEngineBug,
		store.AWSTriageExpected, store.AWSTriageResolved}
)

func (s *Server) listAWSShadowChecks(r *http.Request, _ *params) (int, any, error) {
	q := r.URL.Query()
	verdict, triage := q.Get("verdict"), q.Get("triage")
	if verdict != "" && !slices.Contains(awsShadowVerdicts, verdict) {
		return 0, nil, badRequest("invalid_verdict", "verdict is one of "+strings.Join(awsShadowVerdicts, ", "))
	}
	if triage != "" && !slices.Contains(awsShadowTriages, triage) {
		return 0, nil, badRequest("invalid_triage", "triage is one of "+strings.Join(awsShadowTriages, ", "))
	}
	limit := 100
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 500 {
			return 0, nil, badRequest("invalid_limit", "limit must be 1 to 500")
		}
		limit = n
	}
	rows, err := store.TxFrom(r.Context()).AWSShadowChecks(verdict, triage, limit)
	if err != nil {
		return 0, nil, err
	}
	items := make([]awsShadowCheckView, 0, len(rows))
	for _, c := range rows {
		items = append(items, awsShadowCheckViewOf(c))
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

func awsShadowNotFound() error {
	return &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such shadow check"}
}

func (s *Server) getAWSShadowCheck(r *http.Request, p *params) (int, any, error) {
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return 0, nil, awsShadowNotFound()
	}
	c := store.TxFrom(r.Context())
	x, err := c.AWSShadowCheck(id)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil, awsShadowNotFound()
	} else if err != nil {
		return 0, nil, err
	}
	ts, err := c.AWSShadowTriage(id)
	if err != nil {
		return 0, nil, err
	}
	steps := make([]awsShadowTriageView, 0, len(ts))
	for _, t := range ts {
		steps = append(steps, awsShadowTriageView{Status: t.Status, Note: t.Note, Actor: t.Actor, CreatedAt: store.RT(t.CreatedAt)})
	}
	return http.StatusOK, map[string]any{"check": awsShadowCheckViewOf(x), "triage": steps}, nil
}

func (s *Server) triageAWSShadowCheck(r *http.Request, p *params) (int, any, error) {
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return 0, nil, awsShadowNotFound()
	}
	var in struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if !slices.Contains(awsShadowSettable, in.Status) {
		return 0, nil, badRequest("invalid_status", "status is one of "+strings.Join(awsShadowSettable, ", "))
	}
	if utf8.RuneCountInString(in.Note) > awsShadowNoteMax || !utf8.ValidString(in.Note) {
		return 0, nil, badRequest("invalid_note", fmt.Sprintf("note is at most %d characters", awsShadowNoteMax))
	}
	var out awsShadowCheckView
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		if err := c.TriageAWSShadowCheck(id, in.Status, in.Note, actor(r), now); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such disagreement"}
			}
			return err
		}
		if err := c.Audit(now, actor(r), "aws.shadow.triaged", ojson.Object{{Key: "check_id", Value: id}, {Key: "status", Value: in.Status}}); err != nil {
			return err
		}
		x, err := c.AWSShadowCheck(id)
		if err != nil {
			return err
		}
		out = awsShadowCheckViewOf(x)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

// ---------------------------------------------------------------- the job

// awsShadowSample is one decision picked to be compared.
type awsShadowSample struct {
	connectorID, snapshotID                string
	principal, action, resource            string
	outcome, fidelity, explanationID, want string
}

// rank orders keys by a hash of the seed and the key: the same inputs give the
// same order, and a different seed (another tenant, day or snapshot) another.
func shadowRank(seed string, keys []string) []string {
	type kv struct{ h, k string }
	ks := make([]kv, len(keys))
	for i, k := range keys {
		h := sha256.Sum256([]byte(seed + "\x00" + k))
		ks[i] = kv{hex.EncodeToString(h[:8]), k}
	}
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].h != ks[j].h {
			return ks[i].h < ks[j].h
		}
		return ks[i].k < ks[j].k
	})
	out := make([]string, len(ks))
	for i := range ks {
		out[i] = ks[i].k
	}
	return out
}

type shadowPair struct{ action, resource string }

func (p shadowPair) key() string { return p.action + "\x00" + p.resource }

func shadowPairOf(key string) shadowPair {
	a, r, _ := strings.Cut(key, "\x00")
	return shadowPair{a, r}
}

// pickAWSShadowSamples chooses up to n decisions of one connector's newest
// snapshot (see the file comment for what qualifies), in a read transaction.
func (s *Server) pickAWSShadowSamples(c *store.TenantTx, k *store.AWSConnector, seed string, n int) ([]awsShadowSample, error) {
	ac, err := s.awsContext(c, k.LastSnapshotID)
	if err != nil {
		return nil, err
	}
	qr, _, err := s.awsQuerier(ac, "bare")
	if err != nil {
		return nil, err
	}
	snap := ac.eng.snap
	seed += "\x00" + ac.hdr.ID
	var ids []string
	for arn, p := range snap.Principals {
		if (p.Kind == model.IAMUser || p.Kind == model.IAMRole) && p.ARN == arn && p.AccountID != "" && !p.IsServiceLinked {
			ids = append(ids, arn)
		}
	}
	ids = shadowRank(seed, ids)
	if len(ids) > awsShadowMaxPrincipals {
		ids = ids[:awsShadowMaxPrincipals]
	}
	// real resources only: the index adds a representative resource for each wildcard
	// ARN pattern ("arn:aws:s3:::b/x"), which is not an object anyone has
	own := map[string]map[string]bool{} // principal -> pair keys it has
	var pool []string
	inPool := map[string]bool{}
	for _, arn := range ids {
		perms, err := qr.EffectivePermissions(c.Context(), arn)
		if err != nil {
			continue // a principal the evaluator cannot answer for is not sampled
		}
		own[arn] = map[string]bool{}
		for _, row := range perms.Expand() {
			if _, known := snap.Resources[row.Resource]; !known || row.Cell.Outcome != authz.Allow || row.Cell.Fidelity != authz.Exact {
				continue
			}
			pk := shadowPair{row.Action, row.Resource}.key()
			own[arn][pk] = true
			if !inPool[pk] {
				inPool[pk] = true
				pool = append(pool, pk)
			}
		}
	}
	var out []awsShadowSample
	add := func(arn string, pk string, wantOutcome authz.Outcome) error {
		pr := shadowPairOf(pk)
		d, err := qr.Can(c.Context(), arn, pr.action, pr.resource)
		if err != nil {
			return nil // not answerable: skip it
		}
		if d.Outcome != wantOutcome || d.Fidelity != authz.Exact || len(ac.eng.gapsFor(arn, pr.resource)) > 0 {
			return nil
		}
		x, err := eval.ExplanationID(d)
		if err != nil {
			return err
		}
		out = append(out, awsShadowSample{connectorID: k.ID, snapshotID: ac.hdr.ID, principal: arn, action: pr.action, resource: pr.resource,
			outcome: d.Outcome.String(), fidelity: d.Fidelity.String(), explanationID: x, want: d.AWSEvalDecision()})
		return nil
	}
	// an even share of the samples for each principal, half permissions it has and half it lacks
	perPrincipal := max(1, (n+len(own)-1)/max(1, len(own)))
	for _, arn := range ids {
		mine := own[arn]
		if mine == nil {
			continue
		}
		var have, lack []string
		for _, pk := range pool {
			if mine[pk] {
				have = append(have, pk)
			} else {
				lack = append(lack, pk)
			}
		}
		for _, w := range []struct {
			keys  []string
			want  authz.Outcome
			quota int
			tag   string
		}{{have, authz.Allow, (perPrincipal + 1) / 2, "+"}, {lack, authz.Deny, perPrincipal / 2, "-"}} {
			got := 0
			for _, pk := range shadowRank(seed+"\x00"+w.tag+arn, w.keys) {
				if got >= w.quota || len(out) >= n {
					break
				}
				before := len(out)
				if err := add(arn, pk, w.want); err != nil {
					return nil, err
				}
				got += len(out) - before
			}
		}
	}
	if len(out) > n {
		out = out[:n]
	}
	return out, nil
}

// queueAWSShadow runs the aws_shadow job for one tenant.
func (s *Server) queueAWSShadow(ctx context.Context, j queue.Job) (any, error) {
	ctx = audit.WithSystemActor(ctx, awsShadowActor)
	now := s.clock()
	day := awsShadowDay(now)
	var conns []*store.AWSConnector
	var remaining int
	if err := s.store.ReadTenant(ctx, j.Tenant, func(c *store.TenantTx) error {
		set, err := c.AWSShadowSettings()
		if err != nil || !set.Enabled {
			return err
		}
		used, err := c.AWSShadowSampledOn(day)
		if err != nil {
			return err
		}
		if remaining = min(set.DailyK-used, awsShadowPerRun); remaining <= 0 {
			return nil
		}
		all, err := c.AWSConnectors()
		for _, k := range all {
			if k.Status == store.AWSConnectorOK && k.LastSnapshotID != "" {
				conns = append(conns, k)
			}
		}
		return err
	}); err != nil || remaining <= 0 || len(conns) == 0 {
		return nil, err
	}
	svc, err := s.awsCollector()
	if err != nil {
		return nil, nil // a server with no AWS client or catalog has nothing to ask with
	}
	var agree, disagree, inconclusive, failed int
	var errs []error
	for i, k := range conns {
		quota := remaining / (len(conns) - i) // an even share of what is left
		if quota < 1 {
			continue
		}
		remaining -= quota
		var samples []awsShadowSample
		if err := s.store.ReadTenant(ctx, j.Tenant, func(c *store.TenantTx) (err error) {
			samples, err = s.pickAWSShadowSamples(c, k, j.Tenant.String()+"\x00"+day+"\x00"+k.ID, quota)
			return err
		}); err != nil {
			errs = append(errs, fmt.Errorf("connector %s: %w", k.ID, err))
			continue
		}
		if len(samples) == 0 {
			continue
		}
		sim, err := svc.Simulator(ctx, s.store, j.Tenant, k.ID)
		if err != nil {
			errs = append(errs, fmt.Errorf("connector %s: %w", k.ID, err))
			continue
		}
		var checks []*store.AWSShadowCheck
		streak := 0
		for n, sm := range samples {
			if ctx.Err() != nil {
				break
			}
			if n > 0 && awsShadowGap > 0 {
				select {
				case <-ctx.Done():
				case <-time.After(awsShadowGap):
				}
			}
			ck := &store.AWSShadowCheck{ID: store.NewID(), ConnectorID: sm.connectorID, SnapshotID: sm.snapshotID, SampleDay: day,
				PrincipalARN: sm.principal, Action: sm.action, ResourceARN: sm.resource, TesseraOutcome: sm.outcome,
				TesseraFidelity: sm.fidelity, ExplanationID: sm.explanationID, CheckedAt: s.clock()}
			ans, err := sim.Ask(ctx, awsorg.SimQuery{PrincipalARN: sm.principal, Action: sm.action, Resource: sm.resource})
			switch {
			case err != nil && ctx.Err() != nil:
				// shutting down: this one is not recorded and so not counted
			case err != nil:
				ck.Verdict, ck.Detail = store.AWSShadowError, jobsErrorText(err)
				streak++
				failed++
			default:
				streak = 0
				ck.AWSDecision = ans.Decision
				switch verdict := shadowVerdict(sm.want, ans); verdict {
				case store.AWSShadowAgree:
					agree++
					ck.Verdict = verdict
				case store.AWSShadowDisagree:
					disagree++
					ck.Verdict = verdict
					ck.Detail = fmt.Sprintf("Tessera says %s; the simulator says %s", sm.want, ans.Decision)
				default:
					inconclusive++
					ck.Verdict = verdict
					ck.Detail = "the simulator needs context keys: " + strings.Join(ans.Missing, ", ")
				}
			}
			if ck.Verdict != "" {
				checks = append(checks, ck)
			}
			if streak >= awsShadowMaxFailures {
				errs = append(errs, fmt.Errorf("connector %s: %d simulator calls in a row failed; stopped", k.ID, streak))
				break
			}
		}
		if len(checks) == 0 {
			continue
		}
		rec := context.WithoutCancel(ctx)
		if err := s.store.InTenant(rec, j.Tenant, func(c *store.TenantTx) error {
			for _, ck := range checks {
				if err := c.InsertAWSShadowCheck(ck); err != nil {
					return err
				}
			}
			return c.Audit(s.clock(), awsShadowActor, "aws.shadow.checked", ojson.Object{{Key: "connector_id", Value: k.ID},
				{Key: "checks", Value: len(checks)}})
		}); err != nil {
			errs = append(errs, err)
		}
	}
	res := map[string]int{"agree": agree, "disagree": disagree, "inconclusive": inconclusive, "errors": failed}
	if err := errors.Join(errs...); err != nil {
		return res, err
	}
	return res, nil
}

// shadowVerdict compares the evaluator's answer ("allowed", "explicitDeny" or
// "implicitDeny") with the simulator's, at the level of allow against deny.
func shadowVerdict(want string, ans *awsorg.SimAnswer) string {
	if len(ans.Missing) > 0 {
		return store.AWSShadowInconclusive
	}
	if (want == "allowed") == (ans.Decision == "allowed") {
		return store.AWSShadowAgree
	}
	return store.AWSShadowDisagree
}

func jobsErrorText(err error) string { return jobs.ErrorSummary(err) }
