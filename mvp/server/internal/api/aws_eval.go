package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/catalog"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	awsq "github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The AWS effective-permission evaluator's endpoints (issue #30, PR-11; design
// docs/design/aws-effective-permission-evaluator.md §11.2). All are read-only,
// tenant-scoped, declared in the route table with graph.read, and audited like
// every request. The evaluator runs over a stored snapshot (the newest, or the
// one named by ?snapshot=), against the action catalog the server was started
// with.
//
//	GET  /api/aws/can?principal=&action=&resource=&profile=     one decision with its trace
//	GET  /api/aws/principals/{arn}/effective?service=&profile=  what a principal can do, paged
//	GET  /api/aws/resources/{arn}/who-can?action=&profile=      who can do an action on a resource
//	GET  /api/aws/explanations/{id}                             a decision's trace by id
//	POST /api/aws/simulate-policy-change                        who gains or loses what (aws_simulate.go)
//
// {arn} may hold slashes (a role path, an S3 object key). "profile" is the
// assumption profile for the keys a request does not pin: "default" (the
// current hour and TLS), "none" (every key unknown, so most results are
// CONDITIONAL), "bare" (a concrete request with no context keys) or a comma
// list of any-network, mfa-session, now and tls.
//
// Fail closed (design §3.3): a policy the collector could not read is in the
// snapshot's findings, not in the snapshot. A decision it could affect is
// returned UNSUPPORTED with POLICY_UNPARSEABLE; a bulk answer lists the
// findings that affect it and marks the rows they reach, because a deny the
// index hides cannot be marked.
func (s *Server) registerAWSEvalRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/aws/can", read, need(auth.PermGraphRead), s.rd(s.awsCan))
	s.handle(G, "/api/aws/principals/{arn}/effective", read, need(auth.PermGraphRead), s.rd(s.awsEffective))
	s.handle(G, "/api/aws/resources/{arn}/who-can", read, need(auth.PermGraphRead), s.rd(s.awsWhoCan))
	s.handle(G, "/api/aws/explanations/{id}", read, need(auth.PermGraphRead), s.rd(s.awsExplanation))
	// phased: it computes inside a read transaction, may post a comment with no
	// transaction open, and then records the post (aws_simulate.go)
	s.handle(P, "/api/aws/simulate-policy-change", phased, need(auth.PermGraphRead), s.rd(s.awsSimulate)).answersRead = true
	s.handle(G, "/api/aws/pr-comment", read, need(auth.PermConnectionsRead), s.rd(s.getAWSPRComment))
	s.handle(http.MethodPut, "/api/aws/pr-comment", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.putAWSPRComment))
}

// ---------------------------------------------------------------- the catalog

// AWSCatalog is what an evaluation runs against: the engine's view of the
// action catalog, the action universe the index answers over, and the rule
// for which (action, resource service) cells exist.
type AWSCatalog struct {
	Cat            eval.Catalog
	Actions        []string
	Applies        func(actionPrefix, resourceService string) bool
	MultivaluedKey func(lowerKey string) bool
}

// indexConfig is the index configuration for a snapshot: the catalog's actions
// and, beyond the snapshot's inventory, one representative resource for each
// ARN pattern its policies name (Tessera does not inventory S3 objects, so
// without these "s3:GetObject on prod-pii/*" would be a permission on no
// resource at all).
func (c *AWSCatalog) indexConfig(snap *model.Snapshot) index.Config {
	return index.Config{Catalog: c.Cat, Actions: c.Actions, Applies: c.Applies, Resources: representativeResources(snap)}
}

// maxRepresentatives bounds the extra resources one snapshot adds.
const maxRepresentatives = 5000

// representativeResources makes one resource of each wildcard ARN pattern of
// the snapshot's identity-based and resource policies, by replacing each
// wildcard with "x" ("arn:aws:s3:::prod-pii/*" is represented by
// "arn:aws:s3:::prod-pii/x"). Patterns with policy variables are left out.
// The list is sorted, so the same snapshot gives the same index.
func representativeResources(snap *model.Snapshot) []string {
	seen := map[string]bool{}
	for _, d := range snap.Policies {
		for i := range d.Statements {
			st := &d.Statements[i]
			for _, ps := range []*model.PatternSet{st.Resources, st.NotResources} {
				for _, pat := range ps.MatchPatterns() {
					if !strings.HasPrefix(pat, "arn:") || !strings.ContainsAny(pat, "*?") || strings.Contains(pat, "${") {
						continue
					}
					seen[strings.NewReplacer("*", "x", "?", "x").Replace(pat)] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		if _, known := snap.Resources[k]; !known {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	if len(out) > maxRepresentatives {
		out = out[:maxRepresentatives]
	}
	return out
}

// CatalogFromDir returns a loader for Config.AWSCatalog: the compiled catalog
// of dir (mvp/server/catalog/aws), the given version or, when it is empty, the
// newest. It loads once, on first use; a failure is retried on the next call.
func CatalogFromDir(dir, version string) func() (*AWSCatalog, error) {
	var mu sync.Mutex
	var loaded *AWSCatalog
	return func() (*AWSCatalog, error) {
		mu.Lock()
		defer mu.Unlock()
		if loaded != nil {
			return loaded, nil
		}
		v := version
		if v == "" {
			all, err := catalog.ListCompiled(dir)
			if err != nil {
				return nil, err
			}
			if len(all) == 0 {
				return nil, errors.New("no compiled AWS catalog (run `tessera catalog compile`)")
			}
			v = all[len(all)-1].Version
		}
		c, err := catalog.Load(dir, v)
		if err != nil {
			return nil, err
		}
		view := catalog.NewEvalView(c)
		loaded = &AWSCatalog{Cat: view, Actions: view.Actions(), Applies: catalog.SameServiceRule, MultivaluedKey: c.MultivaluedKey}
		return loaded, nil
	}
}

func (s *Server) awsCatalog() (*AWSCatalog, error) {
	unavailable := &readiness.Error{Status: http.StatusServiceUnavailable, Code: "aws_catalog_unavailable",
		Msg: "the AWS action catalog is not available on this server"}
	if s.cfg.AWSCatalog == nil {
		return nil, unavailable
	}
	c, err := s.cfg.AWSCatalog()
	if err != nil || c == nil || c.Cat == nil {
		if err != nil {
			s.log.Warn("aws catalog unavailable", "err", err)
		}
		return nil, unavailable
	}
	return c, nil
}

// ---------------------------------------------------------------- engines

// awsEngine is one snapshot loaded and indexed for one catalog version. The
// index and the memo are shared by every request that asks about it.
type awsEngine struct {
	once     sync.Once
	err      error
	snap     *model.Snapshot
	findings awsorg.Findings
	ix       *index.Index
	memo     *index.Memo
}

type awsEngineKey struct {
	tenant   tenancy.ID
	snapshot string
	catalog  string
}

type explKey struct {
	tenant tenancy.ID
	id     string
}

// awsRuntime holds what the evaluator keeps between requests: a few indexed
// snapshots, and the traces of recent decisions (a read-only route cannot
// store them). Both are keyed by tenant, so a request can only reach its own.
type awsRuntime struct {
	mu        sync.Mutex
	engines   map[awsEngineKey]*awsEngine
	order     []awsEngineKey
	expl      map[explKey][]byte
	explOrder []explKey
}

const (
	awsMaxEngines      = 4
	awsMaxExplanations = 512
	awsMemoEntries     = 1 << 20
	awsWorkers         = 4
)

func (rt *awsRuntime) engine(k awsEngineKey) *awsEngine {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.engines == nil {
		rt.engines = map[awsEngineKey]*awsEngine{}
	}
	if e, ok := rt.engines[k]; ok {
		return e
	}
	e := &awsEngine{}
	rt.engines[k] = e
	rt.order = append(rt.order, k)
	for len(rt.order) > awsMaxEngines {
		delete(rt.engines, rt.order[0])
		rt.order = rt.order[1:]
	}
	return e
}

func (rt *awsRuntime) forget(k awsEngineKey, e *awsEngine) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.engines[k] == e {
		delete(rt.engines, k)
	}
}

func (rt *awsRuntime) remember(t tenancy.ID, id string, body []byte) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.expl == nil {
		rt.expl = map[explKey][]byte{}
	}
	k := explKey{t, id}
	if _, ok := rt.expl[k]; !ok {
		rt.explOrder = append(rt.explOrder, k)
		for len(rt.explOrder) > awsMaxExplanations {
			delete(rt.expl, rt.explOrder[0])
			rt.explOrder = rt.explOrder[1:]
		}
	}
	rt.expl[k] = body
}

func (rt *awsRuntime) recall(t tenancy.ID, id string) ([]byte, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b, ok := rt.expl[explKey{t, id}]
	return b, ok
}

// awsCtx is a snapshot ready to be queried.
type awsCtx struct {
	cat *AWSCatalog
	eng *awsEngine
	hdr *store.AWSSnapshot
}

// awsContext finds the snapshot (the newest unless id is given) in the
// transaction's tenant, and its indexed engine. The snapshot is looked up in
// the tenant's own rows before the cache is consulted, so another tenant's
// snapshot id is a 404 here and never reaches the cache.
func (s *Server) awsContext(tx *store.TenantTx, id string) (*awsCtx, error) {
	cat, err := s.awsCatalog()
	if err != nil {
		return nil, err
	}
	var hdr *store.AWSSnapshot
	if id == "" {
		all, err := tx.AWSSnapshots(1)
		if err != nil {
			return nil, err
		}
		if len(all) == 0 {
			return nil, &readiness.Error{Status: http.StatusNotFound, Code: "no_snapshot", Msg: "no AWS snapshot has been collected"}
		}
		hdr = all[0]
	} else {
		notFound := &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such snapshot"}
		if !awsSnapshotIDRE.MatchString(id) {
			return nil, notFound
		}
		if hdr, err = tx.AWSSnapshot(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, notFound
			}
			return nil, err
		}
	}
	k := awsEngineKey{tx.Tenant(), hdr.ID, cat.Cat.Version()}
	e := s.aws.engine(k)
	e.once.Do(func() {
		var col *awsorg.Collection
		if col, e.err = awsorg.Load(tx, hdr.ID); e.err != nil {
			return
		}
		e.snap, e.findings = col.Snapshot, col.Findings
		e.ix, e.err = index.Build(col.Snapshot, cat.indexConfig(col.Snapshot))
		e.memo = index.NewMemo(awsMemoEntries)
	})
	if e.err != nil {
		s.aws.forget(k, e)
		s.log.Error("aws snapshot cannot be indexed", "snapshot", hdr.ID, "err", e.err)
		return nil, &readiness.Error{Status: http.StatusInternalServerError, Code: "aws_snapshot_unusable",
			Msg: "the snapshot cannot be loaded for evaluation"}
	}
	return &awsCtx{cat: cat, eng: e, hdr: hdr}, nil
}

// awsOptions turns the profile parameter into query options and the label the
// response carries. The evaluation time is the current hour, so a profile is
// the same for every request of the hour and the memo stays warm.
func awsOptions(profile string, now time.Time) (awsq.Options, string, error) {
	bad := func(format string, a ...any) error {
		return badRequest("invalid_profile", fmt.Sprintf(format, a...))
	}
	hour := now.UTC().Truncate(time.Hour)
	opts := awsq.Options{Mode: eval.Symbolic, Workers: awsWorkers}
	switch profile {
	case "", "default":
		opts.Profile = eval.DefaultProfile(hour)
		return opts, "default", nil
	case "none":
		return opts, "none", nil
	case "bare":
		opts.Mode = eval.Concrete
		return opts, "bare", nil
	}
	names := strings.Split(profile, ",")
	if len(names) > 4 {
		return opts, "", bad("at most four profile names")
	}
	opts.Profile = map[string]eval.ContextValue{}
	for _, n := range names {
		p, err := eval.Profile(strings.TrimSpace(n), hour)
		if err != nil {
			return opts, "", bad("unknown or unsupported profile %q: use default, none, bare, or a list of any-network, mfa-session, now, tls", clipStr(n, 40))
		}
		for k, v := range p {
			opts.Profile[k] = v
		}
	}
	return opts, strings.Join(names, ","), nil
}

func clipStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func (s *Server) awsQuerier(ac *awsCtx, profile string) (*awsq.Querier, string, error) {
	opts, label, err := awsOptions(profile, s.clock())
	if err != nil {
		return nil, "", err
	}
	q, err := awsq.New(ac.eng.ix, ac.eng.memo, opts)
	if err != nil {
		return nil, "", badRequest("invalid_profile", err.Error())
	}
	return q, label, nil
}

// awsEvalErr maps the evaluator's refusals of a request to API errors.
func awsEvalErr(err error) error {
	switch {
	case errors.Is(err, eval.ErrUnknownPrincipal):
		return &readiness.Error{Status: http.StatusNotFound, Code: "principal_not_found", Msg: "no such principal in the snapshot"}
	case errors.Is(err, eval.ErrInvalidRequest):
		return badRequest("invalid_request", err.Error())
	case errors.Is(err, awsq.ErrOptions):
		return badRequest("invalid_profile", err.Error())
	}
	return err
}

// ---------------------------------------------------------------- input

const awsMaxARNLen = 2048

var awsActionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}:[A-Za-z0-9_-]{1,128}$`)
var awsServiceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// awsName validates a principal or resource name taken from a URL: an ARN, a
// service principal, "*" or "anonymous". It must be printable, bounded text.
func awsName(field, v string, required bool) (string, error) {
	if v == "" && required {
		return "", badRequest("invalid_"+field, field+" is required")
	}
	if len(v) > awsMaxARNLen {
		return "", badRequest("invalid_"+field, fmt.Sprintf("%s is longer than %d bytes", field, awsMaxARNLen))
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return "", badRequest("invalid_"+field, field+" holds a control or invalid character")
		}
	}
	return v, nil
}

func awsAction(q string) (string, error) {
	if !awsActionRE.MatchString(q) {
		return "", badRequest("invalid_action", "action must be a service prefix and an action name, for example s3:GetObject")
	}
	return q, nil
}

// ---------------------------------------------------------------- views

type awsReasonView struct {
	Code             string `json:"code"`
	OutcomeSensitive bool   `json:"outcome_sensitive"`
	Detail           string `json:"detail,omitempty"`
}

// awsCellView is the part of a decision a bulk answer keeps (index.Cell).
type awsCellView struct {
	Outcome         string          `json:"outcome"`
	DenyKind        string          `json:"deny_kind,omitempty"`
	Fidelity        string          `json:"fidelity"`
	FidelityReasons []awsReasonView `json:"fidelity_reasons"`
	Residual        *string         `json:"residual"`
}

// cellViewOf renders a cell. gaps are the collection findings that reach it:
// the cell is then UNSUPPORTED, with their reasons added.
func cellViewOf(c *index.Cell, gaps []authz.FidelityReason) *awsCellView {
	if c == nil {
		return nil
	}
	v := &awsCellView{Outcome: c.Outcome.String(), Fidelity: c.Fidelity.String(), FidelityReasons: []awsReasonView{}}
	if c.Outcome == authz.Deny {
		v.DenyKind = c.DenyKind.String()
	}
	if c.Reasons != "" {
		for _, r := range strings.Split(c.Reasons, ",") {
			code, sens := strings.CutSuffix(r, "!")
			v.FidelityReasons = append(v.FidelityReasons, awsReasonView{Code: code, OutcomeSensitive: sens})
		}
	}
	if c.Outcome == authz.Conditional && c.ResidualText != "" {
		t := c.ResidualText
		v.Residual = &t
	}
	if len(gaps) > 0 {
		v.Fidelity = authz.Unsupported.String()
		for _, g := range gaps {
			v.FidelityReasons = append(v.FidelityReasons, awsReasonView{Code: string(g.Code), OutcomeSensitive: g.OutcomeSensitive, Detail: clipStr(g.Detail, 300)})
		}
	}
	return v
}

type awsGapView struct {
	Kind       string `json:"kind"`
	SourceARN  string `json:"source_arn"`
	PolicyKind string `json:"policy_kind"`
	Code       string `json:"code"`
	Detail     string `json:"detail"`
	Scope      string `json:"scope"`
}

func gapViews(fs awsorg.Findings) []awsGapView {
	out := make([]awsGapView, 0, len(fs))
	for _, f := range fs {
		out = append(out, awsGapView{f.Kind, f.SourceARN, f.PolicyKind, f.Code, clipStr(f.Detail, 300), string(f.Scope.Type)})
	}
	return out
}

// findingRequest names the facts of a request that decide which findings reach
// it. An account that is not known is left empty, which is conservative.
func findingRequest(snap *model.Snapshot, principal, resource string) awsorg.Request {
	r := awsorg.Request{PrincipalARN: principal, ResourceARN: resource}
	if p := snap.Principals[principal]; p != nil {
		r.PrincipalAccount = p.AccountID
	} else {
		r.PrincipalAccount = arnAccount(principal)
	}
	if x := snap.Resources[resource]; x != nil {
		r.ResourceAccount = x.AccountID
	} else {
		r.ResourceAccount = arnAccount(resource)
	}
	return r
}

func arnAccount(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 5 || parts[0] != "arn" {
		return ""
	}
	return parts[4]
}

// gapsFor are the findings that could change the decision for a request.
func (e *awsEngine) gapsFor(principal, resource string) []authz.FidelityReason {
	if len(e.findings) == 0 {
		return nil
	}
	return e.findings.Unsupported(findingRequest(e.snap, principal, resource))
}

// findingsFor are those findings themselves. An empty principal or resource
// is unknown, which reaches every finding scoped by account.
func (e *awsEngine) findingsFor(principal, resource string) awsorg.Findings {
	var out awsorg.Findings
	if len(e.findings) == 0 {
		return out
	}
	req := findingRequest(e.snap, principal, resource)
	for _, f := range e.findings {
		if len((awsorg.Findings{f}).Unsupported(req)) > 0 {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------- can

type awsSnapshotRef struct {
	ID      string `json:"id"`
	TakenAt string `json:"taken_at"`
}

func snapshotRef(h *store.AWSSnapshot) awsSnapshotRef {
	return awsSnapshotRef{ID: h.ID, TakenAt: store.RT(h.TakenAt)}
}

type awsCanView struct {
	Decision      *authz.Decision `json:"decision"`
	ExplanationID string          `json:"explanation_id"`
	Summary       string          `json:"summary"`
	Narrative     string          `json:"narrative"`
	Snapshot      awsSnapshotRef  `json:"snapshot"`
	Profile       string          `json:"profile"`
	// Gaps are the collection findings that reach this request; when there are
	// any the decision is UNSUPPORTED (design §3.3).
	Gaps []awsGapView `json:"collection_gaps"`
}

func (s *Server) awsCan(r *http.Request, _ *params) (int, any, error) {
	q := r.URL.Query()
	principal, err := awsName("principal", q.Get("principal"), true)
	if err != nil {
		return 0, nil, err
	}
	action, err := awsAction(q.Get("action"))
	if err != nil {
		return 0, nil, err
	}
	resource, err := awsName("resource", q.Get("resource"), false)
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	ac, err := s.awsContext(tx, q.Get("snapshot"))
	if err != nil {
		return 0, nil, err
	}
	qr, label, err := s.awsQuerier(ac, q.Get("profile"))
	if err != nil {
		return 0, nil, err
	}
	d, err := qr.Can(r.Context(), principal, action, resource)
	if err != nil {
		return 0, nil, awsEvalErr(err)
	}
	if rs := ac.eng.gapsFor(principal, resource); len(rs) > 0 {
		d.Fidelity = authz.Unsupported
		d.FidelityReasons = append(d.FidelityReasons, rs...)
	}
	id, err := eval.ExplanationID(d)
	if err != nil {
		return 0, nil, err
	}
	if body, err := json.Marshal(d); err == nil {
		s.aws.remember(tx.Tenant(), id, body)
	}
	return http.StatusOK, &awsCanView{Decision: d, ExplanationID: id, Summary: eval.Summary(d), Narrative: eval.Narrative(d),
		Snapshot: snapshotRef(ac.hdr), Profile: label, Gaps: gapViews(ac.eng.findingsFor(principal, resource))}, nil
}

// ---------------------------------------------------------------- explanations

var awsExplanationIDRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *Server) awsExplanation(r *http.Request, p *params) (int, any, error) {
	id := p.path["id"]
	notFound := &readiness.Error{Status: http.StatusNotFound, Code: "not_found",
		Msg: "no such explanation; one from a query is kept for a while, run the query again"}
	if !awsExplanationIDRE.MatchString(id) {
		return 0, nil, notFound
	}
	tx := store.TxFrom(r.Context())
	x, err := tx.AWSExplanation(id)
	switch {
	case err == nil:
		return http.StatusOK, map[string]any{"id": id, "decision": x.Trace}, nil
	case !errors.Is(err, store.ErrNotFound):
		return 0, nil, err
	}
	if b, ok := s.aws.recall(tx.Tenant(), id); ok {
		return http.StatusOK, map[string]any{"id": id, "decision": json.RawMessage(b)}, nil
	}
	return 0, nil, notFound
}

// ---------------------------------------------------------------- effective

type awsEffectiveItem struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	awsCellView
	// GapReasons is set when a collection finding reaches the cell.
	Gap bool `json:"gap"`
}

type awsEffectiveView struct {
	Principal string             `json:"principal"`
	Snapshot  awsSnapshotRef     `json:"snapshot"`
	Profile   string             `json:"profile"`
	Service   string             `json:"service"`
	Catalog   string             `json:"catalog_version"`
	Engine    string             `json:"engine_version"`
	Total     int                `json:"total"`
	Items     []awsEffectiveItem `json:"items"`
	Next      *string            `json:"next_cursor"`
	Stats     awsq.Stats         `json:"stats"`
	Gaps      []awsGapView       `json:"collection_gaps"`
}

// awsMaxEffectiveCells bounds the cells one answer expands (design §12.3 pages
// a set that can be very large; this is the limit of what is held to page it).
const (
	awsMaxEffectiveCells = 200000
	awsMaxPage           = 500
	awsDefaultPage       = 100
)

func awsPage(q map[string][]string) (limit, cursor int, err error) {
	limit = awsDefaultPage
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if v := get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 || limit > awsMaxPage {
			return 0, 0, badRequest("invalid_limit", fmt.Sprintf("limit must be 1 to %d", awsMaxPage))
		}
	}
	if v := get("cursor"); v != "" {
		if cursor, err = strconv.Atoi(v); err != nil || cursor < 0 {
			return 0, 0, badRequest("invalid_cursor", "cursor is the next_cursor of a previous answer")
		}
	}
	return limit, cursor, nil
}

func (s *Server) awsEffective(r *http.Request, p *params) (int, any, error) {
	arn, err := awsName("principal", p.path["arn"], true)
	if err != nil {
		return 0, nil, err
	}
	q := r.URL.Query()
	service := strings.ToLower(q.Get("service"))
	if service != "" && !awsServiceRE.MatchString(service) {
		return 0, nil, badRequest("invalid_service", "service must be a service prefix such as s3")
	}
	limit, cursor, err := awsPage(q)
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	ac, err := s.awsContext(tx, q.Get("snapshot"))
	if err != nil {
		return 0, nil, err
	}
	qr, label, err := s.awsQuerier(ac, q.Get("profile"))
	if err != nil {
		return 0, nil, err
	}
	perms, err := qr.EffectivePermissions(r.Context(), arn)
	if err != nil {
		return 0, nil, awsEvalErr(err)
	}

	// count the cells before expanding them
	ix := ac.eng.ix
	inService := func(action string) bool {
		return service == "" || strings.HasPrefix(strings.ToLower(action), service+":")
	}
	total := 0
	for _, row := range perms.Rows {
		n := 0
		for _, a := range ix.Actions.MemberNames(row.Action) {
			if inService(a) {
				n++
			}
		}
		total += n * len(ix.Resources.Atoms[row.Resource].Members)
		if total > awsMaxEffectiveCells {
			return 0, nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "too_large",
				Msg: fmt.Sprintf("more than %d permissions: narrow the answer with service=", awsMaxEffectiveCells)}
		}
	}
	cells := make([]awsq.ExpandedRow, 0, total)
	for _, c := range perms.Expand() {
		if inService(c.Action) {
			cells = append(cells, c)
		}
	}
	if cursor > len(cells) {
		return 0, nil, badRequest("invalid_cursor", "cursor is past the end of the answer")
	}
	end := min(cursor+limit, len(cells))
	items := make([]awsEffectiveItem, 0, end-cursor)
	for _, c := range cells[cursor:end] {
		gaps := ac.eng.gapsFor(arn, c.Resource)
		items = append(items, awsEffectiveItem{Action: c.Action, Resource: c.Resource, awsCellView: *cellViewOf(c.Cell, gaps), Gap: len(gaps) > 0})
	}
	view := &awsEffectiveView{Principal: arn, Snapshot: snapshotRef(ac.hdr), Profile: label, Service: service,
		Catalog: ac.cat.Cat.Version(), Engine: eval.EngineVersion, Total: len(cells), Items: items, Stats: perms.Stats,
		// the findings that reach a request by the principal, whatever the resource: the denies the
		// index leaves out of the answer cannot be trusted where one applies
		Gaps: gapViews(ac.eng.findingsFor(arn, ""))}
	if end < len(cells) {
		next := strconv.Itoa(end)
		view.Next = &next
	}
	return http.StatusOK, view, nil
}

// ---------------------------------------------------------------- who can

type awsWhoItem struct {
	Principal string `json:"principal"`
	awsCellView
	Gap bool `json:"gap"`
}

type awsWhoView struct {
	Resource       string         `json:"resource"`
	Action         string         `json:"action"`
	Snapshot       awsSnapshotRef `json:"snapshot"`
	Profile        string         `json:"profile"`
	Catalog        string         `json:"catalog_version"`
	Engine         string         `json:"engine_version"`
	Items          []awsWhoItem   `json:"items"`
	Anonymous      *awsCellView   `json:"anonymous"`
	External       []string       `json:"external_accounts"`
	Candidates     int            `json:"candidates"`
	AtomsEvaluated int            `json:"atoms_evaluated"`
	Gaps           []awsGapView   `json:"collection_gaps"`
}

func (s *Server) awsWhoCan(r *http.Request, p *params) (int, any, error) {
	resource, err := awsName("resource", p.path["arn"], true)
	if err != nil {
		return 0, nil, err
	}
	q := r.URL.Query()
	action, err := awsAction(q.Get("action"))
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	ac, err := s.awsContext(tx, q.Get("snapshot"))
	if err != nil {
		return 0, nil, err
	}
	qr, label, err := s.awsQuerier(ac, q.Get("profile"))
	if err != nil {
		return 0, nil, err
	}
	who, err := qr.WhoCan(r.Context(), action, resource)
	if err != nil {
		return 0, nil, awsEvalErr(err)
	}
	items := make([]awsWhoItem, 0, len(who.Rows))
	for _, row := range who.Rows {
		gaps := ac.eng.gapsFor(row.PrincipalARN, resource)
		items = append(items, awsWhoItem{Principal: row.PrincipalARN, awsCellView: *cellViewOf(row.Cell, gaps), Gap: len(gaps) > 0})
	}
	var anon *awsCellView
	if who.Anonymous != nil {
		anon = cellViewOf(who.Anonymous, ac.eng.gapsFor("anonymous", resource))
	}
	external := who.External
	if external == nil {
		external = []string{}
	}
	return http.StatusOK, &awsWhoView{Resource: resource, Action: action, Snapshot: snapshotRef(ac.hdr), Profile: label,
		Catalog: ac.cat.Cat.Version(), Engine: eval.EngineVersion, Items: items, Anonymous: anon, External: external,
		Candidates: who.Candidates, AtomsEvaluated: who.AtomsEvaluated,
		// a finding that covers the resource, or the requesters of its account, could hide a principal that can
		Gaps: gapViews(ac.eng.findingsFor("", resource))}, nil
}
