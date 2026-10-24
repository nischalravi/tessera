package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/leastpriv"
	"github.com/nischalravi/tessera/mvp/server/internal/nhi"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// registerRoutes declares every route and how it reaches tenant data:
//
//   - noTenant: no tenant data (health, API docs).
//   - read: a read-only tenant transaction (GET).
//   - swept: expired JIT grants of the tenant are swept first (in their own
//     write transaction), then a read-only tenant transaction, as the
//     original backend swept before every analysis.
//   - write: one tenant write transaction around the whole handler (POST).
func (s *Server) registerRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/health", noTenant, publicRoute, s.health)
	s.handle(G, "/api/connectors", read, need(auth.PermGraphRead), s.listConnectors)
	s.handle(P, "/api/connectors/sync", write, need(auth.PermConnectorsSync), s.syncConnectors).asJob(jobs.Sync, "")
	s.registerConnectorScheduleRoutes()
	s.handle(G, "/api/summary", swept, need(auth.PermGraphRead), s.summary)
	s.handle(G, "/api/identities", swept, need(auth.PermGraphRead), s.listIdentities)
	s.handle(G, "/api/identities/{identity_id}", swept, need(auth.PermGraphRead), s.identityDetail)
	s.handle(G, "/api/accounts", read, need(auth.PermGraphRead), s.listAccounts)
	s.handle(G, "/api/groups", read, need(auth.PermGraphRead), s.listGroups)
	s.handle(G, "/api/resources", swept, need(auth.PermGraphRead), s.listResources)
	s.handle(G, "/api/graph", swept, need(auth.PermGraphRead), s.graphView)
	s.handle(G, "/api/nhi", swept, need(auth.PermGraphRead), s.nhiInventory)
	s.handle(G, "/api/ai-agents", swept, need(auth.PermGraphRead), s.listAIAgents)
	s.handle(G, "/api/ai-agents/mcp-findings", read, need(auth.PermGraphRead), s.listMCPFindings)
	s.handle(G, "/api/ai-agents/blueprints", read, need(auth.PermGraphRead), s.listAgentBlueprints)
	s.handle(G, "/api/least-privilege/recommendations", swept, need(auth.PermGraphRead), s.recommendations)
	s.handle(P, "/api/least-privilege/revoke", write, need(auth.PermGraphRead), s.revoke)
	s.handle(G, "/api/policies", swept, need(auth.PermGraphRead), s.listPolicies)
	s.handle(G, "/api/violations", swept, need(auth.PermGraphRead), s.listViolations)
	// what-if analysis: its answer is data, recorded by nothing but its
	// http.request event, so it fails closed like a read (design §13.4)
	s.handle(P, "/api/simulate", write, need(auth.PermGraphRead), s.simulate).answersRead = true
	s.handle(G, "/api/jit/requests", swept, need(auth.PermGraphRead), s.jitRequests)
	s.handle(P, "/api/jit/requests", write, need(auth.PermJITRequest), s.jitCreate)
	// The former /api/jit/requests/{request_id}/{action} route is split so each
	// decision declares its own requirement (design §16.2); the URLs are the same.
	s.handle(P, "/api/jit/requests/{request_id}/approve", write,
		needStepUp(auth.PermJITDecide, auth.StepUpPolicy), s.jitDecide("approve"))
	s.handle(P, "/api/jit/requests/{request_id}/deny", write, need(auth.PermJITDenyRevoke), s.jitDecide("deny"))
	s.handle(P, "/api/jit/requests/{request_id}/revoke", write, need(auth.PermJITDenyRevoke), s.jitDecide("revoke"))
	s.handle(P, "/api/jit/sweep", write, need(auth.PermJITSweep), s.jitSweep).asJob(jobs.JITSweep, "")
	s.handle(G, "/api/reviews/campaigns", read, need(auth.PermGraphRead), s.listCampaigns)
	s.handle(P, "/api/reviews/campaigns", write, need(auth.PermReviewsManage), s.createCampaign)
	s.handle(G, "/api/reviews/campaigns/{campaign_id}", read, need(auth.PermGraphRead), s.campaign)
	s.handle(P, "/api/reviews/items/{item_id}/decision", write, needStepUp(auth.PermReviewsDecide, auth.StepUpPolicy), s.reviewDecide)
	s.handle(G, "/api/hris/events", read, need(auth.PermGraphRead), s.hrisEvents)
	s.handle(P, "/api/hris/events", write, need(auth.PermHRISSimulateEvent), s.hrisCreate)
	s.handle(G, "/api/hris/events/{event_id}/plan", read, need(auth.PermGraphRead), s.hrisPlan)
	s.handle(P, "/api/hris/events/{event_id}/execute", phased, needStepUp(auth.PermHRISExecute, auth.StepUpPolicy), s.hrisExecute).asJob(jobs.Provision, "")
	s.handle(G, "/api/jml/leaver-plan/{identity_id}", read, need(auth.PermGraphRead), s.leaverPlan)
	s.handle(G, "/openapi.json", noTenant, need(auth.PermAuthenticated), s.openAPI)
	s.handle(G, "/api/openapi.json", noTenant, need(auth.PermAuthenticated), s.fullOpenAPIHandler)
	s.handle(G, "/docs", noTenant, need(auth.PermAuthenticated), s.swaggerUI)
	s.handle(G, "/docs/oauth2-redirect", noTenant, need(auth.PermAuthenticated), s.swaggerRedirect)
	s.handle(G, "/redoc", noTenant, need(auth.PermAuthenticated), s.redoc)
}

// ---------------------------------------------------------------- context

// analysis is the per-request analysis context: graph snapshot, usage index
// and (lazily) policy violations.
type analysis struct {
	c        *store.TenantTx
	now      time.Time
	g        *graph.Snapshot
	u        *usage.Index
	policies []*policy.Policy
	viol     []policy.Violation
	violDone bool
}

// newAnalysis builds the graph and usage index of the transaction's tenant.
// In a write transaction it first sweeps expired JIT grants; a read-only
// transaction was swept by the route's tenant wrapper before it began.
func (s *Server) newAnalysis(c *store.TenantTx) (*analysis, error) {
	now := s.clock()
	if !c.ReadOnly() {
		if need, err := jit.NeedsSweep(c, now); err != nil {
			return nil, err
		} else if need {
			if _, err := jit.Sweep(c, now); err != nil {
				return nil, err
			}
		}
	}
	pols, err := s.effectivePolicies(c)
	if err != nil {
		return nil, err
	}
	g, err := graph.Build(c, now)
	if err != nil {
		return nil, err
	}
	u, err := usage.Build(c, now)
	if err != nil {
		return nil, err
	}
	return &analysis{c: c, now: now, g: g, u: u, policies: pols}, nil
}

// withoutMitigated drops the SoD violations an approved mitigation or acceptance
// covers: they leave the open counts, but stay in the SoD report (GET /api/sod/violations).
func (a *analysis) withoutMitigated(vs []policy.Violation) ([]policy.Violation, error) {
	cov, err := sod.Covers(a.c, a.now)
	if err != nil || len(cov) == 0 {
		return vs, err
	}
	riskID := map[string]string{}
	for _, r := range a.sodRisks() {
		riskID[r.Key] = r.ID
	}
	out := vs[:0:0]
	for _, v := range vs {
		if id, ok := riskID[v.PolicyID]; ok && v.IdentityID != nil {
			if c := cov.For(id, *v.IdentityID); c != nil && sod.Closes(c.Status) {
				continue
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func (a *analysis) violations() ([]policy.Violation, error) {
	if !a.violDone {
		v, err := policy.Evaluate(a.policies, policy.NewContext(a.g, a.c, a.now))
		if err != nil {
			return nil, err
		}
		if v, err = a.withoutMitigated(v); err != nil {
			return nil, err
		}
		a.viol, a.violDone = v, true
	}
	return a.viol, nil
}

// readAnalysis builds an analysis in the request's tenant transaction.
func (s *Server) readAnalysis(r *http.Request) (*analysis, error) {
	return s.newAnalysis(store.TxFrom(r.Context()))
}

// ---------------------------------------------------------------- helpers

// counter is an insertion-ordered Counter.
type counter struct {
	keys []string
	n    map[string]int
}

func newCounter() *counter { return &counter{n: map[string]int{}} }

func (c *counter) add(k string, by int) {
	if _, ok := c.n[k]; !ok {
		c.keys = append(c.keys, k)
	}
	c.n[k] += by
}

func (c *counter) object() ojson.Object {
	o := ojson.Object{}
	for _, k := range c.keys {
		o = append(o, ojson.KV{Key: k, Value: c.n[k]})
	}
	return o
}

func brief(i *store.Identity) any {
	if i == nil {
		return nil
	}
	return briefObj(i)
}

func briefObj(i *store.Identity) ojson.Object {
	return ojson.Object{{Key: "id", Value: i.ID}, {Key: "name", Value: i.Name}, {Key: "type", Value: i.Type},
		{Key: "status", Value: i.Status}, {Key: "department", Value: i.Department}, {Key: "title", Value: i.Title}}
}

func getOrNil[T any](v *T, err error) (*T, error) {
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return v, err
}

func nonEmpty(p *string) bool { return p != nil && *p != "" }

func validated(p *params, more []verr) error {
	errs := append(p.errs, more...)
	if len(errs) > 0 {
		return &validationError{errs}
	}
	return nil
}

type risk struct {
	Effective, Unused, Privileged, Sensitive, Violations, Risk int
}

func (r risk) kvs() ojson.Object {
	return ojson.Object{{Key: "effective", Value: r.Effective}, {Key: "unused", Value: r.Unused},
		{Key: "privileged", Value: r.Privileged}, {Key: "sensitive", Value: r.Sensitive},
		{Key: "violations", Value: r.Violations}, {Key: "risk", Value: r.Risk}}
}

var riskSensitive = map[string]bool{"pii": true, "payments": true, "financial": true, "payroll": true}

// riskScores scores every identity (in graph order).
func (a *analysis) riskScores(unusedDays int) ([]int64, map[int64]risk, error) {
	viols, err := a.violations()
	if err != nil {
		return nil, nil, err
	}
	vio, vioSev := map[int64]int{}, map[int64]int{}
	for _, v := range viols {
		if v.IdentityID != nil {
			vio[*v.IdentityID]++
			rank, ok := policy.SeverityRank[v.Severity]
			if !ok {
				rank = 1
			}
			vioSev[*v.IdentityID] += rank
		}
	}
	ids := a.g.Identities(true)
	out := make(map[int64]risk, len(ids))
	for _, iid := range ids {
		eff := a.g.EffectivePermissions(iid)
		var r risk
		r.Effective = eff.Len()
		for _, ep := range eff.Values() {
			if a.u.Unused(iid, ep.PermID, unusedDays) {
				r.Unused++
			}
			if ep.Privileged {
				r.Privileged++
			}
			for _, t := range ep.Tags {
				if riskSensitive[t] {
					r.Sensitive++
					break
				}
			}
		}
		r.Violations = vio[iid]
		r.Risk = min(100, vioSev[iid]*6+r.Privileged*2+r.Sensitive+r.Unused)
		out[iid] = r
	}
	return ids, out, nil
}

// ---------------------------------------------------------------- meta

func (s *Server) health(_ http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	return ojson.Object{{Key: "status", Value: "ok"}, {Key: "time", Value: timeutil.ISO(s.clock())}}, nil
}

// source is one entry of the tenant's source list: a legacy connector or a
// live governed connection (readiness state active or degraded).
type source struct{ system, name, typeName string }

// sources is the single source of truth for what counts as a source or
// application: the legacy connectors plus the governed connections that are
// live. Draft, not-yet-active and retired connections are not listed. A
// governed connection on a system a legacy connector already covers is not
// listed twice. /api/connectors, the Applications list and page and the Home
// source and connection counts all read this list.
func (s *Server) sources(c *store.TenantTx) ([]source, error) {
	conns, err := s.cfg.Connectors(s.clock())
	if err != nil {
		return nil, err
	}
	var out []source
	seen := map[string]bool{}
	for _, cn := range conns {
		out = append(out, source{cn.System(), cn.DisplayName(), cn.TypeName()})
		seen[cn.System()] = true
	}
	live, err := s.readiness.ActiveConnections(c)
	if err != nil {
		return nil, err
	}
	for _, ac := range live {
		if !seen[ac.System()] {
			out = append(out, source{ac.System(), ac.Name(), ac.ConnectorType()})
			seen[ac.System()] = true
		}
	}
	return out, nil
}

func (s *Server) listConnectors(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c := store.TxFrom(r.Context())
	srcs, err := s.sources(c)
	if err != nil {
		return nil, err
	}
	out := []ojson.Object{}
	for _, cn := range srcs {
		n, err := c.CountSystem(cn.system)
		if err != nil {
			return nil, err
		}
		out = append(out, ojson.Object{{Key: "system", Value: cn.system}, {Key: "name", Value: cn.name},
			{Key: "type", Value: cn.typeName}, {Key: "accounts", Value: n.Accounts}, {Key: "groups", Value: n.Groups},
			{Key: "resources", Value: n.Resources}, {Key: "permissions", Value: n.Permissions}})
	}
	return out, nil
}

func (s *Server) syncConnectors(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	// ?mode=full ignores connector checkpoints and re-reads every source.
	mode := p.queryOptLiteral("mode", []string{"incremental", "full"})
	// ?async=true queues the sync for a worker (issue #302) instead of
	// running it in this request.
	async := p.queryOptLiteral("async", []string{"true", "false"})
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	now := s.clock()
	c := store.TxFrom(r.Context())
	if async != nil && *async == "true" {
		payload := worker.SyncPayload{}
		if mode != nil {
			payload.Mode = *mode
		}
		if pr := principal(r); pr.UserID != nil {
			payload.RequestedBy = pr.UserID.String() // the worker's holds name who queued the run (#487)
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		id := store.NewID()
		if _, err := s.queue.EnqueueTx(c, jobs.ConnectorSync, string(raw), id, now, maxSweepAttempts); err != nil {
			return nil, err
		}
		if err := c.Audit(now, actor(r), "connectors.sync_queued", ojson.Object{{Key: "key", Value: id},
			{Key: "mode", Value: payload.Mode}}); err != nil {
			return nil, err
		}
		return ojson.Object{{Key: "queued", Value: true}, {Key: "key", Value: id}}, nil
	}
	conns, err := s.cfg.Connectors(now)
	if err != nil {
		return nil, err
	}
	out, err := worker.RunSync(r.Context(), c, now, conns, mode != nil && *mode == "full", "system")
	if err != nil {
		return nil, err
	}
	// The live governed connections read remote systems, so a worker reads them (a remote
	// read must not hold this request's write transaction): queue a sync for them.
	live, err := s.readiness.ActiveConnections(c)
	if err != nil {
		return nil, err
	}
	for _, ac := range live {
		if gt, ok := governed.Lookup(ac.ConnectorType()); ok && !gt.Feature {
			payload := worker.SyncPayload{}
			if mode != nil {
				payload.Mode = *mode
			}
			if pr := principal(r); pr.UserID != nil {
				payload.RequestedBy = pr.UserID.String()
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				return nil, err
			}
			id := store.NewID()
			if _, err := s.queue.EnqueueTx(c, jobs.ConnectorSync, string(raw), id, now, maxSweepAttempts); err != nil {
				return nil, err
			}
			if err := c.Audit(now, actor(r), "connectors.sync_queued", ojson.Object{{Key: "key", Value: id},
				{Key: "mode", Value: payload.Mode}, {Key: "governed", Value: true}}); err != nil {
				return nil, err
			}
			return append(out, ojson.KV{Key: "governed_queued", Value: id}), nil
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- summary

func (s *Server) summary(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	c := a.c
	people, idents, err := c.IdentityMap()
	if err != nil {
		return nil, err
	}
	byType := map[string]int{}
	terminated := 0
	for _, i := range idents {
		if i.Status == "active" {
			byType[i.Type]++
		}
		if i.Status == "terminated" {
			terminated++
		}
	}
	ids, risks, err := a.riskScores(60)
	if err != nil {
		return nil, err
	}
	totalEff, totalUnused := 0, 0
	for _, iid := range ids {
		totalEff += risks[iid].Effective
		totalUnused += risks[iid].Unused
	}
	viols, err := a.violations()
	if err != nil {
		return nil, err
	}
	sev, byPolicy := newCounter(), newCounter()
	for _, v := range viols {
		sev.add(v.Severity, 1)
		byPolicy.add(v.PolicyName, 1)
	}
	nhis, err := nhi.Inventory(c, a.g, a.u)
	if err != nil {
		return nil, err
	}
	orphaned, agentsPII := 0, 0
	for _, n := range nhis {
		if slices.Contains(n.Flags, "orphaned") || slices.Contains(n.Flags, "owner_left") {
			orphaned++
		}
		if n.Type == "ai_agent" && slices.Contains(n.Flags, "pii_access") {
			agentsPII++
		}
	}
	secrets, err := c.Secrets()
	if err != nil {
		return nil, err
	}
	stale := 0
	for _, x := range secrets {
		ref := x.CreatedAt
		if x.LastRotatedAt != nil {
			ref = *x.LastRotatedAt
		}
		if timeutil.Days(a.now, ref) > 90 {
			stale++
		}
	}
	recs := leastpriv.GrantRecommendations(a.g, a.u, 60, nil)
	trims := leastpriv.RoleTrimRecommendations(a.g, a.u, 60, 2)
	remove := 0
	for _, rec := range recs {
		if rec.Kind == "remove" {
			remove++
		}
	}
	top := slices.Clone(ids)
	sort.SliceStable(top, func(i, j int) bool { return risks[top[i]].Risk > risks[top[j]].Risk })
	if len(top) > 8 {
		top = top[:8]
	}
	topOut := []ojson.Object{}
	for _, iid := range top {
		topOut = append(topOut, append(briefObj(people[iid]), risks[iid].kvs()...))
	}
	n := map[string]int{}
	for k, count := range map[string]func() (int, error){
		"accounts": c.CountAccounts,
		"systems":  c.CountAccountSystems,
		"grants":   c.CountEdges,
		"open":     c.CountUndecidedItems,
		"pending":  func() (int, error) { return c.CountRequestsByStatus("pending") },
		"active":   func() (int, error) { return c.CountRequestsByStatus("approved") },
		"hris":     func() (int, error) { return c.CountHrisEventsByStatus("pending") },
	} {
		if n[k], err = count(); err != nil {
			return nil, err
		}
	}
	days, err := c.UsageTrend(a.now.Add(-90 * 24 * time.Hour))
	if err != nil {
		return nil, err
	}
	trend := []ojson.Object{}
	for _, d := range days {
		day := d.Day
		if len(day) > 10 {
			day = day[:10]
		}
		trend = append(trend, ojson.Object{{Key: "day", Value: day}, {Key: "events", Value: d.Events}})
	}
	var unusedPct any = 0
	if totalEff > 0 {
		unusedPct = ojson.Float(timeutil.Round(100*float64(totalUnused)/float64(totalEff), 1))
	}
	out := ojson.Object{
		{Key: "identities", Value: ojson.Object{{Key: "human", Value: byType["human"]}, {Key: "service", Value: byType["service"]},
			{Key: "ai_agent", Value: byType["ai_agent"]}, {Key: "terminated", Value: terminated}}},
		{Key: "accounts", Value: n["accounts"]},
		{Key: "systems", Value: n["systems"]},
		{Key: "grants", Value: n["grants"]},
		{Key: "effective_permissions", Value: totalEff},
		{Key: "unused_permissions", Value: totalUnused},
		{Key: "unused_pct", Value: unusedPct},
		{Key: "violations", Value: ojson.Object{{Key: "total", Value: len(viols)}, {Key: "by_severity", Value: sev.object()},
			{Key: "by_policy", Value: byPolicy.object()}}},
		{Key: "nhi", Value: ojson.Object{{Key: "orphaned", Value: orphaned}, {Key: "stale_secrets", Value: stale},
			{Key: "agents_with_pii", Value: agentsPII}}},
		{Key: "jit", Value: ojson.Object{{Key: "pending", Value: n["pending"]}, {Key: "active", Value: n["active"]}}},
		{Key: "reviews", Value: ojson.Object{{Key: "open_items", Value: n["open"]}}},
		{Key: "recommendations", Value: ojson.Object{{Key: "total", Value: len(recs) + len(trims)}, {Key: "remove", Value: remove},
			{Key: "role_trim", Value: len(trims)}}},
		{Key: "hris_pending", Value: n["hris"]},
		{Key: "top_risky", Value: topOut},
		{Key: "usage_trend", Value: trend},
	}
	// The deployment-readiness block is opt-in so the recorded response
	// (and every parity fixture) is unchanged.
	if r.URL.Query().Get("include") == "readiness" {
		rd, err := s.readinessSummary(r.Context(), a.now)
		if err != nil {
			return nil, err
		}
		out = append(out, ojson.KV{Key: "readiness", Value: rd})
	}
	return out, nil
}

// ---------------------------------------------------------------- identities

func (s *Server) listIdentities(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	typ, q, status := p.queryOptStr("type"), p.queryOptStr("q"), p.queryOptStr("status")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	_, risks, err := a.riskScores(60)
	if err != nil {
		return nil, err
	}
	idents, err := a.c.Identities()
	if err != nil {
		return nil, err
	}
	accts, err := a.c.Accounts()
	if err != nil {
		return nil, err
	}
	byIdent := map[int64][]*store.Account{}
	for _, ac := range accts {
		if ac.IdentityID != nil {
			byIdent[*ac.IdentityID] = append(byIdent[*ac.IdentityID], ac)
		}
	}
	type row struct {
		obj  ojson.Object
		risk int
		name string
	}
	var rows []row
	for _, i := range idents {
		if (nonEmpty(typ) && i.Type != *typ) || (nonEmpty(status) && i.Status != *status) {
			continue
		}
		if nonEmpty(q) {
			hay := strings.ToLower(fmt.Sprintf("%s %s %s %s", i.Name, deref(i.Email), deref(i.Department), deref(i.Title)))
			if !strings.Contains(hay, strings.ToLower(*q)) {
				continue
			}
		}
		sys := map[string]bool{}
		for _, ac := range byIdent[i.ID] {
			sys[ac.System] = true
		}
		var last *time.Time
		if t, ok := a.u.ByIdentity[i.ID]; ok {
			last = &t
		}
		o := append(briefObj(i), ojson.KV{Key: "email", Value: i.Email}, ojson.KV{Key: "accounts", Value: len(byIdent[i.ID])},
			ojson.KV{Key: "systems", Value: sortedKeys(sys)}, ojson.KV{Key: "last_activity", Value: timeutil.ISOPtr(last)})
		rk, ok := risks[i.ID]
		if ok {
			o = append(o, rk.kvs()...)
		}
		rows = append(rows, row{o, rk.Risk, i.Name})
	}
	sort.SliceStable(rows, func(x, y int) bool {
		if rows[x].risk != rows[y].risk {
			return rows[x].risk > rows[y].risk
		}
		return rows[x].name < rows[y].name
	})
	out := make([]ojson.Object, len(rows))
	for i, rw := range rows {
		out[i] = rw.obj
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Server) identityDetail(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("identity_id")
	unusedDays := clampInt(p.queryInt("unused_days", 60, nil, nil))
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	c := a.c
	i, err := getOrNil(c.Identity(id))
	if err != nil {
		return nil, err
	}
	if i == nil {
		return nil, errStatus(http.StatusNotFound, "identity not found")
	}
	eff := a.g.EffectivePermissions(id).Values()
	sort.SliceStable(eff, func(x, y int) bool {
		ex, ey := eff[x], eff[y]
		if ex.System != ey.System {
			return ex.System < ey.System
		}
		if ex.ResourceName != ey.ResourceName {
			return ex.ResourceName < ey.ResourceName
		}
		return ex.Action < ey.Action
	})
	perms := []ojson.Object{}
	for _, ep := range eff {
		paths := make([][]graph.PathStep, len(ep.Paths))
		for k, path := range ep.Paths {
			paths[k] = a.g.DescribePath(path, timeutil.ISOPtr)
		}
		perms = append(perms, ojson.Object{{Key: "perm_key", Value: ep.PermKey}, {Key: "action", Value: ep.Action},
			{Key: "system", Value: ep.System}, {Key: "resource", Value: ep.ResourceName}, {Key: "resource_id", Value: ep.ResourceID},
			{Key: "environment", Value: ep.Environment}, {Key: "tags", Value: nonNil(ep.Tags)}, {Key: "privileged", Value: ep.Privileged},
			{Key: "standing", Value: ep.Standing}, {Key: "usage", Value: a.u.Describe(id, ep.PermID)},
			{Key: "unused", Value: a.u.Unused(id, ep.PermID, unusedDays)}, {Key: "paths", Value: paths}})
	}
	accounts, err := c.IdentityAccounts(id)
	if err != nil {
		return nil, err
	}
	secrets := []nhi.SecretView{}
	for _, ac := range accounts {
		secs, err := c.AccountSecrets(ac.ID)
		if err != nil {
			return nil, err
		}
		for _, sec := range secs {
			secrets = append(secrets, nhi.ViewSecret(sec, ac, a.now))
		}
	}
	grants := []ojson.Object{}
	for _, ag := range a.g.GrantEdgesFromAccounts(id) {
		dst := a.g.Node(ag.Dst)
		grants = append(grants, ojson.Object{{Key: "edge_id", Value: ag.Edge.EdgeID}, {Key: "src", Value: ag.Acct},
			{Key: "dst", Value: ag.Dst}, {Key: "label", Value: a.g.Label(ag.Dst)}, {Key: "account", Value: a.g.Label(ag.Acct)},
			{Key: "relation", Value: ag.Edge.Relation}, {Key: "source", Value: ag.Edge.Source},
			{Key: "expires_at", Value: timeutil.ISOPtr(ag.Edge.ExpiresAt)}, {Key: "privileged", Value: dst != nil && dst.Privileged}})
	}
	people, _, err := c.IdentityMap()
	if err != nil {
		return nil, err
	}
	dels, err := c.Delegations()
	if err != nil {
		return nil, err
	}
	delegations := []ojson.Object{}
	for _, d := range dels {
		if d.AgentID != id && d.PrincipalID != id {
			continue
		}
		delegations = append(delegations, ojson.Object{{Key: "agent", Value: brief(people[d.AgentID])},
			{Key: "principal", Value: brief(people[d.PrincipalID])}, {Key: "scopes", Value: d.Scopes}})
	}
	owned, err := c.IdentitiesOwnedBy(id)
	if err != nil {
		return nil, err
	}
	ownedOut := []any{}
	for _, o := range owned {
		ownedOut = append(ownedOut, brief(o))
	}
	viols, err := a.violations()
	if err != nil {
		return nil, err
	}
	myViols := []policy.Violation{}
	for _, v := range viols {
		if v.IdentityID != nil && *v.IdentityID == id {
			myViols = append(myViols, v)
		}
	}
	recs := []leastpriv.Recommendation{}
	if i.Status == "active" {
		recs = leastpriv.GrantRecommendations(a.g, a.u, unusedDays, &id)
	}
	_, risks, err := a.riskScores(unusedDays)
	if err != nil {
		return nil, err
	}
	var riskOut any
	if rk, ok := risks[id]; ok {
		riskOut = rk.kvs()
	}
	var manager, owner any
	if i.ManagerID != nil {
		manager = brief(people[*i.ManagerID])
	}
	if i.OwnerID != nil {
		owner = brief(people[*i.OwnerID])
	}
	acctOut := []ojson.Object{}
	for _, ac := range accounts {
		acctOut = append(acctOut, ojson.Object{{Key: "id", Value: ac.ID}, {Key: "system", Value: ac.System},
			{Key: "username", Value: ac.Username}, {Key: "kind", Value: ac.Kind}, {Key: "status", Value: ac.Status},
			{Key: "last_login_at", Value: timeutil.ISOPtr(ac.LastLoginAt)}})
	}
	return append(briefObj(i),
		ojson.KV{Key: "email", Value: i.Email}, ojson.KV{Key: "description", Value: i.Description},
		ojson.KV{Key: "hired_at", Value: timeutil.ISOPtr(i.HiredAt)}, ojson.KV{Key: "terminated_at", Value: timeutil.ISOPtr(i.TerminatedAt)},
		ojson.KV{Key: "manager", Value: manager}, ojson.KV{Key: "owner", Value: owner},
		ojson.KV{Key: "accounts", Value: acctOut}, ojson.KV{Key: "grants", Value: grants},
		ojson.KV{Key: "effective_permissions", Value: perms}, ojson.KV{Key: "violations", Value: myViols},
		ojson.KV{Key: "recommendations", Value: recs}, ojson.KV{Key: "secrets", Value: secrets},
		ojson.KV{Key: "delegations", Value: delegations}, ojson.KV{Key: "owned_identities", Value: ownedOut},
		ojson.KV{Key: "risk", Value: riskOut}), nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Server) listAccounts(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	system := p.queryOptStr("system")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	if !nonEmpty(system) {
		system = nil
	}
	accts, err := c.AccountsBySystemUsername(system)
	if err != nil {
		return nil, err
	}
	people, _, err := c.IdentityMap()
	if err != nil {
		return nil, err
	}
	out := []ojson.Object{}
	for _, ac := range accts {
		var ident any
		if ac.IdentityID != nil {
			ident = brief(people[*ac.IdentityID])
		}
		out = append(out, ojson.Object{{Key: "id", Value: ac.ID}, {Key: "system", Value: ac.System},
			{Key: "username", Value: ac.Username}, {Key: "kind", Value: ac.Kind}, {Key: "status", Value: ac.Status},
			{Key: "created_at", Value: timeutil.ISOPtr(ac.CreatedAt)}, {Key: "last_login_at", Value: timeutil.ISOPtr(ac.LastLoginAt)},
			{Key: "identity", Value: ident}})
	}
	return out, nil
}

func (s *Server) listGroups(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	req := p.queryOptBool("requestable")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	groups, err := store.TxFrom(r.Context()).GroupsBySystemName(req)
	if err != nil {
		return nil, err
	}
	out := []ojson.Object{}
	for _, g := range groups {
		out = append(out, ojson.Object{{Key: "id", Value: g.ID}, {Key: "key", Value: graph.Key("group", g.ID)},
			{Key: "system", Value: g.System}, {Key: "name", Value: g.Name}, {Key: "kind", Value: g.Kind},
			{Key: "privileged", Value: g.Privileged}, {Key: "requestable", Value: g.Requestable},
			{Key: "description", Value: g.Description}})
	}
	return out, nil
}

func (s *Server) listResources(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	res, err := a.c.ResourcesBySystemName()
	if err != nil {
		return nil, err
	}
	out := []ojson.Object{}
	for _, rs := range res {
		who, _ := a.g.WhoCanAccess(rs.ID)
		types := newCounter()
		for _, iid := range who {
			types.add(a.g.Node(graph.Key("identity", iid)).Type, 1)
		}
		out = append(out, ojson.Object{{Key: "id", Value: rs.ID}, {Key: "system", Value: rs.System},
			{Key: "name", Value: rs.Name}, {Key: "kind", Value: rs.Kind}, {Key: "environment", Value: rs.Environment},
			{Key: "tags", Value: nonNil(rs.Tags)}, {Key: "identities_with_access", Value: len(who)},
			{Key: "by_type", Value: types.object()}})
	}
	return out, nil
}

// ---------------------------------------------------------------- graph

func optString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Server) graphView(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	identityID, resourceID, permKey := p.queryOptInt("identity_id"), p.queryOptInt("resource_id"), p.queryOptStr("perm_key")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	g := a.g
	nodes := map[string]bool{}
	edges := map[[2]string]bool{}
	addPath := func(path []string) {
		for i, k := range path {
			nodes[k] = true
			if i > 0 {
				edges[[2]string{path[i-1], k}] = true
			}
		}
	}
	switch {
	case identityID != nil:
		start := graph.Key("identity", *identityID)
		if n := g.Node(start); n == nil || n.Kind == "" {
			// Unknown here, or another tenant's: the same answer either way.
			return nil, errStatus(http.StatusNotFound, "identity not found")
		}
		nodes[start] = true
		eff := g.EffectivePermissions(*identityID)
		for _, pk := range eff.Keys {
			if nonEmpty(permKey) && pk != *permKey {
				continue
			}
			ep := eff.M[pk]
			for _, path := range ep.Paths {
				addPath(append(slices.Clone(path), graph.Key("resource", ep.ResourceID)))
			}
		}
		for _, acct := range g.Successors(start) {
			nodes[acct] = true
			edges[[2]string{start, acct}] = true
		}
	case resourceID != nil:
		res := graph.Key("resource", *resourceID)
		if n := g.Node(res); n == nil || n.Kind == "" {
			return nil, errStatus(http.StatusNotFound, "resource not found")
		}
		nodes[res] = true
		ids, who := g.WhoCanAccess(*resourceID)
		for _, iid := range ids {
			for _, ep := range who[iid] {
				for k, path := range ep.Paths {
					if k == 3 {
						break
					}
					addPath(append(slices.Clone(path), res))
				}
			}
		}
	default:
		return nil, errStatus(http.StatusBadRequest, "identity_id or resource_id is required")
	}
	keys := make([]string, 0, len(nodes))
	for k := range nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	nodeOut := []ojson.Object{}
	for _, k := range keys {
		n := g.Node(k)
		if n == nil || n.Kind == "" {
			return nil, fmt.Errorf("graph: unknown node %s", k)
		}
		var tags any = []string{}
		if len(n.Tags) > 0 {
			tags = n.Tags
		}
		nodeOut = append(nodeOut, ojson.Object{{Key: "id", Value: k}, {Key: "kind", Value: n.Kind}, {Key: "label", Value: n.Label},
			{Key: "system", Value: optString(n.System)}, {Key: "privileged", Value: n.Privileged}, {Key: "type", Value: optString(n.Type)},
			{Key: "status", Value: optString(n.Status)}, {Key: "tags", Value: tags}, {Key: "environment", Value: n.Environment}})
	}
	ek := make([][2]string, 0, len(edges))
	for e := range edges {
		ek = append(ek, e)
	}
	sort.Slice(ek, func(i, j int) bool {
		if ek[i][0] != ek[j][0] {
			return ek[i][0] < ek[j][0]
		}
		return ek[i][1] < ek[j][1]
	})
	edgeOut := []ojson.Object{}
	for _, e := range ek {
		var rel, src, eid any
		if d := g.EdgeData(e[0], e[1]); d != nil {
			rel, src, eid = d.Relation, d.Source, d.EdgeID
		}
		edgeOut = append(edgeOut, ojson.Object{{Key: "source", Value: e[0]}, {Key: "target", Value: e[1]},
			{Key: "relation", Value: rel}, {Key: "source_kind", Value: src}, {Key: "edge_id", Value: eid}})
	}
	return ojson.Object{{Key: "nodes", Value: nodeOut}, {Key: "edges", Value: edgeOut}}, nil
}

// ---------------------------------------------------------------- NHI

func (s *Server) nhiInventory(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	typ := p.queryOptLiteral("type", []string{"service", "ai_agent"})
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	items, err := nhi.Inventory(a.c, a.g, a.u)
	if err != nil {
		return nil, err
	}
	out := []nhi.Item{}
	for _, it := range items {
		if typ == nil || it.Type == *typ {
			out = append(out, it)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- least privilege

func (s *Server) recommendations(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	days := clampInt(p.queryInt("unused_days", 60, i64(1), i64(90)))
	kind, itype := p.queryOptStr("kind"), p.queryOptStr("identity_type")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	recs := append(leastpriv.GrantRecommendations(a.g, a.u, days, nil), leastpriv.RoleTrimRecommendations(a.g, a.u, days, 2)...)
	leastpriv.SortByScore(recs)
	out := []leastpriv.Recommendation{}
	for _, rec := range recs {
		if nonEmpty(kind) && rec.Kind != *kind {
			continue
		}
		if nonEmpty(itype) && rec.IdentityType != *itype {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// revokeFields: the actor comes from the authenticated principal (design
// §16.2); the former body field "actor" is gone and, like any unknown
// field, refused.
var revokeFields = []field{
	{name: "edge_id", kind: kInt, required: true},
	{name: "dry_run", kind: kBool, def: true},
}

type grantRef struct {
	EdgeID int64  `json:"edge_id"`
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Label  string `json:"label"`
}

type revokeResult struct {
	*simulate.Result
	DryRun  bool     `json:"dry_run"`
	Grant   grantRef `json:"grant"`
	Applied *bool    `json:"applied,omitempty"`
	// Provisioning is set when the revoke went to the target system through
	// the provisioning engine (write-back on): applied is false until a
	// re-read of the target confirms it, and the edge stays until then.
	Provisioning *provisioningRef `json:"provisioning,omitempty"`
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	body, berrs, err := bodyModel(r, revokeFields, true)
	if err != nil {
		return nil, err
	}
	if err := validated(p, berrs); err != nil {
		return nil, err
	}
	return s.revokeEdge(r, body["edge_id"].(int64), body["dry_run"].(bool))
}

// revokeEdge dry-runs or applies the revoke of one grant: applying needs
// grants.revoke and a fresh phishing-resistant sign-in (checked here because
// the requirement depends on the body, §16.2), a dry run only graph.read.
func (s *Server) revokeEdge(r *http.Request, edgeID int64, dryRun bool) (any, error) {
	pr := principal(r)
	if !dryRun {
		// Applying a revoke needs grants.revoke and a fresh phishing-resistant
		// sign-in; a dry run needs only graph.read (the route's permission).
		// Checked here because the requirement depends on the body (§16.2).
		d, err := s.accessCheck(r.Context(), r, store.TxFrom(r.Context()), pr, auth.PermGrantsRevoke, &auth.StepUpPolicy,
			"POST /api/least-privilege/revoke")
		if err != nil {
			return nil, err
		}
		if d != nil {
			// answered here, not as an error: the transaction commits, so the
			// access.decision event of a conditional access refusal is kept
			return deniedBody{d}, nil
		}
	}
	c := store.TxFrom(r.Context())
	a, err := s.newAnalysis(c)
	if err != nil {
		return nil, err
	}
	e, err := getOrNil(c.Edge(edgeID))
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, errStatus(http.StatusNotFound, "grant not found")
	}
	if !dryRun && (e.Outcome == graph.OutcomeConditional || e.Fidelity == graph.FidelityApprox || e.Fidelity == graph.FidelityUnsupp) {
		// least privilege never acts on a grant the evaluator found conditional,
		// approximate or unsupported (design §11.5, spec R2)
		return nil, errStatus(http.StatusConflict, "this grant rests on a conditional or approximate evaluation; review it by hand")
	}
	res, err := simulate.Run(c, simulate.Request{RemoveEdgeIDs: []int64{edgeID}},
		simulate.Inputs{Now: a.now, Policies: a.policies, Usage: a.u, Base: a.g})
	if err != nil {
		return nil, err
	}
	out := &revokeResult{Result: res, DryRun: dryRun,
		Grant: grantRef{e.ID, e.Src, e.Dst, a.g.Label(e.Src) + " → " + a.g.Label(e.Dst)}}
	if dryRun {
		return out, nil
	}
	if op, err := routeGrantRevoke(c, a.now, e, out.Grant.Label, res.Summary.PermissionsRemoved); err != nil {
		return nil, err
	} else if op != nil {
		applied := false
		out.Applied, out.Provisioning = &applied, refOf(op)
		return out, nil
	}
	if err := c.Audit(a.now, pr.Display, "grant.revoke", ojson.Object{{Key: "edge_id", Value: e.ID},
		{Key: "grant", Value: out.Grant.Label}, {Key: "permissions_removed", Value: res.Summary.PermissionsRemoved}}); err != nil {
		return nil, err
	}
	if err := flatfile.GrantRevoked(c, a.now, pr.Display, e.ID, "revoke"); err != nil {
		return nil, err
	}
	if err := c.RevokeEdge(e.ID, a.now, "least-privilege"); err != nil {
		return nil, err
	}
	applied := true
	out.Applied = &applied
	return out, nil
}

// ---------------------------------------------------------------- policies

func (s *Server) listPolicies(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	viols, err := a.violations()
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, v := range viols {
		counts[v.PolicyID]++
	}
	files, err := s.policies()
	if err != nil {
		return nil, err
	}
	listed := map[string]bool{}
	for _, pol := range files {
		listed[pol.ID] = true
	}
	shown := append([]*policy.Policy{}, files...)
	for _, pol := range a.policies { // SoD risks that no policy file defines
		if pol.Type == policy.TypeSoDRisk && !listed[pol.ID] {
			shown = append(shown, pol)
		}
	}
	out := []ojson.Object{}
	for _, pol := range shown {
		typ, src := pol.Type, pol.Source
		if typ == policy.TypeSoDRisk {
			typ, src = "separation_of_duties", "managed as a risk in Policies & SoD (not a policy file)"
		}
		out = append(out, ojson.Object{{Key: "id", Value: pol.ID}, {Key: "name", Value: pol.Name}, {Key: "type", Value: typ},
			{Key: "severity", Value: pol.Severity}, {Key: "description", Value: pol.Description}, {Key: "enabled", Value: pol.Enabled},
			{Key: "source", Value: src}, {Key: "violations", Value: counts[pol.ID]}})
	}
	return out, nil
}

func (s *Server) listViolations(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	pid := p.queryOptStr("policy_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	viols, err := a.violations()
	if err != nil {
		return nil, err
	}
	out := []policy.Violation{}
	for _, v := range viols {
		if pid == nil || v.PolicyID == *pid {
			out = append(out, v)
		}
	}
	return out, nil
}

var edgeFields = []field{
	{name: "src", kind: kStr, required: true},
	{name: "dst", kind: kStr, required: true},
	{name: "relation", kind: kStr, def: "member_of"},
	{name: "duration_hours", kind: kFloat, nullable: true, def: nil}, // set: a time-boxed JIT grant, never standing access
}

var simulateFields = []field{
	{name: "remove_edge_ids", kind: kIntList, def: []int64{}},
	{name: "add_edges", kind: kModelList, model: edgeFields, def: []map[string]any{}},
	{name: "disable_account_ids", kind: kIntList, def: []int64{}},
}

func (s *Server) simulate(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	body, berrs, err := bodyModel(r, simulateFields, true)
	if err != nil {
		return nil, err
	}
	if err := validated(p, berrs); err != nil {
		return nil, err
	}
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	req := simulate.Request{RemoveEdgeIDs: body["remove_edge_ids"].([]int64),
		DisableAccountIDs: body["disable_account_ids"].([]int64)}
	for _, e := range body["add_edges"].([]map[string]any) {
		src, dst, rel := e["src"].(string), e["dst"].(string), e["relation"].(string)
		for _, k := range []string{src, dst} {
			if !a.g.HasNode(k) {
				return nil, errStatus(http.StatusBadRequest, "unknown node "+k)
			}
		}
		if kind, _, _ := strings.Cut(src, ":"); kind != "account" && kind != "group" {
			return nil, errStatus(http.StatusBadRequest, "edges must start at an account or group")
		}
		ae := simulate.AddEdge{Src: src, Dst: dst, Relation: rel}
		if h, ok := e["duration_hours"].(float64); ok {
			if h <= 0 {
				return nil, errStatus(http.StatusBadRequest, "duration_hours must be positive")
			}
			exp := a.now.Add(time.Duration(h * float64(time.Hour)))
			ae.ExpiresAt = &exp
		}
		req.AddEdges = append(req.AddEdges, ae)
	}
	res, err := simulate.Run(a.c, req, simulate.Inputs{Now: a.now, Policies: a.policies, Usage: a.u, Base: a.g})
	var une *graph.UnknownNodeError
	if errors.As(err, &une) {
		return nil, errStatus(http.StatusBadRequest, une.Msg)
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------- JIT

func reqView(c *store.TenantTx, r *store.AccessRequest, hours any) (ojson.Object, error) {
	ident, err := getOrNil(c.Identity(r.IdentityID))
	if err != nil {
		return nil, err
	}
	g, err := c.Group(r.GroupID)
	if err != nil {
		return nil, err
	}
	a, err := c.Account(r.AccountID)
	if err != nil {
		return nil, err
	}
	if hours == nil {
		hours = ojson.Float(r.DurationHours)
	}
	return ojson.Object{{Key: "id", Value: r.ID}, {Key: "identity", Value: brief(ident)},
		{Key: "group", Value: ojson.Object{{Key: "id", Value: g.ID}, {Key: "name", Value: g.Name}, {Key: "system", Value: g.System},
			{Key: "privileged", Value: g.Privileged}}},
		{Key: "account", Value: a.System + ":" + a.Username}, {Key: "justification", Value: r.Justification},
		{Key: "duration_hours", Value: hours}, {Key: "status", Value: r.Status},
		{Key: "requested_at", Value: timeutil.ISO(r.RequestedAt)}, {Key: "decided_at", Value: timeutil.ISOPtr(r.DecidedAt)},
		{Key: "decided_by", Value: r.DecidedBy}, {Key: "expires_at", Value: timeutil.ISOPtr(r.ExpiresAt)}}, nil
}

func (s *Server) jitRequests(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c := store.TxFrom(r.Context())
	reqs, err := c.RequestsByRecency()
	if err != nil {
		return nil, err
	}
	out := []ojson.Object{}
	for _, rq := range reqs {
		v, err := reqView(c, rq, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

var jitFields = []field{
	{name: "identity_id", kind: kInt, required: true},
	{name: "group_id", kind: kInt, required: true},
	{name: "duration_hours", kind: kFloat, def: nil},
	{name: "justification", kind: kStr, required: true},
}

func asJitError(err error) error {
	var je *jit.Error
	if !errors.As(err, &je) {
		return err
	}
	status := http.StatusBadRequest
	switch {
	case je.Kind == jit.KindNotFound:
		status = http.StatusNotFound
	case je.Kind == jit.KindConflict:
		status = http.StatusConflict
	case je.Code != "":
		status = http.StatusUnprocessableEntity // a field-specific refusal, like badRequest
	}
	if je.Code != "" {
		return &readiness.Error{Status: status, Code: je.Code, Msg: je.Msg}
	}
	return errStatus(status, je.Msg)
}

func (s *Server) jitCreate(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	body, berrs, err := bodyModel(r, jitFields, true)
	if err != nil {
		return nil, err
	}
	if err := validated(p, berrs); err != nil {
		return nil, err
	}
	hours := jit.Hours{N: 4, Whole: true} // the default is not validated, so it stays an int
	if v, ok := body["duration_hours"].(float64); ok {
		hours = jit.Hours{N: v}
	}
	c := store.TxFrom(r.Context())
	rq, err := jit.CreateRequest(c, s.clock(), body["identity_id"].(int64), body["group_id"].(int64), hours,
		body["justification"].(string), principal(r).User())
	if err != nil {
		return nil, asJitError(err)
	}
	return reqView(c, rq, hours.JSON())
}

// decisionFields is the (optional) body of a JIT decision: empty. The
// former "approver" field is gone (the decider is the authenticated
// principal, design §16.2) and, like any unknown field, refused.
var decisionFields = []field{}

// jitDecide serves one of the three JIT decision routes.
func (s *Server) jitDecide(action string) handlerFunc {
	return func(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
		id := p.pathInt("request_id")
		_, berrs, err := bodyModel(r, decisionFields, false)
		if err != nil {
			return nil, err
		}
		if err := validated(p, berrs); err != nil {
			return nil, err
		}
		by := principal(r).User()
		c := store.TxFrom(r.Context())
		now := s.clock()
		var rq *store.AccessRequest
		switch action {
		case "approve":
			rq, err = jit.Approve(c, id, by, now, now)
		case "deny":
			rq, err = jit.Deny(c, id, by, now)
		default:
			rq, err = jit.Revoke(c, id, by, now)
		}
		if errors.Is(err, jit.ErrSelfApproval) || errors.Is(err, jit.ErrApproverUnlinked) {
			code, msg := "self_approval", "You cannot approve your own request; another approver must decide it."
			if errors.Is(err, jit.ErrApproverUnlinked) {
				code, msg = "approver_unlinked", "Your account is not linked to an identity, so it cannot approve requests. Ask an administrator to link it."
			}
			// nothing changed; the refusal itself is evidence of the control
			if err := c.Audit(now, by.Display, "jit.approve.refused", ojson.Object{{Key: "request_id", Value: id},
				{Key: "reason", Value: code}}); err != nil {
				return nil, err
			}
			return statusBody{http.StatusForbidden, ojson.Object{{Key: "error", Value: code},
				{Key: "detail", Value: msg}}}, nil
		}
		if err != nil {
			return nil, asJitError(err)
		}
		return reqView(c, rq, nil)
	}
}

func (s *Server) jitSweep(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	n, err := jit.Sweep(store.TxFrom(r.Context()), s.clock())
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "expired", Value: n}}, nil
}

// ---------------------------------------------------------------- reviews

func campaignView(c *store.TenantTx, cmp *store.ReviewCampaign, withItems bool) (ojson.Object, error) {
	items, err := c.CampaignItems(cmp.ID)
	if err != nil {
		return nil, err
	}
	decided, revoked := 0, 0
	reasons := newCounter()
	for _, it := range items {
		if it.Decision != nil && *it.Decision != "" {
			decided++
		}
		if it.Decision != nil && *it.Decision == "revoke" {
			revoked++
		}
		for _, rs := range it.Reasons {
			reasons.add(rs, 1)
		}
	}
	out := ojson.Object{{Key: "id", Value: cmp.ID}, {Key: "name", Value: cmp.Name}, {Key: "status", Value: cmp.Status},
		{Key: "created_at", Value: timeutil.ISO(cmp.CreatedAt)}, {Key: "unused_days", Value: cmp.UnusedDays},
		{Key: "total_grants", Value: cmp.TotalGrants}, {Key: "auto_certified", Value: cmp.AutoCertified},
		{Key: "items", Value: len(items)}, {Key: "decided", Value: decided}, {Key: "revoked", Value: revoked},
		{Key: "reasons", Value: reasons.object()}}
	if withItems {
		people, _, err := c.IdentityMap()
		if err != nil {
			return nil, err
		}
		rows := []ojson.Object{}
		memberships, err := membershipViews(c, cmp.ID)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			var reviewer any
			if it.ReviewerID != nil {
				reviewer = brief(people[*it.ReviewerID])
			}
			row := ojson.Object{{Key: "id", Value: it.ID}, {Key: "identity", Value: brief(people[it.IdentityID])},
				{Key: "grant", Value: it.GrantLabel}, {Key: "edge_id", Value: it.EdgeID}, {Key: "reasons", Value: it.Reasons},
				{Key: "context", Value: it.Context}, {Key: "reviewer", Value: reviewer}, {Key: "decision", Value: it.Decision},
				{Key: "comment", Value: it.Comment}, {Key: "decided_at", Value: timeutil.ISOPtr(it.DecidedAt)}}
			if m, ok := memberships[it.ID]; ok { // a role membership item (issue #214)
				row = append(row, m...)
			}
			rows = append(rows, row)
		}
		out = append(out, ojson.KV{Key: "review_items", Value: rows})
	}
	return out, nil
}

func (s *Server) listCampaigns(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c := store.TxFrom(r.Context())
	cmps, err := c.CampaignsNewestFirst()
	if err != nil {
		return nil, err
	}
	out := []ojson.Object{}
	for _, cmp := range cmps {
		v, err := campaignView(c, cmp, false)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

var campaignFields = []field{
	{name: "name", kind: kStr, def: "Exception-only review"},
	{name: "unused_days", kind: kInt, def: int64(60)},
}

// Campaign input bounds. The unused-days range matches readiness stale_days
// (1 to 3650); the name cap matches maxFilterLen.
const (
	maxCampaignName       = 200
	minCampaignUnusedDays = 1
	maxCampaignUnusedDays = 3650
)

// checkCampaign applies the semantic rules the field kinds cannot express and
// returns the trimmed name. Errors are pydantic-style items with field-specific
// types, at loc ["body", field].
func checkCampaign(body map[string]any) (string, int64, []verr) {
	var errs []verr
	raw := body["name"].(string)
	name := strings.TrimSpace(raw)
	switch n := utf8.RuneCountInString(name); {
	case n == 0:
		errs = append(errs, verr{Type: "string_too_short", Loc: []any{"body", "name"},
			Msg: "String should have at least 1 character", Input: raw, Ctx: ojson.Object{{Key: "min_length", Value: 1}}})
	case n > maxCampaignName:
		errs = append(errs, verr{Type: "string_too_long", Loc: []any{"body", "name"},
			Msg: fmt.Sprintf("String should have at most %d characters", maxCampaignName), Input: raw,
			Ctx: ojson.Object{{Key: "max_length", Value: maxCampaignName}}})
	}
	days := body["unused_days"].(int64)
	switch {
	case days < minCampaignUnusedDays:
		errs = append(errs, verr{Type: "greater_than_equal", Loc: []any{"body", "unused_days"},
			Msg:   fmt.Sprintf("Input should be greater than or equal to %d", minCampaignUnusedDays),
			Input: days, Ctx: ojson.Object{{Key: "ge", Value: minCampaignUnusedDays}}})
	case days > maxCampaignUnusedDays:
		errs = append(errs, verr{Type: "less_than_equal", Loc: []any{"body", "unused_days"},
			Msg:   fmt.Sprintf("Input should be less than or equal to %d", maxCampaignUnusedDays),
			Input: days, Ctx: ojson.Object{{Key: "le", Value: maxCampaignUnusedDays}}})
	}
	return name, days, errs
}

func (s *Server) createCampaign(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	body, berrs, err := bodyModel(r, campaignFields, true)
	if err != nil {
		return nil, err
	}
	name, days := "", int64(0)
	if len(berrs) == 0 {
		var cerrs []verr
		name, days, cerrs = checkCampaign(body)
		berrs = append(berrs, cerrs...)
	}
	if err := validated(p, berrs); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	pols, err := s.effectivePolicies(c)
	if err != nil {
		return nil, err
	}
	id, err := reviews.GenerateCampaign(c, s.clock(), name, clampInt(days), pols)
	if err != nil {
		return nil, err
	}
	// the reviewers are told in the same transaction (issue #189); seeding calls
	// GenerateCampaign directly and tells no one
	if err := notify.ReviewLaunched(c, s.clock(), id); err != nil {
		return nil, err
	}
	cmp, err := c.Campaign(id)
	if err != nil {
		return nil, err
	}
	return campaignView(c, cmp, false)
}

func (s *Server) campaign(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("campaign_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	cmp, err := getOrNil(c.Campaign(id))
	if err != nil {
		return nil, err
	}
	if cmp == nil {
		return nil, errStatus(http.StatusNotFound, "campaign not found")
	}
	return campaignView(c, cmp, true)
}

// reviewDecisionFields: the reviewer is the authenticated principal; the
// former "reviewer" field is gone (design §16.2) and refused.
var reviewDecisionFields = []field{
	{name: "decision", kind: kLiteral, required: true, lits: []string{"keep", "revoke"}},
	{name: "comment", kind: kStr, nullable: true, def: nil},
	// revoking a rule membership: exclude the person from the rule, or flag it to the role owner (issue #214)
	{name: "rule_action", kind: kLiteral, nullable: true, def: nil, lits: []string{"exclude", "flag"}},
	// the answers to the campaign's questionnaire: question id -> value (issue #298)
	{name: "answers", kind: kDict, nullable: true, def: nil},
}

func (s *Server) reviewDecide(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("item_id")
	body, berrs, err := bodyModel(r, reviewDecisionFields, true)
	if err != nil {
		return nil, err
	}
	if err := validated(p, berrs); err != nil {
		return nil, err
	}
	var comment *string
	if v, ok := body["comment"].(string); ok {
		comment = &v
		if utf8.RuneCountInString(v) > reviews.MaxCommentRunes {
			return nil, &validationError{[]verr{{Type: "string_too_long", Loc: []any{"body", "comment"},
				Msg:   fmt.Sprintf("String should have at most %d characters", reviews.MaxCommentRunes),
				Input: v, Ctx: ojson.Object{{Key: "max_length", Value: reviews.MaxCommentRunes}}}}}
		}
	}
	choice, _ := body["rule_action"].(string)
	checked, err := reviewAnswers(store.TxFrom(r.Context()), id, body["answers"])
	if err != nil {
		return nil, err
	}
	it, resolution, err := reviews.DecideItem(store.TxFrom(r.Context()), s.clock(), id, body["decision"].(string), principal(r).User(), comment, choice)
	if errors.Is(err, reviews.ErrUnknownItem) {
		return nil, errStatus(http.StatusNotFound, "unknown review item")
	}
	if body, ok, aerr := s.refusedDecision(r, err, "item_id", id); ok {
		return body, aerr
	}
	var re *reviews.Error
	if errors.As(err, &re) {
		return nil, errStatus(http.StatusBadRequest, re.Msg)
	}
	var ce *reviews.ChoiceRequiredError
	if errors.As(err, &ce) {
		return nil, errStatus(http.StatusUnprocessableEntity, ce.Error())
	}
	var de *reviews.DecidedError
	if errors.As(err, &de) {
		// nothing changed; the refusal itself is evidence of the control
		// (returned as a body, not an error, so the audit event commits)
		by := principal(r).User()
		det := ojson.Object{{Key: "item_id", Value: de.ItemID}, {Key: "current", Value: de.Current},
			{Key: "requested", Value: de.Requested}, {Key: "reason", Value: "review_item_decided"}}
		if comment != nil && *comment != "" {
			det = append(det, ojson.KV{Key: "comment", Value: *comment})
		}
		if _, err := store.TxFrom(r.Context()).RecordAudit(store.AuditRecord{At: s.clock(), Action: "review.decide.refused",
			LegacyActor: by.Display, Detail: det, TargetType: reviews.TargetType,
			TargetID: strconv.FormatInt(de.ItemID, 10)}); err != nil {
			return nil, err
		}
		return statusBody{http.StatusConflict, ojson.Object{{Key: "error", Value: "review_item_decided"},
			{Key: "detail", Value: "This review item was already decided as " + de.Current + "; a decision is final."},
			{Key: "decision", Value: de.Current}}}, nil
	}
	if err != nil {
		return nil, reqErr(err) // a refusal of the role service keeps its status and code
	}
	if len(checked) > 0 { // the reviewer's answers, with their hash in the audit ledger (issue #298)
		tx, by, now := store.TxFrom(r.Context()), principal(r).User(), s.clock()
		if err := questionnaires.Record(tx, store.QSubjectReviewItem, strconv.FormatInt(id, 10), checked, by.Display, now); err != nil {
			return nil, err
		}
		if err := tx.Audit(now, by.Display, "review.answers", ojson.Object{{Key: "item_id", Value: id},
			{Key: "decision", Value: body["decision"]}, {Key: "questionnaires", Value: questionnaires.AuditDetail(checked)}}); err != nil {
			return nil, err
		}
	}
	out := ojson.Object{{Key: "id", Value: it.ID}, {Key: "decision", Value: it.Decision}}
	if resolution != "" { // a role membership: what the revoke did
		out = append(out, ojson.KV{Key: "resolution", Value: resolution})
	}
	return out, nil
}

// ---------------------------------------------------------------- HRIS / JML

func (s *Server) hrisEvents(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c := store.TxFrom(r.Context())
	evs, err := c.HrisEventsForUI()
	if err != nil {
		return nil, err
	}
	out := []jml.EventView{}
	for _, ev := range evs {
		v, err := jml.ViewEvent(c, ev)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

var hrisFields = []field{
	{name: "type", kind: kLiteral, required: true, lits: []string{"joiner", "mover", "leaver"}},
	{name: "identity_id", kind: kInt, nullable: true, def: nil},
	{name: "payload", kind: kDict, def: ojson.Object{}},
}

// truthy mirrors Python truthiness for decoded JSON values.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case ojson.Object:
		return len(x) > 0
	case []any:
		return len(x) > 0
	case fmt.Stringer: // json.Number
		f := x.String()
		return strings.Trim(strings.TrimLeft(f, "-+"), "0.eE+-") != ""
	}
	return true
}

// pyTimestamp is int(naive_datetime.timestamp()): Python interprets a naive
// datetime in the host's local time zone.
func pyTimestamp(t time.Time) int64 {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.Local).Unix()
}

func (s *Server) hrisCreate(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	body, berrs, err := bodyModel(r, hrisFields, true)
	if err != nil {
		return nil, err
	}
	if err := validated(p, berrs); err != nil {
		return nil, err
	}
	typ := body["type"].(string)
	payload := body["payload"].(ojson.Object)
	var identityID *int64
	if v, ok := body["identity_id"].(int64); ok {
		identityID = &v
	}
	if (typ == "mover" || typ == "leaver") && identityID == nil {
		return nil, errStatus(http.StatusBadRequest, "identity_id required")
	}
	if name, _ := payload.Get("name"); typ == "joiner" && !truthy(name) {
		return nil, errStatus(http.StatusBadRequest, "payload.name required")
	}
	if team, _ := payload.Get("to_team"); typ == "mover" && !truthy(team) {
		return nil, errStatus(http.StatusBadRequest, "payload.to_team required")
	}
	c := store.TxFrom(r.Context())
	if typ == "joiner" {
		// Refuse at creation what execution would refuse; execution re-checks.
		var ex *jml.ExistsError
		if err := jml.CheckJoiner(c, payload); errors.As(err, &ex) {
			return s.joinerRefused(c, "create", nil, ex, principal(r).User())
		} else if err != nil {
			return nil, err
		}
	}
	if identityID != nil {
		// An event for an identity that does not exist could never be planned or executed.
		if ident, err := getOrNil(c.Identity(*identityID)); err != nil {
			return nil, err
		} else if ident == nil {
			return nil, &validationError{[]verr{{Type: "value_error", Loc: []any{"body", "identity_id"},
				Msg: fmt.Sprintf("Value error, unknown identity %d", *identityID), Input: *identityID}}}
		}
	}
	now := s.clock()
	n, err := c.CountHrisEvents()
	if err != nil {
		return nil, err
	}
	id, err := c.InsertHrisEvent(&store.HrisEvent{ExternalID: fmt.Sprintf("sim-evt-%d-%d", n+1, pyTimestamp(now)), Type: typ,
		IdentityID: identityID, Payload: payload, EffectiveAt: now, Status: "pending"})
	if err != nil {
		return nil, err
	}
	ev, err := c.HrisEvent(id)
	if err != nil {
		return nil, err
	}
	return jml.ViewEvent(c, ev)
}

// joinerRefused audits a joiner refused because its email or HR id belongs to
// an active identity, and answers 409 identity_exists naming that identity.
// The caller's transaction commits, so nothing else may have been written.
func (s *Server) joinerRefused(c *store.TenantTx, stage string, eventID *int64, ex *jml.ExistsError, by store.UserRef) (any, error) {
	d := ojson.Object{{Key: "stage", Value: stage}, {Key: "existing_identity_id", Value: ex.ExistingID},
		{Key: "matched_on", Value: ex.MatchedOn}, {Key: "reason", Value: "identity_exists"}}
	if eventID != nil {
		d = append(ojson.Object{{Key: "event_id", Value: *eventID}}, d...)
	}
	if err := c.Audit(s.clock(), by.Display, "jml.joiner.refused", d); err != nil {
		return nil, err
	}
	return statusBody{http.StatusConflict, ojson.Object{{Key: "error", Value: "identity_exists"},
		{Key: "detail", Value: ex.Error() + "; use the mover or rehire flow, or the account-match and merge tools."},
		{Key: "existing_identity_id", Value: ex.ExistingID}, {Key: "matched_on", Value: ex.MatchedOn}}}, nil
}

func (s *Server) hrisPlan(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("event_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	pols, err := s.effectivePolicies(c)
	if err != nil {
		return nil, err
	}
	ev, err := getOrNil(c.HrisEvent(id))
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, errStatus(http.StatusNotFound, "event not found")
	}
	view, err := jml.ViewEvent(c, ev)
	if err != nil {
		return nil, err
	}
	var plan any
	if ev.Status != "executed" {
		pl, err := jml.PlanForEvent(c, s.clock(), ev, true, pols)
		var je *jml.Error
		if errors.As(err, &je) { // e.g. an event row left pointing at an identity that no longer exists
			return nil, errStatus(http.StatusConflict, "event cannot be planned: "+je.Msg)
		}
		if err != nil {
			return nil, err
		}
		plan = pl
	}
	return ojson.Object{{Key: "event", Value: view}, {Key: "plan", Value: plan}}, nil
}

func (s *Server) hrisExecute(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("event_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	return s.executeLeaver(r, p, id)
}

func (s *Server) leaverPlan(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	pols, err := s.effectivePolicies(tx)
	if err != nil {
		return nil, err
	}
	plan, err := jml.LeaverPlan(tx, s.clock(), id, true, pols)
	var je *jml.Error
	if errors.As(err, &je) {
		return nil, errStatus(http.StatusNotFound, je.Msg)
	}
	if err != nil {
		return nil, err
	}
	return plan, nil
}

// refusedDecision turns the guard's refusals (self_review, reviewer_unlinked)
// into a 403 body and audits them as review.decide.refused. Nothing changed;
// the refusal itself is evidence of the control, so it is a body, not an error
// (the audit event commits). ok is false for any other error.
func (s *Server) refusedDecision(r *http.Request, err error, key string, id int64) (any, bool, error) {
	var code, msg string
	switch {
	case errors.Is(err, reviews.ErrSelfReview):
		code, msg = "self_review", "You cannot decide a review item about your own access; another reviewer must decide it."
	case errors.Is(err, reviews.ErrReviewerUnlinked):
		code, msg = "reviewer_unlinked", "Your account is not linked to an identity, so it cannot decide reviews. Ask an administrator to link it."
	default:
		return nil, false, nil
	}
	by := principal(r).User()
	if _, aerr := store.TxFrom(r.Context()).RecordAudit(store.AuditRecord{At: s.clock(), Action: "review.decide.refused",
		LegacyActor: by.Display, Detail: ojson.Object{{Key: key, Value: id}, {Key: "reason", Value: code}},
		TargetType: reviews.TargetType, TargetID: strconv.FormatInt(id, 10)}); aerr != nil {
		return nil, true, aerr
	}
	return statusBody{http.StatusForbidden, ojson.Object{{Key: "error", Value: code}, {Key: "detail", Value: msg}}}, true, nil
}
