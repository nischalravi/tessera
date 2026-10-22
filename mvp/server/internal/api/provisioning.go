package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Closed-loop provisioning (issue #103). The routes configure the target
// system of a connection (with its write-back switch) and show, retry and
// cancel the operations the engine runs. Changes to Tessera's own records
// (JML, reviews, JIT, least-privilege revokes) reach the engine through
// provision.Submit in their own packages.

func (s *Server) registerProvisioningRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/provisioning/targets", read, need(auth.PermProvisioningRead), s.rd(s.listTargets))
	// A target holds a credential and decides where Tessera sends changes:
	// connections.manage with step-up, like the connection credential.
	s.handle(http.MethodPut, "/api/provisioning/targets/{id}", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.putTarget))
	s.handle(http.MethodDelete, "/api/provisioning/targets/{id}", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.deleteTarget))
	s.handle(G, "/api/provisioning/ops", read, need(auth.PermProvisioningRead), s.rd(s.listOps))
	s.handle(G, "/api/provisioning/ops/{op_id}", read, need(auth.PermProvisioningRead), s.rd(s.getOp))
	s.handle(P, "/api/provisioning/ops/{op_id}/retry", write, need(auth.PermProvisioningManage), s.rd(s.retryOp))
	s.handle(P, "/api/provisioning/ops/{op_id}/cancel", write, need(auth.PermProvisioningManage), s.rd(s.cancelOp))
	// phased: the run sends requests to targets, so it never holds a
	// transaction open while it waits; the engine opens its own.
	s.handle(P, "/api/provisioning/run", phased, need(auth.PermProvisioningManage), s.rd(s.runProvisioning)).asJob(jobs.Provision, "")
	s.handle(G, "/api/provisioning/findings", read, need(auth.PermProvisioningRead), s.rd(s.listProvFindings))
}

// RunProvisioning runs the provisioning worker every interval until ctx is done.
func (s *Server) RunProvisioning(ctx context.Context, interval time.Duration) {
	s.prov.Loop(ctx, interval)
}

// Provisioning is the engine (tests drive passes with it).
func (s *Server) Provisioning() *provision.Engine { return s.prov }

func provErr(err error) error {
	var pe *provision.Error
	if errors.As(err, &pe) {
		return &readiness.Error{Status: pe.Status, Code: pe.Code, Msg: pe.Msg}
	}
	return err
}

func notFoundErr(what string) error {
	return &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such " + what}
}

// ---------------------------------------------------------------- views

type targetView struct {
	ConnectionID   string  `json:"connection_id"`
	ConnectionName string  `json:"connection_name"`
	System         string  `json:"system"`
	Kind           string  `json:"kind"`
	BaseURL        string  `json:"base_url"`
	Dialect        string  `json:"dialect,omitempty"`
	Fault          string  `json:"fault,omitempty"`
	OnDeprovision  string  `json:"on_deprovision,omitempty"` // "delete": accounts are deleted after the grace period (issue #74)
	AgentID        string  `json:"agent_id,omitempty"`       // the Directory Agent that reaches this target (issue #302)
	WriteBack      bool    `json:"write_back"`
	HasCredential  bool    `json:"has_credential"`
	CredentialVer  *string `json:"credential_version"`
	UpdatedAt      string  `json:"updated_at"`
}

func viewTarget(t *store.ProvTarget, connName string) targetView {
	var st provision.Settings
	_ = json.Unmarshal([]byte(t.Settings), &st)
	return targetView{ConnectionID: t.ConnectionID, ConnectionName: connName, System: t.System, Kind: t.Kind, BaseURL: t.BaseURL,
		Dialect: st.Dialect, Fault: st.Fault, OnDeprovision: st.OnDeprovision, AgentID: st.AgentID, WriteBack: t.WriteBack, HasCredential: len(t.CredentialEnc) > 0,
		CredentialVer: t.CredentialVer, UpdatedAt: timeutil.ISO(t.UpdatedAt)}
}

type opView struct {
	ID             string  `json:"id"`
	ConnectionID   string  `json:"connection_id"`
	ConnectionName string  `json:"connection_name"`
	System         string  `json:"system"`
	Kind           string  `json:"kind"`
	Target         string  `json:"target"`
	Source         string  `json:"source"`
	Status         string  `json:"status"`
	Attempts       int     `json:"attempts"`
	VerifyAttempts int     `json:"verify_attempts"`
	NextAttemptAt  string  `json:"next_attempt_at"`
	LastError      *string `json:"last_error"`
	Observed       *string `json:"observed"`
	RequestedBy    string  `json:"requested_by"`
	Key            string  `json:"idempotency_key"`
	Completion     *string `json:"completion"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
	CompletedAt    *string `json:"completed_at"`
	// SponsorshipID links an operation of a guest's access bundle back to its
	// sponsorship (the key is guest:<sponsorship>:...).
	SponsorshipID *string `json:"sponsorship_id"`
	CanRetry      bool    `json:"can_retry"`
	CanCancel     bool    `json:"can_cancel"`
}

type connInfo struct{ name, system string }

func connNames(c *store.TenantTx) (map[string]connInfo, error) {
	cs, err := c.Connections()
	if err != nil {
		return nil, err
	}
	out := make(map[string]connInfo, len(cs))
	for _, cn := range cs {
		out[cn.ID] = connInfo{cn.Name, cn.System}
	}
	return out, nil
}

func viewOp(o *store.ProvOp, names map[string]connInfo) opView {
	ci := names[o.ConnectionID]
	v := opView{ID: o.ID, ConnectionID: o.ConnectionID, ConnectionName: ci.name, System: ci.system, Kind: o.Kind, Target: o.TargetRef,
		Source: o.Source, Status: o.Status, Attempts: o.Attempts, VerifyAttempts: o.VerifyAttempts,
		NextAttemptAt: timeutil.ISO(o.NextAttemptAt), LastError: o.LastError, Observed: o.Observed, RequestedBy: o.RequestedBy,
		Key: o.IdempotencyKey, CreatedAt: timeutil.ISO(o.CreatedAt), UpdatedAt: timeutil.ISO(o.UpdatedAt),
		CompletedAt: timeutil.ISOPtr(o.CompletedAt),
		CanRetry:    o.Status == provision.Failed || o.Status == provision.Mismatch || o.Status == provision.Cancelled,
		CanCancel:   o.Status == provision.Queued || o.Status == provision.Failed || o.Status == provision.Mismatch}
	if o.Source == provision.SourceGuest {
		if parts := strings.SplitN(o.IdempotencyKey, ":", 3); len(parts) == 3 && parts[0] == "guest" {
			v.SponsorshipID = &parts[1]
		}
	}
	if o.Completion != nil {
		var env struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(*o.Completion), &env) == nil && env.Name != "" {
			v.Completion = &env.Name
		}
	}
	return v
}

type findingView struct {
	ID           string  `json:"id"`
	OpID         string  `json:"op_id"`
	ConnectionID string  `json:"connection_id"`
	Code         string  `json:"code"`
	Severity     string  `json:"severity"`
	Title        string  `json:"title"`
	Expected     string  `json:"expected"`
	Observed     string  `json:"observed"`
	Status       string  `json:"status"`
	CreatedAt    string  `json:"created_at"`
	ResolvedAt   *string `json:"resolved_at"`
}

func viewFinding(f *store.ProvFinding) findingView {
	return findingView{ID: f.ID, OpID: f.OpID, ConnectionID: f.ConnectionID, Code: f.Code, Severity: f.Severity, Title: f.Title,
		Expected: f.Expected, Observed: f.Observed, Status: f.Status, CreatedAt: timeutil.ISO(f.CreatedAt),
		ResolvedAt: timeutil.ISOPtr(f.ResolvedAt)}
}

// provisioningRef points a response at the operation a change went through.
type provisioningRef struct {
	OpID   string `json:"op_id"`
	Status string `json:"status"`
}

func refOf(o *store.ProvOp) *provisioningRef { return &provisioningRef{OpID: o.ID, Status: o.Status} }

// routeGrantRevoke sends a least-privilege revoke to the target when the
// grant is a group membership in a system whose connection has write-back on.
// It returns the queued operation, or nil when the revoke is a direct graph
// change.
func routeGrantRevoke(c *store.TenantTx, now time.Time, e *store.GrantEdge, label string, removed int) (*store.ProvOp, error) {
	kind, aid, err := graph.ParseKey(e.Src)
	if err != nil || kind != "account" {
		return nil, nil
	}
	kind, gid, err := graph.ParseKey(e.Dst)
	if err != nil || kind != "group" {
		return nil, nil
	}
	a, err := getOrNil(c.Account(aid))
	if err != nil || a == nil {
		return nil, err
	}
	g, err := getOrNil(c.Group(gid))
	if err != nil || g == nil {
		return nil, err
	}
	op, routed, err := provision.Submit(c, now, provision.Change{System: g.System, Kind: target.RemoveEntitlement,
		Account: target.Account{Username: a.Username, ExternalID: a.ExternalID},
		Group:   target.Group{ExternalID: g.ExternalID, Name: g.Name}, Source: provision.SourceLeastPriv,
		Key: "leastpriv:edge:" + strconv.FormatInt(e.ID, 10), Completion: provision.CompleteGrantRevoke,
		Data: provision.GrantRevokeData{EdgeID: e.ID, Grant: label, PermissionsRemoved: removed}})
	if err != nil || !routed {
		return nil, err
	}
	return op, nil
}

// ---------------------------------------------------------------- targets

func (s *Server) listTargets(r *http.Request, _ *params) (int, any, error) {
	c := store.TxFrom(r.Context())
	ts, err := c.ProvTargets()
	if err != nil {
		return 0, nil, err
	}
	names, err := connNames(c)
	if err != nil {
		return 0, nil, err
	}
	out := make([]targetView, 0, len(ts))
	for _, t := range ts {
		out = append(out, viewTarget(t, names[t.ConnectionID].name))
	}
	return http.StatusOK, out, nil
}

// targetInput is PUT /api/provisioning/targets/{id}. token is write-only; an
// omitted token keeps the stored credential, unless the edit changes the kind
// or origin, which then needs a new token (422 credential_required).
type targetInput struct {
	Kind      string `json:"kind"`
	BaseURL   string `json:"base_url"`
	Dialect   string `json:"dialect"`
	Fault     string `json:"fault"`
	Token     string `json:"token"`
	WriteBack bool   `json:"write_back"`
	// OnDeprovision is "disable" (the default: leave a deprovisioned guest's
	// account disabled) or "delete" it once the grace period has passed.
	OnDeprovision string `json:"on_deprovision"`
	// AgentID, for a SCIM or Okta target in a private network, is the active
	// Directory Agent of the tenant that reaches it. Tessera then does not call
	// the target: it queues each operation for that agent, which pulls it over
	// its mutual-TLS channel and pushes from inside the network (issue #302).
	// The base URL must then be https, and its host:port must be on the agent's
	// own allowed_push_targets.
	AgentID string `json:"agent_id"`
}

func (s *Server) validateTarget(in *targetInput) (provision.Settings, error) {
	var st provision.Settings
	switch in.Kind {
	case provision.KindSCIM, provision.KindOkta:
		if s.cfg.Env == "prod" && !strings.HasPrefix(strings.ToLower(in.BaseURL), "https://") {
			return st, badRequest("invalid_base_url", "base_url must be https")
		}
		u, err := url.Parse(in.BaseURL)
		switch {
		case err != nil, u.Host == "", u.User != nil, u.RawQuery != "", u.Fragment != "", len(in.BaseURL) > 300,
			u.Scheme != "https" && u.Scheme != "http":
			return st, badRequest("invalid_base_url", "base_url must be an http(s) URL without credentials, query or fragment")
		}
		if in.Fault != "" {
			return st, badRequest("invalid_fault", "fault applies to the dev fake target only")
		}
	case provision.KindFake:
		if s.cfg.FakeTargetURL == "" {
			return st, badRequest("fake_unavailable", "the fake target is available only in dev (TESSERA_DEV_FAKE_TARGET)")
		}
		in.BaseURL = strings.TrimRight(s.cfg.FakeTargetURL, "/") + "/scim/v2"
		in.Token = ""
		if !slices.Contains([]string{"", "none", "fail_writes", "drop_writes"}, in.Fault) {
			return st, badRequest("invalid_fault", "fault must be none, fail_writes or drop_writes")
		}
		if in.Fault != "none" {
			st.Fault = in.Fault
		}
	default:
		return st, badRequest("invalid_kind", "kind must be scim, okta or fake")
	}
	switch {
	case in.Kind == provision.KindOkta && in.Dialect != "":
		return st, badRequest("invalid_dialect", "dialect applies to SCIM targets only")
	case in.Kind != provision.KindOkta && !slices.Contains([]string{"", "standard", "entra"}, in.Dialect):
		return st, badRequest("invalid_dialect", "dialect must be standard or entra")
	}
	st.Dialect = in.Dialect
	if in.Kind == provision.KindOkta {
		st.Dialect = ""
	}
	if in.AgentID != "" {
		switch {
		case in.Kind == provision.KindFake:
			return st, badRequest("invalid_agent", "the dev fake target cannot be reached through an agent")
		case !idRE.MatchString(in.AgentID):
			return st, badRequest("invalid_agent", "agent_id is not a Directory Agent id")
		case !strings.HasPrefix(strings.ToLower(in.BaseURL), "https://"):
			return st, badRequest("invalid_base_url", "a target reached through an agent must use https")
		}
		st.AgentID = in.AgentID
	}
	switch in.OnDeprovision {
	case "", "disable":
	case "delete":
		st.OnDeprovision = "delete"
	default:
		return st, badRequest("invalid_on_deprovision", "on_deprovision must be disable or delete")
	}
	if len(in.Token) > 4096 {
		return st, badRequest("invalid_credential", "token is longer than 4 KiB")
	}
	return st, nil
}

func (s *Server) putTarget(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	var in targetInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	st, err := s.validateTarget(&in)
	if err != nil {
		return 0, nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock()
	conn, err := c.Connection(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && conn.RetiredAt != nil) {
		return 0, nil, notFoundErr("connection")
	} else if err != nil {
		return 0, nil, err
	}
	if in.AgentID != "" {
		a, err := c.DirectoryAgent(in.AgentID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && a.Status != store.AgentActive) {
			return 0, nil, badRequest("invalid_agent", "agent_id must be an active Directory Agent of this tenant")
		} else if err != nil {
			return 0, nil, err
		}
	}
	t := &store.ProvTarget{ID: store.NewID(), ConnectionID: id, Kind: in.Kind, BaseURL: in.BaseURL, WriteBack: in.WriteBack,
		CreatedBy: actor(r)}
	settings, err := json.Marshal(st)
	if err != nil {
		return 0, nil, err
	}
	t.Settings = string(settings)
	old, err := c.ProvTarget(id)
	existing := err == nil
	switch {
	case existing:
		t.ID, t.CredentialEnc, t.CredentialVer, t.CreatedBy = old.ID, old.CredentialEnc, old.CredentialVer, old.CreatedBy
	case !errors.Is(err, store.ErrNotFound):
		return 0, nil, err
	}
	// The sealed credential is bound to the row, not to the destination, so a
	// stored token must never follow the target to another origin or kind: an
	// edit that moves it has to bring a new token (#315).
	moved := existing && (old.Kind != in.Kind || targetOrigin(old.BaseURL) != targetOrigin(in.BaseURL))
	credential := "none"
	if len(t.CredentialEnc) > 0 {
		credential = "kept"
	}
	switch {
	case in.Token != "":
		if t.CredentialEnc, err = provision.SealToken(s.provSeal, c.Tenant(), t.ID, in.Token); err != nil {
			return 0, nil, err
		}
		ver := store.NewID()
		t.CredentialVer = &ver
		credential = "set"
		if existing && len(old.CredentialEnc) > 0 {
			credential = "rotated"
		}
	case in.Kind == provision.KindFake:
		if len(t.CredentialEnc) > 0 {
			credential = "cleared"
		}
		t.CredentialEnc, t.CredentialVer = nil, nil
	case moved && len(t.CredentialEnc) > 0:
		return 0, nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "credential_required",
			Msg: "changing the target's kind or origin (scheme, host, port) needs a new token; the stored credential does not move with it"}
	case in.Kind == provision.KindOkta && len(t.CredentialEnc) == 0:
		return 0, nil, badRequest("invalid_credential", "an Okta target needs an API token")
	}
	if err := c.UpsertProvTarget(t, now); err != nil {
		return 0, nil, err
	}
	detail := ojson.Object{{Key: "connection_id", Value: id},
		{Key: "kind", Value: in.Kind}, {Key: "write_back", Value: in.WriteBack}, {Key: "dialect", Value: st.Dialect},
		{Key: "origin", Value: targetOrigin(t.BaseURL)}, {Key: "credential", Value: credential}}
	if in.AgentID != "" {
		detail = append(detail, ojson.KV{Key: "agent_id", Value: in.AgentID})
	}
	if moved {
		detail = append(detail, ojson.KV{Key: "previous_kind", Value: old.Kind},
			ojson.KV{Key: "previous_origin", Value: targetOrigin(old.BaseURL)})
	}
	if err := c.Audit(now, actor(r), "provision.target_set", detail); err != nil {
		return 0, nil, err
	}
	saved, err := c.ProvTarget(id)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewTarget(saved, conn.Name), nil
}

// targetOrigin is the scheme, host and port of a target URL, lower-cased and
// with the default port made explicit, so equal origins compare equal. A URL
// that does not parse yields "" (validateTarget has already rejected those).
func targetOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[scheme]
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

func (s *Server) deleteTarget(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	if err := c.DeleteProvTarget(id); errors.Is(err, store.ErrNotFound) {
		return 0, nil, notFoundErr("target")
	} else if err != nil {
		return 0, nil, err
	}
	if err := c.Audit(s.clock(), actor(r), "provision.target_removed", ojson.Object{{Key: "connection_id", Value: id}}); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"removed": true}, nil
}

// ---------------------------------------------------------------- operations

func (s *Server) listOps(r *http.Request, _ *params) (int, any, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, nil, badRequest("invalid_query", "the query string is not valid")
	}
	f := store.ProvOpFilter{Status: q.Get("status"), Kind: q.Get("kind"), ConnectionID: q.Get("connection_id"), Limit: 200}
	if f.Status != "" && !slices.Contains(provision.Statuses, f.Status) {
		return 0, nil, badRequest("invalid_status", "status must be one of "+strings.Join(provision.Statuses, ", "))
	}
	if f.Kind != "" && !slices.Contains(target.Kinds, f.Kind) {
		return 0, nil, badRequest("invalid_kind", "unknown operation kind")
	}
	if f.ConnectionID != "" && !idRE.MatchString(f.ConnectionID) {
		return 0, nil, badRequest("invalid_connection", "connection_id must be a connection id")
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 500 {
			return 0, nil, badRequest("invalid_limit", "limit must be 1 to 500")
		}
		f.Limit = n
	}
	c := store.TxFrom(r.Context())
	ops, err := c.ProvOps(f)
	if err != nil {
		return 0, nil, err
	}
	counts, err := c.ProvOpCounts()
	if err != nil {
		return 0, nil, err
	}
	names, err := connNames(c)
	if err != nil {
		return 0, nil, err
	}
	items := make([]opView, 0, len(ops))
	for _, o := range ops {
		items = append(items, viewOp(o, names))
	}
	return http.StatusOK, map[string]any{"items": items, "counts": counts}, nil
}

func opID(p *params) (string, error) {
	id := p.path["op_id"]
	if !idRE.MatchString(id) {
		return "", notFoundErr("operation")
	}
	return id, nil
}

type opDetail struct {
	opView
	Payload  json.RawMessage `json:"payload"`
	Findings []findingView   `json:"findings"`
}

func (s *Server) opDetail(c *store.TenantTx, id string) (opDetail, error) {
	o, err := c.ProvOp(id)
	if errors.Is(err, store.ErrNotFound) {
		return opDetail{}, notFoundErr("operation")
	} else if err != nil {
		return opDetail{}, err
	}
	names, err := connNames(c)
	if err != nil {
		return opDetail{}, err
	}
	fs, err := c.ProvFindings("", id)
	if err != nil {
		return opDetail{}, err
	}
	d := opDetail{opView: viewOp(o, names), Payload: json.RawMessage(o.Payload), Findings: make([]findingView, 0, len(fs))}
	for _, f := range fs {
		d.Findings = append(d.Findings, viewFinding(f))
	}
	return d, nil
}

func (s *Server) getOp(r *http.Request, p *params) (int, any, error) {
	id, err := opID(p)
	if err != nil {
		return 0, nil, err
	}
	d, err := s.opDetail(store.TxFrom(r.Context()), id)
	return http.StatusOK, d, err
}

func (s *Server) retryOp(r *http.Request, p *params) (int, any, error) {
	id, err := opID(p)
	if err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := provision.Retry(c, s.clock(), id); errors.Is(err, store.ErrNotFound) {
		return 0, nil, notFoundErr("operation")
	} else if err != nil {
		return 0, nil, provErr(err)
	}
	d, err := s.opDetail(c, id)
	return http.StatusOK, d, err
}

func (s *Server) cancelOp(r *http.Request, p *params) (int, any, error) {
	id, err := opID(p)
	if err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := provision.Cancel(c, s.clock(), id); errors.Is(err, store.ErrNotFound) {
		return 0, nil, notFoundErr("operation")
	} else if err != nil {
		return 0, nil, provErr(err)
	}
	d, err := s.opDetail(c, id)
	return http.StatusOK, d, err
}

// runProvisioning takes the tenant's due operations now instead of at the
// worker's next tick.
func (s *Server) runProvisioning(r *http.Request, p *params) (int, any, error) {
	ctx := audit.AsSystem(r.Context(), provision.WorkerActor)
	stats, err := s.prov.RunTenant(ctx, p.scope.Tenant)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, stats, nil
}

func (s *Server) listProvFindings(r *http.Request, _ *params) (int, any, error) {
	status := r.URL.Query().Get("status")
	if status != "" && status != "open" && status != "resolved" {
		return 0, nil, badRequest("invalid_status", "status must be open or resolved")
	}
	fs, err := store.TxFrom(r.Context()).ProvFindings(status, "")
	if err != nil {
		return 0, nil, err
	}
	out := make([]findingView, 0, len(fs))
	for _, f := range fs {
		out = append(out, viewFinding(f))
	}
	return http.StatusOK, out, nil
}
