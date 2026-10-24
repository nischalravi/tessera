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
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/atlassian"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/salesforce"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/servicenow"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sqldb"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	scimpreset "github.com/nischalravi/tessera/mvp/server/internal/provision/scim"
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
	// phased: the dry run reads from the target, so it holds no transaction open while it waits.
	s.handle(P, "/api/provisioning/targets/{id}/dry-run", phased, need(auth.PermProvisioningManage), s.dryRunTarget)
	// Discovery reads the target's ServiceProviderConfig and ResourceTypes (issue #542); phased for the same reason.
	s.handle(P, "/api/provisioning/targets/{id}/discover", phased, need(auth.PermProvisioningManage), s.discoverTarget)
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
	ConnectionID   string `json:"connection_id"`
	ConnectionName string `json:"connection_name"`
	System         string `json:"system"`
	Kind           string `json:"kind"`
	BaseURL        string `json:"base_url"`
	Dialect        string `json:"dialect,omitempty"`
	Preset         string `json:"preset,omitempty"` // SCIM vendor preset (quirk flags), when the target was set up from one
	APIRoot        string `json:"api_root,omitempty"`
	Fault          string `json:"fault,omitempty"`
	OnDeprovision  string `json:"on_deprovision,omitempty"` // "delete": accounts are deleted after the grace period (issue #74)
	AgentID        string `json:"agent_id,omitempty"`       // the Directory Agent that reaches this target (issue #302)
	// SQL is a database target's connection (no secret in it; issue #553).
	SQL *sqldb.Config `json:"sql,omitempty"`
	// Rest is a REST target's spec as saved (no base URL, no secret; issue #552).
	Rest json.RawMessage `json:"rest,omitempty"`
	// Discovery is the last read of a SCIM target's ServiceProviderConfig and ResourceTypes (issue #542).
	Discovery     *provision.DiscoveryRecord `json:"discovery,omitempty"`
	WriteBack     bool                       `json:"write_back"`
	HasCredential bool                       `json:"has_credential"`
	CredentialVer *string                    `json:"credential_version"`
	UpdatedAt     string                     `json:"updated_at"`
}

func viewTarget(t *store.ProvTarget, connName string) targetView {
	var st provision.Settings
	_ = json.Unmarshal([]byte(t.Settings), &st)
	return targetView{ConnectionID: t.ConnectionID, ConnectionName: connName, System: t.System, Kind: t.Kind, BaseURL: t.BaseURL,
		Dialect: st.Dialect, Preset: st.Preset, APIRoot: st.APIRoot, Fault: st.Fault, OnDeprovision: st.OnDeprovision, AgentID: st.AgentID, Rest: st.REST, SQL: st.SQL, Discovery: st.Discovery, WriteBack: t.WriteBack, HasCredential: len(t.CredentialEnc) > 0,
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
	Kind    string `json:"kind"`
	BaseURL string `json:"base_url"`
	Dialect string `json:"dialect"`
	// Preset is a SCIM vendor preset id (provision/scim): its PATCH quirks apply to this target.
	Preset string `json:"preset"`
	Fault  string `json:"fault"`
	// APIRoot overrides the API path of a vault target.
	APIRoot string `json:"api_root"`
	// Rest is the declarative spec of a REST target (kind rest): base URL, auth type, mapping and the
	// write operations as request templates (internal/connectors/restgen). It holds no secret.
	Rest json.RawMessage `json:"rest"`
	// Token is the credential: an API token (Okta, SCIM), "user:secret" (a vault), or for a REST target
	// the secret its auth type uses (or a JSON object of client_secret, api_key, password, token).
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
	// SQL is the database connection of a sql target (issue #553). The password is token.
	SQL *sqldb.Config `json:"sql"`
}

func (s *Server) validateTarget(in *targetInput) (provision.Settings, error) {
	var st provision.Settings
	switch in.Kind {
	case provision.KindSCIM, provision.KindOkta, provision.KindCyberArk, provision.KindDelinea, provision.KindBeyondTrust, provision.KindSAP, provision.KindOracle, provision.KindREST, provision.KindSalesforce, provision.KindServiceNow, provision.KindAtlassian:
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
	case provision.KindSQL:
		// a database: the connection is the sql object, the base URL is derived from it (no
		// credential in it) so the origin check that keeps a stored password from moving still works
		if in.SQL == nil {
			return st, badRequest("invalid_sql", "sql (the database settings) is required for a sql target")
		}
		rt := connsync.Runtime{Env: config.Prod} // only dev may disable TLS; "test" gets the production rules
		if s.cfg.Env == config.Dev {
			rt.Env = config.Dev
		}
		if err := in.SQL.Validate(rt); err != nil {
			return st, badRequest("invalid_sql", err.Error())
		}
		if in.Fault != "" || in.AgentID != "" {
			return st, badRequest("invalid_sql", "fault and agent_id do not apply to a sql target")
		}
		in.BaseURL = "sql://" + net.JoinHostPort(strings.ToLower(in.SQL.Host), strconv.Itoa(in.SQL.EffectivePort())) + "/" + in.SQL.Engine
		st.SQL = in.SQL
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
		return st, badRequest("invalid_kind", "kind must be scim, okta, rest, cyberark, delinea, beyondtrust, sap, oracle, sql, salesforce, servicenow, atlassian or fake")
	}
	if in.Kind == provision.KindSalesforce {
		if _, err := salesforce.CheckURL(in.BaseURL, s.sfRuntime()); err != nil {
			// a fixed message: the error text can carry the submitted URL, which is not echoed back
			return st, badRequest("invalid_base_url", sfURLRule("base_url"))
		}
	}
	switch in.Kind {
	case provision.KindServiceNow:
		if u, err := servicenow.CheckURL(in.BaseURL, s.sfRuntime()); err != nil || u.Path != "" {
			// a fixed message: the error text can carry the submitted URL, which is not echoed back
			return st, badRequest("invalid_base_url", "base_url must be an https URL on a ServiceNow domain (*.service-now.com or *.servicenowservices.com), with no path")
		}
	case provision.KindAtlassian:
		if u, err := atlassian.CheckSiteURL(in.BaseURL, s.sfRuntime()); err != nil || u.Path != "" {
			return st, badRequest("invalid_base_url", "base_url must be an https URL on an Atlassian Cloud site (*.atlassian.net), with no path")
		}
	}
	if in.Kind == provision.KindREST {
		if err := s.validateRest(in, &st); err != nil {
			return st, err
		}
	} else if len(in.Rest) > 0 {
		return st, badRequest("invalid_rest", "rest applies to REST targets only")
	}
	vault := slices.Contains(provision.PAMKinds, in.Kind) || slices.Contains(provision.ERPKinds, in.Kind) // a target with a path root and a user:secret credential
	noDialect := vault || in.Kind == provision.KindSalesforce || in.Kind == provision.KindServiceNow || in.Kind == provision.KindAtlassian
	switch {
	case (in.Kind == provision.KindOkta || noDialect || in.Kind == provision.KindREST) && in.Dialect != "":
		return st, badRequest("invalid_dialect", "dialect applies to SCIM targets only")
	case in.Kind != provision.KindOkta && !noDialect && in.Kind != provision.KindREST && !slices.Contains([]string{"", "standard", "entra"}, in.Dialect):
		return st, badRequest("invalid_dialect", "dialect must be standard or entra")
	case in.APIRoot != "" && !vault:
		return st, badRequest("invalid_api_root", "api_root applies to vault and ERP targets only")
	case in.APIRoot != "" && (!strings.HasPrefix(in.APIRoot, "/") || strings.Contains(in.APIRoot, "..") || strings.Contains(in.APIRoot, "//") || len(in.APIRoot) > 200):
		return st, badRequest("invalid_api_root", "api_root must be an absolute path")
	}
	st.Dialect, st.APIRoot = in.Dialect, in.APIRoot
	if in.Preset != "" {
		if _, ok := scimpreset.PresetByID(in.Preset); !ok || in.Kind != provision.KindSCIM {
			return st, badRequest("invalid_preset", "preset must be the id of a SCIM vendor preset, on a scim target")
		}
		st.Preset = in.Preset
	}
	if in.Kind == provision.KindOkta || noDialect || in.Kind == provision.KindREST {
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

// validateRest checks the spec of a REST target and keeps it, without the base URL (which is the
// target's own), in the settings. Every problem is returned at once, by field.
func (s *Server) validateRest(in *targetInput, st *provision.Settings) error {
	if len(in.Rest) == 0 {
		return badRequest("invalid_rest", "a REST target needs its rest spec")
	}
	spec, err := restgen.ParseSpec(in.Rest)
	if err != nil {
		return badRequest("invalid_rest", err.Error())
	}
	spec.BaseURL = in.BaseURL
	if errs := spec.Validate(connsync.Runtime{Env: s.cfg.Env, AllowLoopback: s.cfg.Env == config.Dev}); len(errs) > 0 {
		fields := make([]readiness.FieldError, len(errs))
		for i, e := range errs {
			fields[i] = readiness.FieldError{Field: e.Field, Msg: e.Msg}
		}
		return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_rest",
			Msg: "the rest spec is not valid", Fields: fields}
	}
	if spec.Writes == nil {
		return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_rest", Msg: "the rest spec is not valid",
			Fields: []readiness.FieldError{{Field: "writes", Msg: "a provisioning target needs at least one write operation"}}}
	}
	if in.Token != "" {
		if _, err := restgen.ParseSecrets(spec.Auth.Type, in.Token); err != nil {
			return badRequest("invalid_credential", err.Error()) // the message never holds the secret
		}
	}
	spec.BaseURL = "" // the target's base_url is the one of record
	raw, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	st.REST = raw
	return nil
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
	// A change to a database target's settings (engine, host, port, database, user, TLS, CA, mode
	// or any statement) moves it too: the password was entered for those settings, not for new ones.
	moved := existing && (old.Kind != in.Kind || targetOrigin(old.BaseURL) != targetOrigin(in.BaseURL) || sqlSettingsChanged(old.Settings, st.SQL))
	if existing && !moved && in.Kind == provision.KindREST {
		// where a REST target sends its secret is also in the spec: the token URL's origin, the auth type and
		// the header or query parameter. Moving any of them moves the credential.
		var os provision.Settings
		if json.Unmarshal([]byte(old.Settings), &os) != nil || restDestination(os.REST, old.BaseURL) != restDestination(st.REST, in.BaseURL) {
			moved = true
		}
	}
	if existing && !moved {
		// an edit that leaves the destination alone keeps what discovery found there
		var os provision.Settings
		if json.Unmarshal([]byte(old.Settings), &os) == nil && os.Discovery != nil {
			st.Discovery = os.Discovery
			if b, err := json.Marshal(st); err == nil {
				t.Settings = string(b)
			}
		}
	}
	credential := "none"
	if len(t.CredentialEnc) > 0 {
		credential = "kept"
	}
	if in.Token != "" && in.Kind == provision.KindSalesforce {
		cred, err := salesforce.ParseCredential(in.Token)
		if err != nil {
			return 0, nil, badRequest("invalid_credential", err.Error())
		}
		if cred.LoginURL != "" {
			if _, err := salesforce.CheckURL(cred.LoginURL, s.sfRuntime()); err != nil {
				return 0, nil, badRequest("invalid_credential", sfURLRule("login_url"))
			}
		}
	}
	if in.Token != "" && in.Kind == provision.KindServiceNow {
		if _, err := servicenow.ParseCredential(in.Token); err != nil {
			// fixed text: the parser's error is never echoed back
			return 0, nil, badRequest("invalid_credential", "the ServiceNow credential is JSON: auth basic with username and password, or oauth with client_id and client_secret; optional mode (direct or ticket) and assignment_group (a sys_id)")
		}
	}
	if in.Token != "" && in.Kind == provision.KindAtlassian {
		if _, err := atlassian.ParseTargetCredential(in.Token); err != nil {
			return 0, nil, badRequest("invalid_credential", "the Atlassian credential is JSON with email and api_token")
		}
	}
	switch {
	case in.Token != "" && isUserSecretKind(in.Kind) && !strings.Contains(strings.Trim(in.Token, ":"), ":"):
		return 0, nil, badRequest("invalid_credential", "the credential is user:secret")
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
	case in.Kind == provision.KindSQL && len(t.CredentialEnc) == 0:
		return 0, nil, badRequest("invalid_credential", "a sql target needs the database password as token")
	case in.Kind == provision.KindOkta && len(t.CredentialEnc) == 0:
		return 0, nil, badRequest("invalid_credential", "an Okta target needs an API token")
	case in.Kind == provision.KindSalesforce && len(t.CredentialEnc) == 0:
		return 0, nil, badRequest("invalid_credential", "a Salesforce target needs its credential (JSON with client_id, username and private_key)")
	case in.Kind == provision.KindServiceNow && len(t.CredentialEnc) == 0:
		return 0, nil, badRequest("invalid_credential", "a ServiceNow target needs its credential (JSON: auth basic with username and password, or oauth with client_id and client_secret)")
	case in.Kind == provision.KindAtlassian && len(t.CredentialEnc) == 0:
		return 0, nil, badRequest("invalid_credential", "an Atlassian target needs its credential (JSON with email and api_token)")
	case in.Kind == provision.KindREST && len(t.CredentialEnc) == 0:
		return 0, nil, badRequest("invalid_credential", "a REST target needs its credential (the secret its auth type uses)")
	case isUserSecretKind(in.Kind) && len(t.CredentialEnc) == 0:
		return 0, nil, badRequest("invalid_credential", "a vault or ERP target needs its credential as user:secret (client_id:client_secret for an ERP)")
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

// sfURLRule is the fixed error text for a Salesforce URL that fails salesforce.CheckURL.
func sfURLRule(field string) string {
	return field + " must be an https URL on a Salesforce domain (*.my.salesforce.com, *.salesforce.com or *.force.com), with no path"
}

// sfRuntime is the outbound runtime of Salesforce, ServiceNow and Atlassian targets: the dev loopback exception exists in dev only.
func (s *Server) sfRuntime() connsync.Runtime {
	return connsync.Runtime{Env: s.cfg.Env, AllowLoopback: s.cfg.Env == config.Dev}
}

// sqlSettingsChanged reports whether a database target's saved settings differ from the new ones.
func sqlSettingsChanged(oldSettings string, now *sqldb.Config) bool {
	var os provision.Settings
	if json.Unmarshal([]byte(oldSettings), &os) != nil {
		return true
	}
	a, _ := json.Marshal(os.SQL)
	b, _ := json.Marshal(now)
	return string(a) != string(b)
}

// restDestination is the secret destination of a stored REST spec, whose own base URL is the target's.
func restDestination(raw json.RawMessage, baseURL string) string {
	spec, err := restgen.ParseSpec(raw)
	if err != nil {
		return "unreadable"
	}
	spec.BaseURL = baseURL
	return spec.SecretDestination()
}

// isUserSecretKind: the kinds whose credential is "user:secret" (vaults and ERPs).
func isUserSecretKind(k string) bool {
	return slices.Contains(provision.PAMKinds, k) || slices.Contains(provision.ERPKinds, k)
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

// dryRunInput is POST /api/provisioning/targets/{id}/dry-run: the change to preview.
type dryRunInput struct {
	Kind            string `json:"kind"`
	Username        string `json:"username"`
	Email           string `json:"email"`
	DisplayName     string `json:"display_name"`
	GroupExternalID string `json:"group_external_id"`
	GroupName       string `json:"group_name"`
}

// dryRunTarget shows what a change would send to the target of a connection: the target is read, and every
// request that would change it is listed instead of sent (issue #498). It works with write-back on or off,
// and it is audited (provision.dry_run) because it calls the target with the stored credential.
func (s *Server) dryRunTarget(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := connID(p)
	if err != nil {
		return nil, err
	}
	var in dryRunInput
	if err := decodeBody(r, &in, false); err != nil {
		return nil, err
	}
	in.Username, in.GroupName, in.GroupExternalID = strings.TrimSpace(in.Username), strings.TrimSpace(in.GroupName), strings.TrimSpace(in.GroupExternalID)
	switch {
	case !slices.Contains(target.Kinds, in.Kind):
		return nil, badRequest("invalid_kind", "kind must be one of "+strings.Join(target.Kinds, ", "))
	case in.Username == "" || len(in.Username) > 200:
		return nil, badRequest("invalid_account", "username is required (at most 200 characters)")
	case len(in.Email) > 320 || len(in.DisplayName) > 200 || len(in.GroupName) > 200 || len(in.GroupExternalID) > 200:
		return nil, badRequest("invalid_account", "a field is too long")
	case (in.Kind == target.AddEntitlement || in.Kind == target.RemoveEntitlement) && in.GroupName == "" && in.GroupExternalID == "":
		return nil, badRequest("invalid_group", "an entitlement change needs a group name or id")
	}
	req := target.Request{Kind: in.Kind, Key: "dry-run:" + id,
		Account: target.Account{Username: in.Username, Email: in.Email, DisplayName: in.DisplayName},
		Group:   target.Group{ExternalID: in.GroupExternalID, Name: in.GroupName}}
	res, err := s.prov.DryRun(r.Context(), p.scope.Tenant, id, req)
	if err != nil {
		return nil, provErr(err)
	}
	var writeBack bool
	if err := p.scope.Write(r.Context(), func(tx *store.TenantTx) error {
		t, err := tx.ProvTarget(id)
		if err != nil {
			return err
		}
		writeBack = t.WriteBack
		det := ojson.Object{{Key: "connection_id", Value: id}, {Key: "kind", Value: in.Kind}, {Key: "target", Value: in.Username},
			{Key: "writes", Value: res.Writes()}, {Key: "reads", Value: len(res.Steps) - res.Writes()}, {Key: "stopped", Value: res.Error != ""}}
		return tx.Audit(s.clock(), actor(r), "provision.dry_run", det)
	}); errors.Is(err, store.ErrNotFound) {
		return nil, notFoundErr("target")
	} else if err != nil {
		return nil, err
	}
	return map[string]any{"connection_id": id, "kind": in.Kind, "write_back": writeBack, "steps": res.Steps, "writes": res.Writes(), "error": res.Error}, nil
}

// discoverTarget reads the ServiceProviderConfig and ResourceTypes of a SCIM target and records whether it
// advertises the Agent resource (issue #542). Read-only toward the target; a failed read is recorded on the
// target and returned in the body, never as an error, and never touches Users/Groups provisioning.
func (s *Server) discoverTarget(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := connID(p)
	if err != nil {
		return nil, err
	}
	rec, err := s.prov.Discover(r.Context(), p.scope.Tenant, id)
	if err != nil {
		return nil, provErr(err)
	}
	if err := p.scope.Write(r.Context(), func(tx *store.TenantTx) error {
		det := ojson.Object{{Key: "connection_id", Value: id}, {Key: "agent_advertised", Value: rec.AgentAdvertised},
			{Key: "ok", Value: rec.Error == ""}}
		return tx.Audit(s.clock(), actor(r), "provision.discover", det)
	}); err != nil {
		return nil, err
	}
	return rec, nil
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
