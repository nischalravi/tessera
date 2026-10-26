package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/catalog"
	"github.com/nischalravi/tessera/mvp/server/internal/leastpriv"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The least-privilege loop's staged revocation (issue #661, LP-5; design docs/design/least-privilege-loop.md
// sections 3, 5 and 11; the state machine and its rules are internal/lp).
//
//	GET    /api/lp/settings                       mode, kill switch, caps and what the caps have used
//	POST   /api/lp/pause {reason}                 the kill switch: one person; resuming is an admin change request
//	                                              of type lp.settings.update (two people; so are a stronger mode,
//	                                              larger caps and shorter periods)
//	GET    /api/lp/revocations?state=&limit=      the revocations, newest first
//	GET    /api/lp/revocations/{id}               one with its events and restore digest
//	POST   /api/lp/candidates                     propose a verified right-size of one policy as a candidate
//	POST   /api/lp/revocations/approve            {batch: [ids], items: [ids]}: announce candidates
//	POST   /api/lp/revocations/{id}/object        {reason}: an owner's objection (exempt for 180 days)
//	POST   /api/lp/revocations/{id}/restore       put a revoked grant back (until it is final)
//	GET    /api/lp/protected                      principals and policies the loop never touches
//	POST   /api/lp/protected                      {kind, ref, reason}: add one (removing needs a two-person change, not built yet)
//
// A queued job (lp_tick) does the work: after the announce period it computes the right-size again, supersedes the
// revocation if anything moved, and queues the change through the AWS write target of LP-4 within the caps; it
// verifies what the engine did, finalizes after the finalize period and pauses the loop on a failure.

func (s *Server) registerLPRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/lp/settings", read, need(auth.PermGraphRead), s.rd(s.lpGetSettings))
	s.handle(P, "/api/lp/pause", write, need(auth.PermLPManage), s.rd(s.lpPause))
	s.handle(G, "/api/lp/revocations", read, need(auth.PermGraphRead), s.rd(s.lpList))
	s.handle(G, "/api/lp/revocations/{id}", read, need(auth.PermGraphRead), s.rd(s.lpGet))
	s.handle(P, "/api/lp/candidates", write, need(auth.PermLPManage), s.rd(s.lpPropose))
	s.handle(P, "/api/lp/revocations/approve", write, needStepUp(auth.PermLPManage, auth.StepUpPolicy), s.rd(s.lpApprove))
	s.handle(P, "/api/lp/revocations/{id}/object", write, need(auth.PermLPManage), s.rd(s.lpObject))
	s.handle(P, "/api/lp/revocations/{id}/restore", write, need(auth.PermLPManage), s.rd(s.lpRestore))
	s.handle(G, "/api/lp/protected", read, need(auth.PermGraphRead), s.rd(s.lpProtectedList))
	s.handle(P, "/api/lp/protected", write, need(auth.PermLPManage), s.rd(s.lpProtectedAdd))
}

// lpErr maps the loop's refusals to API errors.
func lpErr(err error) error {
	var le *lp.Error
	if errors.As(err, &le) {
		return &readiness.Error{Status: le.Status, Code: le.Code, Msg: le.Msg}
	}
	return provErr(err)
}

// ---------------------------------------------------------------- views

type lpSettingsView struct {
	Mode            string  `json:"mode"`
	Paused          bool    `json:"paused"`
	PausedReason    string  `json:"paused_reason,omitempty"`
	PausedBy        string  `json:"paused_by,omitempty"`
	PausedAt        *string `json:"paused_at,omitempty"`
	OperatorDisable bool    `json:"operator_disabled"`
	// Active: new announcements and executions are allowed (staged, not paused, not disabled).
	Active          bool `json:"active"`
	CapPerRun       int  `json:"cap_per_run"`
	CapPerDay       int  `json:"cap_per_day"`
	CapPerAccount   int  `json:"cap_per_account"`
	CapPerPrincipal int  `json:"cap_per_principal"`
	AnnounceDays    int  `json:"announce_days"`
	FinalizeDays    int  `json:"finalize_days"`
	AutoMinDays     int  `json:"auto_min_days"`
	// ExecutedLast24h is what the day cap counts.
	ExecutedLast24h int    `json:"executed_last_24h"`
	UpdatedBy       string `json:"updated_by,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

func lpTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := store.RT(*t)
	return &s
}

func (s *Server) lpSettingsView(tx *store.TenantTx) (*lpSettingsView, error) {
	st, err := tx.LPSettings()
	if err != nil {
		return nil, err
	}
	n, err := tx.LPExecutedSince(s.clock().Add(-24*time.Hour), "", "")
	if err != nil {
		return nil, err
	}
	v := &lpSettingsView{Mode: st.Mode, Paused: st.Paused, PausedReason: st.PausedReason, PausedBy: st.PausedBy, PausedAt: lpTime(st.PausedAt),
		OperatorDisable: s.cfg.LPDisabled, Active: lp.Active(st) && !s.cfg.LPDisabled, CapPerRun: st.CapPerRun, CapPerDay: st.CapPerDay,
		CapPerAccount: st.CapPerAccount, CapPerPrincipal: st.CapPerPrincipal, AnnounceDays: st.AnnounceDays, FinalizeDays: st.FinalizeDays,
		AutoMinDays: st.AutoMinDays, ExecutedLast24h: n, UpdatedBy: st.UpdatedBy}
	if !st.UpdatedAt.IsZero() {
		v.UpdatedAt = store.RT(st.UpdatedAt)
	}
	return v, nil
}

type lpRevocationView struct {
	ID          string          `json:"id"`
	State       string          `json:"state"`
	Kind        string          `json:"kind"`
	Eligibility string          `json:"eligibility"`
	Principal   string          `json:"principal"`
	PolicyARN   string          `json:"policy_arn"`
	AccountID   string          `json:"account_id"`
	Connector   string          `json:"connector"`
	Snapshot    string          `json:"snapshot"`
	UnusedDays  int             `json:"unused_days"`
	Confidence  string          `json:"confidence"`
	Evidence    json.RawMessage `json:"evidence"`
	// CandidateSHA256 is the digest of the document the right-size leaves; RestoreSHA256 of the exact prior state.
	CandidateSHA256    string  `json:"candidate_sha256"`
	RestoreSHA256      string  `json:"restore_sha256"`
	CreatedBy          string  `json:"created_by"`
	CreatedAt          string  `json:"created_at"`
	ApprovedBy         string  `json:"approved_by,omitempty"`
	ApprovedAt         *string `json:"approved_at,omitempty"`
	AnnounceUntil      *string `json:"announce_until,omitempty"`
	ExecutedAt         *string `json:"executed_at,omitempty"`
	OpID               string  `json:"op_id,omitempty"`
	RevokedAt          *string `json:"revoked_at,omitempty"`
	RestoreUntil       *string `json:"restore_until,omitempty"`
	FinalizedAt        *string `json:"finalized_at,omitempty"`
	RestoreOpID        string  `json:"restore_op_id,omitempty"`
	RestoreTrigger     string  `json:"restore_trigger,omitempty"`
	RestoreRequestedAt *string `json:"restore_requested_at,omitempty"`
	RestoredAt         *string `json:"restored_at,omitempty"`
	Reason             string  `json:"reason,omitempty"`
	UpdatedAt          string  `json:"updated_at"`
	// RestorePayload and Events are in the detail only.
	RestorePayload json.RawMessage `json:"restore_payload,omitempty"`
	Events         []lpEventView   `json:"events,omitempty"`
}

type lpEventView struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Actor  string `json:"actor"`
	Detail string `json:"detail,omitempty"`
	At     string `json:"at"`
}

func lpRevocationViewOf(r *store.LPRevocation) lpRevocationView {
	ev := json.RawMessage(r.Evidence)
	if !json.Valid(ev) {
		ev = json.RawMessage(`{}`)
	}
	return lpRevocationView{ID: r.ID, State: r.State, Kind: r.Kind, Eligibility: r.Eligibility, Principal: r.Principal, PolicyARN: r.PolicyARN,
		AccountID: r.AccountID, Connector: r.ConnectorID, Snapshot: r.SnapshotID, UnusedDays: r.UnusedDays, Confidence: r.Confidence, Evidence: ev,
		CandidateSHA256: r.CandidateSHA256, RestoreSHA256: r.RestoreSHA256, CreatedBy: r.CreatedBy, CreatedAt: store.RT(r.CreatedAt),
		ApprovedBy: r.ApprovedBy, ApprovedAt: lpTime(r.ApprovedAt), AnnounceUntil: lpTime(r.AnnounceUntil), ExecutedAt: lpTime(r.ExecutedAt),
		OpID: r.OpID, RevokedAt: lpTime(r.RevokedAt), RestoreUntil: lpTime(r.RestoreUntil), FinalizedAt: lpTime(r.FinalizedAt),
		RestoreOpID: r.RestoreOpID, RestoreTrigger: r.RestoreTrigger, RestoreRequestedAt: lpTime(r.RestoreRequestedAt),
		RestoredAt: lpTime(r.RestoredAt), Reason: r.Reason, UpdatedAt: store.RT(r.UpdatedAt)}
}

// ---------------------------------------------------------------- reads and the kill switch

func (s *Server) lpGetSettings(r *http.Request, _ *params) (int, any, error) {
	v, err := s.lpSettingsView(store.TxFrom(r.Context()))
	return http.StatusOK, v, err
}

type lpPauseIn struct {
	Reason string `json:"reason"`
}

func (s *Server) lpPause(r *http.Request, _ *params) (int, any, error) {
	var in lpPauseIn
	if err := decodeBody(r, &in, true); err != nil {
		return 0, nil, err
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" {
		in.Reason = "paused by " + actor(r)
	}
	if len(in.Reason) > 300 {
		return 0, nil, badRequest("invalid_reason", "reason is at most 300 characters")
	}
	tx := store.TxFrom(r.Context())
	if _, err := lp.Pause(tx, s.clock(), actor(r), in.Reason, lpExec{s}); err != nil {
		return 0, nil, lpErr(err)
	}
	v, err := s.lpSettingsView(tx)
	return http.StatusOK, v, err
}

var lpStates = []string{store.LPCandidate, store.LPAnnounced, store.LPRevoking, store.LPRevoked, store.LPFinalized, store.LPRestoring,
	store.LPRestored, store.LPExempted, store.LPFailed, store.LPSuperseded}

func (s *Server) lpList(r *http.Request, _ *params) (int, any, error) {
	q := r.URL.Query()
	state := q.Get("state")
	if state != "" && !slices.Contains(lpStates, state) {
		return 0, nil, badRequest("invalid_state", "state is one of "+strings.Join(lpStates, ", "))
	}
	limit := 100
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 500 {
			return 0, nil, badRequest("invalid_limit", "limit must be 1 to 500")
		}
		limit = n
	}
	rows, err := store.TxFrom(r.Context()).LPRevocations(state, limit)
	if err != nil {
		return 0, nil, err
	}
	items := make([]lpRevocationView, 0, len(rows))
	for _, x := range rows {
		items = append(items, lpRevocationViewOf(x))
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

func (s *Server) lpGet(r *http.Request, p *params) (int, any, error) {
	tx := store.TxFrom(r.Context())
	x, err := lpLoad(tx, p.path["id"])
	if err != nil {
		return 0, nil, err
	}
	v := lpRevocationViewOf(x)
	if json.Valid([]byte(x.RestorePayload)) {
		v.RestorePayload = json.RawMessage(x.RestorePayload)
	}
	es, err := tx.LPEvents(x.ID)
	if err != nil {
		return 0, nil, err
	}
	v.Events = make([]lpEventView, 0, len(es))
	for _, e := range es {
		v.Events = append(v.Events, lpEventView{From: e.From, To: e.To, Actor: e.Actor, Detail: e.Detail, At: store.RT(e.CreatedAt)})
	}
	return http.StatusOK, v, nil
}

func lpLoad(tx *store.TenantTx, id string) (*store.LPRevocation, error) {
	if !idRE.MatchString(id) {
		return nil, notFoundErr("revocation")
	}
	x, err := tx.LPRevocation(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFoundErr("revocation")
	}
	return x, err
}

// ---------------------------------------------------------------- candidates

type lpProposeIn struct {
	awsRightSizeIn
	// Principal is the ARN of the role, user or group whose policy is right-sized.
	Principal string `json:"principal"`
	// CandidateSHA256 is the document_sha256 of the right-size the person reviewed.
	CandidateSHA256 string `json:"candidate_sha256"`
}

var lpAccountRE = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):(role|user|group)/`)

// lpPayload is the exact state a restore puts back: the AWS change that was queued, with the prior document
// verbatim and its digest. It is stored as JSON with a digest of its own.
type lpPayload = target.AWSChange

func (s *Server) lpPropose(r *http.Request, _ *params) (int, any, error) {
	var in lpProposeIn
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	arn, err := awsName("principal", in.Principal, true)
	if err != nil {
		return 0, nil, err
	}
	if err := in.check(); err != nil {
		return 0, nil, err
	}
	if raw, err := hex.DecodeString(in.CandidateSHA256); err != nil || len(raw) != 32 {
		return 0, nil, badRequest("invalid_candidate_sha256", "candidate_sha256 is required: the document_sha256 of the right-size you reviewed")
	}
	m := lpAccountRE.FindStringSubmatch(arn)
	if m == nil {
		return 0, nil, badRequest("invalid_principal", "principal is the ARN of an IAM role, user or group")
	}
	res, err := s.rightSize(r, arn, in.awsRightSizeIn)
	if err != nil {
		return 0, nil, err
	}
	v := res.view
	refuse := func(code, msg string) (int, any, error) {
		return 0, nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: code, Msg: msg}
	}
	switch {
	case v.Verdict != leastpriv.VerdictVerified:
		return refuse("right_size_not_verified", "only a verified right-size is a candidate: "+strings.Join(v.Reasons, "; "))
	case !v.Exclusive:
		return refuse("policy_is_shared", "the policy is attached to other principals too: right-sizing a shared policy is a suggestion only")
	case res.doc == nil || res.doc.VersionID == "" || len(res.doc.RawJSON) == 0:
		return refuse("policy_version_unknown", "the snapshot has no default version of the policy: collect again")
	case v.DocumentSHA256 != in.CandidateSHA256:
		return 0, nil, &readiness.Error{Status: http.StatusConflict, Code: "stale_candidate", Msg: "the right-size changed since it was reviewed (snapshot or usage moved): review it again"}
	}
	conf := string(v.Confidence.Level)
	if conf != string(leastpriv.ConfHigh) && conf != string(leastpriv.ConfMedium) {
		return refuse("confidence_too_low", "the evidence for the removed permissions is rated "+conf+": only high or medium is acted on")
	}
	ac, err := s.awsContext(store.TxFrom(r.Context()), in.Snapshot)
	if err != nil {
		return 0, nil, err
	}
	if why := lpProtectedByTag(ac, arn); why != "" {
		return refuse("grant_protected", why)
	}
	if a := s.lpPrivilegedRemoved(ac, v); a != "" {
		return refuse("privileged_suggest_only", "the right-size removes "+a+", a permissions-management action: privileged permissions are suggested, never revoked by the loop")
	}
	prior := string(res.doc.RawJSON)
	payload, err := json.Marshal(lpPayload{PolicyARN: in.PolicyARN, Document: v.Document, Prior: prior, PriorSHA256: target.DocDigest(prior),
		PriorVersionID: res.doc.VersionID})
	if err != nil {
		return 0, nil, err
	}
	evidence, err := json.Marshal(map[string]any{"confidence": v.Confidence, "verification": v.Check, "diff_summary": v.Diff.Summary,
		"unused_days": v.UnusedDays, "snapshot": v.Snapshot.ID})
	if err != nil {
		return 0, nil, err
	}
	c := &store.LPRevocation{Kind: target.AWSSetPolicyVersion, ConnectorID: v.Connector, SnapshotID: v.Snapshot.ID, AccountID: m[1], Principal: arn,
		PolicyARN: in.PolicyARN, UnusedDays: v.UnusedDays, Confidence: conf, Evidence: string(evidence), CandidateSHA256: v.DocumentSHA256,
		RestorePayload: string(payload), RestoreSHA256: lp.DigestPayload(string(payload))}
	tx := store.TxFrom(r.Context())
	if err := (lpExec{s}).Ready(tx, c); err != nil {
		return 0, nil, err
	}
	if err := lp.Propose(tx, s.clock(), actor(r), c); err != nil {
		return 0, nil, lpErr(err)
	}
	return http.StatusCreated, lpRevocationViewOf(c), nil
}

// lpProtectedByTag says why a principal is out of bounds by what the snapshot knows of it: the tessera:protected tag
// or a service-linked role.
func lpProtectedByTag(ac *awsCtx, arn string) string {
	p := ac.eng.snap.Principals[arn]
	switch {
	case p == nil:
		return ""
	case p.Tags["tessera:protected"] == "true":
		return "the principal is tagged tessera:protected=true: the loop never touches it"
	case p.IsServiceLinked:
		return "a service-linked role is never changed by the loop"
	}
	return ""
}

// lpPrivilegedRemoved returns a permissions-management action the right-size takes from the principal ("" if none),
// from the catalog's access levels. A list of removed actions cut short counts as privileged: it cannot be vouched for.
func (s *Server) lpPrivilegedRemoved(ac *awsCtx, v *awsRightSizeView) string {
	cv, ok := ac.cat.Cat.(*catalog.EvalView)
	if !ok || cv.C == nil || v.Diff == nil {
		return ""
	}
	for _, c := range v.Diff.Changes {
		if c.Kind != "lost" {
			continue
		}
		for _, a := range c.Actions {
			if cv.C.AccessLevel(a) == catalog.AccessPermissionsManagement {
				return a
			}
		}
		if len(c.Actions) < c.ActionCount {
			return "more actions than can be listed"
		}
	}
	if v.Diff.OmittedChanges > 0 {
		return "more changes than can be listed"
	}
	return ""
}

// ---------------------------------------------------------------- approve, object, restore

type lpApproveIn struct {
	Batch []string `json:"batch"`
	Items []string `json:"items"`
}

func lpIDs(field string, ids []string) error {
	for _, id := range ids {
		if !idRE.MatchString(id) {
			return badRequest("invalid_"+field, field+" holds revocation ids")
		}
	}
	return nil
}

func (s *Server) lpApprove(r *http.Request, _ *params) (int, any, error) {
	var in lpApproveIn
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if err := lpIDs("batch", in.Batch); err != nil {
		return 0, nil, err
	}
	if err := lpIDs("items", in.Items); err != nil {
		return 0, nil, err
	}
	rs, err := lp.Approve(store.TxFrom(r.Context()), s.clock(), actor(r), in.Batch, in.Items, s.cfg.LPDisabled, lpExec{s})
	if err != nil {
		return 0, nil, lpErr(err)
	}
	items := make([]lpRevocationView, 0, len(rs))
	for _, x := range rs {
		items = append(items, lpRevocationViewOf(x))
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

type lpObjectIn struct {
	Reason string `json:"reason"`
}

func (s *Server) lpObject(r *http.Request, p *params) (int, any, error) {
	var in lpObjectIn
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" || len(in.Reason) > 300 {
		return 0, nil, badRequest("invalid_reason", "reason is required, at most 300 characters")
	}
	tx := store.TxFrom(r.Context())
	x, err := lpLoad(tx, p.path["id"])
	if err != nil {
		return 0, nil, err
	}
	o, err := lp.Object(tx, s.clock(), actor(r), x.ID, in.Reason)
	if err != nil {
		return 0, nil, lpErr(err)
	}
	return http.StatusOK, lpRevocationViewOf(o), nil
}

type lpRestoreIn struct {
	// Trigger says who asked: owner or admin (the denial and JIT triggers are LP-6 and LP-7).
	Trigger string `json:"trigger"`
}

func (s *Server) lpRestore(r *http.Request, p *params) (int, any, error) {
	var in lpRestoreIn
	if err := decodeBody(r, &in, true); err != nil {
		return 0, nil, err
	}
	if in.Trigger == "" {
		in.Trigger = "admin"
	}
	if in.Trigger != "owner" && in.Trigger != "admin" {
		return 0, nil, badRequest("invalid_trigger", "trigger is owner or admin")
	}
	tx := store.TxFrom(r.Context())
	x, err := lpLoad(tx, p.path["id"])
	if err != nil {
		return 0, nil, err
	}
	got, err := lp.Restore(tx, s.clock(), actor(r), in.Trigger, x.ID, lpExec{s})
	if err != nil {
		return 0, nil, lpErr(err)
	}
	return http.StatusAccepted, lpRevocationViewOf(got), nil
}

// ---------------------------------------------------------------- the protected list

type lpProtectedIn struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Reason string `json:"reason"`
}

type lpProtectedView struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Ref       string `json:"ref"`
	Reason    string `json:"reason,omitempty"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

func (s *Server) lpProtectedList(r *http.Request, _ *params) (int, any, error) {
	rows, err := store.TxFrom(r.Context()).LPProtected()
	if err != nil {
		return 0, nil, err
	}
	items := make([]lpProtectedView, 0, len(rows))
	for _, p := range rows {
		items = append(items, lpProtectedView{ID: p.ID, Kind: p.Kind, Ref: p.Ref, Reason: p.Reason, CreatedBy: p.CreatedBy, CreatedAt: store.RT(p.CreatedAt)})
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

// lpProtectedAdd protects a principal or a policy from the loop. Adding is tightening and takes one person.
func (s *Server) lpProtectedAdd(r *http.Request, _ *params) (int, any, error) {
	var in lpProtectedIn
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	ref, err := awsName("ref", in.Ref, true)
	if err != nil {
		return 0, nil, err
	}
	if in.Kind != "principal" && in.Kind != "policy" {
		return 0, nil, badRequest("invalid_kind", "kind is principal or policy")
	}
	if len(in.Reason) > 300 {
		return 0, nil, badRequest("invalid_reason", "reason is at most 300 characters")
	}
	tx, now := store.TxFrom(r.Context()), s.clock()
	p := &store.LPProtectedRef{Kind: in.Kind, Ref: ref, Reason: strings.TrimSpace(in.Reason), CreatedBy: actor(r), CreatedAt: now}
	if err := tx.InsertLPProtected(p); errors.Is(err, store.ErrDuplicate) {
		return 0, nil, &readiness.Error{Status: http.StatusConflict, Code: "already_protected", Msg: "it is on the protected list already"}
	} else if err != nil {
		return 0, nil, err
	}
	if err := tx.Audit(now, actor(r), "lp.protected_added", ojson.Object{{Key: "kind", Value: p.Kind}, {Key: "ref", Value: p.Ref}}); err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, lpProtectedView{ID: p.ID, Kind: p.Kind, Ref: p.Ref, Reason: p.Reason, CreatedBy: p.CreatedBy, CreatedAt: store.RT(now)}, nil
}

// ---------------------------------------------------------------- the executor: the LP-4 write target

// lpExec carries out the loop's changes through the provisioning engine's AWS write target (issue #660). It queues
// operations; the engine sends them with the writer role and verifies them with the reader role.
type lpExec struct{ s *Server }

func (lpExec) payload(r *store.LPRevocation) (*lpPayload, error) {
	if lp.DigestPayload(r.RestorePayload) != r.RestoreSHA256 {
		return nil, &lp.Error{Status: http.StatusConflict, Code: "payload_digest_mismatch", Msg: "the stored payload does not match its recorded digest"}
	}
	var p lpPayload
	if err := json.Unmarshal([]byte(r.RestorePayload), &p); err != nil {
		return nil, &lp.Error{Status: http.StatusConflict, Code: "payload_unreadable", Msg: "the stored payload cannot be read"}
	}
	return &p, nil
}

// Ready: the connector that collected the snapshot has an AWS target with write-back on.
func (lpExec) Ready(tx *store.TenantTx, r *store.LPRevocation) error {
	t, err := awsTarget(tx, r.ConnectorID)
	if err != nil {
		return err
	}
	if !t.WriteBack {
		return &lp.Error{Status: http.StatusConflict, Code: "write_back_off",
			Msg: "write-back is off on the AWS target: a different admin must approve enabling it (change request provisioning.write_back.enable)"}
	}
	return nil
}

func (e lpExec) Enqueue(tx *store.TenantTx, now time.Time, r *store.LPRevocation) (string, error) {
	t, err := awsTarget(tx, r.ConnectorID)
	if err != nil {
		return "", err
	}
	p, err := e.payload(r)
	if err != nil {
		return "", err
	}
	if target.DocDigest(p.Document) != r.CandidateSHA256 {
		return "", &lp.Error{Status: http.StatusConflict, Code: "stale_candidate", Msg: "the stored document is not the one that was reviewed"}
	}
	op, err := provision.Enqueue(tx, now, t.ConnectionID, provision.Change{Kind: r.Kind, Account: target.Account{Username: r.Principal}, AWS: p,
		Source: provision.SourceLeastPriv, Key: "lp:" + r.ID + ":revoke"})
	var pe *provision.Error
	if errors.As(err, &pe) {
		return "", &lp.Error{Status: pe.Status, Code: pe.Code, Msg: pe.Msg}
	} else if err != nil {
		return "", err
	}
	return op.ID, nil
}

func (e lpExec) EnqueueRestore(tx *store.TenantTx, now time.Time, r *store.LPRevocation) (string, error) {
	t, err := awsTarget(tx, r.ConnectorID)
	if err != nil {
		return "", err
	}
	p, err := e.payload(r)
	if err != nil {
		return "", err
	}
	kind := target.AWSRestoreKind(r.Kind)
	if kind == "" {
		return "", &lp.Error{Status: http.StatusUnprocessableEntity, Code: "not_restorable", Msg: "this kind of change has no restore"}
	}
	p.RestoreOf = r.OpID
	op, err := provision.Enqueue(tx, now, t.ConnectionID, provision.Change{Kind: kind, Account: target.Account{Username: r.Principal}, AWS: p,
		Source: provision.SourceLeastPriv, Key: "lp:" + r.ID + ":restore"})
	if err != nil {
		return "", err
	}
	return op.ID, nil
}

func (lpExec) Cancel(tx *store.TenantTx, now time.Time, opID string) (bool, error) {
	op, err := tx.ProvOp(opID)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil // nothing to withdraw
	} else if err != nil {
		return false, err
	}
	if op.Status != provision.Queued {
		return false, nil
	}
	if _, err := provision.Cancel(tx, now, opID); err != nil {
		return false, err
	}
	return true, nil
}

func (lpExec) OpStatus(tx *store.TenantTx, opID string) (string, error) {
	op, err := tx.ProvOp(opID)
	if err != nil {
		return "", err
	}
	return op.Status, nil
}

// ---------------------------------------------------------------- the job

// lpEvery is how often the loop's job runs: announce periods are days, the engine verifies within minutes.
const lpEvery = 5 * time.Minute

// queueLP runs the lp_tick job of one tenant. A tenant whose loop is off has nothing to do, and nothing here reads
// AWS for it.
func (s *Server) queueLP(ctx context.Context, j queue.Job) (any, error) {
	ctx = audit.WithSystemActor(ctx, lp.ActorTick)
	now := s.clock()
	rechecks := map[string]lp.Recheck{}
	var busy bool
	// First read what has to be computed again, without holding a write transaction over the evaluator.
	if err := s.store.ReadTenant(ctx, j.Tenant, func(tx *store.TenantTx) error {
		st, err := tx.LPSettings()
		if err != nil {
			return err
		}
		if st.Mode != store.LPModeStaged && st.Mode != store.LPModeAuto {
			return nil
		}
		busy = true
		if !lp.Active(st) || s.cfg.LPDisabled {
			return nil
		}
		due, err := tx.LPRevocationsToAdvance(store.LPAnnounced, 500)
		if err != nil {
			return err
		}
		for _, x := range due {
			if x.AnnounceUntil == nil || x.AnnounceUntil.After(now) {
				continue
			}
			rc, err := s.lpRecheck(ctx, tx, x)
			if err != nil {
				s.log.Warn("lp recheck failed", "revocation", x.ID, "err", err)
				continue // left for the next pass
			}
			rechecks[x.ID] = rc
		}
		return nil
	}); err != nil || !busy {
		return nil, err
	}
	var res *lp.Tick
	err := s.store.InTenant(ctx, j.Tenant, func(tx *store.TenantTx) (err error) {
		res, err = lp.Run(tx, now, lpExec{s}, s.cfg.LPDisabled, rechecks)
		return err
	})
	if err != nil || res == nil {
		return nil, err
	}
	if res.Revoking+res.Revoked+res.Finalized+res.Restored+res.Failed+res.Superseded+res.Expired+res.Held == 0 && res.Paused == "" {
		return nil, nil // nothing happened: no job run to show
	}
	return res, nil
}

// lpRecheck computes the right-size again just before the revoke. It is OK only if it is the same verified
// right-size that was announced: the same document, so no call of the principal was used since and the policy is
// unchanged, and the evidence still as good.
func (s *Server) lpRecheck(ctx context.Context, tx *store.TenantTx, x *store.LPRevocation) (lp.Recheck, error) {
	in := awsRightSizeIn{PolicyARN: x.PolicyARN, UnusedDays: x.UnusedDays, Connector: x.ConnectorID}
	if err := in.check(); err != nil {
		return lp.Recheck{Reason: "the stored candidate is no longer valid"}, nil
	}
	req := (&http.Request{}).WithContext(store.WithTx(ctx, tx))
	res, err := s.rightSize(req, x.Principal, in)
	var re *readiness.Error
	if errors.As(err, &re) && (re.Status == http.StatusNotFound || re.Status == http.StatusUnprocessableEntity) {
		return lp.Recheck{Reason: "the grant is gone or cannot be right-sized any more: " + re.Msg}, nil
	} else if err != nil {
		return lp.Recheck{}, err
	}
	v := res.view
	var p lpPayload
	_ = json.Unmarshal([]byte(x.RestorePayload), &p)
	switch {
	case v.Verdict != leastpriv.VerdictVerified:
		return lp.Recheck{Reason: "no longer a verified right-size: " + strings.Join(v.Reasons, "; ")}, nil
	case !v.Exclusive:
		return lp.Recheck{Reason: "the policy is now attached to other principals"}, nil
	case res.doc == nil || target.DocDigest(string(res.doc.RawJSON)) != p.PriorSHA256 || res.doc.VersionID != p.PriorVersionID:
		return lp.Recheck{Reason: "the policy changed in AWS since it was announced"}, nil
	case v.DocumentSHA256 != x.CandidateSHA256:
		return lp.Recheck{Reason: "the principal used a permission since it was announced, or the evidence changed"}, nil
	case v.Confidence.Level != leastpriv.ConfHigh && (v.Confidence.Level != leastpriv.ConfMedium || x.Confidence != string(leastpriv.ConfMedium)):
		return lp.Recheck{Reason: "the evidence is now rated " + string(v.Confidence.Level)}, nil
	}
	return lp.Recheck{OK: true}, nil
}
