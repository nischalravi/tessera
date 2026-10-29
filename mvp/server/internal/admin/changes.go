// Package admin is Tessera's admin-change workflow (design §15, §19 PR12):
// two-person, step-up, cooling-off changes to who can administer the tenant
// and how people sign in, the notifications every transition queues, and
// operator-assisted recovery.
//
//   - changes.go: the state machine (submit, approve, reject, cancel, apply,
//     expire) and the sweeper entry points ApplyDue and ExpireDue.
//   - change_types.go: a validator, a policy (who approves, how long it
//     waits) and an applier for each change type of §15.2.
//   - notify.go: the notification queued for every transition.
//   - connections.go: test login and activation of an IdP connection,
//     disabling a user.
//   - recovery.go: operator recovery of a tenant that lost all its admins.
//   - idpconfig.go: the validator of an IdP connection's configuration,
//     shared with the operator CLI.
//
// The package never calls time.Now: time comes from Service.Clock
// (timeutil.Clock). It never opens SQL: everything goes through
// internal/store.
package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Change types (design §15.2). api_client.* joins with the PR that adds its
// table (PR10/11).
const (
	TypeRoleGrant         = "role.grant"
	TypeRoleRevoke        = "role.revoke"
	TypeIdPCreate         = "idp_connection.create"
	TypeIdPUpdateTrust    = "idp_connection.update_trust"
	TypeIdPUpdateCosmetic = "idp_connection.update_cosmetic"
	TypeIdPDisable        = "idp_connection.disable"
	TypeTenantSettings    = "tenant.settings.update"
	TypeSecurityContacts  = "tenant.security_contacts.update"
	TypeBGRegister        = "breakglass.register"
	TypeBGRevoke          = "breakglass.revoke"
)

const (
	// ApprovalWindow is how long a request waits for its approver (§15.2).
	ApprovalWindow = 72 * time.Hour
	// CoolingOff is the delay of a change that widens trust or privilege.
	CoolingOff = 24 * time.Hour
	// bootstrapAdmins: a tenant with fewer active admins is in bootstrap (§15.2).
	bootstrapAdmins = 2
)

// Transitions (the suffix of the admin.change.* audit action and of the
// notification kind).
const (
	TransSubmitted = "submitted"
	TransApproved  = "approved"
	TransRejected  = "rejected"
	TransCancelled = "cancelled"
	TransExpired   = "expired"
	TransApplied   = "applied"
	TransFailed    = "failed"
)

// Service runs the admin-change workflow. The zero Clock is the wall clock.
type Service struct {
	DB *store.DB
	// Clock is the injected clock (never time.Now in this package).
	Clock timeutil.Clock
	// Sealer seals the client secret of an idp_connection.create request and
	// the connection's secrets when it is applied.
	Sealer *seal.Sealer
	// Prod refuses dev_mock connections and plain-http endpoints (§18.4).
	Prod bool
	// Log receives the details of an applier failure, which the request
	// itself records only generically. Nil: slog.Default.
	Log *slog.Logger
	// WebAuthn runs the break-glass ceremonies (NewWebAuthn). Nil: break-glass
	// registration and sign-in answer 503 break_glass_unavailable.
	WebAuthn *webauthn.WebAuthn
	// PolicyMaxSteps is the most grant steps one roles.bundle.apply may make (TESSERA_POLICY_MAX_STEPS); 0 is
	// rolesascode.DefaultMaxSteps.
	PolicyMaxSteps int
}

func (s *Service) now() time.Time {
	if s.Clock == nil {
		return timeutil.System()
	}
	return s.Clock()
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// plan says how a valid change is handled: who must approve and how long it
// waits after approval (§15.2).
type plan struct {
	twoPerson bool
	cooling   time.Duration
	target    string // the user or connection id, for filtering and display
}

// env is what validators, policies and appliers see: the transaction and the
// facts they need, loaded once.
type env struct {
	svc    *Service
	tx     *store.TenantTx
	now    time.Time
	by     uuid.UUID // the requester
	tenant *store.Tenant
	admins []*store.PlatformUser
	loaded bool
}

func (s *Service) env(tx *store.TenantTx, now time.Time, by uuid.UUID) *env {
	return &env{svc: s, tx: tx, now: now, by: by}
}

func (e *env) tenantRecord() (store.Tenant, error) {
	if e.tenant == nil {
		t, err := e.tx.TenantRecord()
		if err != nil {
			return store.Tenant{}, err
		}
		e.tenant = &t
	}
	return *e.tenant, nil
}

func (e *env) activeAdmins() ([]*store.PlatformUser, error) {
	if !e.loaded {
		as, err := e.tx.ActiveAdminUsers(e.now)
		if err != nil {
			return nil, err
		}
		e.admins, e.loaded = as, true
	}
	return e.admins, nil
}

func (e *env) isActiveAdmin(id uuid.UUID) (bool, error) {
	as, err := e.activeAdmins()
	if err != nil {
		return false, err
	}
	for _, a := range as {
		if a.ID == id {
			return true, nil
		}
	}
	return false, nil
}

// user returns an active-or-not user of this tenant (404 for another tenant's).
func (e *env) user(id uuid.UUID) (*store.PlatformUser, error) {
	if id == uuid.Nil {
		return nil, invalid("user_id is required")
	}
	u, err := e.tx.PlatformUser(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("user")
	}
	return u, err
}

func (e *env) connection(id uuid.UUID) (*store.IdPConnection, error) {
	if id == uuid.Nil {
		return nil, invalid("connection_id is required")
	}
	c, err := e.tx.IdPConnection(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("connection")
	}
	return c, err
}

// changeType is one entry of the §15.2 table.
type changeType struct {
	name string
	// decode strictly decodes a payload (unknown fields refused) and returns
	// the typed value and its canonical JSON.
	decode func(raw json.RawMessage) (any, json.RawMessage, error)
	// plan validates the change against the tenant's current state and says
	// who approves and how long it waits. The applier runs it again.
	plan func(e *env, v any) (plan, error)
	// apply makes the change, in the transaction that records it applied.
	apply func(e *env, ch *store.AdminChange, v any) error
	// summary is one non-secret line describing the change.
	summary func(e *env, v any) string
	// submitSecret seals the client secret that travels with the request
	// (idp_connection.create only); nil for the other types.
	submitSecret func(e *env, v any, id uuid.UUID, secret string) ([]byte, error)
	// afterSubmit runs in the transaction that records the request, once it is inserted (breach.item.attest
	// marks its item in progress); nil for the other types.
	afterSubmit func(e *env, ch *store.AdminChange, v any) error
	// afterEnd runs in the transaction that rejects, cancels or expires a request; nil for the other types.
	afterEnd func(e *env, ch *store.AdminChange, v any) error
}

// ended runs the type's afterEnd hook for a request that ended without being applied.
func (e *env) ended(ch *store.AdminChange) error {
	typ, v, err := decodeStored(ch)
	if err != nil || typ.afterEnd == nil {
		return nil
	}
	return typ.afterEnd(e, ch, v)
}

// typed builds a changeType for payload struct T. prep may fill server-chosen
// fields before the payload is canonicalized.
func typed[T any](name string, prep func(*T), planFn func(*env, *T) (plan, error),
	applyFn func(*env, *store.AdminChange, *T) error, summaryFn func(*env, *T) string) *changeType {
	return &changeType{name: name,
		decode: func(raw json.RawMessage) (any, json.RawMessage, error) {
			var v T
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&v); err != nil {
				return nil, nil, invalid("%s payload: %v", name, err)
			}
			if dec.More() {
				return nil, nil, invalid("%s payload: trailing data", name)
			}
			if prep != nil {
				prep(&v)
			}
			canon, err := json.Marshal(&v)
			if err != nil {
				return nil, nil, invalid("%s payload: %v", name, err)
			}
			return &v, canon, nil
		},
		plan:    func(e *env, v any) (plan, error) { return planFn(e, v.(*T)) },
		apply:   func(e *env, ch *store.AdminChange, v any) error { return applyFn(e, ch, v.(*T)) },
		summary: func(e *env, v any) string { return summaryFn(e, v.(*T)) }}
}

// Types lists the supported change types.
func Types() []string {
	out := make([]string, 0, len(changeTypes))
	for k := range changeTypes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func lookupType(name string) (*changeType, error) {
	if t, ok := changeTypes[name]; ok {
		return t, nil
	}
	if strings.HasPrefix(name, "api_client.") {
		return nil, invalid("type %q is not available yet (its table arrives with machine clients)", name)
	}
	return nil, invalid("unsupported type %q (want one of %s)", name, strings.Join(Types(), ", "))
}

// HashPayload is the SHA-256 hex of a canonical payload, which an approver
// must echo to approve exactly what was requested.
func HashPayload(canonical []byte) string {
	h := sha256.Sum256(canonical)
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------- submit

// SubmitInput is a new change request. ClientSecret accompanies an
// idp_connection.create of an OIDC or OAuth 2.0 connection; it is sealed and
// is never part of the payload, its hash, an audit event or a response.
type SubmitInput struct {
	Type         string
	Payload      json.RawMessage
	ClientSecret string
}

const maxSecretBytes = 4096

// Submit validates and records a change request (design §15.2). It needs
// admin.change.request and a fresh STEP_UP_ADMIN. A change that needs no
// second person waits out its cooling-off (none for narrowing changes) and
// is applied at once when that is zero.
func (s *Service) Submit(ctx context.Context, p *auth.Principal, in SubmitInput) (*store.AdminChange, error) {
	if d := auth.Check(p, auth.PermAdminChangeReq, &auth.StepUpAdmin, s.now()); d != nil {
		return nil, denied(d)
	}
	return s.submit(ctx, p, in, "")
}

// SubmitChecked files a groups.loader.save or groups.folder.delete_recursive
// request for a caller whose own route has already checked what that needs
// (groups.loader.admin or groups.write, a fresh STEP_UP_POLICY and stem_admin on
// the folders): such a caller holds no admin.change.request. It files no other type.
// Approval is the workflow's: another admin, with admin.change.approve.
func (s *Service) SubmitChecked(ctx context.Context, p *auth.Principal, in SubmitInput) (*store.AdminChange, error) {
	if in.Type != TypeGroupLoaderSave && in.Type != TypeGroupFolderDelete {
		return nil, invalid("only %s and %s requests are filed this way", TypeGroupLoaderSave, TypeGroupFolderDelete)
	}
	if p == nil || p.UserID == nil {
		return nil, newErr(http.StatusForbidden, "forbidden", "a signed-in user is required")
	}
	return s.submit(ctx, p, in, "")
}

// submit records a request. clientID is the machine client that proposes it (SubmitProposal): the request is then
// filed in the name of the client's owner and the proposer is recorded before the submitted event is written.
func (s *Service) submit(ctx context.Context, p *auth.Principal, in SubmitInput, clientID string) (*store.AdminChange, error) {
	now := s.now()
	typ, err := lookupType(in.Type)
	if err != nil {
		return nil, err
	}
	if len(in.Payload) == 0 {
		return nil, invalid("payload is required")
	}
	v, canon, err := typ.decode(in.Payload)
	if err != nil {
		return nil, err
	}
	var ch *store.AdminChange
	err = s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		requester := uuid.Nil
		if clientID != "" {
			var err error
			if requester, err = s.env(tx, now, uuid.Nil).proposerUser(clientID); err != nil {
				return err
			}
		} else {
			requester = *p.UserID
		}
		e := s.env(tx, now, requester)
		pl, err := typ.plan(e, v)
		if err != nil {
			return err
		}
		admins, err := e.activeAdmins()
		if err != nil {
			return err
		}
		if pl.twoPerson && len(admins) < bootstrapAdmins {
			return conflict("bootstrap_restricted", "this tenant has fewer than %d active admins: only role.grant of "+
				"tenant_admin is allowed until it has two, and %s needs an operator co-sign through the admin CLI",
				bootstrapAdmins, typ.name)
		}
		id := uuid.New()
		var sealed []byte
		switch {
		case typ.submitSecret != nil:
			if sealed, err = typ.submitSecret(e, v, id, in.ClientSecret); err != nil {
				return err
			}
		case in.ClientSecret != "":
			return invalid("client_secret is not part of a %s request", typ.name)
		}
		ch = &store.AdminChange{ID: id, TenantID: p.TenantID, Type: typ.name, Payload: canon, PayloadHash: HashPayload(canon),
			SecretEnc: sealed, TargetID: pl.target, Status: store.ChangePendingApproval, TwoPerson: pl.twoPerson,
			CoolingOffSeconds: int64(pl.cooling / time.Second), RequestedBy: requester, RequestedAt: now,
			ExpiresAt: now.Add(ApprovalWindow)}
		if !pl.twoPerson {
			// no approver: the change waits only its own cooling-off
			ch.Status = store.ChangeCoolingOff
			eff := now.Add(pl.cooling)
			ch.EffectiveAt = &eff
		}
		if err := tx.InsertAdminChange(ch); err != nil {
			return err
		}
		if clientID != "" {
			if err := tx.InsertAdminChangeProposal(ch.ID, clientID, now); err != nil {
				return err
			}
		}
		if typ.afterSubmit != nil {
			if err := typ.afterSubmit(e, ch, v); err != nil {
				return err
			}
		}
		return e.transition(ch, TransSubmitted, p.Display)
	})
	if err != nil {
		return nil, mapStore(err)
	}
	if ch.Status == store.ChangeCoolingOff && !ch.EffectiveAt.After(now) {
		return s.apply(ctx, p.TenantID, ch.ID, p.Display)
	}
	return ch, nil
}

// mapStore turns the store's sentinel errors into API errors.
func mapStore(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return notFound("change request")
	case errors.Is(err, store.ErrAdminChangeState):
		return conflict("invalid_state", "the request is not in a state that allows this")
	case errors.Is(err, store.ErrDuplicate):
		return conflict("duplicate", "that already exists")
	case errors.Is(err, store.ErrCrossTenant):
		return notFound("change request")
	}
	return err
}

// ---------------------------------------------------------------- approve, reject, cancel

// Approve is the second person's approval (design §15.2): a different
// tenant_admin, with a fresh STEP_UP_ADMIN, echoing the hash of the payload
// they reviewed. The change then cools off (and, with no cooling-off, is
// applied at once).
func (s *Service) Approve(ctx context.Context, p *auth.Principal, id uuid.UUID, payloadHash string) (*store.AdminChange, error) {
	now := s.now()
	if d := auth.Check(p, auth.PermAdminChangeAppr, &auth.StepUpAdmin, now); d != nil {
		return nil, denied(d)
	}
	var ch *store.AdminChange
	err := s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		var err error
		if ch, err = tx.AdminChange(id); err != nil {
			return err
		}
		own, err := tx.SameActor(ch.RequestedBy.String(), p.UserID.String())
		if err != nil {
			return err
		}
		switch {
		case ch.Status != store.ChangePendingApproval:
			return conflict("invalid_state", "the request is %s, not pending approval", ch.Status)
		case !ch.TwoPerson:
			return conflict("invalid_state", "this change needs no approval")
		case own:
			return newErr(http.StatusForbidden, "self_approval_refused", "a request cannot be approved by the person who made it")
		case !now.Before(ch.ExpiresAt):
			return conflict("expired", "the request was not approved within %s and has expired", ApprovalWindow)
		case !seal.Equal([]byte(payloadHash), []byte(ch.PayloadHash)):
			return conflict("payload_hash_mismatch", "the payload changed since you reviewed it; reload the request")
		}
		typ, v, err := decodeStored(ch)
		if err != nil {
			return err
		}
		if _, err := typ.plan(s.env(tx, now, ch.RequestedBy), v); err != nil {
			return err // the tenant changed since the request: approve nothing stale
		}
		eff := now.Add(time.Duration(ch.CoolingOffSeconds) * time.Second)
		if err := tx.ApproveAdminChange(id, *p.UserID, now, eff); err != nil {
			return err
		}
		if ch, err = tx.AdminChange(id); err != nil {
			return err
		}
		return s.env(tx, now, ch.RequestedBy).transition(ch, TransApproved, p.Display)
	})
	if err != nil {
		return nil, mapStore(err)
	}
	if ch.EffectiveAt != nil && !ch.EffectiveAt.After(now) {
		return s.apply(ctx, p.TenantID, ch.ID, p.Display)
	}
	return ch, nil
}

// Reject refuses a request that awaits approval. Any other admin may; the
// requester cancels instead.
func (s *Service) Reject(ctx context.Context, p *auth.Principal, id uuid.UUID) (*store.AdminChange, error) {
	return s.decide(ctx, p, id, auth.PermAdminChangeAppr, TransRejected)
}

// Cancel withdraws a request that is pending or cooling off. Any admin may.
func (s *Service) Cancel(ctx context.Context, p *auth.Principal, id uuid.UUID) (*store.AdminChange, error) {
	return s.decide(ctx, p, id, auth.PermAdminChangeReq, TransCancelled)
}

func (s *Service) decide(ctx context.Context, p *auth.Principal, id uuid.UUID, perm auth.Permission, trans string) (*store.AdminChange, error) {
	now := s.now()
	if d := auth.Check(p, perm, nil, now); d != nil {
		return nil, denied(d)
	}
	var ch *store.AdminChange
	err := s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		var err error
		if ch, err = tx.AdminChange(id); err != nil {
			return err
		}
		if trans == TransRejected {
			var own bool
			own, err = tx.SameActor(ch.RequestedBy.String(), p.UserID.String())
			if err != nil {
				return err
			}
			if own {
				return newErr(http.StatusForbidden, "self_rejection_refused", "cancel your own request instead of rejecting it")
			}
			err = tx.RejectAdminChange(id, *p.UserID, now)
		} else {
			err = tx.CancelAdminChange(id, *p.UserID, now)
		}
		if errors.Is(err, store.ErrAdminChangeState) {
			return conflict("invalid_state", "the request is %s and cannot be %s", ch.Status, trans)
		}
		if err != nil {
			return err
		}
		if ch, err = tx.AdminChange(id); err != nil {
			return err
		}
		if err := s.env(tx, now, ch.RequestedBy).ended(ch); err != nil {
			return err
		}
		return s.env(tx, now, ch.RequestedBy).transition(ch, trans, p.Display)
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return ch, nil
}

// ---------------------------------------------------------------- apply

// Apply applies a cooling-off request whose effective_at has passed (the
// POST …/apply route). Applying early is 409. It needs admin.change.approve
// and a fresh STEP_UP_ADMIN; the sweeper does the same without a person.
func (s *Service) Apply(ctx context.Context, p *auth.Principal, id uuid.UUID) (*store.AdminChange, error) {
	if d := auth.Check(p, auth.PermAdminChangeAppr, &auth.StepUpAdmin, s.now()); d != nil {
		return nil, denied(d)
	}
	return s.apply(ctx, p.TenantID, id, p.Display)
}

var errApplierFailed = errors.New("admin: the applier failed")

// apply runs the applier in the transaction that marks the request applied,
// so a failure rolls the change back; the failure is then recorded in a
// transaction of its own (status failed, audited, notified).
func (s *Service) apply(ctx context.Context, tenant tenancy.ID, id uuid.UUID, by string) (*store.AdminChange, error) {
	var ch *store.AdminChange
	var failure error
	err := s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		now := s.now()
		var err error
		if ch, err = tx.AdminChange(id); err != nil {
			return err
		}
		switch {
		case ch.Status != store.ChangeCoolingOff:
			return conflict("invalid_state", "the request is %s, not cooling off", ch.Status)
		case ch.EffectiveAt == nil:
			return conflict("invalid_state", "the request has no effective time")
		case now.Before(*ch.EffectiveAt):
			return conflict("cooling_off_active", "the cooling-off period ends at %s; the change cannot be applied before",
				ch.EffectiveAt.UTC().Format(time.RFC3339))
		case !seal.Equal([]byte(HashPayload(ch.Payload)), []byte(ch.PayloadHash)):
			return conflict("payload_hash_mismatch", "the stored payload no longer matches its approved hash")
		}
		typ, v, err := decodeStored(ch)
		if err != nil {
			failure = err
			return errApplierFailed
		}
		if err := typ.apply(s.env(tx, now, ch.RequestedBy), ch, v); err != nil {
			failure = err
			return errApplierFailed
		}
		if err := tx.MarkAdminChangeApplied(id, now); err != nil {
			return err
		}
		if ch, err = tx.AdminChange(id); err != nil {
			return err
		}
		return s.env(tx, now, ch.RequestedBy).transition(ch, TransApplied, by)
	})
	switch {
	case errors.Is(err, errApplierFailed):
		return s.fail(ctx, tenant, id, failure, by)
	case err != nil:
		return nil, mapStore(err)
	}
	return ch, nil
}

// fail records that the applier of request id raised err.
func (s *Service) fail(ctx context.Context, tenant tenancy.ID, id uuid.UUID, cause error, by string) (*store.AdminChange, error) {
	msg := "the change could not be applied"
	var ae *Error
	if errors.As(cause, &ae) {
		msg = ae.Msg
	} else {
		s.log().Error("admin change applier failed", "change", id.String(), "err", cause)
	}
	var ch *store.AdminChange
	err := s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		now := s.now()
		if err := tx.MarkAdminChangeFailed(id, truncate(msg, 500)); err != nil {
			return err
		}
		var err error
		if ch, err = tx.AdminChange(id); err != nil {
			return err
		}
		return s.env(tx, now, ch.RequestedBy).transition(ch, TransFailed, by)
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return ch, newErr(http.StatusConflict, "apply_failed", "%s", msg)
}

// decodeStored decodes a stored request's payload (it was validated and
// canonicalized when submitted; decoding again also catches a type that no
// longer exists).
func decodeStored(ch *store.AdminChange) (*changeType, any, error) {
	typ, err := lookupType(ch.Type)
	if err != nil {
		return nil, nil, err
	}
	v, _, err := typ.decode(ch.Payload)
	return typ, v, err
}

// ---------------------------------------------------------------- sweeper

// SweepResult counts what one sweep did.
type SweepResult struct{ Applied, Expired, Failed int }

// Sweep applies the cooling-off changes that are due and expires the requests
// nobody approved within 72 hours, in every active tenant (design §15.2).
// ctx should carry the sweeper's system actor (audit.WithSystemActor). An
// error in one tenant is joined with the others and does not stop them.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	var total SweepResult
	tenants, err := s.DB.ActiveTenants(ctx)
	if err != nil {
		return total, err
	}
	var errs []error
	for _, t := range tenants {
		if ctx.Err() != nil {
			return total, errors.Join(append(errs, ctx.Err())...)
		}
		r, err := s.SweepTenant(ctx, t.ID)
		total.Applied += r.Applied
		total.Expired += r.Expired
		total.Failed += r.Failed
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
		}
	}
	return total, errors.Join(errs...)
}

// SweepTenant is Sweep for one tenant.
func (s *Service) SweepTenant(ctx context.Context, t tenancy.ID) (SweepResult, error) {
	var r SweepResult
	n, err := s.ExpireDue(ctx, t)
	r.Expired = n
	if err != nil {
		return r, err
	}
	a, f, err := s.ApplyDue(ctx, t)
	r.Applied, r.Failed = a, f
	return r, err
}

// ExpireDue expires the tenant's pending requests whose 72 hours are up and
// returns how many.
func (s *Service) ExpireDue(ctx context.Context, t tenancy.ID) (int, error) {
	now := s.now()
	var due []*store.AdminChange
	if err := s.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		due, err = tx.ExpirableAdminChanges(now)
		return err
	}); err != nil {
		return 0, err
	}
	n := 0
	for _, d := range due {
		err := s.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
			if err := tx.ExpireAdminChange(d.ID, now); err != nil {
				return err
			}
			ch, err := tx.AdminChange(d.ID)
			if err != nil {
				return err
			}
			if err := s.env(tx, now, ch.RequestedBy).ended(ch); err != nil {
				return err
			}
			return s.env(tx, now, ch.RequestedBy).transition(ch, TransExpired, "system")
		})
		switch {
		case errors.Is(err, store.ErrAdminChangeState):
			continue // approved or cancelled in the meantime
		case err != nil:
			return n, err
		}
		n++
	}
	return n, nil
}

// ApplyDue applies the tenant's cooling-off requests whose effective_at has
// passed. It returns how many were applied and how many failed (a failure is
// recorded on the request and does not stop the others).
func (s *Service) ApplyDue(ctx context.Context, t tenancy.ID) (applied, failed int, err error) {
	now := s.now()
	var due []*store.AdminChange
	if err := s.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		due, err = tx.DueAdminChanges(now)
		return err
	}); err != nil {
		return 0, 0, err
	}
	var errs []error
	for _, d := range due {
		_, err := s.apply(ctx, t, d.ID, "system")
		var ae *Error
		switch {
		case err == nil:
			applied++
		case errors.As(err, &ae) && ae.Code == "apply_failed":
			failed++
		case errors.As(err, &ae) && ae.Code == "invalid_state":
			// cancelled or applied by someone else since the list was read
		default:
			errs = append(errs, err)
		}
	}
	return applied, failed, errors.Join(errs...)
}

// ---------------------------------------------------------------- audit

// changeDetail is the audit detail of a transition. It names the request,
// its type and target and who is involved; never the payload or a secret
// (the hash identifies exactly what was requested).
func changeDetail(ch *store.AdminChange, by string) ojson.Object {
	d := ojson.Object{{Key: "change_id", Value: ch.ID.String()}, {Key: "type", Value: ch.Type},
		{Key: "target_id", Value: ch.TargetID}, {Key: "status", Value: ch.Status},
		{Key: "requested_by", Value: ch.RequestedBy.String()}, {Key: "two_person", Value: ch.TwoPerson},
		{Key: "payload_hash", Value: ch.PayloadHash}, {Key: "by", Value: by}}
	if ch.ApprovedBy != nil {
		d = append(d, ojson.KV{Key: "approved_by", Value: ch.ApprovedBy.String()})
	}
	if ch.EffectiveAt != nil {
		d = append(d, ojson.KV{Key: "effective_at", Value: ch.EffectiveAt.UTC().Format(time.RFC3339)})
	}
	if ch.Failure != "" {
		d = append(d, ojson.KV{Key: "failure", Value: ch.Failure})
	}
	return d
}

// transition writes the audit event of a transition and queues its
// notifications, in the transaction that made the transition (design §15.2:
// every transition writes an audit event and queues a notification).
func (e *env) transition(ch *store.AdminChange, trans, by string) error {
	detail := changeDetail(ch, by)
	// a change a machine client proposed carries the client id in every event: proposal, approval and apply
	client, err := e.tx.AdminChangeProposer(ch.ID)
	if err != nil {
		return err
	}
	if client != "" {
		detail = append(detail, ojson.KV{Key: "client_id", Value: client})
	}
	outcome := store.OutcomeSuccess
	if trans == TransFailed {
		outcome = store.OutcomeFailure
	}
	if _, err := audit.Record(e.tx.Context(), e.tx, "admin.change."+trans, detail, audit.At(e.now),
		audit.Target("admin_change", ch.ID.String()), audit.Outcome(outcome)); err != nil {
		return err
	}
	return e.notifyChange(ch, trans)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
