package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Break-glass (design §9.6, §15.4, §19 PR13): hardware WebAuthn keys that sign
// a user in when the tenant's IdP is down, misconfigured or compromised.
//
//   - Enrolment: a breakglass.register change request (two people, 24 h
//     cooling-off, change_types) creates the break-glass user and opens a 24 h
//     window in which the requester registers one key
//     (BeginRegistration / FinishRegistration). Our code, not the library,
//     refuses a backup-eligible key, a "none" or self attestation and a model
//     outside the tenant's breakglass_aaguid_allowlist.
//   - Use: BeginAssertion / SignIn. The session has kind break_glass, one
//     role (break_glass), an AAL3 phrh context, 15 min idle and 60 min
//     absolute; the sign-in writes auth.break_glass.used and queues a
//     critical notification to every admin, every security contact and
//     Tessera security operations.
//   - What the session may do: view admin state, and BreakGlassAction: disable
//     an IdP connection, change its trust or grant tenant_admin to a named
//     user (each a change request with no approver and a 1 h cooling-off any
//     admin may cancel), and revoke every other session.
//   - Afterwards: the sign-in is a break_glass_uses row that stays open until
//     a tenant admin answers "why was break-glass used" (AttestUse).
//
// Attestation trust: the library verifies the attestation signature but not
// the certificate chain (the MDS3 chain verification of §15.4 is open
// question OQ11), so a key is recorded with trust "basic"; the AAGUID
// allowlist plus the two-person enrolment are the controls until then.

const (
	// RegistrationWindow is how long after its cooling-off a breakglass.register
	// request lets its requester register the key (§15.2).
	RegistrationWindow = 24 * time.Hour
	// BreakGlassCooling is the cooling-off of a break-glass action (§15.4).
	BreakGlassCooling = time.Hour
	// CeremonyTTL is how long a WebAuthn challenge is good for.
	CeremonyTTL = 5 * time.Minute
	// UseReviewWindow is how long a sign-in stays on the dashboard (§15.4).
	UseReviewWindow = 30 * 24 * time.Hour
	// SecurityOperations is the operator recipient of a break-glass
	// notification ("Tessera security operations", §9.6).
	SecurityOperations = "tessera-security-operations"

	maxOpenAssertions = 200
	maxKeysPerUser    = 5
	purgeAfter        = 24 * time.Hour
	maxCeremonyBody   = 64 << 10
)

// Break-glass actions (§15.4). The first three are the change types of the
// same name, requested without a second approver.
const (
	ActionIdPDisable        = TypeIdPDisable
	ActionIdPUpdateTrust    = TypeIdPUpdateTrust
	ActionGrantTenantAdmin  = TypeRoleGrant
	ActionRevokeAllSessions = "sessions.revoke_all"
)

// Actions lists the break-glass actions.
func Actions() []string {
	return []string{ActionIdPDisable, ActionIdPUpdateTrust, ActionGrantTenantAdmin, ActionRevokeAllSessions}
}

// NewWebAuthn is the relying party of the break-glass ceremonies with the
// §15.4 settings: direct attestation, cross-platform authenticators only, no
// resident key, user verification required. rpID is TESSERA_RP_ID and origins
// the browser origins the ceremony may run on (TESSERA_PUBLIC_URL's).
func NewWebAuthn(rpID string, origins []string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         "Tessera",
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferDirectAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.CrossPlatform,
			ResidentKey:             protocol.ResidentKeyRequirementDiscouraged,
			UserVerification:        protocol.VerificationRequired,
		},
	})
}

// AAGUIDAllowlist is the tenant's break-glass AAGUID allowlist (canonical
// lower-case UUIDs); empty means any authenticator model.
func AAGUIDAllowlist(t store.Tenant) []string { return viewSettings(t).aaguids }

// Available reports whether break-glass ceremonies can run (a relying party is configured).
func (s *Service) Available() bool { return s.WebAuthn != nil }

func (s *Service) webAuthn() (*webauthn.WebAuthn, error) {
	if s.WebAuthn == nil {
		return nil, newErr(http.StatusServiceUnavailable, "break_glass_unavailable",
			"break-glass is not configured on this server (TESSERA_RP_ID and TESSERA_PUBLIC_URL)")
	}
	return s.WebAuthn, nil
}

// ---------------------------------------------------------------- change types

type bgRegisterPayload struct {
	// UserID is the break-glass user the key signs in: an existing one (a
	// second key for it) or, when absent from the request, a new one the
	// server names.
	UserID    uuid.UUID `json:"user_id"`
	Label     string    `json:"label"`
	Custodian string    `json:"custodian"`
}

func prepBGRegister(v *bgRegisterPayload) {
	if v.UserID == uuid.Nil {
		v.UserID = uuid.New()
	}
	v.Label, v.Custodian = strings.TrimSpace(v.Label), strings.TrimSpace(v.Custodian)
}

// validLine reports whether s is 1 to max characters with no control characters.
func validLine(s string, max int) bool {
	n := utf8.RuneCountInString(s)
	return n >= 1 && n <= max && !strings.ContainsFunc(s, unicode.IsControl)
}

// planBGRegister: two people and 24 h. The user, when it exists, is an active
// break-glass user with room for another key.
func planBGRegister(e *env, v *bgRegisterPayload) (plan, error) {
	if !validLine(v.Label, 100) {
		return plan{}, invalid("label is required (1 to 100 characters, no control characters), e.g. \"Safe A, key 1\"")
	}
	if !validLine(v.Custodian, 200) {
		return plan{}, invalid("custodian is required (1 to 200 characters): who holds the key")
	}
	u, err := e.tx.PlatformUser(v.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// a new break-glass user is created when the request is applied
	case err != nil:
		return plan{}, err
	case !u.IsBreakGlass:
		return plan{}, conflict("not_break_glass_user", "that user is not a break-glass user; leave user_id out to create one")
	case u.Status != "active":
		return plan{}, conflict("user_disabled", "the break-glass user is disabled")
	default:
		keys, err := e.userKeys(u.ID)
		if err != nil {
			return plan{}, err
		}
		if len(keys) >= maxKeysPerUser {
			return plan{}, conflict("too_many_keys", "the user already has %d active keys", len(keys))
		}
	}
	return plan{twoPerson: true, cooling: CoolingOff, target: v.UserID.String()}, nil
}

// applyBGRegister creates the break-glass user when it does not exist yet and
// gives it the break_glass role. The key itself is registered afterwards by
// the requester, within RegistrationWindow.
func applyBGRegister(e *env, ch *store.AdminChange, v *bgRegisterPayload) error {
	if _, err := planBGRegister(e, v); err != nil {
		return err
	}
	if _, err := e.tx.PlatformUser(v.UserID); errors.Is(err, store.ErrNotFound) {
		u := &store.PlatformUser{ID: v.UserID, DisplayName: "Break-glass: " + v.Label, IsBreakGlass: true, CreatedAt: e.now}
		if err := e.tx.InsertPlatformUser(u); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	by, cid := ch.RequestedBy, ch.ID.String()
	err := e.tx.InsertRoleAssignment(&store.RoleAssignment{UserID: v.UserID, Role: store.RoleBreakGlass,
		Source: store.RoleSourceBreakGlass, GrantedByUserID: &by, ChangeRequestID: &cid, CreatedAt: e.now})
	if errors.Is(err, store.ErrDuplicate) {
		return nil // a second key of an existing break-glass user
	}
	return err
}

type bgRevokePayload struct {
	CredentialID uuid.UUID `json:"credential_id"`
}

func (e *env) bgKeyName(id uuid.UUID) string {
	c, err := e.tx.BreakGlassCredential(id)
	if err != nil {
		return "unknown key"
	}
	return fmt.Sprintf("%q (custodian %s)", c.Label, c.Custodian)
}

// planBGRevoke: one admin with a step-up, immediate (§15.2).
func planBGRevoke(e *env, v *bgRevokePayload) (plan, error) {
	if v.CredentialID == uuid.Nil {
		return plan{}, invalid("credential_id is required")
	}
	c, err := e.tx.BreakGlassCredential(v.CredentialID)
	if errors.Is(err, store.ErrNotFound) {
		return plan{}, notFound("break-glass key")
	}
	if err != nil {
		return plan{}, err
	}
	if c.RevokedAt != nil {
		return plan{}, conflict("already_revoked", "the key is already revoked")
	}
	return plan{target: c.ID.String()}, nil
}

// applyBGRevoke revokes the key and ends the sessions it signed in.
func applyBGRevoke(e *env, _ *store.AdminChange, v *bgRevokePayload) error {
	c, err := e.tx.BreakGlassCredential(v.CredentialID)
	if err != nil {
		return err
	}
	if _, err := planBGRevoke(e, v); err != nil {
		return err
	}
	if err := e.tx.RevokeBreakGlassCredential(c.ID, e.now); err != nil {
		return err
	}
	_, err = e.tx.RevokeUserSessions(c.UserID, auth.RevokedBreakGlassKey, e.now)
	return err
}

// userKeys lists the active (not revoked) keys of a user.
func (e *env) userKeys(user uuid.UUID) ([]*store.BreakGlassCredential, error) {
	all, err := e.tx.BreakGlassCredentials()
	if err != nil {
		return nil, err
	}
	var out []*store.BreakGlassCredential
	for _, c := range all {
		if c.UserID == user && c.RevokedAt == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- go-webauthn glue

// bgWebUser is the go-webauthn view of a break-glass user.
type bgWebUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u *bgWebUser) WebAuthnID() []byte                         { return u.id }
func (u *bgWebUser) WebAuthnName() string                       { return u.name }
func (u *bgWebUser) WebAuthnDisplayName() string                { return u.name }
func (u *bgWebUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// userHandle is the WebAuthn user handle of a platform user: its 16 id bytes.
func userHandle(id uuid.UUID) []byte { return id[:] }

// waCredential rebuilds the library's record of a stored key. The flags are
// those a break-glass key has by construction: user present, user verified,
// not backup-eligible.
func waCredential(c *store.BreakGlassCredential) webauthn.Credential {
	var aaguid []byte
	if id, err := uuid.Parse(c.AAGUID); err == nil {
		aaguid = id[:]
	}
	tr := make([]protocol.AuthenticatorTransport, len(c.Transports))
	for i, t := range c.Transports {
		tr[i] = protocol.AuthenticatorTransport(t)
	}
	return webauthn.Credential{ID: c.CredentialID, PublicKey: c.PublicKey, AttestationFormat: c.AttestationFormat,
		Transport: tr, Flags: webauthn.NewCredentialFlags(protocol.FlagUserPresent | protocol.FlagUserVerified),
		Authenticator: webauthn.Authenticator{AAGUID: aaguid, SignCount: c.SignCount, Attachment: protocol.CrossPlatform}}
}

func waCredentials(cs []*store.BreakGlassCredential) []webauthn.Credential {
	out := make([]webauthn.Credential, len(cs))
	for i, c := range cs {
		out[i] = waCredential(c)
	}
	return out
}

// challengeHash is what the challenge is stored as.
func challengeHash(challenge string) string { return seal.SHA256Hex([]byte(challenge)) }

// anonymous attributes the events of ctx to an unauthenticated caller.
func anonymous(ctx context.Context) context.Context {
	ac, _ := store.AuditContextFrom(ctx)
	ac.Actor = store.AuditActor{Type: store.ActorAnonymous}
	return store.WithAuditContext(ctx, ac)
}

func sessionJSON(sd *webauthn.SessionData) (json.RawMessage, error) {
	sd.Expires = time.Time{} // expiry is the challenge row's, on the injected clock
	return json.Marshal(sd)
}

// ---------------------------------------------------------------- registration

// registration is an open enrolment: the applied breakglass.register request,
// its payload and the break-glass user.
type registration struct {
	change  *store.AdminChange
	payload *bgRegisterPayload
	user    *store.PlatformUser
}

// openRegistration checks that request id lets requester register a key now:
// an applied breakglass.register request of requester, within its 24 h
// window, with no key registered yet.
func (e *env) openRegistration(id, requester uuid.UUID) (*registration, error) {
	ch, err := e.tx.AdminChange(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && ch.Type != TypeBGRegister) {
		return nil, notFound("break-glass enrolment request")
	}
	if err != nil {
		return nil, err
	}
	switch {
	case ch.Status != store.ChangeApplied:
		return nil, conflict("registration_not_open", "the enrolment request is %s: it must be applied (after its cooling-off) first", ch.Status)
	case ch.RequestedBy != requester:
		return nil, newErr(http.StatusForbidden, "registration_requester_only", "only the admin who requested the enrolment can register its key")
	case ch.AppliedAt == nil || !e.now.Before(ch.AppliedAt.Add(RegistrationWindow)):
		return nil, conflict("registration_window_closed", "the %s registration window of the enrolment request has closed; request a new enrolment",
			RegistrationWindow)
	}
	if _, err := e.tx.BreakGlassCredentialForChange(id); err == nil {
		return nil, conflict("already_registered", "a key is already registered for this enrolment request")
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	_, v, err := decodeStored(ch)
	if err != nil {
		return nil, err
	}
	payload := v.(*bgRegisterPayload)
	u, err := e.tx.PlatformUser(payload.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, conflict("registration_not_open", "the break-glass user does not exist")
	}
	if err != nil {
		return nil, err
	}
	if !u.IsBreakGlass || u.Status != "active" {
		return nil, conflict("registration_not_open", "the user is not an active break-glass user")
	}
	return &registration{change: ch, payload: payload, user: u}, nil
}

// BeginRegistration starts the registration of the key of an applied
// breakglass.register request: the WebAuthn creation options (direct
// attestation, cross-platform, no resident key, user verification required)
// with the user's existing keys excluded. The requester needs
// admin.change.request and a fresh STEP_UP_ADMIN.
func (s *Service) BeginRegistration(ctx context.Context, p *auth.Principal, changeID uuid.UUID) (*protocol.CredentialCreation, error) {
	now := s.now()
	if d := auth.Check(p, auth.PermAdminChangeReq, &auth.StepUpAdmin, now); d != nil {
		return nil, denied(d)
	}
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	var creation *protocol.CredentialCreation
	err = s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		e := s.env(tx, now, *p.UserID)
		reg, err := e.openRegistration(changeID, *p.UserID)
		if err != nil {
			return err
		}
		keys, err := e.userKeys(reg.user.ID)
		if err != nil {
			return err
		}
		if len(keys) >= maxKeysPerUser {
			return conflict("too_many_keys", "the user already has %d active keys", len(keys))
		}
		user := &bgWebUser{id: userHandle(reg.user.ID), name: reg.user.DisplayName, creds: waCredentials(keys)}
		var sd *webauthn.SessionData
		creation, sd, err = wa.BeginRegistration(user, webauthn.WithExclusions(webauthn.Credentials(user.creds).CredentialDescriptors()))
		if err != nil {
			return fmt.Errorf("begin break-glass registration: %w", err)
		}
		data, err := sessionJSON(sd)
		if err != nil {
			return err
		}
		if err := tx.PurgeBreakGlassChallenges(now.Add(-purgeAfter)); err != nil {
			return err
		}
		uid, by, cid := reg.user.ID, *p.UserID, changeID
		h := &store.BreakGlassChallenge{Purpose: store.BreakGlassRegistration, ChallengeHash: challengeHash(sd.Challenge),
			SessionData: data, ChangeRequestID: &cid, UserID: &uid, CreatedBy: &by, CreatedAt: now, ExpiresAt: now.Add(CeremonyTTL)}
		if err := tx.InsertBreakGlassChallenge(h); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, "breakglass.registration.started", ojson.Object{{Key: "change_id", Value: changeID.String()},
			{Key: "user_id", Value: reg.user.ID.String()}, {Key: "label", Value: reg.payload.Label}}, audit.At(now),
			audit.Target("admin_change", changeID.String()))
		return err
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return creation, nil
}

// FinishRegistration verifies the authenticator's registration response
// (body is the PublicKeyCredential JSON) and stores the key. After the
// library has checked the ceremony, our own checks refuse a key whose
// backup-eligible flag is set, whose attestation is none or self, or whose
// model is not in the tenant's AAGUID allowlist (§15.4). A refusal is
// audited as breakglass.registration.rejected and the challenge is spent.
func (s *Service) FinishRegistration(ctx context.Context, p *auth.Principal, changeID uuid.UUID, body []byte) (*store.BreakGlassCredential, error) {
	now := s.now()
	if d := auth.Check(p, auth.PermAdminChangeReq, &auth.StepUpAdmin, now); d != nil {
		return nil, denied(d)
	}
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return nil, newErr(http.StatusBadRequest, "invalid_credential", "the registration response is not a valid WebAuthn credential")
	}
	hash := challengeHash(parsed.Response.CollectedClientData.Challenge)
	var reg *registration
	var ch *store.BreakGlassChallenge
	var allow []string
	err = s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		e := s.env(tx, now, *p.UserID)
		var err error
		if reg, err = e.openRegistration(changeID, *p.UserID); err != nil {
			return err
		}
		if ch, err = tx.BreakGlassChallengeByHash(store.BreakGlassRegistration, hash); err != nil {
			return unknownChallenge(err)
		}
		if ch.ChangeRequestID == nil || *ch.ChangeRequestID != changeID || ch.CreatedBy == nil || *ch.CreatedBy != *p.UserID {
			return unknownChallenge(store.ErrNotFound)
		}
		// single use: spent before the response is looked at, and kept spent
		// when the response is refused
		if err := tx.ConsumeBreakGlassChallenge(ch.ID, now); err != nil {
			return unknownChallenge(err)
		}
		t, err := e.tenantRecord()
		if err != nil {
			return err
		}
		allow = viewSettings(t).aaguids
		return nil
	})
	if err != nil {
		return nil, mapStore(err)
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(ch.SessionData, &sd); err != nil {
		return nil, fmt.Errorf("break-glass challenge %s: %w", ch.ID, err)
	}
	user := &bgWebUser{id: userHandle(reg.user.ID), name: reg.user.DisplayName}
	cred, err := wa.CreateCredential(user, sd, parsed)
	if err != nil {
		var pe *protocol.Error
		detail := err.Error()
		if errors.As(err, &pe) {
			detail = pe.Details
		}
		return nil, s.registrationRejected(ctx, p, reg, "webauthn_verification_failed", newErr(http.StatusUnprocessableEntity,
			"webauthn_verification_failed", "the authenticator's response failed verification: %s", detail), nil)
	}
	trust, rej := checkAttestation(cred, allow)
	if rej != nil {
		return nil, s.registrationRejected(ctx, p, reg, rej.Code, rej, cred)
	}
	aaguid := aaguidText(cred.Authenticator.AAGUID)
	rec := &store.BreakGlassCredential{TenantID: p.TenantID, UserID: reg.user.ID, ChangeRequestID: changeID, CredentialID: cred.ID,
		PublicKey: cred.PublicKey, SignCount: cred.Authenticator.SignCount, AAGUID: aaguid, AttestationFormat: cred.AttestationFormat,
		AttestationTrust: trust, Transports: transportNames(cred.Transport), Label: reg.payload.Label,
		Custodian: reg.payload.Custodian, CreatedAt: now}
	err = s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		e := s.env(tx, now, *p.UserID)
		if _, err := e.openRegistration(changeID, *p.UserID); err != nil {
			return err
		}
		if err := tx.InsertBreakGlassCredential(rec); errors.Is(err, store.ErrDuplicate) {
			return conflict("already_registered", "that key, or this enrolment request, is already registered")
		} else if err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, "breakglass.registered", bgKeyDetail(rec), audit.At(now),
			audit.Target("break_glass_credential", rec.ID.String())); err != nil {
			return err
		}
		body := fmt.Sprintf("A break-glass key was registered: %s (custodian %s, model %s, attestation %s).\n"+
			"Registered by %s. If you did not expect this, revoke it: Admin > Break-glass > Revoke.\n",
			rec.Label, rec.Custodian, rec.AAGUID, rec.AttestationTrust, e.name(*p.UserID))
		return e.queueAll(&changeID, nil, "breakglass.registered", "[Tessera] Break-glass key registered: "+rec.Label, body,
			"bgreg:"+rec.ID.String())
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return rec, nil
}

func unknownChallenge(err error) error {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrBreakGlassState) {
		return newErr(http.StatusBadRequest, "challenge_invalid", "the registration challenge is unknown, expired or already used; start again")
	}
	return err
}

func aaguidText(b []byte) string {
	id, err := uuid.FromBytes(b)
	if err != nil {
		return uuid.Nil.String()
	}
	return id.String()
}

func transportNames(ts []protocol.AuthenticatorTransport) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = string(t)
	}
	return out
}

func bgKeyDetail(c *store.BreakGlassCredential) ojson.Object {
	return ojson.Object{{Key: "credential_id", Value: c.ID.String()}, {Key: "user_id", Value: c.UserID.String()},
		{Key: "change_id", Value: c.ChangeRequestID.String()}, {Key: "label", Value: c.Label},
		{Key: "custodian", Value: c.Custodian}, {Key: "aaguid", Value: c.AAGUID},
		{Key: "attestation_format", Value: c.AttestationFormat}, {Key: "attestation_trust", Value: c.AttestationTrust}}
}

// checkAttestation applies the §15.4 registration policy to a credential the
// library has verified: refuse a backup-eligible key (a synced passkey), an
// unverified user, a "none" or self attestation, and, when the tenant
// lists models, an AAGUID that is not listed. It returns the trust to record.
func checkAttestation(c *webauthn.Credential, allowlist []string) (string, *Error) {
	refuse := func(code, format string, a ...any) (string, *Error) {
		return "", newErr(http.StatusUnprocessableEntity, code, format, a...)
	}
	aaguid := aaguidText(c.Authenticator.AAGUID)
	switch {
	case c.Flags.BackupEligible || c.Flags.BackupState:
		return refuse("backup_eligible_refused", "the authenticator is backup-eligible (a synced passkey); "+
			"break-glass keys must be device-bound hardware keys")
	case !c.Flags.UserVerified:
		return refuse("user_verification_required", "the authenticator did not verify the user (PIN or biometric)")
	case c.AttestationFormat == string(protocol.AttestationFormatNone) || c.AttestationType == string(protocol.AttestationFormatNone):
		return refuse("attestation_none_refused", "the authenticator gave no attestation; break-glass keys must attest their model")
	case c.AttestationType == "basic_surrogate":
		return refuse("attestation_self_refused", "the authenticator gave a self attestation; break-glass keys must attest with a certificate")
	}
	var trust string
	switch c.AttestationType {
	case "basic_full":
		trust = "basic"
	case "attca":
		trust = "attca"
	default:
		return refuse("attestation_unsupported", "attestation type %q is not accepted for a break-glass key", c.AttestationType)
	}
	if len(allowlist) > 0 && !slices.Contains(allowlist, aaguid) {
		return refuse("aaguid_not_allowed", "the authenticator model %s is not in the tenant's break-glass AAGUID allowlist", aaguid)
	}
	return trust, nil
}

// registrationRejected audits a refused registration (its own transaction, so
// the event survives) and returns the refusal.
func (s *Service) registrationRejected(ctx context.Context, p *auth.Principal, reg *registration, reason string, refusal *Error,
	c *webauthn.Credential) error {
	d := ojson.Object{{Key: "change_id", Value: reg.change.ID.String()}, {Key: "user_id", Value: reg.user.ID.String()},
		{Key: "reason", Value: reason}}
	if c != nil {
		d = append(d, ojson.KV{Key: "aaguid", Value: aaguidText(c.Authenticator.AAGUID)},
			ojson.KV{Key: "attestation_format", Value: c.AttestationFormat},
			ojson.KV{Key: "attestation_type", Value: c.AttestationType},
			ojson.KV{Key: "backup_eligible", Value: c.Flags.BackupEligible})
	}
	err := s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		_, err := audit.Record(ctx, tx, "breakglass.registration.rejected", d, audit.At(s.now()),
			audit.Target("admin_change", reg.change.ID.String()), audit.Outcome(store.OutcomeFailure))
		return err
	})
	if err != nil {
		return err
	}
	return refusal
}

// ---------------------------------------------------------------- sign-in

// BeginAssertion starts a break-glass sign-in of a tenant (public: the caller
// is not signed in): the WebAuthn request options with user verification
// required and the tenant's active break-glass keys as the allowed
// credentials. A tenant with no usable key is 404 break_glass_unavailable, the
// same answer the API gives for an unknown tenant.
func (s *Service) BeginAssertion(ctx context.Context, tenant tenancy.ID) (*protocol.CredentialAssertion, error) {
	now := s.now()
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	ctx = anonymous(ctx)
	var assertion *protocol.CredentialAssertion
	err = s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		if err := tx.PurgeBreakGlassChallenges(now.Add(-purgeAfter)); err != nil {
			return err
		}
		keys, err := usableKeys(tx, now)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return errNoBreakGlass
		}
		open, err := tx.CountOpenBreakGlassChallenges(store.BreakGlassAssertion, now)
		if err != nil {
			return err
		}
		if open >= maxOpenAssertions {
			return newErr(http.StatusTooManyRequests, "too_many_requests", "too many break-glass sign-ins are in progress; try again in a few minutes")
		}
		var sd *webauthn.SessionData
		assertion, sd, err = wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired),
			webauthn.WithAllowedCredentials(webauthn.Credentials(waCredentials(keys)).CredentialDescriptors()))
		if err != nil {
			return fmt.Errorf("begin break-glass sign-in: %w", err)
		}
		data, err := sessionJSON(sd)
		if err != nil {
			return err
		}
		h := &store.BreakGlassChallenge{Purpose: store.BreakGlassAssertion, ChallengeHash: challengeHash(sd.Challenge),
			SessionData: data, CreatedAt: now, ExpiresAt: now.Add(CeremonyTTL)}
		if err := tx.InsertBreakGlassChallenge(h); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, "auth.break_glass.challenge", ojson.Object{{Key: "challenge_id", Value: h.ID.String()},
			{Key: "credentials", Value: len(keys)}}, audit.At(now), audit.Target("break_glass_challenge", h.ID.String()))
		return err
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return assertion, nil
}

var errNoBreakGlass = newErr(http.StatusNotFound, "break_glass_unavailable", "break-glass sign-in is not available for this tenant")

// usableKeys lists the active keys of active break-glass users that still
// hold the break_glass role.
func usableKeys(tx *store.TenantTx, now time.Time) ([]*store.BreakGlassCredential, error) {
	all, err := tx.BreakGlassCredentials()
	if err != nil {
		return nil, err
	}
	var out []*store.BreakGlassCredential
	for _, c := range all {
		if c.RevokedAt != nil {
			continue
		}
		if _, err := breakGlassUser(tx, c.UserID, now); errors.Is(err, errNotEligible) {
			continue
		} else if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

var errNotEligible = errors.New("admin: not an active break-glass user")

// breakGlassUser returns the user if it is an active break-glass user with an
// unexpired break_glass role.
func breakGlassUser(tx *store.TenantTx, id uuid.UUID, now time.Time) (*store.PlatformUser, error) {
	u, err := tx.PlatformUser(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotEligible
	}
	if err != nil {
		return nil, err
	}
	if !u.IsBreakGlass || u.Status != "active" {
		return nil, errNotEligible
	}
	as, err := tx.RoleAssignments(u.ID)
	if err != nil {
		return nil, err
	}
	if !auth.AssignedRoles(as, now).Has(auth.RoleBreakGlass) {
		return nil, errNotEligible
	}
	return u, nil
}

// ClientInfo is what the sign-in records about the caller.
type ClientInfo struct{ IP, UserAgent *string }

// SignInResult is a successful break-glass sign-in.
type SignInResult struct {
	Issued auth.Issued
	User   *store.PlatformUser
	Authn  *store.AuthnContextRecord
	Use    *store.BreakGlassUse
}

// errSignInFailed is all an unauthenticated caller learns of a refused
// sign-in; the reason is in the audit event.
var errSignInFailed = newErr(http.StatusUnauthorized, "break_glass_failed", "break-glass sign-in failed")

// SignIn verifies a break-glass assertion (body is the PublicKeyCredential
// JSON) for the tenant and creates the break-glass session. The challenge is
// single use (spent before the response is verified), user verification is
// required, a backup-eligible assertion and a sign count that does not rise
// are refused (a cloned key also raises a critical notification), and a
// success writes auth.break_glass.used and queues a critical notification to
// every admin, every security contact and Tessera security operations, in
// the transaction that creates the session. Every refusal is audited as
// auth.break_glass.rejected; the caller only sees 401 break_glass_failed.
func (s *Service) SignIn(ctx context.Context, tenant tenancy.ID, body []byte, ci ClientInfo) (*SignInResult, error) {
	now := s.now()
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	ctx = anonymous(ctx)
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, s.signInRejected(ctx, tenant, "malformed_response", nil, false)
	}
	hash := challengeHash(parsed.Response.CollectedClientData.Challenge)
	var ch *store.BreakGlassChallenge
	var cred *store.BreakGlassCredential
	var user *store.PlatformUser
	var refusal string
	err = s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		var err error
		if ch, err = tx.BreakGlassChallengeByHash(store.BreakGlassAssertion, hash); errors.Is(err, store.ErrNotFound) {
			refusal = "unknown_challenge"
			return nil
		} else if err != nil {
			return err
		}
		// single use: spent now, and kept spent whatever follows
		if err := tx.ConsumeBreakGlassChallenge(ch.ID, now); errors.Is(err, store.ErrBreakGlassState) {
			refusal = "challenge_expired_or_used"
			return nil
		} else if err != nil {
			return err
		}
		if cred, err = tx.BreakGlassCredentialByCredentialID(parsed.RawID); errors.Is(err, store.ErrNotFound) {
			refusal = "unknown_credential"
			return nil
		} else if err != nil {
			return err
		}
		if user, err = breakGlassUser(tx, cred.UserID, now); errors.Is(err, errNotEligible) {
			refusal = "user_not_eligible"
			return nil
		}
		return err
	})
	if err != nil {
		return nil, mapStore(err)
	}
	if refusal != "" {
		return nil, s.signInRejected(ctx, tenant, refusal, nil, false)
	}
	detail := ojson.Object{{Key: "credential_id", Value: cred.ID.String()}, {Key: "user_id", Value: user.ID.String()}}
	flags := parsed.Response.AuthenticatorData.Flags
	if flags.HasBackupEligible() || flags.HasBackupState() {
		return nil, s.signInRejected(ctx, tenant, "backup_eligible", detail, false)
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(ch.SessionData, &sd); err != nil {
		return nil, fmt.Errorf("break-glass challenge %s: %w", ch.ID, err)
	}
	// The challenge listed every key; the response names one, whose owner is
	// now known: verify against that user and that key only.
	sd.UserID, sd.AllowedCredentialIDs = userHandle(user.ID), nil
	wu := &bgWebUser{id: userHandle(user.ID), name: user.DisplayName, creds: []webauthn.Credential{waCredential(cred)}}
	verified, err := wa.ValidateLogin(wu, sd, parsed)
	if err != nil {
		var pe *protocol.Error
		msg := err.Error()
		if errors.As(err, &pe) {
			msg = pe.Details
		}
		return nil, s.signInRejected(ctx, tenant, "assertion_invalid", append(detail, ojson.KV{Key: "detail", Value: truncate(msg, 300)}), false)
	}
	count := parsed.Response.AuthenticatorData.Counter
	if verified.Authenticator.CloneWarning || ((cred.SignCount > 0 || count > 0) && count <= cred.SignCount) {
		return nil, s.signInRejected(ctx, tenant, "sign_count_regression", append(detail,
			ojson.KV{Key: "stored_sign_count", Value: int64(cred.SignCount)}, ojson.KV{Key: "presented_sign_count", Value: int64(count)}), true)
	}
	res, err := s.openSession(ctx, tenant, cred, user, parsed, count, ci, now)
	if errors.Is(err, store.ErrBreakGlassState) {
		return nil, s.signInRejected(ctx, tenant, "sign_count_regression", detail, true)
	}
	if err != nil {
		return nil, mapStore(err)
	}
	// Tessera security operations read the platform chain (§9.6, §15.5).
	if err := s.DB.InTenant(audit.WithSystemActor(ctx, "break_glass"), tenancy.Platform, func(tx *store.TenantTx) error {
		_, err := audit.Record(ctx, tx, "auth.break_glass.used", ojson.Object{{Key: "tenant_id", Value: tenant.String()},
			{Key: "user_id", Value: user.ID.String()}, {Key: "credential_id", Value: cred.ID.String()},
			{Key: "session_id", Value: res.Issued.Session.ID.String()}}, audit.At(now))
		return err
	}); err != nil {
		s.log().Error("break-glass use was not written to the platform audit chain", "tenant", tenant.String(), "err", err)
	}
	return res, nil
}

// openSession records the verified assertion: the key's new sign count, the
// authentication context, the session, the use, the audit event and the
// critical notification, in one transaction.
func (s *Service) openSession(ctx context.Context, tenant tenancy.ID, cred *store.BreakGlassCredential, user *store.PlatformUser,
	parsed *protocol.ParsedCredentialAssertionData, count uint32, ci ClientInfo, now time.Time) (*SignInResult, error) {
	uid := user.ID.String()
	display := user.DisplayName
	actor := store.AuditActor{Type: store.ActorUser, ID: &uid, Display: &display}
	ctxID := uuid.New()
	summary := (&auth.Principal{Authn: &auth.AuthnContext{ID: ctxID, AAL: 3, PhishingResistant: true, TesseraACR: auth.ACRPhrh,
		AuthTime: now}}).AuditAuthn(now)
	ctx = audit.SetPrincipal(ctx, audit.Principal{Tenant: tenant, Actor: actor, Authn: summary})
	var res *SignInResult
	err := s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		t, err := tx.TenantRecord()
		if err != nil {
			return err
		}
		if err := tx.UseBreakGlassCredential(cred.ID, count, now); err != nil {
			return err
		}
		rec := &store.AuthnContextRecord{ID: ctxID, UserID: user.ID, Protocol: "webauthn", Purpose: "break_glass", AMR: []string{},
			Methods: []string{"hwk", "user"}, AAL: 3, PhishingResistant: true, PhrBasis: "webauthn_attested",
			TesseraACR: string(auth.ACRPhrh), AuthTime: now, IP: ci.IP, UserAgent: ci.UserAgent, MappingProfile: "webauthn",
			MappingVersion: 1, ClaimsSHA256: seal.SHA256Hex(append(append([]byte{}, parsed.Raw.AssertionResponse.AuthenticatorData...),
				parsed.Raw.AssertionResponse.ClientDataJSON...)), CreatedAt: now}
		if err := tx.InsertAuthnContext(rec); err != nil {
			return err
		}
		issued, err := auth.CreateSession(tx, auth.SessionInput{User: user, Authn: rec, Kind: store.SessionBreakGlass, IP: ci.IP,
			UA: ci.UserAgent, Settings: auth.TenantSettings(t.Settings), Now: now})
		if err != nil {
			return err
		}
		use := &store.BreakGlassUse{TenantID: tenant, CredentialID: cred.ID, UserID: user.ID, SessionID: issued.Session.ID, UsedAt: now,
			IP: ci.IP, UserAgent: ci.UserAgent}
		if err := tx.InsertBreakGlassUse(use); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, "auth.break_glass.used", ojson.Object{{Key: "use_id", Value: use.ID.String()},
			{Key: "session_id", Value: issued.Session.ID.String()}, {Key: "authn_context_id", Value: rec.ID.String()},
			{Key: "user_id", Value: user.ID.String()}, {Key: "credential_id", Value: cred.ID.String()},
			{Key: "label", Value: cred.Label}, {Key: "custodian", Value: cred.Custodian}, {Key: "aaguid", Value: cred.AAGUID},
			{Key: "sign_count", Value: int64(count)},
			{Key: "expires_at", Value: issued.Session.AbsoluteExpiresAt.UTC().Format(time.RFC3339)}}, audit.At(now),
			audit.Target("session", issued.Session.ID.String())); err != nil {
			return err
		}
		e := s.env(tx, now, user.ID)
		body := fmt.Sprintf("A BREAK-GLASS SIGN-IN just happened.\n\nKey: %s (custodian %s)\nTime: %s\nFrom: %s\n"+
			"The session lasts at most %d minutes and can only view admin state, disable an IdP connection, change its trust, "+
			"grant tenant_admin (each with a %d hour cooling-off any admin can cancel) and revoke other sessions.\n"+
			"If this was not planned, treat it as a compromise: revoke the key (Admin > Break-glass) and review Admin > Change requests.\n"+
			"An admin must record why break-glass was used: Admin > Break-glass.\n",
			cred.Label, cred.Custodian, now.UTC().Format(time.RFC3339), deref(ci.IP, "unknown address"),
			int(auth.BreakGlassAbsolute/time.Minute), int(BreakGlassCooling/time.Hour))
		if err := e.queueAll(nil, nil, KindBreakGlassUsed, "[Tessera] CRITICAL: break-glass sign-in for your tenant", body,
			"bguse:"+use.ID.String(), SecurityOperations); err != nil {
			return err
		}
		res = &SignInResult{Issued: issued, User: user, Authn: rec, Use: use}
		return nil
	})
	return res, err
}

func deref(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}

// signInRejected audits a refused sign-in in the tenant's chain (its own
// transaction, so the event survives) and returns the generic refusal. A
// cloned key (critical) is also told to every admin, contact and operator.
func (s *Service) signInRejected(ctx context.Context, tenant tenancy.ID, reason string, detail ojson.Object, critical bool) error {
	now := s.now()
	d := append(ojson.Object{{Key: "reason", Value: reason}}, detail...)
	err := s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		ev, err := audit.Record(ctx, tx, "auth.break_glass.rejected", d, audit.At(now), audit.Outcome(store.OutcomeFailure))
		if err != nil || !critical {
			return err
		}
		body := "A break-glass sign-in was refused because the key's sign count did not rise: the key may have been cloned.\n" +
			"Revoke the key now (Admin > Break-glass) and replace it. Audit event " + ev.ID.String() + ".\n"
		return s.env(tx, now, uuid.Nil).queueAll(nil, nil, KindBreakGlassCloned,
			"[Tessera] CRITICAL: a break-glass key may be cloned", body, "bgclone:"+ev.ID.String(), SecurityOperations)
	})
	if err != nil {
		return mapStore(err)
	}
	return errSignInFailed
}

// Notification kinds of break-glass events.
const (
	KindBreakGlassUsed   = "auth.break_glass.used"
	KindBreakGlassAction = "breakglass.action"
	KindBreakGlassCloned = "auth.break_glass.clone_suspected"
)

// NotificationSeverity is "critical" for the notifications that mean a
// break-glass key was used or may be compromised, and "info" otherwise.
func NotificationSeverity(kind string) string {
	switch kind {
	case KindBreakGlassUsed, KindBreakGlassAction, KindBreakGlassCloned:
		return "critical"
	}
	return "info"
}

// ---------------------------------------------------------------- actions

// ActionResult is what a break-glass action did: the change request it filed
// (idp_connection.disable, idp_connection.update_trust, role.grant) or the
// number of sessions it revoked (sessions.revoke_all).
type ActionResult struct {
	Action          string
	Change          *store.AdminChange
	RevokedSessions int64
}

// BreakGlassAction runs one of the actions a break-glass session may take
// (§15.4). It needs the break_glass role, which only a WebAuthn-attested
// AAL3 session has. The first three file the same change request any admin
// could, with no second approver and a BreakGlassCooling cooling-off during
// which any admin can cancel it; role.grant is limited to tenant_admin. Every
// action is audited as breakglass.action and queued as a critical
// notification to all admins, contacts and operators.
func (s *Service) BreakGlassAction(ctx context.Context, p *auth.Principal, action string, payload json.RawMessage) (*ActionResult, error) {
	now := s.now()
	if d := auth.Check(p, auth.PermBreakGlassRecover, nil, now); d != nil {
		return nil, denied(d)
	}
	if p.UserID == nil || p.SessionID == nil || p.Authn == nil || p.Authn.Protocol != "webauthn" {
		return nil, newErr(http.StatusForbidden, "forbidden", "break-glass actions need a break-glass session")
	}
	if action == ActionRevokeAllSessions {
		if len(strings.TrimSpace(string(payload))) > 0 && string(payload) != "{}" && string(payload) != "null" {
			return nil, invalid("%s takes no payload", action)
		}
		return s.revokeAllSessions(ctx, p, now)
	}
	typ, ok := changeTypes[action]
	if !ok || !slices.Contains(Actions(), action) {
		return nil, newErr(http.StatusNotFound, "unknown_action", "unknown break-glass action %q (want one of %s)", action,
			strings.Join(Actions(), ", "))
	}
	if len(payload) == 0 {
		return nil, invalid("payload is required")
	}
	v, canon, err := typ.decode(payload)
	if err != nil {
		return nil, err
	}
	if g, ok := v.(*roleGrantPayload); ok && g.Role != string(auth.RoleTenantAdmin) {
		return nil, invalid("a break-glass session may grant tenant_admin only")
	}
	var ch *store.AdminChange
	err = s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		e := s.env(tx, now, *p.UserID)
		pl, err := typ.plan(e, v)
		if err != nil {
			return err
		}
		eff := now.Add(BreakGlassCooling)
		ch = &store.AdminChange{ID: uuid.New(), TenantID: p.TenantID, Type: typ.name, Payload: canon, PayloadHash: HashPayload(canon),
			TargetID: pl.target, Status: store.ChangeCoolingOff, TwoPerson: false, CoolingOffSeconds: int64(BreakGlassCooling / time.Second),
			RequestedBy: *p.UserID, RequestedAt: now, ExpiresAt: now.Add(ApprovalWindow), EffectiveAt: &eff}
		if err := tx.InsertAdminChange(ch); err != nil {
			return err
		}
		if err := e.transition(ch, TransSubmitted, p.Display); err != nil {
			return err
		}
		return s.recordAction(ctx, e, p, action, ch, 0, "bgaction:"+ch.ID.String(), fmt.Sprintf(
			"A break-glass session requested: %s.\nIt takes effect at %s unless an admin cancels it: Admin > Change requests > Cancel.\n",
			e.describe(ch), eff.UTC().Format(time.RFC3339)))
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return &ActionResult{Action: action, Change: ch}, nil
}

// revokeAllSessions revokes every other session of the tenant.
func (s *Service) revokeAllSessions(ctx context.Context, p *auth.Principal, now time.Time) (*ActionResult, error) {
	var n int64
	err := s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		var err error
		if n, err = tx.RevokeAllSessionsExcept(*p.SessionID, auth.RevokedBreakGlass, now); err != nil {
			return err
		}
		e := s.env(tx, now, *p.UserID)
		return s.recordAction(ctx, e, p, ActionRevokeAllSessions, nil, n, "bgaction:"+uuid.NewString(), fmt.Sprintf(
			"A break-glass session revoked every other session of the tenant (%d). Everyone signs in again.\n", n))
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return &ActionResult{Action: ActionRevokeAllSessions, RevokedSessions: n}, nil
}

// recordAction writes breakglass.action and queues its critical notification,
// in the transaction of the action.
func (s *Service) recordAction(ctx context.Context, e *env, p *auth.Principal, action string, ch *store.AdminChange, revoked int64,
	dedupe, what string) error {
	d := ojson.Object{{Key: "action", Value: action}, {Key: "session_id", Value: p.SessionID.String()},
		{Key: "user_id", Value: p.UserID.String()}}
	var change *uuid.UUID
	if ch != nil {
		change = &ch.ID
		d = append(d, ojson.KV{Key: "change_id", Value: ch.ID.String()}, ojson.KV{Key: "target_id", Value: ch.TargetID},
			ojson.KV{Key: "effective_at", Value: ch.EffectiveAt.UTC().Format(time.RFC3339)})
	} else {
		d = append(d, ojson.KV{Key: "revoked_sessions", Value: revoked})
	}
	if _, err := audit.Record(ctx, e.tx, "breakglass.action", d, audit.At(e.now), audit.Target("session", p.SessionID.String())); err != nil {
		return err
	}
	return e.queueAll(change, nil, KindBreakGlassAction, "[Tessera] CRITICAL: break-glass action: "+action, what, dedupe, SecurityOperations)
}

// ---------------------------------------------------------------- attestation of a use

const (
	minReasonChars = 10
	maxReasonChars = 2000
)

// AttestUse records why a break-glass sign-in happened (§15.4: after use, an
// attestation form is required, and stays on the admin dashboard until it is
// answered). Any tenant admin (admin.change.request) may answer; the
// break-glass session itself cannot.
func (s *Service) AttestUse(ctx context.Context, p *auth.Principal, id uuid.UUID, reason string) (*store.BreakGlassUse, error) {
	now := s.now()
	if d := auth.Check(p, auth.PermAdminChangeReq, nil, now); d != nil {
		return nil, denied(d)
	}
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n < minReasonChars || n > maxReasonChars {
		return nil, invalid("reason is required: %d to %d characters saying why break-glass was used", minReasonChars, maxReasonChars)
	}
	var use *store.BreakGlassUse
	err := s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		var err error
		if use, err = tx.BreakGlassUse(id); errors.Is(err, store.ErrNotFound) {
			return notFound("break-glass use")
		} else if err != nil {
			return err
		}
		if err := tx.AnswerBreakGlassUse(id, *p.UserID, reason, now); errors.Is(err, store.ErrBreakGlassState) {
			return conflict("already_attested", "this break-glass use was already explained")
		} else if err != nil {
			return err
		}
		if use, err = tx.BreakGlassUse(id); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, "breakglass.use.attested", ojson.Object{{Key: "use_id", Value: id.String()},
			{Key: "session_id", Value: use.SessionID.String()}, {Key: "by", Value: p.Display}, {Key: "reason", Value: reason}},
			audit.At(now), audit.Target("break_glass_use", id.String()))
		return err
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return use, nil
}
