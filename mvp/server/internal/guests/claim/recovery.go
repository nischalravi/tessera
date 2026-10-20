package claim

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/terms"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Account recovery (guest accounts design §7.5, issue #73).
//
// A sponsor or the help desk issues a purpose=recovery claim token for a guest
// who has lost their sign-in. The person goes through the same claim session
// (contact code, then identity verification, then the credential), with these
// differences:
//
//   - the identity is already active, with a platform user; recovery adds the
//     new sign-in to that user, it does not make a new one;
//   - the identity must be re-verified at its RECORDED IAL, never lower, whatever
//     the sponsorship now says (RequiredIAL of the case);
//   - every channel on file is told when a recovery starts, waits, finishes or is
//     cancelled (notify.GuestRecoveryNotice);
//   - an identity that holds a privileged or high-risk bundle waits 24 hours
//     (CoolingOff) between the new sign-in and its activation, so the owner of
//     the account can object; all the user's sessions end when it activates.
//
// Federated identities recover at their home IdP and customer-IdP identities use
// the IdP's own recovery: this is the Tessera re-claim path (§7.5).

// CoolingOff is how long a recovered privileged account waits for its new sign-in.
const CoolingOff = 24 * time.Hour

// RecoveryLifetime is how long a recovery link works.
const RecoveryLifetime = 24 * time.Hour

// Refusals of the recovery path, for the audit event.
var (
	ErrTerms    = errors.New("claim: terms of use are outstanding")
	ErrConsent  = errors.New("claim: the attribute-release consent is not recorded")
	ErrIAL      = errors.New("claim: identity assurance is below the identity's recorded level")
	ErrNoUser   = errors.New("claim: the identity has no sign-in user to recover")
	ErrCoolDone = errors.New("claim: not in cooling-off")
)

// IsRecovery reports whether the session is a recovery of an existing account.
func IsRecovery(sess *store.ClaimSession) bool {
	return readVerified(sess).Purpose == store.ClaimPurposeRecovery
}

// RecoveryInput says who is recovering whom.
type RecoveryInput struct {
	IdentityID int64
	IssuedBy   string // the issuing user's id, for the record
	Via        string // store.RecoveryViaSponsor or store.RecoveryViaDesk
	Reason     string
}

// Recovered is an issued recovery. It holds no secret.
type Recovered struct {
	Case           *store.RecoveryCase
	TokenID        string
	NotificationID string
	ExpiresAt      time.Time
}

type bundleItemRef struct {
	GroupID    int64  `json:"group_id"`
	Risk       string `json:"risk"`
	Privileged bool   `json:"privileged"`
}

// liveSponsorshipOf is the guest's live sponsorship, whichever intake it came with.
func liveSponsorshipOf(tx *store.TenantTx, guest int64) (*store.Sponsorship, error) {
	all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: guest})
	if err != nil {
		return nil, err
	}
	for _, x := range all {
		if x.Live() {
			return x, nil
		}
	}
	return nil, nil
}

// HoldsPrivileged reports whether the guest holds, or is about to hold, a
// privileged or high-risk access bundle.
func HoldsPrivileged(tx *store.TenantTx, guest int64) (bool, error) {
	all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: guest})
	if err != nil {
		return false, err
	}
	for _, s := range all {
		if !s.Live() {
			continue
		}
		var items []bundleItemRef
		if s.AccessBundle != "" && json.Unmarshal([]byte(s.AccessBundle), &items) == nil {
			if slices.ContainsFunc(items, func(i bundleItemRef) bool { return i.Privileged || i.Risk == "high" }) {
				return true, nil
			}
		}
	}
	rows, err := tx.BundleItems(store.BundleItemFilter{Guest: guest})
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.Status == "removed" {
			continue
		}
		g, err := tx.Group(r.GroupID)
		if err != nil {
			return false, err
		}
		if g.Privileged {
			return true, nil
		}
	}
	return false, nil
}

// RecordedIAL is the identity assurance level on record for a person (0 when none).
func RecordedIAL(tx *store.TenantTx, identity int64) (int, error) {
	a, err := tx.IdentityAssurance(identity)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return a.IAL, nil
}

// IssueRecovery makes a recovery link for an active guest, emails it to the
// guest's address, tells every channel on file, and records the case. Any
// earlier open recovery of the person is cancelled. The required IAL is the
// higher of the sponsorship's and the one on record: a recovery never asks for
// less than the identity was proven at. Call it in the caller's transaction.
func (s *Service) IssueRecovery(tx *store.TenantTx, in RecoveryInput, now time.Time) (*Recovered, error) {
	if !s.Ready() {
		return nil, refuse(503, "claim_unavailable", "recovery links need TESSERA_PUBLIC_URL and the identifier key")
	}
	if in.Via != store.RecoveryViaSponsor && in.Via != store.RecoveryViaDesk {
		return nil, refuse(422, "invalid_via", "via is sponsor or help_desk")
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) > 500 {
		return nil, refuse(422, "invalid_reason", "the reason is at most 500 characters")
	}
	guest, err := tx.Identity(in.IdentityID)
	if err != nil {
		return nil, err
	}
	ss, err := liveSponsorshipOf(tx, guest.ID)
	if err != nil {
		return nil, err
	}
	switch {
	case guest.Status != "active" || ss == nil:
		return nil, refuse(409, "not_recoverable", "only a guest with active access can be recovered")
	case guest.Email == nil || strings.TrimSpace(*guest.Email) == "":
		return nil, refuse(422, "no_email", "the guest has no email address on file")
	}
	if users, err := tx.UsersLinkedTo(guest.ID); err != nil {
		return nil, err
	} else if len(users) == 0 {
		return nil, refuse(409, "not_recoverable", "the guest has no sign-in to recover")
	}
	mac, err := s.ContactHash(tx.Tenant(), *guest.Email)
	if err != nil {
		return nil, refuse(422, "invalid_email", "%s", err.Error())
	}
	ial, err := RecordedIAL(tx, guest.ID)
	if err != nil {
		return nil, err
	}
	ial = max(ial, ss.RequiredIAL)
	priv, err := HoldsPrivileged(tx, guest.ID)
	if err != nil {
		return nil, err
	}
	// a new recovery replaces any open one
	open, err := tx.OpenRecoveryCases(guest.ID)
	if err != nil {
		return nil, err
	}
	for _, o := range open {
		if err := s.cancelCase(tx, o, "superseded", now); err != nil {
			return nil, err
		}
	}
	if _, err := tx.RevokeRecoveryTokens(guest.ID); err != nil {
		return nil, err
	}
	token := NewToken()
	expires := now.Add(RecoveryLifetime)
	if ss.EndsAt.Before(expires) {
		expires = ss.EndsAt
	}
	if !expires.After(now) {
		return nil, refuse(409, "not_recoverable", "the sponsorship ends before a link could be used")
	}
	t := &store.ClaimToken{ID: uuid.NewString(), IntakeID: ss.IntakeID, IdentityID: guest.ID, Kind: store.ClaimKindLink,
		Purpose: store.ClaimPurposeRecovery, TokenHash: HashToken(tx.Tenant(), token), EmailHMAC: mac, Status: store.ClaimIssued,
		NotBefore: now, ExpiresAt: expires, CreatedAt: now}
	if err := tx.InsertClaimToken(t); err != nil {
		return nil, err
	}
	c := &store.RecoveryCase{ID: uuid.NewString(), IdentityID: guest.ID, IntakeID: ss.IntakeID, TokenID: t.ID, IssuedBy: in.IssuedBy,
		Via: in.Via, Reason: reason, RequiredIAL: ial, Privileged: priv, Status: store.RecoveryIssued, CreatedAt: now, UpdatedAt: now}
	if err := tx.InsertRecoveryCase(c); err != nil {
		return nil, err
	}
	tenant := s.tenantName(tx.Context(), tx.Tenant())
	nid, err := notify.GuestRecoveryLink(tx, now, t.ID, guest.ID, strings.TrimSpace(*guest.Email), guest.Name, tenant, expires)
	if err != nil {
		return nil, err
	}
	// the link goes to the dispatcher through memory only
	s.Secrets.Put(nid, "Your one-time recovery link:\n"+s.BaseURL+"/claim#t="+token, expires)
	if err := notify.GuestRecoveryNotice(tx, now, notify.RecoveryStageIssued, c, ss.SponsorIdentityID, tenant, nil); err != nil {
		return nil, err
	}
	err = auditEvent(tx, now, "recovery.issue", "identity", int64s(guest.ID), ojson.Object{{Key: "case_id", Value: c.ID},
		{Key: "identity_id", Value: guest.ID}, {Key: "token_id", Value: t.ID}, {Key: "notification_id", Value: nid},
		{Key: "via", Value: in.Via}, {Key: "issued_by", Value: in.IssuedBy}, {Key: "required_ial", Value: ial},
		{Key: "privileged", Value: priv}, {Key: "expires_at", Value: expires.UTC().Format("2006-01-02T15:04:05Z")}})
	return &Recovered{Case: c, TokenID: t.ID, NotificationID: nid, ExpiresAt: expires}, err
}

// cancelCase ends an open case: its sessions and token stop working.
func (s *Service) cancelCase(tx *store.TenantTx, c *store.RecoveryCase, reason string, now time.Time) error {
	c.Status, c.UpdatedAt = store.RecoveryCaseCancelled, now
	c.CoolingUntil = nil
	if err := tx.SaveRecoveryCase(c); err != nil {
		return err
	}
	if _, err := tx.RevokeRecoveryTokens(c.IdentityID); err != nil {
		return err
	}
	if err := tx.RevokeClaimSessions(c.IntakeID, now); err != nil {
		return err
	}
	return auditEvent(tx, now, "recovery.cancel", "identity", int64s(c.IdentityID), ojson.Object{{Key: "case_id", Value: c.ID},
		{Key: "identity_id", Value: c.IdentityID}, {Key: "reason", Value: reason}})
}

// CancelRecovery ends an open recovery (including one in its cooling-off) and
// tells every channel on file. The sign-in that was in place stays.
func (s *Service) CancelRecovery(tx *store.TenantTx, caseID, reason string, now time.Time) error {
	c, err := tx.RecoveryCase(caseID)
	if err != nil {
		return err
	}
	switch c.Status {
	case store.RecoveryIssued, store.RecoveryStarted, store.RecoveryCooling:
	default:
		return refuse(409, "not_open", "this recovery is already %s", c.Status)
	}
	if err := s.cancelCase(tx, c, reason, now); err != nil {
		return err
	}
	ss, err := liveSponsorshipOf(tx, c.IdentityID)
	if err != nil {
		return err
	}
	var sponsor int64
	if ss != nil {
		sponsor = ss.SponsorIdentityID
	}
	return notify.GuestRecoveryNotice(tx, now, notify.RecoveryStageCancelled, c, sponsor, s.tenantName(tx.Context(), tx.Tenant()), nil)
}

// RecoveryOutcome is what finishing the credential step of a recovery did.
type RecoveryOutcome struct {
	// Cooling is true when the new sign-in waits for Until (a privileged account).
	Cooling bool
	Until   time.Time
}

// outstandingGate refuses a claim or recovery that has terms outstanding or a
// consent not recorded: acceptance comes before a credential is bound.
func (s *Service) outstandingGate(tx *store.TenantTx, sess *store.ClaimSession, authority string, now time.Time) error {
	reqs, err := terms.Required(tx, sess.IdentityID, now)
	if err != nil {
		return err
	}
	if len(terms.Outstanding(reqs)) > 0 {
		return ErrTerms
	}
	if terms.ConsentApplies(authority) {
		given, err := terms.ConsentGiven(tx, sess.IDHash)
		if err != nil {
			return err
		}
		if !given {
			return ErrConsent
		}
	}
	return nil
}

// CompleteRecovery finishes a recovery after a sign-in at the required assurance
// level through the bound authority. The new sign-in is added to the existing
// user (a sign-in that already belongs to another user is refused). For an
// identity with a privileged bundle it is held 24 hours (cooling-off) and
// bound by ActivateDue; otherwise it is bound now. Every refusal comes before
// the first write.
func (s *Service) CompleteRecovery(tx *store.TenantTx, sess *store.ClaimSession, b Binding, now time.Time) (*RecoveryOutcome, error) {
	if sess.Step != StepCredential || sess.CompletedAt != nil || sess.RevokedAt != nil {
		return nil, ErrNotReady
	}
	if sess.CredentialSubject == nil || !seal.Equal([]byte(*sess.CredentialSubject), []byte(b.Subject)) {
		return nil, ErrSubject
	}
	c, err := tx.RecoveryCaseBySession(sess.IDHash)
	if errors.Is(err, store.ErrNotFound) || err == nil && c.Status != store.RecoveryStarted {
		return nil, ErrNotReady
	}
	if err != nil {
		return nil, err
	}
	guest, err := tx.Identity(sess.IdentityID)
	if err != nil {
		return nil, err
	}
	ss, err := liveSponsorshipOf(tx, guest.ID)
	if err != nil {
		return nil, err
	}
	if ss == nil || guest.Status != "active" {
		return nil, ErrNotReady
	}
	v := readVerified(sess)
	if v.IAL < c.RequiredIAL {
		return nil, ErrIAL
	}
	if !MeetsAAL(ss.RequiredAAL, b.AAL, b.ACR) {
		return nil, ErrAAL
	}
	if err := s.outstandingGate(tx, sess, b.Authority, now); err != nil {
		return nil, err
	}
	user, err := recoveryUser(tx, guest.ID)
	if err != nil {
		return nil, err
	}
	if err := checkSubjectFree(tx, user, b.ConnectionID, b.Subject); err != nil {
		return nil, err
	}
	v.AAL, v.ACR, v.Authority = b.AAL, b.ACR, b.Authority
	saveVerified(sess, v)
	sess.Step, sess.CompletedAt, sess.LastSeenAt = StepComplete, &now, now
	if err := tx.SaveClaimSession(sess); err != nil {
		return nil, err
	}
	tenant := s.tenantName(tx.Context(), tx.Tenant())
	email := b.Email
	conn := b.ConnectionID.String()
	c.PendingConnectionID, c.PendingIssuer, c.PendingSubject, c.PendingEmail = &conn, &b.Issuer, &b.Subject, &email
	if c.Privileged {
		until := now.Add(CoolingOff)
		c.Status, c.CoolingUntil, c.UpdatedAt = store.RecoveryCooling, &until, now
		if err := tx.SaveRecoveryCase(c); err != nil {
			return nil, err
		}
		if err := notify.GuestRecoveryNotice(tx, now, notify.RecoveryStageCooling, c, ss.SponsorIdentityID, tenant, &until); err != nil {
			return nil, err
		}
		return &RecoveryOutcome{Cooling: true, Until: until}, auditEvent(tx, now, "recovery.cooling_off", "identity", int64s(guest.ID),
			ojson.Object{{Key: "case_id", Value: c.ID}, {Key: "identity_id", Value: guest.ID}, {Key: "until", Value: until.UTC().Format("2006-01-02T15:04:05Z")},
				{Key: "aal", Value: b.AAL}, {Key: "acr", Value: b.ACR}})
	}
	return &RecoveryOutcome{}, s.activate(tx, c, user, ss.SponsorIdentityID, now)
}

// recoveryUser is the platform user a recovery adds a sign-in to.
func recoveryUser(tx *store.TenantTx, identity int64) (uuid.UUID, error) {
	users, err := tx.UsersLinkedTo(identity)
	if err != nil {
		return uuid.Nil, err
	}
	if len(users) == 0 {
		return uuid.Nil, ErrNoUser
	}
	return uuid.Parse(users[0])
}

// checkSubjectFree refuses a sign-in that belongs to a different user. One that
// already belongs to this user is the same account recovered at its authority.
func checkSubjectFree(tx *store.TenantTx, user, connection uuid.UUID, subject string) error {
	ext, err := tx.ExternalLoginBySubject(connection, subject)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	case ext.UserID != user:
		return ErrSubjectBound
	}
	return nil
}

// activate binds the recovered sign-in, ends the user's sessions, completes the
// case and tells every channel on file.
func (s *Service) activate(tx *store.TenantTx, c *store.RecoveryCase, user uuid.UUID, sponsor int64, now time.Time) error {
	if c.PendingConnectionID == nil || c.PendingIssuer == nil || c.PendingSubject == nil {
		return ErrNotReady
	}
	conn, err := uuid.Parse(*c.PendingConnectionID)
	if err != nil {
		return err
	}
	if err := checkSubjectFree(tx, user, conn, *c.PendingSubject); err != nil {
		return err
	}
	if _, err := tx.ExternalLoginBySubject(conn, *c.PendingSubject); errors.Is(err, store.ErrNotFound) {
		var email *string
		if c.PendingEmail != nil && *c.PendingEmail != "" {
			email = c.PendingEmail
		}
		if err := tx.InsertExternalLogin(&store.ExternalLogin{UserID: user, IdPConnectionID: conn, Issuer: *c.PendingIssuer,
			Subject: *c.PendingSubject, EmailAtLastLogin: email, CreatedAt: now}); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	ended, err := tx.RevokeUserSessions(user, "account_recovery", now)
	if err != nil {
		return err
	}
	c.Status, c.CompletedAt, c.CoolingUntil, c.UpdatedAt = store.RecoveryCaseCompleted, &now, nil, now
	if err := tx.SaveRecoveryCase(c); err != nil {
		return err
	}
	if err := notify.GuestRecoveryNotice(tx, now, notify.RecoveryStageCompleted, c, sponsor, s.tenantName(tx.Context(), tx.Tenant()), nil); err != nil {
		return err
	}
	return auditEvent(tx, now, "recovery.complete", "identity", int64s(c.IdentityID), ojson.Object{{Key: "case_id", Value: c.ID},
		{Key: "identity_id", Value: c.IdentityID}, {Key: "user_id", Value: user.String()}, {Key: "sessions_ended", Value: ended},
		{Key: "privileged", Value: c.Privileged}})
}

// ActivateDue binds the new sign-in of every recovery whose cooling-off has
// ended. A case whose guest is no longer active, or whose sign-in has meanwhile
// been taken, is cancelled instead. It says how many it finished.
func (s *Service) ActivateDue(tx *store.TenantTx, now time.Time) (int, error) {
	due, err := tx.DueRecoveries(now)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range due {
		guest, err := tx.Identity(c.IdentityID)
		if err != nil {
			return n, err
		}
		ss, err := liveSponsorshipOf(tx, c.IdentityID)
		if err != nil {
			return n, err
		}
		user, uerr := recoveryUser(tx, c.IdentityID)
		if guest.Status != "active" || ss == nil || uerr != nil {
			if uerr != nil && !errors.Is(uerr, ErrNoUser) {
				return n, uerr
			}
			if err := s.cancelCase(tx, c, "identity_not_active", now); err != nil {
				return n, err
			}
			continue
		}
		if err := s.activate(tx, c, user, ss.SponsorIdentityID, now); errors.Is(err, ErrSubjectBound) {
			if err := s.cancelCase(tx, c, "subject_already_bound", now); err != nil {
				return n, err
			}
			continue
		} else if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ---------------------------------------------------------------- recovery codes

// RecoveryCodeCount is how many codes a hosted identity gets.
const RecoveryCodeCount = 10

const recoveryCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0 O 1 I

const recoveryCodePurpose = "recovery-code"

func normalizeCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
}

func (s *Service) codeHash(tx *store.TenantTx, identity int64, norm string) (string, error) {
	return s.Keyer.MAC(tx.Tenant(), recoveryCodePurpose, strconv.FormatInt(identity, 10), norm)
}

// GenerateRecoveryCodes makes a new batch of 10 single-use codes for a hosted
// identity and voids the earlier batch. The codes are returned once and never
// stored: only a tenant-keyed hash of each is. Call it in the caller's
// transaction; the audit event names the batch and the count, never a code.
func (s *Service) GenerateRecoveryCodes(tx *store.TenantTx, identity int64, now time.Time) ([]string, error) {
	if s.Keyer == nil {
		return nil, refuse(503, "claim_unavailable", "recovery codes need the identifier key")
	}
	if _, err := tx.Identity(identity); err != nil {
		return nil, err
	}
	voided, err := tx.VoidRecoveryCodes(identity, now)
	if err != nil {
		return nil, err
	}
	batch := uuid.NewString()
	codes := make([]string, 0, RecoveryCodeCount)
	for len(codes) < RecoveryCodeCount {
		raw := randomCode()
		h, err := s.codeHash(tx, identity, normalizeCode(raw))
		if err != nil {
			return nil, err
		}
		if err := tx.InsertRecoveryCode(&store.RecoveryCode{ID: uuid.NewString(), IdentityID: identity, Batch: batch, CodeHash: h, CreatedAt: now}); err != nil {
			return nil, err
		}
		codes = append(codes, raw)
	}
	return codes, auditEvent(tx, now, "recovery.codes.generate", "identity", int64s(identity), ojson.Object{{Key: "identity_id", Value: identity},
		{Key: "batch", Value: batch}, {Key: "count", Value: len(codes)}, {Key: "voided", Value: voided}})
}

// UseRecoveryCode spends one of the identity's codes. It is true once for each
// code and false for a wrong, spent or voided one; both outcomes are audited
// (without the code).
func (s *Service) UseRecoveryCode(tx *store.TenantTx, identity int64, code string, now time.Time) (bool, error) {
	if s.Keyer == nil {
		return false, refuse(503, "claim_unavailable", "recovery codes need the identifier key")
	}
	h, err := s.codeHash(tx, identity, normalizeCode(code))
	if err != nil {
		return false, err
	}
	err = tx.UseRecoveryCode(identity, h, now)
	ok := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	outcome := store.OutcomeSuccess
	if !ok {
		outcome = store.OutcomeFailure
	}
	return ok, auditEvent(tx, now, "recovery.code.use", "identity", int64s(identity),
		ojson.Object{{Key: "identity_id", Value: identity}}, audit.Outcome(outcome))
}

func randomChars(n int) string { return seal.RandomString(n, recoveryCodeAlphabet) }

func randomCode() string {
	r := randomChars(12)
	return r[:4] + "-" + r[4:8] + "-" + r[8:]
}
