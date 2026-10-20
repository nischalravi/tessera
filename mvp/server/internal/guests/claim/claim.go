package claim

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Steps of a claim, in order. The list is the single place that knows the
// order, so a later step (identity verification, terms, recovery) is added here.
const (
	StepVerifyContact   = "verify_contact"
	StepVerifyIdentity  = "verify_identity" // IAL above 0: GU-7, not built; the claim waits here
	StepExistingAccount = "existing_account"
	StepCredential      = "credential"
	StepComplete        = "complete"
)

// Steps lists the steps in order (the "start" step is the exchange of the link).
var Steps = []string{StepVerifyContact, StepVerifyIdentity, StepExistingAccount, StepCredential, StepComplete}

// Lifetimes and limits.
const (
	DefaultIdleTTL     = 60 * time.Minute
	DefaultAbsoluteTTL = 24 * time.Hour
	DefaultCodeTTL     = 10 * time.Minute
	CodeAttempts       = 5
	contactIssuer      = "claim-contact" // issuer of the invited address's keyed hash
	codePurpose        = "confirmation-code"
)

// Error is a refused change; Code is stable for API clients.
type Error = requests.Error

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// ErrNoSession is the one answer for a missing, expired, revoked or unknown session.
var ErrNoSession = errors.New("claim: no valid session")

// Service issues claim links and runs claims. The zero value is not usable;
// set Keyer, Secrets and BaseURL.
type Service struct {
	Keyer   *identifiers.Keyer
	Secrets *notify.Secrets
	// BaseURL is the public base URL of the claim page (TESSERA_PUBLIC_URL):
	// the link is BaseURL + "/claim#t=" + token.
	BaseURL string
	// Names returns a tenant's display name (the emails and the claim page show it).
	Names func(ctx context.Context, t tenancy.ID) string

	IdleTTL, AbsoluteTTL, CodeTTL time.Duration
	// Replays is the memory of accepted proofs (see proof.go).
	Replays *Replays
}

// New returns a Service.
func New(k *identifiers.Keyer, secrets *notify.Secrets, baseURL string, names func(context.Context, tenancy.ID) string) *Service {
	return &Service{Keyer: k, Secrets: secrets, BaseURL: strings.TrimRight(baseURL, "/"), Names: names, Replays: NewReplays()}
}

func (s *Service) idle() time.Duration {
	if s.IdleTTL > 0 {
		return s.IdleTTL
	}
	return DefaultIdleTTL
}

func (s *Service) absolute() time.Duration {
	if s.AbsoluteTTL > 0 {
		return s.AbsoluteTTL
	}
	return DefaultAbsoluteTTL
}

// CodeLifetime is how long a confirmation code works.
func (s *Service) CodeLifetime() time.Duration {
	if s.CodeTTL > 0 {
		return s.CodeTTL
	}
	return DefaultCodeTTL
}

// AbsoluteLifetime is how long a claim session lives at most.
func (s *Service) AbsoluteLifetime() time.Duration { return s.absolute() }

func (s *Service) tenantName(ctx context.Context, t tenancy.ID) string {
	if s.Names != nil {
		if n := s.Names(ctx, t); n != "" {
			return n
		}
	}
	return "your organization"
}

// Ready reports whether the service can issue links (a key and a public URL).
func (s *Service) Ready() bool {
	return s != nil && s.Keyer != nil && s.Secrets != nil && s.BaseURL != ""
}

// ContactHash is the tenant-keyed hash of an address, the same for every
// invitation of that address (it is how "send me a new link" finds one).
func (s *Service) ContactHash(t tenancy.ID, email string) (string, error) {
	_, mac, err := s.Keyer.Digest(t, store.IdentEmail, contactIssuer, email)
	return mac, err
}

// liveSponsorship is the live sponsorship that owns the intake.
func liveSponsorship(tx *store.TenantTx, intakeID string, guest int64) (*store.Sponsorship, error) {
	all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: guest})
	if err != nil {
		return nil, err
	}
	for _, x := range all {
		if x.IntakeID == intakeID && x.Live() {
			return x, nil
		}
	}
	return nil, nil
}

// Issued is a new invitation. It holds no secret.
type Issued struct {
	TokenID        string
	NotificationID string
	ExpiresAt      time.Time
}

// Issue makes a new claim link for the sponsorship's guest and emails it. It
// revokes every earlier token (and open session) of the intake, stores only the
// new token's hash, queues the invitation email through the notification outbox
// (the link is handed to the dispatcher in memory, never stored: notify.Secrets)
// and moves the intake's invitation to "sent". via is "activation", "resend" or
// "requested". Call it in the caller's transaction.
func (s *Service) Issue(tx *store.TenantTx, ss *store.Sponsorship, via string, now time.Time) (*Issued, error) {
	if !s.Ready() {
		return nil, refuse(503, "claim_unavailable", "claim links need TESSERA_PUBLIC_URL and the identifier key")
	}
	if !ss.Live() {
		return nil, refuse(409, "not_active", "the sponsorship is not active")
	}
	guest, err := tx.Identity(ss.GuestIdentityID)
	if err != nil {
		return nil, err
	}
	intake, err := tx.Intake(ss.IntakeID)
	if err != nil {
		return nil, err
	}
	switch {
	case guest.Status != "invited" || intake.InvitationStatus == store.InvitationClaimed:
		return nil, refuse(409, "already_claimed", "this guest has already claimed their invitation")
	case intake.InvitationStatus == store.InvitationRevoked:
		return nil, refuse(409, "invitation_revoked", "this invitation was revoked; invite the person again")
	case guest.Email == nil || strings.TrimSpace(*guest.Email) == "":
		return nil, refuse(422, "no_email", "the guest has no email address to invite")
	}
	mac, err := s.ContactHash(tx.Tenant(), *guest.Email)
	if err != nil {
		return nil, refuse(422, "invalid_email", "%s", err.Error())
	}
	sponsor, err := tx.Identity(ss.SponsorIdentityID)
	if err != nil {
		return nil, err
	}
	if _, err := tx.RevokeClaimTokens(intake.ID); err != nil {
		return nil, err
	}
	if err := tx.RevokeClaimSessions(intake.ID, now); err != nil {
		return nil, err
	}
	token := NewToken()
	expires := now.Add(Lifetime(ss.Population))
	if ss.EndsAt.Before(expires) {
		expires = ss.EndsAt
	}
	if !expires.After(now) {
		return nil, refuse(409, "not_active", "the sponsorship ends before a link could be used")
	}
	t := &store.ClaimToken{ID: uuid.NewString(), IntakeID: intake.ID, IdentityID: guest.ID, Kind: store.ClaimKindLink,
		Purpose: store.ClaimPurposeClaim, TokenHash: HashToken(tx.Tenant(), token), EmailHMAC: mac, Status: store.ClaimIssued,
		NotBefore: now, ExpiresAt: expires, CreatedAt: now}
	if err := tx.InsertClaimToken(t); err != nil {
		return nil, err
	}
	nid, err := notify.GuestInvitation(tx, now, notify.GuestInvite{TokenID: t.ID, IdentityID: guest.ID, Email: strings.TrimSpace(*guest.Email),
		Name: firstName(guest.Name), Tenant: s.tenantName(tx.Context(), tx.Tenant()), Sponsor: sponsor.Name, Population: ss.Population,
		EndsAt: ss.EndsAt, Expires: expires})
	if err != nil {
		return nil, err
	}
	// the link goes to the dispatcher through memory only
	s.Secrets.Put(nid, "Your one-time link:\n"+s.BaseURL+"/claim#t="+token, expires)
	if err := tx.SetIntakeInvitation(intake.ID, store.InvitationSent, now); err != nil {
		return nil, err
	}
	err = auditEvent(tx, now, "claim.invitation.issue", "intake", intake.ID, ojson.Object{{Key: "intake_id", Value: intake.ID},
		{Key: "token_id", Value: t.ID}, {Key: "notification_id", Value: nid}, {Key: "guest_identity_id", Value: guest.ID},
		{Key: "sponsorship_id", Value: ss.ID}, {Key: "population", Value: ss.Population},
		{Key: "expires_at", Value: expires.UTC().Format("2006-01-02T15:04:05Z")}, {Key: "via", Value: via}})
	return &Issued{TokenID: t.ID, NotificationID: nid, ExpiresAt: expires}, err
}

// Revoke cancels the invitation of the sponsorship's intake: its tokens and
// open sessions stop working and the intake reads "revoked" (a claimed one is
// left alone).
func (s *Service) Revoke(tx *store.TenantTx, ss *store.Sponsorship, reason string, now time.Time) error {
	intake, err := tx.Intake(ss.IntakeID)
	if err != nil {
		return err
	}
	if intake.InvitationStatus == store.InvitationClaimed || intake.InvitationStatus == store.InvitationRevoked {
		return nil
	}
	n, err := tx.RevokeClaimTokens(intake.ID)
	if err != nil {
		return err
	}
	if err := tx.RevokeClaimSessions(intake.ID, now); err != nil {
		return err
	}
	if err := tx.SetIntakeInvitation(intake.ID, store.InvitationRevoked, now); err != nil {
		return err
	}
	return auditEvent(tx, now, "claim.invitation.revoke", "intake", intake.ID, ojson.Object{{Key: "intake_id", Value: intake.ID},
		{Key: "sponsorship_id", Value: ss.ID}, {Key: "tokens_revoked", Value: n}, {Key: "reason", Value: reason}})
}

func firstName(full string) string {
	f := strings.Fields(full)
	if len(f) == 0 {
		return "there"
	}
	return f[0]
}

// auditEvent records a claim event. It never carries a token, a code or a cookie.
func auditEvent(tx *store.TenantTx, now time.Time, action, targetType, targetID string, detail ojson.Object, opts ...audit.Option) error {
	opts = append([]audit.Option{audit.At(now), audit.Target(targetType, targetID)}, opts...)
	_, err := audit.Record(tx.Context(), tx, action, detail, opts...)
	return err
}

// Audit records a claim event from the API layer (throttles, refused proofs).
func Audit(tx *store.TenantTx, now time.Time, action string, detail ojson.Object, outcome string) error {
	return auditEvent(tx, now, action, "claim", "-", detail, audit.Outcome(outcome))
}

// ---------------------------------------------------------------- start

// Started is a new claim session. Cookie is the one place the session's secret
// exists in clear: the API sets it and forgets it.
type Started struct {
	Cookie  string
	Nonce   string
	Session *store.ClaimSession
}

// Refusal reasons of Start, for the audit event (never shown to the caller).
const (
	ReasonUnknown   = "unknown"
	ReasonExpired   = "expired"
	ReasonUsed      = "used"
	ReasonRevoked   = "revoked"
	ReasonNotActive = "not_active"
)

// dummyHash is compared in constant time when no token matched, so the path
// does the same work whether or not the token exists.
var dummyHash = HashToken(tenancy.Platform, "dummy-token-for-the-constant-time-path")

// Start exchanges a claim token for a session. A token that is unknown, expired,
// used, revoked or whose sponsorship is no longer running yields a non-empty
// reason and no error: the caller answers all of them identically. The token is
// consumed by one atomic UPDATE (ConsumeClaimToken); the first of two
// concurrent starts wins. keyJSON is the public key the page generated; pub
// has been checked by the caller (ParseKey) before the token is touched, so a
// malformed request never burns a token.
func (s *Service) Start(tx *store.TenantTx, token, canonicalKey, jkt string, now time.Time) (*Started, string, error) {
	hash := HashToken(tx.Tenant(), token)
	t, err := tx.ClaimTokenByHash(hash)
	stored, found := dummyHash, false
	switch {
	case err == nil:
		stored, found = t.TokenHash, true
	case !errors.Is(err, store.ErrNotFound):
		return nil, "", err
	}
	if !seal.Equal([]byte(stored), []byte(hash)) || !found {
		return nil, ReasonUnknown, nil
	}
	switch {
	case t.Status == store.ClaimConsumed || t.Status == store.ClaimLocked:
		return nil, ReasonUsed, nil
	case t.Status == store.ClaimRevoked:
		return nil, ReasonRevoked, nil
	case t.Status == store.ClaimExpired || !now.Before(t.ExpiresAt):
		return nil, ReasonExpired, nil
	case t.Purpose != store.ClaimPurposeClaim && t.Purpose != store.ClaimPurposeRecovery || now.Before(t.NotBefore):
		return nil, ReasonUnknown, nil
	}
	recovery := t.Purpose == store.ClaimPurposeRecovery
	guest, err := tx.Identity(t.IdentityID)
	if err != nil {
		return nil, "", err
	}
	ss, err := liveSponsorship(tx, t.IntakeID, t.IdentityID)
	if err != nil {
		return nil, "", err
	}
	if recovery {
		// a recovery is for an active guest and an open case (a cancelled one revoked its token)
		ss, err = liveSponsorshipOf(tx, t.IdentityID)
		if err != nil {
			return nil, "", err
		}
		if ss == nil || guest.Status != "active" {
			return nil, ReasonNotActive, nil
		}
		if rc, err := tx.RecoveryCaseByToken(t.ID); errors.Is(err, store.ErrNotFound) || err == nil && rc.Status != store.RecoveryIssued {
			return nil, ReasonRevoked, nil
		} else if err != nil {
			return nil, "", err
		}
	} else if ss == nil || guest.Status != "invited" {
		return nil, ReasonNotActive, nil
	}
	consume := tx.ConsumeClaimToken
	if recovery {
		consume = tx.ConsumeRecoveryToken
	}
	if _, err := consume(hash, now); errors.Is(err, store.ErrNotFound) {
		return nil, ReasonUsed, nil // lost the race to another start
	} else if err != nil {
		return nil, "", err
	}
	cookie := seal.RandomSecret(32)
	sess := &store.ClaimSession{IDHash: seal.SHA256Hex([]byte(cookie)), TokenID: t.ID, IntakeID: t.IntakeID, IdentityID: t.IdentityID,
		KeyJWK: canonicalKey, KeyJKT: jkt, Nonce: seal.RandomSecret(16), Step: StepVerifyContact, Verified: "{}",
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(s.absolute())}
	detail := ojson.Object{{Key: "intake_id", Value: t.IntakeID}, {Key: "token_id", Value: t.ID}, {Key: "key_jkt", Value: jkt}}
	if recovery {
		saveVerified(sess, verified{Purpose: store.ClaimPurposeRecovery})
		detail = append(detail, ojson.KV{Key: "purpose", Value: store.ClaimPurposeRecovery})
	}
	if err := tx.InsertClaimSession(sess); err != nil {
		return nil, "", err
	}
	if recovery {
		rc, err := tx.RecoveryCaseByToken(t.ID)
		if err != nil {
			return nil, "", err
		}
		rc.Status, rc.SessionHash, rc.UpdatedAt = store.RecoveryStarted, &sess.IDHash, now
		if err := tx.SaveRecoveryCase(rc); err != nil {
			return nil, "", err
		}
		detail = append(detail, ojson.KV{Key: "case_id", Value: rc.ID})
	}
	err = auditEvent(tx, now, "claim.start", "intake", t.IntakeID, detail)
	return &Started{Cookie: cookie, Nonce: sess.Nonce, Session: sess}, "", err
}

// ---------------------------------------------------------------- sessions

// Lookup finds the session of a cookie without touching it: ErrNoSession if it
// is unknown, revoked or past its idle or absolute lifetime.
func (s *Service) Lookup(tx *store.TenantTx, cookie string, now time.Time) (*store.ClaimSession, error) {
	if cookie == "" || len(cookie) > 128 {
		return nil, ErrNoSession
	}
	sess, err := tx.ClaimSession(seal.SHA256Hex([]byte(cookie)))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	if sess.RevokedAt != nil || !now.Before(sess.ExpiresAt) || !now.Before(sess.LastSeenAt.Add(s.idle())) {
		return nil, ErrNoSession
	}
	return sess, nil
}

// Touch slides the session's idle window.
func (s *Service) Touch(tx *store.TenantTx, sess *store.ClaimSession, now time.Time) error {
	sess.LastSeenAt = now
	return tx.SaveClaimSession(sess)
}

// VerifyProof checks the request's proof against the session's key and nonce
// and the request body, and records its one use in the tenant's database.
func (s *Service) VerifyProof(tx *store.TenantTx, sess *store.ClaimSession, header, method, path, bodyHash string, now time.Time) error {
	pub, _, _, err := ParseKey([]byte(sess.KeyJWK))
	if err != nil {
		return ErrProofBad
	}
	p, err := Verify(pub, header, method, path, sess.Nonce, bodyHash, now, s.Replays)
	if err != nil {
		return err
	}
	return UseProof(tx, p, now)
}

// UseProof records an accepted proof's one use; ErrProofReplay if it was used.
func UseProof(tx *store.TenantTx, p Proof, now time.Time) error {
	fresh, err := tx.UseClaimProof(p.ID, p.UseUntil, now)
	if err != nil {
		return err
	}
	if !fresh {
		return ErrProofReplay
	}
	return nil
}

// Status is what the claim page may know: the step, the guest's first name,
// the organization, the sponsor, the kind of access and when it ends. Nothing else.
type Status struct {
	Step       string
	FirstName  string
	Tenant     string
	Sponsor    string
	Population string
	EndsAt     time.Time
	// Pending says why the claim waits: "" (it does not), "organization"
	// (no credential authority is set up yet) or "identity_verification".
	Pending string
}

// StatusOf reads the session's status.
func (s *Service) StatusOf(tx *store.TenantTx, sess *store.ClaimSession) (*Status, error) {
	guest, err := tx.Identity(sess.IdentityID)
	if err != nil {
		return nil, err
	}
	// after a link by sign-in the guest's sponsorship belongs to the person they linked to
	holder := sess.IdentityID
	if guest.Status == store.IdentityStatusMerged {
		surv, err := tx.MergeSurvivors()
		if err != nil {
			return nil, err
		}
		if to, ok := surv[holder]; ok {
			holder = to
		}
	}
	all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: holder})
	if err != nil {
		return nil, err
	}
	st := &Status{Step: sess.Step, FirstName: firstName(guest.Name), Tenant: s.tenantName(tx.Context(), tx.Tenant())}
	for _, x := range all {
		if x.IntakeID != sess.IntakeID {
			continue
		}
		st.Population, st.EndsAt = x.Population, x.EndsAt
		sp, err := tx.Identity(x.SponsorIdentityID)
		if err != nil {
			return nil, err
		}
		st.Sponsor = sp.Name
		break
	}
	if sess.Step == StepVerifyIdentity {
		st.Pending = "identity_verification"
	}
	return st, nil
}

// ---------------------------------------------------------------- sweep

// NeedsSweep reports whether Sweep would change anything at now.
func NeedsSweep(tx *store.TenantTx, now time.Time) (bool, error) {
	if cooling, err := tx.HasCoolingRecoveries(); err != nil || cooling {
		return cooling, err
	}
	sent, err := tx.IntakesByInvitation(store.InvitationSent)
	return len(sent) > 0, err
}

// Sweep marks claim tokens past their lifetime expired and the invitations
// whose last token expired unused as "expired".
func (s *Service) Sweep(tx *store.TenantTx, now time.Time) (int, error) {
	if _, err := tx.ExpireClaimTokens(now); err != nil {
		return 0, err
	}
	// recoveries whose cooling-off has ended get their new sign-in (GU-10)
	if _, err := s.ActivateDue(tx, now); err != nil {
		return 0, err
	}
	sent, err := tx.IntakesByInvitation(store.InvitationSent)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, in := range sent {
		ts, err := tx.ClaimTokensForIntake(in.ID)
		if err != nil {
			return n, err
		}
		if len(ts) == 0 || ts[0].Status != store.ClaimExpired {
			continue // a link still works, or one was used and the claim is under way
		}
		if err := tx.SetIntakeInvitation(in.ID, store.InvitationExpired, now); err != nil {
			return n, err
		}
		if err := auditEvent(tx, now, "claim.invitation.expire", "intake", in.ID, ojson.Object{{Key: "intake_id", Value: in.ID}}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// SweepAll runs Sweep for every active tenant that has an invitation out.
func (s *Service) SweepAll(ctx context.Context, db *store.DB, now time.Time) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		need, err := NeedsSweep(tx, now)
		if err != nil || !need {
			return err
		}
		_, err = s.Sweep(tx, now)
		return err
	})
}

// Requirements are what the session's sponsorship asks of the claim: the
// identity assurance and the authenticator assurance of the sign-in.
func (s *Service) Requirements(tx *store.TenantTx, sess *store.ClaimSession) (ial, aal int, err error) {
	ss, err := liveSponsorship(tx, sess.IntakeID, sess.IdentityID)
	if err != nil {
		return 0, 0, err
	}
	if ss == nil {
		return 0, 0, refuse(409, "not_active", "the sponsorship is not active")
	}
	ial, err = s.requiredIAL(tx, sess, ss)
	return ial, ss.RequiredAAL, err
}

// requiredIAL is the identity assurance a session must reach: the sponsorship's.
// A recovery asks for at least the level on record for the identity, so
// recovering an account can never be easier than claiming it was (§7.5).
func (s *Service) requiredIAL(tx *store.TenantTx, sess *store.ClaimSession, ss *store.Sponsorship) (int, error) {
	ial := ss.RequiredIAL
	if IsRecovery(sess) {
		rec, err := RecordedIAL(tx, sess.IdentityID)
		if err != nil {
			return 0, err
		}
		ial = max(ial, rec)
		if c, err := tx.RecoveryCaseBySession(sess.IDHash); err == nil {
			ial = max(ial, c.RequiredIAL)
		} else if !errors.Is(err, store.ErrNotFound) {
			return 0, err
		}
	}
	return ial, nil
}

// Sponsorship returns the live sponsorship an intake's invitation belongs to, or nil.
func Sponsorship(tx *store.TenantTx, intakeID string, guest int64) (*store.Sponsorship, error) {
	return liveSponsorship(tx, intakeID, guest)
}

// FindByEmail returns the live sponsorship of an unclaimed, unrevoked
// invitation made to this address, or nil. It is how "send me a new link" finds
// an invitation without the address being stored in clear next to a token.
func (s *Service) FindByEmail(tx *store.TenantTx, email string) (*store.Sponsorship, error) {
	mac, err := s.ContactHash(tx.Tenant(), email)
	if err != nil {
		return nil, nil // not an address: no invitation
	}
	ts, err := tx.ClaimTokensByEmail(mac)
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		in, err := tx.Intake(t.IntakeID)
		if err != nil {
			return nil, err
		}
		if in.InvitationStatus != store.InvitationSent && in.InvitationStatus != store.InvitationExpired && in.InvitationStatus != store.InvitationReady {
			continue
		}
		ss, err := liveSponsorship(tx, t.IntakeID, t.IdentityID)
		if err != nil {
			return nil, err
		}
		if ss != nil {
			return ss, nil
		}
	}
	return nil, nil
}

// RevokeIfIssued revokes the invitation of an ended sponsorship's intake when a
// link was ever sent (an invitation that never left stays as it was).
func (s *Service) RevokeIfIssued(tx *store.TenantTx, ss *store.Sponsorship, reason string, now time.Time) error {
	in, err := tx.Intake(ss.IntakeID)
	if err != nil {
		return err
	}
	if in.InvitationStatus != store.InvitationSent && in.InvitationStatus != store.InvitationExpired {
		return nil
	}
	return s.Revoke(tx, ss, reason, now)
}
