package claim

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// verified is the session's record of what was proven.
type verified struct {
	EmailAt    string `json:"email_at,omitempty"`
	ExistingAt string `json:"existing_account_at,omitempty"`
	IAL        int    `json:"ial"`
	VouchedBy  string `json:"vouched_by,omitempty"` // A0: the sponsor's attestation
	AAL        int    `json:"aal,omitempty"`
	ACR        string `json:"acr,omitempty"`
	Authority  string `json:"authority,omitempty"`
}

func readVerified(sess *store.ClaimSession) verified {
	var v verified
	_ = json.Unmarshal([]byte(sess.Verified), &v)
	return v
}

func saveVerified(sess *store.ClaimSession, v verified) {
	b, _ := json.Marshal(v)
	sess.Verified = string(b)
}

// ---------------------------------------------------------------- confirmation codes

// SendResult says whether a code was written. The API answers the same either
// way, so the caller learns nothing from it.
type SendResult struct{ Sent bool }

// SendCode writes a 6-digit confirmation code for the session and queues it to
// the invited address through the notification outbox. The code is held only as
// a keyed hash (and in memory until the dispatcher has mailed it). It does
// nothing, silently, when the session is past the contact step. Earlier live
// codes of the session are voided.
func (s *Service) SendCode(tx *store.TenantTx, sess *store.ClaimSession, now time.Time) (SendResult, error) {
	if sess.Step != StepVerifyContact {
		return SendResult{}, nil
	}
	guest, err := tx.Identity(sess.IdentityID)
	if err != nil {
		return SendResult{}, err
	}
	if guest.Email == nil || strings.TrimSpace(*guest.Email) == "" {
		return SendResult{}, nil
	}
	dest, err := s.ContactHash(tx.Tenant(), *guest.Email)
	if err != nil {
		return SendResult{}, err
	}
	code := seal.RandomString(6, "0123456789")
	id := uuid.NewString()
	hash, err := s.Keyer.MAC(tx.Tenant(), codePurpose, sess.IDHash, id, code)
	if err != nil {
		return SendResult{}, err
	}
	if err := tx.VoidConfirmationCodes(sess.IDHash, now); err != nil {
		return SendResult{}, err
	}
	expires := now.Add(s.CodeLifetime())
	if err := tx.InsertConfirmationCode(&store.ConfirmationCode{ID: id, SessionIDHash: sess.IDHash, Channel: store.ConfirmChanEmail,
		DestinationHMAC: dest, CodeHash: hash, CreatedAt: now, ExpiresAt: expires}); err != nil {
		return SendResult{}, err
	}
	nid, err := notify.ClaimCode(tx, now, id, guest.ID, strings.TrimSpace(*guest.Email), s.tenantName(tx.Context(), tx.Tenant()), s.CodeLifetime())
	if err != nil {
		return SendResult{}, err
	}
	s.Secrets.Put(nid, "Your confirmation code: "+code, expires.Add(time.Minute))
	return SendResult{Sent: true}, auditEvent(tx, now, "claim.code.send", "intake", sess.IntakeID, ojson.Object{
		{Key: "intake_id", Value: sess.IntakeID}, {Key: "code_id", Value: id}, {Key: "channel", Value: store.ConfirmChanEmail},
		{Key: "notification_id", Value: nid}})
}

// CodeCheck is the outcome of CheckCode: OK, or a reason for the audit event
// (the caller always answers a generic failure).
type CodeCheck struct {
	OK     bool
	Reason string
}

// CheckCode compares a submitted code with the session's live code in constant
// time. Every submission counts as an attempt; the fifth wrong one voids the
// code. A right code marks the invited address verified and moves the claim on:
// to the existing-account question for A0, or to identity verification (not
// built: GU-7) when the sponsorship needs IAL 1 or 2.
func (s *Service) CheckCode(tx *store.TenantTx, sess *store.ClaimSession, submitted string, now time.Time) (CodeCheck, error) {
	if sess.Step != StepVerifyContact {
		return CodeCheck{Reason: "wrong_step"}, nil
	}
	c, err := tx.LiveConfirmationCode(sess.IDHash)
	if errors.Is(err, store.ErrNotFound) {
		return CodeCheck{Reason: "no_code"}, nil
	}
	if err != nil {
		return CodeCheck{}, err
	}
	if !now.Before(c.ExpiresAt) {
		if err := tx.VoidConfirmationCode(c.ID, now); err != nil {
			return CodeCheck{}, err
		}
		return CodeCheck{Reason: "expired"}, nil
	}
	if err := tx.AddConfirmationAttempt(c.ID); err != nil {
		return CodeCheck{}, err
	}
	attempts := c.Attempts + 1
	want := c.CodeHash
	got, err := s.Keyer.MAC(tx.Tenant(), codePurpose, sess.IDHash, c.ID, strings.TrimSpace(submitted))
	if err != nil {
		return CodeCheck{}, err
	}
	if !seal.Equal([]byte(want), []byte(got)) {
		if attempts >= CodeAttempts {
			if err := tx.VoidConfirmationCode(c.ID, now); err != nil {
				return CodeCheck{}, err
			}
			if err := auditEvent(tx, now, "claim.code.locked", "intake", sess.IntakeID, ojson.Object{
				{Key: "intake_id", Value: sess.IntakeID}, {Key: "code_id", Value: c.ID}, {Key: "attempts", Value: attempts}}); err != nil {
				return CodeCheck{}, err
			}
			return CodeCheck{Reason: "locked"}, nil
		}
		return CodeCheck{Reason: "wrong"}, nil
	}
	if err := tx.UseConfirmationCode(c.ID, now); err != nil {
		return CodeCheck{}, err
	}
	ss, err := liveSponsorship(tx, sess.IntakeID, sess.IdentityID)
	if err != nil {
		return CodeCheck{}, err
	}
	if ss == nil {
		return CodeCheck{Reason: "not_active"}, nil
	}
	v := readVerified(sess)
	v.EmailAt, v.IAL, v.VouchedBy = now.UTC().Format("2006-01-02T15:04:05Z"), 0, "sponsor"
	saveVerified(sess, v)
	sess.Step, sess.LastSeenAt = StepExistingAccount, now
	if ss.RequiredIAL > 0 {
		sess.Step = StepVerifyIdentity
	}
	if err := tx.SaveClaimSession(sess); err != nil {
		return CodeCheck{}, err
	}
	err = auditEvent(tx, now, "claim.verify_contact", "intake", sess.IntakeID, ojson.Object{{Key: "intake_id", Value: sess.IntakeID},
		{Key: "channel", Value: store.ConfirmChanEmail}, {Key: "next", Value: sess.Step}})
	return CodeCheck{OK: true}, err
}

// ---------------------------------------------------------------- existing account

// ExistingAccount records the claimant's answer to "do you already have an
// account?". It is asked of every claimant, so asking it reveals nothing. The
// answer is stored on the intake for the review queue and never links anyone
// (K3). A "yes" is followed by a sign-in as the existing person (the API starts
// it; the callback links by sign-in, CompleteLinked). It moves the claim to the
// credential step: if the sign-in does not link, that is where the claim goes on.
func (s *Service) ExistingAccount(tx *store.TenantTx, sess *store.ClaimSession, answer string, now time.Time) error {
	if answer != "yes" && answer != "no" {
		return refuse(422, "invalid_answer", "answer is yes or no")
	}
	if sess.Step != StepExistingAccount {
		return refuse(409, "wrong_step", "this step is not open")
	}
	if err := tx.SetIntakeExistingAccount(sess.IntakeID, answer, now); err != nil {
		return err
	}
	v := readVerified(sess)
	v.ExistingAt = now.UTC().Format("2006-01-02T15:04:05Z")
	saveVerified(sess, v)
	sess.Step, sess.LastSeenAt = StepCredential, now
	if err := tx.SaveClaimSession(sess); err != nil {
		return err
	}
	return auditEvent(tx, now, "claim.existing_account", "intake", sess.IntakeID, ojson.Object{{Key: "intake_id", Value: sess.IntakeID},
		{Key: "answer", Value: answer}, {Key: "linked", Value: false}})
}

// ---------------------------------------------------------------- link by sign-in

// ErrLinkNotReady is a link by sign-in for a claim that is not open.
var ErrLinkNotReady = errors.New("claim: the claim is not open")

// Linked is what a link by sign-in did to the claim: the invitation is done, as
// the person the claimant signed in as. No credential was created for the guest
// and none was transferred; the person's own credential is the one that proved it.
// The caller has already linked the intake (merge.LinkBySignIn, which moved the
// sponsorship, bundle and affiliations to the person, started the affiliations
// and told the sponsor); this closes the claim session and records the assurance
// the sign-in reached.
func (s *Service) CompleteLinked(tx *store.TenantTx, sess *store.ClaimSession, person int64, b Binding, now time.Time) error {
	if sess.CompletedAt != nil || sess.RevokedAt != nil || sess.Step == StepComplete {
		return ErrLinkNotReady
	}
	if err := tx.PutIdentityAssurance(&store.Assurance{IdentityID: person, IAL: 0, AAL: b.AAL, Source: "claim_link", RecordedAt: now}); err != nil {
		return err
	}
	v := readVerified(sess)
	v.AAL, v.ACR, v.Authority = b.AAL, b.ACR, "existing_account"
	saveVerified(sess, v)
	sess.Step, sess.CompletedAt, sess.LastSeenAt = StepComplete, &now, now
	if err := tx.SaveClaimSession(sess); err != nil {
		return err
	}
	return auditEvent(tx, now, "claim.complete", "identity", int64s(person), ojson.Object{{Key: "intake_id", Value: sess.IntakeID},
		{Key: "identity_id", Value: person}, {Key: "linked_by_sign_in", Value: true}, {Key: "connection_id", Value: b.ConnectionID.String()},
		{Key: "aal", Value: b.AAL}, {Key: "acr", Value: b.ACR}})
}

// ---------------------------------------------------------------- credential

// RecordCredentialStart remembers which subject the authority was told to expect
// and which login transaction carries the sign-in, so the callback can check both.
func (s *Service) RecordCredentialStart(tx *store.TenantTx, sess *store.ClaimSession, authority, subject, loginTxn string, now time.Time) error {
	if sess.Step != StepCredential {
		return refuse(409, "wrong_step", "this step is not open")
	}
	sess.CredentialSubject, sess.LoginTxnID, sess.LastSeenAt = &subject, &loginTxn, now
	v := readVerified(sess)
	v.Authority = authority
	saveVerified(sess, v)
	if err := tx.SaveClaimSession(sess); err != nil {
		return err
	}
	return auditEvent(tx, now, "claim.credential.start", "intake", sess.IntakeID, ojson.Object{{Key: "intake_id", Value: sess.IntakeID},
		{Key: "authority", Value: authority}, {Key: "login_transaction_id", Value: loginTxn}})
}

// RecordCredentialPending notes, once, that the claim waits for the organization
// to set up a sign-in method (no credential authority is configured).
func (s *Service) RecordCredentialPending(tx *store.TenantTx, sess *store.ClaimSession, why string, now time.Time) error {
	if sess.Step != StepCredential {
		return refuse(409, "wrong_step", "this step is not open")
	}
	sess.LastSeenAt = now
	if err := tx.SaveClaimSession(sess); err != nil {
		return err
	}
	return auditEvent(tx, now, "claim.credential.pending", "intake", sess.IntakeID, ojson.Object{{Key: "intake_id", Value: sess.IntakeID},
		{Key: "reason", Value: why}})
}

// Binding is what a sign-in through the bound authority proved.
type Binding struct {
	ConnectionID uuid.UUID
	Issuer       string
	Subject      string
	Email        string
	Name         string
	AAL          int
	ACR          string // Tessera's normalized ACR
	Authority    string
}

// MeetsAAL reports whether a sign-in meets the sponsorship's required AAL:
// AAL 1 and 2 by the authenticator assurance of the sign-in, AAL 3 only with a
// device-bound phishing-resistant method (the phrh context).
func MeetsAAL(required, aal int, acr string) bool {
	if required >= 3 {
		return acr == normalize.ACRPhrh
	}
	return aal >= max(required, 1)
}

// Refusals of Complete, for the audit event.
var (
	ErrAAL          = errors.New("claim: the sign-in does not meet the required assurance level")
	ErrSubject      = errors.New("claim: the sign-in is not the account set up for this claim")
	ErrSubjectBound = errors.New("claim: that sign-in already belongs to a user")
	ErrNotReady     = errors.New("claim: the claim is not at the credential step")
)

// Complete finishes the claim after a sign-in at the required assurance level
// through the bound authority: a NEW platform user, with no roles, linked to the
// guest's identity, with the sign-in's (issuer, subject) bound as its external
// login (never by email); the identity becomes active, the sponsorship's pending
// affiliations active, the intake claimed; the sponsor is told. It is all one
// transaction. A sign-in that is not for the subject the authority was told to
// expect, that does not meet the AAL, or whose (issuer, subject) already
// belongs to a user completes nothing (the claim stays pending).
func (s *Service) Complete(tx *store.TenantTx, sess *store.ClaimSession, b Binding, now time.Time) (*store.PlatformUser, error) {
	if sess.Step != StepCredential || sess.CompletedAt != nil || sess.RevokedAt != nil {
		return nil, ErrNotReady
	}
	if sess.CredentialSubject == nil || !seal.Equal([]byte(*sess.CredentialSubject), []byte(b.Subject)) {
		return nil, ErrSubject
	}
	guest, err := tx.Identity(sess.IdentityID)
	if err != nil {
		return nil, err
	}
	ss, err := liveSponsorship(tx, sess.IntakeID, sess.IdentityID)
	if err != nil {
		return nil, err
	}
	if ss == nil || guest.Status != "invited" {
		return nil, ErrNotReady
	}
	if !MeetsAAL(ss.RequiredAAL, b.AAL, b.ACR) {
		return nil, ErrAAL
	}
	if users, err := tx.UsersLinkedTo(guest.ID); err != nil {
		return nil, err
	} else if len(users) > 0 {
		return nil, ErrSubjectBound
	}
	// all refusals come before the first write, so a refused claim writes nothing
	if _, err := tx.ExternalLoginBySubject(b.ConnectionID, b.Subject); err == nil {
		return nil, ErrSubjectBound
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	email := strings.TrimSpace(b.Email)
	if email == "" && guest.Email != nil {
		email = *guest.Email
	}
	u := &store.PlatformUser{ID: uuid.New(), DisplayName: guest.Name, Status: "active", IdentityID: &guest.ID, CreatedAt: now}
	if email != "" {
		u.Email = &email
	}
	if err := tx.InsertPlatformUser(u); err != nil {
		return nil, err
	}
	if err := tx.InsertExternalLogin(&store.ExternalLogin{UserID: u.ID, IdPConnectionID: b.ConnectionID, Issuer: b.Issuer,
		Subject: b.Subject, EmailAtLastLogin: u.Email, CreatedAt: now}); err != nil {
		return nil, err
	}
	if err := tx.SetIdentityStatus(guest.ID, "active"); err != nil {
		return nil, err
	}
	all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: guest.ID})
	if err != nil {
		return nil, err
	}
	for _, x := range all {
		if !x.Live() {
			continue
		}
		a, err := affiliations.ForSponsorship(tx, guest.ID, x.ID)
		if err != nil {
			return nil, err
		}
		if a != nil && a.Status == store.AffPending {
			if err := tx.ActivateAffiliation(a.ID); err != nil {
				return nil, err
			}
		}
	}
	v := readVerified(sess)
	v.AAL, v.ACR, v.Authority = b.AAL, b.ACR, b.Authority
	saveVerified(sess, v)
	sess.Step, sess.CompletedAt, sess.LastSeenAt = StepComplete, &now, now
	if err := tx.SaveClaimSession(sess); err != nil {
		return nil, err
	}
	if err := tx.SetIntakeInvitation(sess.IntakeID, store.InvitationClaimed, now); err != nil {
		return nil, err
	}
	if err := notify.GuestClaimed(tx, now, ss); err != nil {
		return nil, err
	}
	// the access bundle is granted and the guest joins the reference groups of
	// their affiliations (GU-12); the identity assurance reached is recorded
	if err := access.Claimed(tx, now, guest.ID, v.IAL, b.AAL); err != nil {
		return nil, err
	}
	err = auditEvent(tx, now, "claim.complete", "identity", int64s(guest.ID), ojson.Object{{Key: "intake_id", Value: sess.IntakeID},
		{Key: "identity_id", Value: guest.ID}, {Key: "user_id", Value: u.ID.String()}, {Key: "sponsorship_id", Value: ss.ID},
		{Key: "connection_id", Value: b.ConnectionID.String()}, {Key: "authority", Value: b.Authority}, {Key: "aal", Value: b.AAL},
		{Key: "acr", Value: b.ACR}, {Key: "required_aal", Value: ss.RequiredAAL}})
	return u, err
}

func int64s(n int64) string { return strconv.FormatInt(n, 10) }
