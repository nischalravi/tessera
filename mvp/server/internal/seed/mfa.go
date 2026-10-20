package seed

import (
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/mfa"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// MFADemo seeds the MFA posture report of the demo company so the page shows
// something. Everything here is synthetic and says so: the demo Okta feed has
// no factor data and the demo GitHub, Snowflake and AWS feeds report no
// password, MFA or SSO facts, so a stable hash of each id picks which method
// classes a person has and which app accounts bypass SSO or MFA. Dates of
// enrolment are spread over the last 90 days so the passkey trend moves, and
// the snapshot history is computed from them (not drawn separately).
//
// A real sync (okta / entra connectors) replaces the Okta methods and adds
// real sources; the app signals stay until a connector reports its own.
func MFADemo(c *store.TenantTx, now time.Time) error {
	in, err := mfa.LoadInput(c, now)
	if err != nil {
		return err
	}
	people := map[int64]*mfa.Identity{}
	for _, v := range mfa.Compute(in).Identities {
		people[v.ID] = v
	}
	// stable bucket 0..99 of an id and a salt (no randomness: a reseed is identical)
	bucket := func(id, salt int64) int { return int((id*2654435761 + salt*40503) % 100) }
	daysAgo := func(n int) *time.Time { t := now.AddDate(0, 0, -n); return &t }

	var methods []store.AuthMethod
	add := func(acct int64, name, strength, kind, label string, enrolled *time.Time) {
		methods = append(methods, store.AuthMethod{AccountID: acct, ExternalID: fmt.Sprintf("demo-%d-%s", acct, name),
			System: "okta", Strength: strength, Kind: kind, Label: label, EnrolledAt: enrolled, ObservedAt: now})
	}
	for _, a := range in.Accounts {
		if a.System != "okta" || a.IdentityID == nil || a.Status != "active" {
			continue
		}
		p := people[*a.IdentityID]
		if p == nil {
			continue
		}
		b := bucket(a.ID, 1)
		old := daysAgo(120 + bucket(a.ID, 2)*6)
		recent := daysAgo(3 + bucket(a.ID, 3)*85/100) // a passkey enrolled inside the last 90 days
		// privileged people are better protected than the rest, but not all of them
		passkey, number, otp, sms := 25, 65, 80, 90
		if p.Privileged {
			passkey, number, otp, sms = 55, 80, 92, 97
		}
		switch {
		case b < passkey:
			add(a.ID, "passkey", string(mfa.PhishingResistant), mfa.KindPasskey, "YubiKey 5C", recent)
			add(a.ID, "push", string(mfa.PushNumberMatch), mfa.KindAppPush, "Okta Verify", old)
		case b < number:
			add(a.ID, "push", string(mfa.PushNumberMatch), mfa.KindAppPush, "Okta Verify", old)
			add(a.ID, "totp", string(mfa.OTP), mfa.KindTOTP, "", old)
		case b < otp:
			add(a.ID, "totp", string(mfa.OTP), mfa.KindTOTP, "", old)
		case b < sms:
			add(a.ID, "sms", string(mfa.SMSVoice), mfa.KindSMS, "", old)
		} // the rest registered nothing
	}
	if err := c.ReplaceAuthMethods("okta", methods); err != nil {
		return err
	}
	if err := c.PutAuthMethodSource(store.AuthMethodSource{System: "okta", Status: mfa.SourceOK, UpdatedAt: now}); err != nil {
		return err
	}

	// app sign-in facts, only the ones each platform could report
	flag := func(id, salt int64, trueBelow int) *bool { v := bucket(id, salt) < trueBelow; return &v }
	for _, a := range in.Accounts {
		if a.IdentityID == nil || a.Status != "active" || a.Kind != "user" {
			continue
		}
		g := store.AccountAuthSignals{AccountID: a.ID, ObservedAt: now}
		switch a.System {
		case "snowflake": // SHOW USERS: has_password, ext_authn_duo / mfa; no SSO flag per user
			g.HasLocalPassword, g.MFAEnabled = flag(a.ID, 4, 35), flag(a.ID, 5, 60)
		case "github": // org members: 2FA state and SAML SSO identity link; GitHub always keeps a password
			g.MFAEnabled, g.SSOEnforced = flag(a.ID, 6, 90), flag(a.ID, 7, 80)
		case "aws": // IAM users: login profile and MFA devices
			g.HasLocalPassword, g.MFAEnabled = flag(a.ID, 8, 50), flag(a.ID, 9, 70)
		default:
			continue
		}
		if err := c.PutAccountAuthSignals(g); err != nil {
			return err
		}
	}

	// history: each day's coverage from the methods enrolled by then
	in, err = mfa.LoadInput(c, now)
	if err != nil {
		return err
	}
	all := in.Methods
	for d := mfa.TrendDays; d >= 1; d-- {
		day := now.AddDate(0, 0, -d)
		past := in
		past.Now, past.Methods = day, nil
		for _, m := range all {
			if m.EnrolledAt == nil || !m.EnrolledAt.After(day) {
				past.Methods = append(past.Methods, m)
			}
		}
		for _, r := range mfa.Compute(past).SnapshotRows(day.UTC().Format("2006-01-02")) {
			if err := c.PutMFASnapshot(r); err != nil {
				return err
			}
		}
	}
	return mfa.RecordSnapshot(c, now)
}
