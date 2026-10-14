package terms

import (
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Attribute-release consent (design §7.4). A guest who signs in through a
// federated authority (a partner's home IdP, InCommon, eduGAIN) is shown which
// attributes the IdP releases to this organization and why, and chooses which
// optional ones to release. The consent is recorded against the claim session
// and in the audit ledger. Consent is recorded only where it is the basis: the
// attributes without which the sign-in cannot work are marked Required and are
// listed as notice, not asked for.

// Attribute is one attribute the home IdP releases and why it is wanted.
type Attribute struct {
	Name     string `json:"name"`
	Why      string `json:"why"`
	Required bool   `json:"required"`
}

// Attributes are the attributes a federated sign-in releases. Required ones are
// the minimum (a stable subject and the invited address); the rest are optional.
var Attributes = []Attribute{
	{"subject", "Identifies your account at your home organization. Without it you cannot sign in.", true},
	{"email", "Lets us confirm the invitation was for you and send you notices.", true},
	{"name", "Shown to your sponsor and in the directory.", false},
	{"affiliation", "Tells us your role at your home organization (for example staff or member).", false},
	{"organization", "Shows which organization you come from.", false},
}

// FederatedAuthorities are the credential authorities that sign a guest in at
// their own home identity provider, so the consent screen applies.
var FederatedAuthorities = []string{"home_idp", "incommon", "edugain"}

// ConsentApplies reports whether a claim through this authority shows the
// attribute-release consent screen.
func ConsentApplies(authority string) bool { return slices.Contains(FederatedAuthorities, authority) }

// ConsentGiven reports whether the claim session already recorded a consent.
func ConsentGiven(tx *store.TenantTx, sessionHash string) (bool, error) {
	_, err := tx.AttributeConsentFor(sessionHash)
	if err == store.ErrNotFound {
		return false, nil
	}
	return err == nil, err
}

// RecordConsent records which attributes the guest agreed to release. The
// required ones are always included; an unknown attribute is refused. Once
// recorded for a session it cannot be changed.
func RecordConsent(tx *store.TenantTx, identityID int64, sessionHash, authority string, consented []string, now time.Time) error {
	chosen := map[string]bool{}
	for _, c := range consented {
		if !slices.ContainsFunc(Attributes, func(a Attribute) bool { return a.Name == c }) {
			return refuse(422, "invalid_attribute", "%q is not an attribute this sign-in releases", c)
		}
		chosen[c] = true
	}
	var offered, final []string
	for _, a := range Attributes {
		offered = append(offered, a.Name)
		if a.Required || chosen[a.Name] {
			final = append(final, a.Name)
		}
	}
	o, _ := json.Marshal(offered)
	f, _ := json.Marshal(final)
	fresh, err := tx.InsertAttributeConsent(&store.AttributeConsent{ID: uuid.NewString(), IdentityID: identityID, SessionHash: sessionHash,
		Authority: authority, Offered: string(o), Consented: string(f), ConsentedAt: now})
	if err != nil {
		return err
	}
	if !fresh {
		return refuse(409, "already_recorded", "your choice was already recorded")
	}
	return audited(tx, now, "consent.attributes", "identity", strconv.FormatInt(identityID, 10), ojson.Object{
		{Key: "identity_id", Value: identityID}, {Key: "authority", Value: authority}, {Key: "offered", Value: offered},
		{Key: "consented", Value: final}})
}
