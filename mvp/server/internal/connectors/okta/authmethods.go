package okta

import (
	"context"
	"fmt"
	"net/url"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/mfa"
)

// apiFactor is the part of an enrolled factor that is read. The profile holds
// phone numbers and credential ids for some factors; only the authenticator
// name of a security key is kept, never a phone number.
type apiFactor struct {
	ID         string `json:"id"`
	FactorType string `json:"factorType"`
	Provider   string `json:"provider"`
	Status     string `json:"status"`
	Created    string `json:"created"`
	Profile    struct {
		AuthenticatorName string `json:"authenticatorName"`
	} `json:"profile"`
}

type apiAuthenticator struct {
	Key      string `json:"key"`
	Status   string `json:"status"`
	Settings struct {
		ChannelBinding struct {
			Style    string `json:"style"`
			Required string `json:"required"`
		} `json:"channelBinding"`
	} `json:"settings"`
}

// numberMatch reports whether the org always requires number matching for
// Okta Verify push. It is an org setting that the factors API does not show,
// so it is read from the authenticator list (scope okta.authenticators.read
// for OAuth; add it to Config.Scopes). When the listing is refused the
// operator's declaration (Config.PushNumberMatch) decides.
func (c *Connector) numberMatch(ctx context.Context) bool {
	if c.cfg.PushNumberMatch {
		return true
	}
	var auths []apiAuthenticator
	if _, err := c.api.GetJSON(ctx, c.path("/api/v1/authenticators", nil), nil, &auths); err != nil {
		return false
	}
	for _, a := range auths {
		if a.Status == "ACTIVE" && mfa.OktaNumberMatch(a.Key, a.Settings.ChannelBinding.Style, a.Settings.ChannelBinding.Required) {
			return true
		}
	}
	return false
}

// readAuthMethods reads the active factors of every active user. It is an
// enrichment: when Okta refuses (403: the app lacks the scope or admin role)
// or fails, no methods are returned and the source is reported unavailable, so
// ingest keeps what it has and the report shows the gap instead of treating
// every user as unprotected. Factors are not part of the user's lastUpdated,
// so they are read for every user on every sync, not only changed ones.
func (c *Connector) readAuthMethods(ctx context.Context, st *state) ([]connectors.AuthMethodRecord, *connectors.AuthMethodSource) {
	if c.cfg.SkipAuthMethods {
		return nil, nil
	}
	unavailable := func(detail string) ([]connectors.AuthMethodRecord, *connectors.AuthMethodSource) {
		return nil, &connectors.AuthMethodSource{System: System, Unavailable: true, Detail: detail}
	}
	numberMatch := c.numberMatch(ctx)
	var out []connectors.AuthMethodRecord
	for _, id := range sortedKeys(st.Users) {
		if st.Users[id].Acct.Status != "active" {
			continue
		}
		var factors []apiFactor
		if _, err := c.api.GetJSON(ctx, c.path("/api/v1/users/"+url.PathEscape(id)+"/factors", nil), nil, &factors); err != nil {
			switch s := connsync.Status(err); {
			case s == 404:
				continue // the user was removed since the listing
			case s == 401 || s == 403:
				return unavailable("Okta refused the factor listing (HTTP " + fmt.Sprint(s) + "): grant okta.users.read and a read-only admin role to the service app")
			default:
				return unavailable("reading factors failed; MFA data was not updated")
			}
		}
		seen := map[string]bool{}
		for _, f := range factors {
			if f.Status != "ACTIVE" || !validID(f.ID) || seen[f.ID] {
				continue
			}
			cl, ok := mfa.ClassifyOkta(f.FactorType, f.Provider, numberMatch)
			if !ok {
				continue
			}
			seen[f.ID] = true
			out = append(out, connectors.AuthMethodRecord{
				Account:    connectors.Ref{Kind: "account", System: System, ExternalID: id},
				ExternalID: f.ID, Strength: string(cl.Strength), Kind: cl.Kind,
				Label: f.Profile.AuthenticatorName, EnrolledAt: parseTime(f.Created)})
		}
	}
	return out, &connectors.AuthMethodSource{System: System}
}
