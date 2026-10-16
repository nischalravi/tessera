package entra

import (
	"context"
	"fmt"
	"net/url"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/mfa"
)

// authMethod is one entry of GET /users/{id}/authentication/methods. The list
// is polymorphic: @odata.type names the method. Phone numbers and e-mail
// addresses in the entries are not read.
type authMethod struct {
	Type        string `json:"@odata.type"`
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Created     string `json:"createdDateTime"`
	PhoneType   string `json:"phoneType"`
}

// readAuthMethods reads the registered authentication methods of every enabled
// member user. It needs the read-only application permission
// UserAuthenticationMethod.Read.All. Graph answers 403 without it: the source
// is then reported unavailable, no methods are returned, and ingest keeps what
// it has, so a missing scope never looks like "nobody has MFA". Any other
// failure is treated the same way, because partial data would misreport the
// users that were not reached.
func (c *Connector) readAuthMethods(ctx context.Context, st *state) ([]connectors.AuthMethodRecord, *connectors.AuthMethodSource) {
	if c.cfg.SkipAuthMethods {
		return nil, nil
	}
	unavailable := func(detail string) ([]connectors.AuthMethodRecord, *connectors.AuthMethodSource) {
		return nil, &connectors.AuthMethodSource{System: System, Unavailable: true, Detail: detail}
	}
	var out []connectors.AuthMethodRecord
	for _, id := range sortedKeys(st.Users) {
		u := st.Users[id]
		if !validID(id) || (u.AccountEnabled != nil && !*u.AccountEnabled) || u.UserType == "Guest" {
			continue
		}
		seen := map[string]bool{}
		_, err := listAll(ctx, c, c.graph("/users/"+url.PathEscape(id)+"/authentication/methods", ""), func(m authMethod) error {
			cl, ok := mfa.ClassifyEntra(m.Type)
			if m.Type == "#microsoft.graph.phoneAuthenticationMethod" {
				cl, ok = mfa.ClassifyEntraPhone(m.PhoneType), true
			}
			if !ok || m.ID == "" || len(m.ID) > 128 || seen[m.ID] {
				return nil
			}
			seen[m.ID] = true
			out = append(out, connectors.AuthMethodRecord{
				Account:    connectors.Ref{Kind: "account", System: System, ExternalID: id},
				ExternalID: m.ID, Strength: string(cl.Strength), Kind: cl.Kind,
				Label: m.DisplayName, EnrolledAt: parseTime(m.Created)})
			return nil
		})
		if err != nil {
			switch s := connsync.Status(err); {
			case s == 404:
				continue // the user was removed since the listing
			case s == 401 || s == 403:
				return unavailable("Graph refused the authentication methods listing (HTTP " + fmt.Sprint(s) +
					"): grant the application permission UserAuthenticationMethod.Read.All and admin consent")
			default:
				return unavailable("reading authentication methods failed; MFA data was not updated")
			}
		}
	}
	return out, &connectors.AuthMethodSource{System: System}
}
