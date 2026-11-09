package notify

import (
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
)

// A chat webhook with a non-ASCII host is refused with 422 url_non_ascii_authority in both the allow-listed and the
// any-host mode, without echoing it; punycode and ASCII hosts pass (#939).
func TestCheckWebhookURL_NonASCIIHost(t *testing.T) {
	for _, any := range []bool{false, true} {
		e := ChatEnv{AnyHost: any}
		for _, u := range []string{"https://ẋ.webhook.office.com/hook", "https://hooks.slack.com%E2%88%B6@evil.test/x", "https://hooks.%C3%A4.slack.com/x"} {
			_, err := e.CheckWebhookURL(ProviderTeams, u)
			var ce *cfgerr.Error
			if !errors.As(err, &ce) || ce.Code != CodeURLNonASCIIAuthority || ce.Status != 422 || strings.Contains(err.Error(), "evil") || strings.Contains(err.Error(), "office.com") {
				t.Errorf("any=%v %s: %v", any, u, err)
			}
		}
		if _, err := e.CheckWebhookURL(ProviderTeams, "https://xn--acme-bn.webhook.office.com/hook"); err != nil {
			t.Errorf("any=%v punycode: %v", any, err)
		}
		if _, err := e.CheckWebhookURL(ProviderSlack, "https://hooks.slack.com/services/x"); err != nil {
			t.Errorf("any=%v ascii: %v", any, err)
		}
	}
}
