package loaders

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A stored URL only counts as kept for the setting it was stored under: copying the SCIM base_url into token_url is a
// new URL and gets the ASCII-host check (#953).
func TestKeptURL_PerSetting(t *testing.T) {
	const legacy = "https://scïm.example.com/scim/v2"
	cfg := func(base, token string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"base_url":%q,"auth":"client_credentials","token_url":%q,"client_id":"c","subject_attr":"email"}`, base, token))
	}
	stored := cfg(legacy, "https://idp.example.com/t")
	keep := storedURLs(string(stored))
	if _, err := validateConfig(TypeSCIM, stored, false, keep); err != nil {
		t.Fatalf("unchanged config refused: %v", err)
	}
	_, err := validateConfig(TypeSCIM, cfg(legacy, legacy), false, keep)
	if err == nil || !strings.Contains(err.Error(), "token_url") || !strings.Contains(err.Error(), "must be ASCII") {
		t.Fatalf("stored base_url copied to token_url: got %v", err)
	}
}
