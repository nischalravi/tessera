package provisioning

import (
	"encoding/json"
	"strings"
	"testing"
)

// A stored URL only counts as kept for the target setting it was stored under: moving it to another setting (here the
// webhook's read_url) is a new URL and gets the ASCII-host check (#953).
func TestKeptURL_PerSetting(t *testing.T) {
	const legacy = "https://hoök.example.com/hook"
	cfg := func(target map[string]any) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"account_system": "dir", "group_name": "{{.Extension}}", "target": target})
		return b
	}
	stored := cfg(map[string]any{"url": legacy})
	keep := storedTargetURLs(stored)
	parse := func(raw json.RawMessage) error {
		c, err := parseCommonFor(TypeWebhook, raw, keep)
		if err != nil {
			return err
		}
		_, err = parseWebhookConfig(c)
		return err
	}
	if err := parse(stored); err != nil {
		t.Fatalf("unchanged url refused: %v", err)
	}
	moved := cfg(map[string]any{"url": "https://ok.example.com/hook", "read_url": legacy})
	if err := parse(moved); err == nil || !strings.Contains(err.Error(), "must be ASCII") {
		t.Fatalf("stored url moved to read_url: got %v", err)
	}
	added := cfg(map[string]any{"url": legacy, "read_url": legacy})
	if err := parse(added); err == nil || !strings.Contains(err.Error(), "target.read_url") {
		t.Fatalf("stored url copied to read_url: got %v", err)
	}
}
