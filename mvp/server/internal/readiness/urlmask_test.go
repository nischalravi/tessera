package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func TestMaskURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"https://scim.example.com", "https://scim.example.com"},
		{"https://scim.example.com/v2", "https://scim.example.com/v2"},
		{"https://u:pw@scim.example.com/v2", "https://masked@scim.example.com/v2"},
		{"https://scim.example.com/?token=abc&a=b", "https://scim.example.com/?a=masked&token=masked"},
		{"https://scim.example.com/#frag", "https://scim.example.com/"},
		{"https://%zz@scim.example.com", URLMask},
	} {
		got := MaskURL(tc.in)
		if got != tc.want {
			t.Errorf("MaskURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.Contains(got, "pw") || strings.Contains(got, "abc") {
			t.Errorf("MaskURL(%q) leaks: %q", tc.in, got)
		}
	}
}

func TestURLCredentialError(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  ConnConfig
		bad  string
	}{
		{"clean", ConnConfig{BaseURL: "https://scim.example.com/v2", OrgURL: "https://a.okta.com"}, ""},
		{"base userinfo", ConnConfig{BaseURL: "https://u:pw@scim.example.com"}, "base_url"},
		{"base query", ConnConfig{BaseURL: "https://scim.example.com/?token=abc"}, "base_url"},
		{"base fragment", ConnConfig{BaseURL: "https://scim.example.com/#abc"}, "base_url"},
		{"org userinfo", ConnConfig{OrgURL: "https://u@a.okta.com"}, "org_url"},
		{"org query", ConnConfig{OrgURL: "https://a.okta.com?x=1"}, "org_url"},
		{"setting userinfo", ConnConfig{Settings: map[string]string{"api_url": "https://u:pw@x.example.com"}}, "settings.api_url"},
		{"setting value url", ConnConfig{Settings: map[string]string{"feed": "https://u:pw@x.example.com"}}, "settings.feed"},
		{"setting query ok", ConnConfig{Settings: map[string]string{"api_url": "https://x.example.com/?v=1"}}, ""},
		{"setting plain", ConnConfig{Settings: map[string]string{"username": "a@b"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := urlCredentialError(ConnConfig{}, tc.cfg)
			if tc.bad == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var re *Error
			if !errors.As(err, &re) || re.Status != http.StatusBadRequest || re.Code != CodeURLCredentialsRefused {
				t.Fatalf("err = %v", err)
			}
			if len(re.Fields) != 1 || re.Fields[0].Field != tc.bad {
				t.Errorf("fields = %v, want %s", re.Fields, tc.bad)
			}
			if b, _ := json.Marshal(re); strings.Contains(string(b), "pw") || strings.Contains(re.Msg, "abc") {
				t.Errorf("error echoes the value: %s", b)
			}
		})
	}
}

func TestMaskedConfigAndMap(t *testing.T) {
	cfg := ConnConfig{BaseURL: "https://u:pw@x.example.com", OrgURL: "https://ok.example.com", Settings: map[string]string{"api_url": "https://x.example.com/?k=abc", "n": "v"}}
	m, masked := MaskedConfig(cfg)
	if strings.Join(masked, ",") != "base_url,settings.api_url" || strings.Contains(m.BaseURL, "pw") || strings.Contains(m.Settings["api_url"], "abc") || m.OrgURL != cfg.OrgURL {
		t.Errorf("masked = %v, cfg = %+v", masked, m)
	}
	if cfg.BaseURL != "https://u:pw@x.example.com" || cfg.Settings["api_url"] != "https://x.example.com/?k=abc" {
		t.Error("the stored config was modified")
	}
	var raw map[string]any
	_ = json.Unmarshal([]byte(`{"base_url":"https://u:pw@x.example.com","settings":{"api_url":"https://x.example.com/?k=abc"}}`), &raw)
	if got := MaskConfigMap(raw); strings.Join(got, ",") != "base_url,settings.api_url" || strings.Contains(raw["base_url"].(string), "pw") {
		t.Errorf("map masked = %v %v", got, raw)
	}
}

// Issue #908: a stored URL that carries a credential is shown masked; the wizard sends the config back whole,
// and the masked value neither overwrites the stored one nor clears the sealed credential. A different value is
// refused when it carries credentials.
func TestPatchConfig_MaskedURLRoundTrip(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	const stored = "https://u:pw@scim.example.com/v2?token=abc"
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "C", ConnectorType: "scim_app", System: "sys",
			Config: json.RawMessage(`{"technical_owner":"Ingrid","business_owner":"Thandiwe","base_url":"https://scim.example.com/v2"}`)}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		if _, err = s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/tessera/x"}, "admin", t0); err != nil {
			return err
		}
		// a value stored before the write-side refusal
		rev := *b.Rev
		cfg := b.Config
		cfg.BaseURL = stored
		if err := setRevisionConfig(&rev, b.Conn, cfg); err != nil {
			return err
		}
		return c.UpdateRevisionConfig(rev.ID, rev.Config, rev.ConfigHash, rev.WriteMode, rev.ExpectedCounts, t0)
	})
	var view *RevisionView
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Current(c, id, t0)
		view = RevisionOf(b)
		return err
	})
	if strings.Contains(view.Config.BaseURL, "pw") || strings.Contains(view.Config.BaseURL, "abc") || len(view.MaskedFields) != 1 || view.MaskedFields[0] != "base_url" {
		t.Fatalf("view not masked: %+v %v", view.Config, view.MaskedFields)
	}
	// the wizard loads the view and saves it back whole
	body, _ := json.Marshal(map[string]any{"base_url": view.Config.BaseURL, "stale_days": 60})
	var res *ConfigResult
	write(t, st, func(c *store.TenantTx) error {
		var err error
		res, err = s.PatchConfig(c, id, body, "admin", t0)
		return err
	})
	if res.Bundle.Config.BaseURL != stored {
		t.Error("the masked value overwrote the stored URL")
	}
	if res.Bundle.Rev.SecretRef == nil {
		t.Error("the round trip cleared the credential")
	}
	if res.Bundle.Config.StaleDays != 60 {
		t.Error("the other field was not saved")
	}
	// a different value that still carries credentials is refused with the code, not echoed
	err := st.Write(context.Background(), func(c *store.TenantTx) error {
		_, err := s.CheckPatch(c, id, []byte(`{"base_url":"https://x:y@other.example.com"}`), t0)
		return err
	})
	var re *Error
	if !errors.As(err, &re) || re.Code != CodeURLCredentialsRefused || re.Status != http.StatusBadRequest {
		t.Fatalf("err = %v", err)
	}
	// a clean replacement is accepted (and, being a move, clears the credential)
	write(t, st, func(c *store.TenantTx) error {
		var err error
		res, err = s.PatchConfig(c, id, []byte(`{"base_url":"https://new.example.com"}`), "admin", t0)
		return err
	})
	if res.Bundle.Config.BaseURL != "https://new.example.com" {
		t.Error("a clean URL was not saved")
	}
}
