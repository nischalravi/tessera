package okta

import (
	"strings"
	"testing"
)

// FromStored reads the org URL from the stored config and the client from the sealed credential,
// refuses what does not open without echoing the credential, and lets only the dev override
// replace the stored org URL.
func TestFromStored(t *testing.T) {
	noEnv := func(string) string { return "" }
	hc := prodClient(t)
	const org = "https://acme.okta.com"
	pemKey, _ := genKey(t)
	for _, tc := range []struct {
		name       string
		s          Stored
		good       bool
		wantNoLeak string
	}{
		{"api token", Stored{OrgURL: org, Credential: `{"api_token":"SSWS-SECRET"}`}, true, ""},
		{"oauth client", Stored{OrgURL: org, Credential: `{"client_id":"0oa1","private_key":"` + strings.ReplaceAll(pemKey, "\n", `\n`) + `","key_id":"k1"}`}, true, ""},
		{"no credential", Stored{OrgURL: org}, false, ""},
		{"credential is not JSON", Stored{OrgURL: org, Credential: "SSWS-SECRET-plain"}, false, "SSWS-SECRET-plain"},
		{"empty JSON", Stored{OrgURL: org, Credential: `{}`}, false, ""},
		{"token and client", Stored{OrgURL: org, Credential: `{"api_token":"SSWS-SECRET","client_id":"0oa1","private_key":"x"}`}, false, "SSWS-SECRET"},
		{"client without key", Stored{OrgURL: org, Credential: `{"client_id":"0oa1"}`}, false, ""},
		{"no org url", Stored{Credential: `{"api_token":"SSWS-SECRET"}`}, false, "SSWS-SECRET"},
		{"http org url", Stored{OrgURL: "http://acme.okta.com", Credential: `{"api_token":"SSWS-SECRET"}`}, false, "SSWS-SECRET"},
		{"org url with a path", Stored{OrgURL: org + "/x", Credential: `{"api_token":"SSWS-SECRET"}`}, false, "SSWS-SECRET"},
		{"metadata host", Stored{OrgURL: "https://169.254.169.254", Credential: `{"api_token":"SSWS-SECRET"}`}, false, "SSWS-SECRET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := FromStored(tc.s, noEnv, prodRT, hc, nil)
			if (err == nil) != tc.good {
				t.Fatalf("FromStored = %v, want ok=%v", err, tc.good)
			}
			if err != nil {
				if tc.wantNoLeak != "" && strings.Contains(err.Error(), tc.wantNoLeak) {
					t.Errorf("error echoes the credential: %v", err)
				}
				return
			}
			o := c.(*Connector)
			if o.base.String() != org || !o.cfg.EmitIdentities || o.cfg.SkipAuthMethods {
				t.Errorf("base %s, config %+v", o.base, o.cfg)
			}
		})
	}
	// the dev override replaces the stored org URL (refused outside dev by the caller)
	env := func(k string) string {
		if k == "TESSERA_OKTA_ORG_URL" {
			return "https://override.okta.com"
		}
		return ""
	}
	c, err := FromStored(Stored{OrgURL: org, Credential: `{"api_token":"t"}`}, env, prodRT, hc, nil)
	if err != nil || c.(*Connector).base.Host != "override.okta.com" {
		t.Errorf("override: %v", err)
	}
}
