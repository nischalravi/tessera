package githubscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fakeSecrets are built at run time so that no file in the repository holds a
// string that looks like a real credential (GitHub's push protection would
// rightly refuse one).
func fakeSecrets() map[string]string {
	return map[string]string{
		"GITHUB":    "gh" + "p_" + strings.Repeat("aB3dE5", 6),
		"ANTHROPIC": "sk-" + "ant-" + "api03-" + strings.Repeat("Zy9xW8", 5),
		"BEARER":    strings.Repeat("tokenpart", 3),
		"PASSWORD":  "Tr0ub4dor&3-horse",
		"QUERYKEY":  "q9w8e7r6t5y4u3i2",
		"SLACK":     "xox" + "b-" + "1234567890-abcdefghij",
		"SESSION":   "c2Vzc2lvbi1zZWNyZXQtdmFsdWU",
	}
}

// render reads a testdata template and fills in the fake secrets.
func render(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for k, v := range fakeSecrets() {
		s = strings.ReplaceAll(s, "@@"+k+"@@", v)
	}
	return []byte(s)
}

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want fileClass
	}{
		{".mcp.json", classMCP},
		{"mcp.json", classMCP},
		{"tools/mcp.json", classMCP},
		{"claude_desktop_config.json", classMCP},
		{".cursor/mcp.json", classMCP},
		{"app/.cursor/mcp.json", classMCP},
		{".vscode/mcp.json", classMCP},
		{".vscode/settings.json", classMCP},
		{".windsurf/mcp_config.json", classMCP},
		{".env", classCreds},
		{"service/.env.production", classCreds},
		{".claude/settings.local.json", classCreds},
		{".env.example", classNone},
		{".env.sample", classNone},
		{"node_modules/pkg/mcp.json", classNone},
		{"web/node_modules/pkg/mcp.json", classNone},
		{"vendor/x/.mcp.json", classNone},
		{"src/main.go", classNone},
		{"mcp.json.bak", classNone},
		{"", classNone},
	}
	for _, c := range cases {
		if got := Classify(c.path); got != c.want {
			t.Errorf("Classify(%q) = %d, want %d", c.path, got, c.want)
		}
	}
}

func byLocation(fs []Finding, kind string) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range fs {
		if f.Kind == kind {
			out[f.Location] = f
		}
	}
	return out
}

func TestScanMCPConfig(t *testing.T) {
	fs := Scan(".mcp.json", render(t, "mcp_json.tmpl"))
	servers := byLocation(fs, KindMCPServer)
	wantServers := map[string][2]string{ // location -> transport, target
		"mcpServers.github":       {"stdio", "npx @modelcontextprotocol/server-github"},
		"mcpServers.remote-tools": {"sse", "tools.example.com"},
		"mcpServers.safe":         {"stdio", "node server.js"},
		"mcpServers.db":           {"stdio", "uvx mcp-server-db"},
		"mcpServers.query":        {"http", "mcp.example.com"},
	}
	if len(servers) != len(wantServers) {
		t.Errorf("servers = %v", servers)
	}
	for loc, w := range wantServers {
		if s := servers[loc]; s.Transport != w[0] || s.Target != w[1] {
			t.Errorf("%s = transport %q target %q, want %v", loc, s.Transport, s.Target, w)
		}
	}
	creds := byLocation(fs, KindAgentCredential)
	wantCreds := map[string]string{
		"mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN": "github_token",
		"mcpServers.remote-tools.headers.Authorization":      "bearer_token",
		"mcpServers.remote-tools.headers.X-Api-Key":          "anthropic_api_key",
		"mcpServers.db.args[2]":                              "generic_secret",
		"mcpServers.query.url":                               "generic_secret",
	}
	if len(creds) != len(wantCreds) {
		t.Errorf("credentials = %v (placeholders, file paths and plain settings must not be findings)", creds)
	}
	for loc, typ := range wantCreds {
		if c := creds[loc]; c.SecretType != typ || c.Server == "" {
			t.Errorf("%s = %+v, want type %s", loc, c, typ)
		}
	}
}

// Nothing a scan returns may contain a secret value, and every fingerprint is
// 16 hex digits.
func TestScanNeverReturnsSecretValues(t *testing.T) {
	hex16 := regexp.MustCompile(`^[0-9a-f]{16}$`)
	var all []Finding
	all = append(all, Scan(".mcp.json", render(t, "mcp_json.tmpl"))...)
	all = append(all, Scan(".env", render(t, "env.tmpl"))...)
	all = append(all, Scan(".vscode/mcp.json", render(t, "platform_mcp.json"))...)
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range fakeSecrets() {
		if strings.Contains(string(raw), v) || strings.Contains(string(raw), v[:12]) {
			t.Errorf("the findings contain (part of) the %s value", name)
		}
	}
	n := 0
	for _, f := range all {
		if f.Kind != KindAgentCredential {
			if f.Fingerprint != "" || f.SecretType != "" {
				t.Errorf("a server finding carries a secret: %+v", f)
			}
			continue
		}
		n++
		if !hex16.MatchString(f.Fingerprint) || f.SecretType == "" {
			t.Errorf("credential finding = %+v", f)
		}
	}
	if n == 0 {
		t.Fatal("no credentials found at all")
	}
	// the same value has the same fingerprint wherever it is found; a different value does not
	a := Scan(".mcp.json", []byte(`{"mcpServers":{"a":{"env":{"T":"`+fakeSecrets()["GITHUB"]+`"}}}}`))
	b := Scan("tools/mcp.json", []byte(`{"mcpServers":{"zzz":{"env":{"OTHER":"`+fakeSecrets()["GITHUB"]+`"}}}}`))
	c := Scan(".mcp.json", []byte(`{"mcpServers":{"a":{"env":{"T":"`+fakeSecrets()["GITHUB"][:35]+`Q"}}}}`))
	fp := func(fs []Finding) string { return byLocationFP(fs) }
	if fp(a) == "" || fp(a) != fp(b) || fp(a) == fp(c) {
		t.Errorf("fingerprints: %q %q %q", fp(a), fp(b), fp(c))
	}
}

func byLocationFP(fs []Finding) string {
	for _, f := range fs {
		if f.Fingerprint != "" {
			return f.Fingerprint
		}
	}
	return ""
}

func TestScanEnvFile(t *testing.T) {
	fs := Scan("service/.env", render(t, "env.tmpl"))
	got := map[string]string{}
	for _, f := range fs {
		got[f.Location] = f.SecretType
	}
	want := map[string]string{"L3": "anthropic_api_key", "L4": "slack_token", "L5": "generic_secret"}
	if len(got) != len(want) {
		t.Errorf("env findings = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if len(Scan(".env.example", render(t, "env.tmpl"))) != 0 {
		t.Error("a committed template was scanned")
	}
}

func TestScanJSONCAndVSCodeShapes(t *testing.T) {
	fs := Scan(".vscode/mcp.json", render(t, "platform_mcp.json"))
	servers, creds := byLocation(fs, KindMCPServer), byLocation(fs, KindAgentCredential)
	if s := servers["servers.fetch"]; s.Transport != "http" || s.Target != "fetch.example.com" {
		t.Errorf("servers = %v", servers)
	}
	if c := creds["servers.fetch.headers.Authorization"]; c.SecretType != "bearer_token" {
		t.Errorf("credentials = %v", creds)
	}
	// VS Code settings.json nests the servers under "mcp"
	settings := `{"editor.fontSize": 14, // keep
	  "mcp": {"servers": {"git": {"command": "uvx", "args": ["mcp-server-git"]}}}}`
	fs = Scan(".vscode/settings.json", []byte(settings))
	if s := byLocation(fs, KindMCPServer)["mcp.servers.git"]; s.Target != "uvx mcp-server-git" {
		t.Errorf("settings.json servers = %+v", fs)
	}
	// an unrelated JSON file, malformed JSON and an oversize file report nothing
	for name, content := range map[string][]byte{"unrelated": []byte(`{"name":"x"}`), "malformed": []byte(`{"mcpServers": {`),
		"huge": append([]byte(`{"mcpServers":{}}`), make([]byte, MaxFileBytes+1)...)} {
		if got := Scan(".mcp.json", content); len(got) != 0 {
			t.Errorf("%s: findings = %v", name, got)
		}
	}
}

func TestPlaceholdersAreNotSecrets(t *testing.T) {
	for _, v := range []string{"${GITHUB_TOKEN}", "$GITHUB_TOKEN", "${env:TOKEN}", "${input:api-key}", "<your-token-here>", "{{ secrets.TOKEN }}",
		"%API_KEY%", "your_api_key_here", "changeme-please", "xxxxxxxxxxxx", "true"} {
		if typ, _, ok := detect("API_KEY", v); ok {
			t.Errorf("detect(%q) = %s", v, typ)
		}
	}
	for _, k := range []string{"TOKEN_FILE", "API_KEY_PATH", "SECRET_NAME", "client_id", "AUTH_URL"} {
		if typ, _, ok := detect(k, "abcdefgh12345678"); ok {
			t.Errorf("detect(%q, literal) = %s", k, typ)
		}
	}
}
