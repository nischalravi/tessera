// Package githubscan scans the repositories of a GitHub organization for MCP
// server configurations and agent credentials, and links each finding to an
// owner (issue #116).
//
// What it keeps. A finding is a location (repository, path, and where in the
// file), the kind of thing found, and for a secret its TYPE ("github_token",
// "anthropic_api_key") and a fingerprint: the first 16 hex digits of a SHA-256
// of the type and the matched text. The matched text itself is never stored,
// logged or returned: it exists only inside detect, which hands back a
// fingerprint. A truncated hash cannot be turned back into the secret, and
// the same secret found in two repositories has the same fingerprint, which is
// what lets a reviewer see that one leaked key sits in several places. (A very
// short, guessable value could be recovered by guessing and comparing; that is
// why generic matches need eight characters and a secret-like key name.)
package githubscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Finding kinds.
const (
	KindMCPServer       = "mcp_server"
	KindAgentCredential = "agent_credential" // #nosec G101 -- a finding kind name, not a credential
)

// Finding is what one scan of one file produces, before an owner is linked.
type Finding struct {
	Kind        string
	Location    string
	Server      string
	Transport   string
	Target      string
	SecretType  string
	Fingerprint string
}

// fileClass says how a path is scanned.
type fileClass int

const (
	classNone fileClass = iota
	// classMCP files are parsed as MCP server configuration (JSON or JSONC).
	classMCP
	// classCreds files are scanned line by line for credentials.
	classCreds
)

var mcpBasenames = map[string]bool{
	".mcp.json": true, "mcp.json": true, "claude_desktop_config.json": true, "mcp_config.json": true,
	"mcp-config.json": true, "mcp.config.json": true, ".claude.json": true,
}

// mcpPaths are config files that hold MCP servers among other settings.
var mcpPaths = []string{".vscode/settings.json", ".gemini/settings.json", ".zed/settings.json", ".cursor/mcp.json",
	".vscode/mcp.json", ".windsurf/mcp_config.json", ".codeium/windsurf/mcp_config.json", ".roo/mcp.json"}

var credPaths = []string{".claude/settings.json", ".claude/settings.local.json"}

// envFile matches .env, .env.local, .env.production, ... but not the committed
// templates (.env.example, .env.sample, .env.template, .env.dist, .env.defaults).
var envFile = regexp.MustCompile(`^\.env(\.[A-Za-z0-9_-]+)?$`)
var envTemplate = regexp.MustCompile(`(?i)\.(example|sample|template|dist|defaults?)$`)

// MaxFileBytes bounds a file that is fetched and scanned.
const MaxFileBytes = 256 << 10

var skipDirs = []string{"node_modules/", "vendor/", ".git/", "dist/", "build/"}

// Classify says how the file at a repository path is scanned.
func Classify(p string) fileClass {
	if p == "" || len(p) > 512 {
		return classNone
	}
	for _, d := range skipDirs {
		if strings.HasPrefix(p, d) || strings.Contains(p, "/"+d) {
			return classNone
		}
	}
	base := path.Base(p)
	if mcpBasenames[base] {
		return classMCP
	}
	for _, s := range mcpPaths {
		if p == s || strings.HasSuffix(p, "/"+s) {
			return classMCP
		}
	}
	for _, s := range credPaths {
		if p == s || strings.HasSuffix(p, "/"+s) {
			return classCreds
		}
	}
	if envFile.MatchString(base) && !envTemplate.MatchString(base) {
		return classCreds
	}
	return classNone
}

// Scan scans one file's content. The result is deterministic.
func Scan(p string, content []byte) []Finding {
	if len(content) > MaxFileBytes {
		return nil
	}
	switch Classify(p) {
	case classMCP:
		return scanMCP(content)
	case classCreds:
		return scanLines(content)
	}
	return nil
}

// ---------------------------------------------------------------- secrets

type tokenPattern struct {
	typ string
	re  *regexp.Regexp
}

// tokenPatterns are secret shapes recognised anywhere in a value. Order
// matters: the first match names the type (an Anthropic key also looks like an
// OpenAI one).
var tokenPatterns = []tokenPattern{
	{"anthropic_api_key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)},
	{"openai_api_key", regexp.MustCompile(`sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}`)},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}`)},
	{"gitlab_token", regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`)},
	{"aws_access_key_id", regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`)},
	{"slack_token", regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"google_api_key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"npm_token", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{"bearer_token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/\-]{20,}=*`)},
}

var (
	secretKey    = regexp.MustCompile(`(?i)(secret|token|passw(or)?d|api[_-]?key|private[_-]?key|credentials?)`)
	notSecretKey = regexp.MustCompile(`(?i)(_file|_path|_url|_uri|_name|_id|_env|_dir|_count|_ttl|_expiry|_endpoint|_header)$`)
	placeholder  = regexp.MustCompile(`(?i)^(\$\{?[A-Za-z_]|\{\{|<.*>$|%[A-Za-z_].*%$|\$\{input:|\$\{env:)|your[_-]|example|placeholder|changeme|xxxx|\*\*\*|^(true|false|null|none)$`)
)

// fingerprint is the first 16 hex digits of SHA-256(type NUL value).
func fingerprint(typ, value string) string {
	h := sha256.New()
	h.Write([]byte(typ))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// detect reports whether value, found under key, is a secret, and if so its
// type and fingerprint. The value is not returned.
func detect(key, value string) (typ, fp string, ok bool) {
	v := strings.TrimSpace(value)
	if len(v) < 8 || len(v) > 4096 || placeholder.MatchString(v) {
		return "", "", false
	}
	for _, p := range tokenPatterns {
		if m := p.re.FindString(v); m != "" {
			return p.typ, fingerprint(p.typ, m), true
		}
	}
	k := strings.ToLower(strings.TrimSpace(key))
	switch k {
	case "authorization", "proxy-authorization":
		scheme, rest, _ := strings.Cut(v, " ")
		switch {
		case strings.EqualFold(scheme, "basic") && len(rest) >= 8:
			return "basic_auth", fingerprint("basic_auth", rest), true
		case strings.EqualFold(scheme, "bearer") && len(rest) >= 8 && !placeholder.MatchString(rest):
			return "bearer_token", fingerprint("bearer_token", rest), true
		}
		return "", "", false
	}
	if k != "" && secretKey.MatchString(k) && !notSecretKey.MatchString(k) && looksLiteral(v) {
		return "generic_secret", fingerprint("generic_secret", v), true
	}
	return "", "", false
}

// looksLiteral is true for a value that could be a secret itself: one word,
// not a path or a number.
func looksLiteral(v string) bool {
	if strings.ContainsAny(v, " \t") || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "~") {
		return false
	}
	letters := 0
	for _, r := range v {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			letters++
		}
	}
	return letters >= 2
}

// ---------------------------------------------------------------- MCP configs

// serverContainers are the keys that hold the servers of an MCP config.
var serverContainers = []string{"mcpServers", "servers", "context_servers"}

func scanMCP(content []byte) []Finding {
	var doc map[string]any
	if err := json.Unmarshal(stripJSONC(content), &doc); err != nil {
		return nil // not JSON we can read: nothing to report, and nothing is quoted
	}
	var out []Finding
	seen := map[string]bool{}
	add := func(f Finding) {
		k := f.Kind + "|" + f.Location + "|" + f.Fingerprint
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	scanContainers(doc, "", add)
	if m, ok := doc["mcp"].(map[string]any); ok { // VS Code settings.json: "mcp": {"servers": {...}}
		scanContainers(m, "mcp.", add)
	}
	return out
}

func scanContainers(doc map[string]any, prefix string, add func(Finding)) {
	for _, ck := range serverContainers {
		servers, ok := doc[ck].(map[string]any)
		if !ok {
			continue
		}
		names := make([]string, 0, len(servers))
		for n := range servers {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			srv, ok := servers[name].(map[string]any)
			if !ok {
				continue
			}
			loc := prefix + ck + "." + clip(name, 64)
			transport, target := describe(srv)
			add(Finding{Kind: KindMCPServer, Location: loc, Server: clip(name, 64), Transport: transport, Target: target})
			walk(loc, "", srv, 0, func(l, typ, fp string) {
				add(Finding{Kind: KindAgentCredential, Location: l, Server: clip(name, 64), Transport: transport, Target: target,
					SecretType: typ, Fingerprint: fp})
			})
		}
	}
}

// describe returns the transport and a short, secret-free description of how
// the server is reached: a command name and its package, or a URL host.
func describe(srv map[string]any) (transport, target string) {
	typ, _ := srv["type"].(string)
	u := ""
	for _, k := range []string{"url", "serverUrl", "httpUrl", "uri"} {
		if s, ok := srv[k].(string); ok && s != "" {
			u = s
			break
		}
	}
	cmd, _ := srv["command"].(string)
	switch t := strings.ToLower(typ); {
	case t == "sse":
		transport = "sse"
	case t == "stdio":
		transport = "stdio"
	case t == "http" || t == "streamable-http" || t == "streamablehttp":
		transport = "http"
	case u != "":
		transport = "http"
	case cmd != "":
		transport = "stdio"
	default:
		transport = "unknown"
	}
	if u != "" {
		if pu, err := url.Parse(u); err == nil && pu.Hostname() != "" {
			return transport, clip(pu.Hostname(), 128)
		}
		return transport, ""
	}
	target = path.Base(strings.ReplaceAll(cmd, `\`, "/"))
	if target == "." || target == "/" {
		target = ""
	}
	if args, ok := srv["args"].([]any); ok {
		for _, a := range args {
			s, _ := a.(string)
			if s == "" || strings.HasPrefix(s, "-") {
				continue
			}
			if _, _, secret := detect("", s); !secret && !strings.ContainsAny(s, "=:") || strings.HasPrefix(s, "@") {
				target += " " + clip(s, 80)
			}
			break
		}
	}
	return transport, clip(strings.TrimSpace(target), 128)
}

// walk visits every string of a server definition and calls found for each
// secret, with the JSON path it sits at.
func walk(loc, key string, v any, depth int, found func(loc, typ, fp string)) {
	if depth > 8 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			walk(loc+"."+clip(k, 64), k, x[k], depth+1, found)
		}
	case []any:
		prevFlag := ""
		for i, e := range x {
			s, isStr := e.(string)
			l := fmt.Sprintf("%s[%d]", loc, i)
			if !isStr {
				walk(l, key, e, depth+1, found)
				continue
			}
			k := key
			if key == "args" {
				k = ""
				if name, val, ok := strings.Cut(strings.TrimLeft(s, "-"), "="); ok && strings.HasPrefix(s, "-") {
					k, s = name, val
				} else if prevFlag != "" {
					k = prevFlag
				}
				prevFlag = ""
				if strings.HasPrefix(e.(string), "-") && !strings.Contains(e.(string), "=") {
					prevFlag = strings.TrimLeft(e.(string), "-")
				}
			}
			if typ, fp, ok := detect(k, s); ok {
				found(l, typ, fp)
			}
		}
	case string:
		if isURLKey(key) {
			if typ, fp, ok := detectURL(x); ok {
				found(loc, typ, fp)
			}
			return
		}
		if typ, fp, ok := detect(key, x); ok {
			found(loc, typ, fp)
		}
	}
}

func isURLKey(k string) bool {
	switch k {
	case "url", "serverUrl", "httpUrl", "uri":
		return true
	}
	return false
}

// detectURL finds credentials in a URL: a password in the user info, or a
// secret-named query parameter.
func detectURL(raw string) (typ, fp string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return detect("", raw)
	}
	if u.User != nil {
		if pw, has := u.User.Password(); has && !placeholder.MatchString(pw) && len(pw) >= 8 {
			return "url_credential", fingerprint("url_credential", pw), true
		}
	}
	q, _ := url.ParseQuery(u.RawQuery)
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range q[k] {
			if typ, fp, ok := detect(k, v); ok {
				return typ, fp, true
			}
		}
	}
	return "", "", false
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------------------------------------------------------------- credential files

var kvLine = regexp.MustCompile(`^\s*(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[=:]\s*["']?([^"'\s,#]+)`)

// scanLines scans a .env style or JSON settings file line by line. A line is a
// finding when a known token shape is anywhere on it, or when its key names a
// secret and its value is a literal.
func scanLines(content []byte) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for i, line := range bytes.Split(content, []byte("\n")) {
		if len(line) > 4096 {
			continue
		}
		l := string(line)
		typ, fp, ok := "", "", false
		for _, p := range tokenPatterns {
			if m := p.re.FindString(l); m != "" && !placeholder.MatchString(m) {
				typ, fp, ok = p.typ, fingerprint(p.typ, m), true
				break
			}
		}
		if !ok {
			if m := kvLine.FindStringSubmatch(l); m != nil {
				typ, fp, ok = detect(m[1], m[2])
			}
		}
		if !ok {
			continue
		}
		loc := fmt.Sprintf("L%d", i+1)
		k := loc + "|" + fp
		if !seen[k] {
			seen[k] = true
			out = append(out, Finding{Kind: KindAgentCredential, Location: loc, SecretType: typ, Fingerprint: fp})
		}
	}
	return out
}

// ---------------------------------------------------------------- JSONC

// stripJSONC removes // and /* */ comments and trailing commas, which VS Code
// and Zed allow in their JSON settings, leaving strings untouched.
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				i++
				out = append(out, b[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			// drop a comma that is followed only by whitespace, comments and a closer
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
