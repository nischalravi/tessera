package vault

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// PathRule is one path block of an ACL policy.
type PathRule struct {
	Path         string
	Capabilities []string
}

const maxPolicyRules = 2000

var (
	pathBlockRE = regexp.MustCompile(`\bpath\s+"([^"\n]{1,512})"\s*\{`)
	capsRE      = regexp.MustCompile(`capabilities\s*=\s*\[([^\]]*)\]`)
	capWordRE   = regexp.MustCompile(`"([a-z]{1,16})"`)
)

// validCaps are the capabilities Vault defines.
var validCaps = map[string]bool{"create": true, "read": true, "update": true, "patch": true, "delete": true, "list": true, "sudo": true, "deny": true, "subscribe": true, "recover": true}

// ParsePolicy extracts the path blocks and their capabilities from an ACL policy in HCL or JSON. It reads the
// two things the graph needs and nothing else (parameter constraints, response wrapping and the like are not
// interpreted). A policy it cannot read yields an error, never a guess.
func ParsePolicy(src string) ([]PathRule, error) {
	src = strings.TrimSpace(src)
	if len(src) > 1<<20 {
		return nil, errors.New("vault: the policy is too large to read")
	}
	if strings.HasPrefix(src, "{") {
		return parseJSONPolicy(src)
	}
	src = stripComments(src)
	var out []PathRule
	for pos := 0; ; {
		m := pathBlockRE.FindStringSubmatchIndex(src[pos:])
		if m == nil {
			return out, nil
		}
		open := pos + m[1] - 1
		end, ok := matchBrace(src, open)
		if !ok {
			return nil, errors.New("vault: the policy has an unbalanced block")
		}
		if len(out) >= maxPolicyRules {
			return nil, errors.New("vault: the policy has too many path blocks")
		}
		out = append(out, PathRule{Path: src[pos+m[2] : pos+m[3]], Capabilities: capsIn(src[open+1 : end])})
		pos = end + 1
	}
}

func capsIn(block string) []string {
	var caps []string
	if m := capsRE.FindStringSubmatch(block); m != nil {
		for _, w := range capWordRE.FindAllStringSubmatch(m[1], -1) {
			if validCaps[w[1]] {
				caps = append(caps, w[1])
			}
		}
	}
	return caps
}

func parseJSONPolicy(src string) ([]PathRule, error) {
	var p struct {
		Path map[string]struct {
			Capabilities []string `json:"capabilities"`
		} `json:"path"`
	}
	if err := json.Unmarshal([]byte(src), &p); err != nil {
		return nil, errors.New("vault: the policy is not valid JSON")
	}
	if len(p.Path) > maxPolicyRules {
		return nil, errors.New("vault: the policy has too many path blocks")
	}
	out := make([]PathRule, 0, len(p.Path))
	for path, v := range p.Path {
		r := PathRule{Path: path}
		for _, c := range v.Capabilities {
			if validCaps[c] {
				r.Capabilities = append(r.Capabilities, c)
			}
		}
		out = append(out, r)
	}
	sortRules(out)
	return out, nil
}

func sortRules(r []PathRule) {
	for i := 1; i < len(r); i++ {
		for j := i; j > 0 && r[j].Path < r[j-1].Path; j-- {
			r[j], r[j-1] = r[j-1], r[j]
		}
	}
}

// stripComments removes # and // line comments and /* */ blocks outside string literals.
func stripComments(s string) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if c == '"' || c == '\n' {
				inStr = false
			}
		case c == '"':
			inStr = true
			b.WriteByte(c)
		case c == '#' || (c == '/' && i+1 < len(s) && s[i+1] == '/'):
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			i += end + 3
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// matchBrace returns the index of the brace that closes the one at open, ignoring braces inside strings.
func matchBrace(s string, open int) (int, bool) {
	depth, inStr := 0, false
	for i := open; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr:
			if c == '\\' {
				i++
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func has(caps []string, want ...string) bool {
	for _, c := range caps {
		for _, w := range want {
			if c == w {
				return true
			}
		}
	}
	return false
}

// RulePrivileged reports whether a path block gives control over Vault itself or an unrestricted write: the
// sudo capability, a write on the sys/, identity/ or auth/token/ paths (policies, mounts, auth methods, raw
// storage, tokens, identities) or on every path. A deny block is never privileged.
func RulePrivileged(r PathRule) bool {
	if has(r.Capabilities, "deny") {
		return false
	}
	if has(r.Capabilities, "sudo") {
		return true
	}
	if !has(r.Capabilities, "create", "update", "patch", "delete") {
		return false
	}
	p := strings.TrimPrefix(r.Path, "/")
	switch {
	case p == "*" || p == "+" || p == "+/*" || p == "**":
		return true
	case strings.HasPrefix(p, "sys/") || strings.HasPrefix(p, "identity/") || strings.HasPrefix(p, "auth/token/"):
		return true
	}
	return false
}
