package unixssh

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits on what a host may hand back. The output of a command is parsed strictly: a line that does
// not match its grammar is counted and dropped, never half-read.
const (
	maxAccounts = 100000
	maxGroups   = 100000
	maxMembers  = 100000
	maxRules    = 20000
	maxField    = 256
	maxLine     = 4096
	// HumanUID is the lowest uid of a login (non-system) account on most distributions.
	HumanUID = 1000
)

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,62}\$?$`)
	// aliasRE is a sudoers alias name: upper-case letters, digits and underscores.
	aliasRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	runasRE = regexp.MustCompile(`\(\s*ALL\s*(:\s*ALL\s*)?\)`)
	allRE   = regexp.MustCompile(`(^|[\s,=:)])ALL($|[\s,:])`)
	commaRE = regexp.MustCompile(`\s*,\s*`)
)

// Account is one line of `getent passwd`.
type Account struct {
	Name       string
	UID, GID   uint32
	Home       string
	Shell      string
	Privileged bool // uid 0
}

// Group is one line of `getent group`.
type Group struct {
	Name    string
	GID     uint32
	Members []string
}

// printable reports whether s is valid UTF-8 without control characters and no longer than max.
func printable(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// lines splits command output into lines, without the final empty one.
func lines(b []byte) []string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// ParsePasswd reads the output of `getent passwd`: seven colon separated fields per line. bad counts
// the lines dropped (wrong shape, bad name or number, duplicate name).
func ParsePasswd(b []byte) (out []Account, bad int) {
	seen := map[string]bool{}
	for _, l := range lines(b) {
		if l == "" {
			continue
		}
		f := strings.Split(l, ":")
		if len(f) != 7 || !nameRE.MatchString(f[0]) || seen[f[0]] || !printable(f[4], maxField) || !printable(f[5], maxField) || !printable(f[6], maxField) {
			bad++
			continue
		}
		uid, err1 := strconv.ParseUint(f[2], 10, 32)
		gid, err2 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil || len(out) >= maxAccounts {
			bad++
			continue
		}
		seen[f[0]] = true
		out = append(out, Account{Name: f[0], UID: uint32(uid), GID: uint32(gid), Home: f[5], Shell: f[6], Privileged: uid == 0})
	}
	return out, bad
}

// ParseGroup reads the output of `getent group`: four colon separated fields per line.
func ParseGroup(b []byte) (out []Group, bad int) {
	seen := map[string]bool{}
	for _, l := range lines(b) {
		if l == "" {
			continue
		}
		f := strings.Split(l, ":")
		if len(f) != 4 || !nameRE.MatchString(f[0]) || seen[f[0]] {
			bad++
			continue
		}
		gid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil || len(out) >= maxGroups {
			bad++
			continue
		}
		var members []string
		ok := true
		if f[3] != "" {
			for _, m := range strings.Split(f[3], ",") {
				if !nameRE.MatchString(m) || len(members) >= maxMembers {
					ok = false
					break
				}
				members = append(members, m)
			}
		}
		if !ok {
			bad++
			continue
		}
		seen[f[0]] = true
		out = append(out, Group{Name: f[0], GID: uint32(gid), Members: members})
	}
	return out, bad
}

// lastlogLayouts are the timestamps `lastlog` prints (util-linux, with and without a zone).
var lastlogLayouts = []string{"Mon Jan _2 15:04:05 -0700 2006", "Mon Jan _2 15:04:05 2006"}

var lastlogTimeRE = regexp.MustCompile(`[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}(?: [+-]\d{4})? \d{4}$`)

// ParseLastlog reads `lastlog`: the first column is the user name, the last columns the time of the
// last login, or "**Never logged in**". The format is not standard, so a line it cannot read is
// skipped; the result is only ever used to fill a last-login time.
func ParseLastlog(b []byte) map[string]time.Time {
	out := map[string]time.Time{}
	for _, l := range lines(b) {
		if !printable(l, maxLine) || len(out) >= maxAccounts || strings.Contains(l, "Never logged in") {
			continue
		}
		name, _, ok := strings.Cut(l, " ")
		if !ok || !nameRE.MatchString(name) {
			continue
		}
		ts := lastlogTimeRE.FindString(l)
		for _, layout := range lastlogLayouts {
			if t, err := time.Parse(layout, ts); err == nil {
				out[name] = t.UTC()
				break
			}
		}
	}
	return out
}

// Rule is one sudoers rule line, resolved to its principals.
type Rule struct {
	// Principals are "u:<user>" and "g:<group>" (aliases expanded). The ALL user and negations are
	// not listed: the first is no one in particular, the second grants nothing.
	Principals []string
	// Text is the normalised rule without its principals, for display.
	Text string
	// Full is true for a runas of (ALL) or (ALL:ALL), or a rule that runs ALL commands.
	Full bool
	// ID is stable across reads: a hash of the normalised line.
	ID string
}

// ParseSudoers reads the concatenated text of /etc/sudoers and /etc/sudoers.d. It understands user
// specifications, User_Alias and Cmnd_Alias; Defaults, includes, Host_Alias and Runas_Alias are not
// rules and are ignored. skipped counts the lines that look like a rule but could not be read, so the
// caller can say the analysis may be incomplete.
func ParseSudoers(b []byte) (rules []Rule, skipped int) {
	var logical []string
	var cur strings.Builder
	overflow := false // an endless continuation: the whole logical line is dropped, not its tail read as a rule
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if cur.Len()+len(l) > maxLine {
			overflow = true
		}
		if strings.HasSuffix(l, "\\") {
			if !overflow {
				cur.WriteString(strings.TrimSuffix(l, "\\") + " ")
			}
			continue
		}
		if overflow {
			skipped++
			overflow = false
		} else {
			cur.WriteString(l)
			logical = append(logical, strings.TrimSpace(cur.String()))
		}
		cur.Reset()
	}
	userAlias := map[string][]string{}
	cmdAlias := map[string]string{}
	var specs []string
	for _, l := range logical {
		switch {
		case l == "":
		case !printable(l, maxLine):
			skipped++
		case strings.HasPrefix(l, "#") && !isUIDSpec(l), strings.HasPrefix(l, "@"):
		case isUIDSpec(l):
			skipped++ // "#1000 ALL=(ALL) ALL" names a user by uid: not resolved
		case strings.HasPrefix(l, "Defaults"), strings.HasPrefix(l, "Host_Alias"), strings.HasPrefix(l, "Runas_Alias"):
		case strings.HasPrefix(l, "User_Alias"), strings.HasPrefix(l, "Cmnd_Alias"):
			kind, rest, _ := strings.Cut(l, " ")
			name, def, ok := strings.Cut(strings.TrimSpace(rest), "=")
			name = strings.TrimSpace(name)
			if !ok || !aliasRE.MatchString(name) {
				skipped++
				continue
			}
			if kind == "User_Alias" {
				userAlias[name] = splitList(def)
			} else {
				cmdAlias[name] = def
			}
		default:
			specs = append(specs, l)
		}
	}
	for _, l := range specs {
		r, ok := parseSpec(l, userAlias, cmdAlias)
		if !ok || len(rules) >= maxRules {
			skipped++
			continue
		}
		rules = append(rules, r)
	}
	return rules, skipped
}

// isUIDSpec is a line starting "#<digit>": a user given by uid, not a comment.
func isUIDSpec(l string) bool {
	return len(l) > 1 && l[0] == '#' && l[1] >= '0' && l[1] <= '9'
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseSpec(l string, userAlias map[string][]string, cmdAlias map[string]string) (Rule, bool) {
	lhs, rhs, ok := strings.Cut(l, "=")
	if !ok {
		return Rule{}, false
	}
	lhs = commaRE.ReplaceAllString(strings.TrimSpace(lhs), ",")
	f := strings.Fields(lhs)
	lhs = strings.Join(f, " ")
	rhs = strings.Join(strings.Fields(rhs), " ")
	if len(f) != 2 || rhs == "" {
		return Rule{}, false
	}
	var principals []string
	seen := map[string]bool{}
	add := func(p string) bool {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		kind, name := "u:", p
		if g, isGroup := strings.CutPrefix(p, "%"); isGroup {
			kind, name = "g:", g
		}
		switch {
		case p == "ALL" || neg:
			return true
		case !nameRE.MatchString(name):
			return false
		case !seen[kind+name]:
			seen[kind+name] = true
			principals = append(principals, kind+name)
		}
		return true
	}
	for _, p := range strings.Split(f[0], ",") {
		if aliasRE.MatchString(p) && p != "ALL" {
			members, defined := userAlias[p]
			if !defined {
				return Rule{}, false
			}
			for _, m := range members {
				if !add(m) {
					return Rule{}, false
				}
			}
			continue
		}
		if !add(p) {
			return Rule{}, false
		}
	}
	full := runasRE.MatchString(rhs) || allRE.MatchString(rhs)
	for name, def := range cmdAlias {
		if allRE.MatchString(def) && strings.Contains(rhs, name) {
			full = true
		}
	}
	text := rhs
	if len(text) > 200 {
		text = strings.ToValidUTF8(text[:200], "")
	}
	sum := sha256.Sum256([]byte(lhs + "=" + rhs))
	return Rule{Principals: principals, Text: f[1] + " = " + text, Full: full, ID: hex.EncodeToString(sum[:6])}, true
}
