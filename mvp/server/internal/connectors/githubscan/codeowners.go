package githubscan

import (
	"path"
	"regexp"
	"strings"
)

// CodeownersPaths are where GitHub looks for a CODEOWNERS file, in order.
var CodeownersPaths = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

type codeownersRule struct {
	re     *regexp.Regexp
	owners []string
}

// Codeowners is a parsed CODEOWNERS file.
type Codeowners struct{ rules []codeownersRule }

// ParseCodeowners parses CODEOWNERS text. Lines that do not parse are skipped.
func ParseCodeowners(text string) *Codeowners {
	c := &Codeowners{}
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		// a pattern with no owner is a rule too: it leaves the path unowned
		if len(f) < 1 || strings.HasPrefix(f[0], "#") {
			continue
		}
		re, err := patternRegexp(f[0])
		if err != nil {
			continue
		}
		c.rules = append(c.rules, codeownersRule{re: re, owners: f[1:]})
	}
	return c
}

// patternRegexp compiles a CODEOWNERS (gitignore style) pattern:
//
//	*.json      any file of that name, at any depth
//	/mcp.json   only at the repository root
//	docs/       a directory and everything under it
//	/a/**/b     ** matches any number of directories
//	*           every file
func patternRegexp(p string) (*regexp.Regexp, error) {
	anchored := strings.HasPrefix(p, "/") || strings.Contains(strings.TrimSuffix(p, "/"), "/")
	dir := strings.HasSuffix(p, "/")
	p = strings.Trim(p, "/")
	var b strings.Builder
	b.WriteString("^")
	if !anchored {
		b.WriteString("(?:.*/)?")
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '*' && i+1 < len(p) && p[i+1] == '*':
			i++
			if i+1 < len(p) && p[i+1] == '/' {
				i++
				b.WriteString("(?:.*/)?")
			} else {
				b.WriteString(".*")
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if dir {
		b.WriteString("/.*")
	} else {
		b.WriteString("(?:/.*)?") // a pattern naming a directory covers what is under it
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// OwnersOf returns the owners of the last rule that matches the path, or nil.
func (c *Codeowners) OwnersOf(p string) []string {
	if c == nil {
		return nil
	}
	p = strings.TrimPrefix(path.Clean("/"+p), "/")
	for i := len(c.rules) - 1; i >= 0; i-- {
		if c.rules[i].re.MatchString(p) {
			return c.rules[i].owners
		}
	}
	return nil
}
