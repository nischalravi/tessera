// Package match decides whether an intake record is a person Tessera already
// knows (guest accounts design §5.2 to §5.3, issue #68 / GU-5).
//
// The package has two layers. The rules (this file, jw.go, rules.go) are pure:
// they compare an Intake with Candidates and return a Result per candidate
// with the tier, the score, the rules that fired and the masked attributes
// compared, so "why did this match" is answerable for every link. load.go reads
// the people from the tenant's store and writes the results.
//
// Self-asserted intake (a sponsor invitation, a self-registration) never links
// by itself: the best a rule can do is raise a "suspected existing person" flag
// (§5.5). Only proof of possession (the claimant signed in as the candidate),
// an authoritative source or an existing federated binding links without a
// reviewer.
//
// A national identifier (SSN, SIN, NI) rule is deliberately absent: whether to
// keep a keyed hash of one is an open question (design §13.4). NationalIDRule
// in rules.go is the one place it would plug in.
package match

import (
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// foldExtra maps letters that Unicode does not decompose to their plain Latin
// form, for comparison only.
var foldExtra = map[rune]string{'ø': "o", 'đ': "d", 'ł': "l", 'ð': "d", 'þ': "th", 'æ': "ae", 'œ': "oe", 'ı': "i"}

// Fold normalizes a name for comparison: Unicode NFKC, case folding,
// diacritics removed, punctuation and hyphens read as spaces, runs of spaces
// collapsed. "José  GARCÍA-López" and "jose garcia lopez" fold to the same text.
func Fold(s string) string {
	s = norm.NFKC.String(s)
	s = cases.Fold().String(s)
	s = norm.NFD.String(s)
	var b strings.Builder
	space := true // drops leading spaces
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Mn, r):
			continue // a combining mark: the diacritic
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			if x, ok := foldExtra[r]; ok {
				b.WriteString(x)
			} else {
				b.WriteRune(r)
			}
			space = false
		default: // space, hyphen, apostrophe, dot, ...
			if !space {
				b.WriteByte(' ')
				space = true
			}
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// Name is the names one source gives a person.
type Name struct {
	Given     string
	Family    string
	Preferred string // preferred given name, if any
}

// Variants returns the folded forms a name is compared in: "given family" and
// "family given" for the legal name, and the same two with the preferred name.
func (n Name) Variants() []string {
	g, f, p := Fold(n.Given), Fold(n.Family), Fold(n.Preferred)
	var out []string
	add := func(a, b string) {
		for _, v := range []string{strings.TrimSpace(a + " " + b), strings.TrimSpace(b + " " + a)} {
			if v == "" {
				continue
			}
			dup := false
			for _, o := range out {
				dup = dup || o == v
			}
			if !dup {
				out = append(out, v)
			}
		}
	}
	add(g, f)
	if p != "" && p != g {
		add(p, f)
	}
	return out
}

// SplitName splits a display name into given and family at its last space; the
// matcher reads both orders, so a wrong split costs nothing.
func SplitName(full string) Name {
	full = strings.TrimSpace(full)
	if i := strings.LastIndexByte(full, ' '); i > 0 {
		return Name{Given: strings.TrimSpace(full[:i]), Family: strings.TrimSpace(full[i+1:])}
	}
	return Name{Given: full}
}

// NameScore is the best Jaro-Winkler similarity between any variant of a and
// any variant of b (0 when either has no name).
func NameScore(a, b []Name) float64 {
	best := 0.0
	for _, x := range a {
		for _, y := range b {
			for _, vx := range x.Variants() {
				for _, vy := range y.Variants() {
					if s := JaroWinkler(vx, vy); s > best {
						best = s
					}
				}
			}
		}
	}
	return best
}
