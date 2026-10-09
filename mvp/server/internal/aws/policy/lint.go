package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// Severity of a lint finding.
type Severity string

const (
	// SeverityError: AWS would reject the policy, or the statement is ignored.
	SeverityError Severity = "error"
	// SeverityWarning: AWS may accept it, but it probably does not do what the
	// author meant, or it relies on undocumented behaviour.
	SeverityWarning Severity = "warning"
	// SeverityInfo: correct but worth knowing (for example, NotAction with
	// Allow grants actions that do not exist yet).
	SeverityInfo Severity = "info"
)

// Finding is one lint result.
type Finding struct {
	Severity       Severity `json:"severity"`
	Code           string   `json:"code"`
	StatementIndex int      `json:"statement_index"` // -1 for the document
	Span           *Span    `json:"span"`
	Message        string   `json:"message"`
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.StatementIndex != b.StatementIndex {
			return a.StatementIndex < b.StatementIndex
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Message < b.Message
	})
}

// Lint checks a parsed document against the rules for its policy kind. It
// needs only the model, so it also works on documents built in code. Parse
// calls it and adds the findings that need the raw text.
func Lint(doc *model.PolicyDoc) []Finding {
	l := &linter{doc: doc}
	l.document()
	for i := range doc.Statements {
		l.statement(&doc.Statements[i])
	}
	sortFindings(l.out)
	return l.out
}

type linter struct {
	doc *model.PolicyDoc
	out []Finding
}

func (l *linter) add(sev Severity, code string, st *model.Statement, format string, args ...any) {
	f := Finding{Severity: sev, Code: code, StatementIndex: -1, Message: fmt.Sprintf(format, args...)}
	if st != nil {
		f.StatementIndex, f.Span = st.Index, st.Span
	}
	l.out = append(l.out, f)
}

func (l *linter) document() {
	d := l.doc
	switch {
	case d.Kind == model.PolicySCP || d.Kind == model.PolicyRCP:
		// "Every SCP must include a Version element with the value
		// "2012-10-17"", and the RCP syntax page says the same [S4b, S5b].
		if d.LanguageVersion != model.LanguageVersion2012 {
			l.add(SeverityError, "VERSION_REQUIRED", nil, `%s policies must have "Version": "2012-10-17"`, d.Kind)
		}
	case d.LanguageVersion == "":
		l.add(SeverityWarning, "MISSING_VERSION", nil, `no "Version": policy variables are literal text; use "2012-10-17"`)
	case d.LanguageVersion == model.LanguageVersion2008:
		l.add(SeverityInfo, "VERSION_2008", nil, `"Version": "2008-10-17" makes policy variables literal text`)
	}
	if d.IDElement != "" && d.Kind.IsIdentityBased() {
		// The grammar: the id_block "must not be included in identity-based policies".
		l.add(SeverityError, "ID_NOT_ALLOWED", nil, `"Id" must not be included in identity-based policies`)
	}
	if len(d.Statements) == 0 {
		l.add(SeverityError, "NO_STATEMENTS", nil, "the policy has no usable statements")
	}
	sids := map[string]int{}
	for i := range d.Statements {
		if s := d.Statements[i].Sid; s != "" {
			sids[s]++
			if sids[s] == 2 {
				l.add(SeverityWarning, "DUPLICATE_SID", &d.Statements[i], "Sid %q is used by more than one statement", s)
			}
		}
	}
}

func (l *linter) statement(st *model.Statement) {
	kind := l.doc.Kind
	hasPrincipal := st.Principals != nil || st.NotPrincipals != nil

	// Which policy kinds may name principals (§4.1 facts 6–8, the grammar notes).
	switch {
	case (kind.IsIdentityBased() || kind == model.PolicySCP) && hasPrincipal:
		l.add(SeverityError, "PRINCIPAL_NOT_ALLOWED", st, "%s policies must not contain Principal or NotPrincipal", kind)
	case (kind.IsResourceBased() || kind == model.PolicyRCP) && !hasPrincipal:
		l.add(SeverityError, "PRINCIPAL_REQUIRED", st, "%s policies require Principal", kind)
	}
	if st.NotPrincipals != nil {
		switch kind {
		case model.PolicyTrust, model.PolicyRCP:
			l.add(SeverityError, "NOTPRINCIPAL_NOT_ALLOWED", st, "NotPrincipal is not allowed in %s policies", kind)
		}
		if st.Effect == model.EffectDeny {
			l.add(SeverityInfo, "NOTPRINCIPAL_DENY", st,
				"Deny with NotPrincipal always denies principals that have a permissions boundary, and exempts a principal only if its account ARN is listed too")
		}
	}
	switch kind {
	case model.PolicyRCP:
		l.rcp(st)
	case model.PolicySCP:
		l.scp(st)
	}
	if st.Sid != "" && (kind.IsIdentityBased() || kind == model.PolicyTrust) && !isAlnum(st.Sid) {
		l.add(SeverityWarning, "SID_CHARSET", st, "IAM policies allow only A–Z, a–z and 0–9 in Sid, got %q", st.Sid)
	}

	for _, e := range []struct {
		name string
		ps   *model.PatternSet
	}{{"Action", st.Actions}, {"NotAction", st.NotActions}, {"Resource", st.Resources}, {"NotResource", st.NotResources}} {
		if e.ps != nil && len(e.ps.Patterns) == 0 {
			l.add(SeverityError, "EMPTY_LIST", st, "%s is an empty list", e.name)
		}
	}
	if st.Effect == model.EffectAllow && st.NotActions != nil {
		l.add(SeverityInfo, "NOTACTION_WITH_ALLOW", st, "Allow with NotAction grants every action not listed, including actions AWS adds later")
	}
	if st.Effect == model.EffectAllow && st.NotResources != nil {
		l.add(SeverityInfo, "NOTRESOURCE_WITH_ALLOW", st, "Allow with NotResource grants every resource not listed")
	}
	l.actions(st)
	l.resources(st)
	l.principals(st, st.Principals, "Principal")
	l.principals(st, st.NotPrincipals, "NotPrincipal")
	l.conditions(st)
}

// scp checks the SCP-only rules.
func (l *linter) scp(st *model.Statement) {
	// The SCP syntax page: "In statements where the Effect element has a value
	// of Allow, you can specify only "*" in the Resource element of an SCP."
	// The September 2025 launch of the full IAM language in SCPs allows
	// individual resource ARNs in Allow statements, so the docs conflict
	// (ambiguity A2): this is a warning, and the evaluator follows the launch.
	if st.Effect == model.EffectAllow && st.Resources != nil {
		for _, r := range st.Resources.Patterns {
			if r != "*" {
				l.add(SeverityWarning, "SCP_ALLOW_RESOURCE_NOT_STAR", st,
					`the SCP syntax page allows only "Resource": "*" in Allow statements, got %q; the 2025 full-language launch allows ARNs (ambiguity A2)`, r)
				break
			}
		}
	}
}

func (l *linter) rcp(st *model.Statement) {
	// "You can only specify "*" in the Principal element of an RCP." Only the
	// bare string form counts: {"AWS": "*"} is a wildcard for matching but is
	// not the spelling AWS accepts, so Star (not Entries) is checked.
	if st.Principals != nil && !st.Principals.Star {
		l.add(SeverityError, "RCP_PRINCIPAL_NOT_WILDCARD", st, `RCPs must use "Principal": "*" (the bare string, not a map)`)
	}
	if l.doc.AWSManaged {
		return // RCPFullAWSAccess is the one Allow RCP
	}
	if st.Effect == model.EffectAllow {
		l.add(SeverityError, "RCP_ALLOW_NOT_ALLOWED", st, "customer-managed RCPs may only contain Deny statements")
	}
	if st.NotActions != nil {
		l.add(SeverityError, "RCP_NOTACTION_UNSUPPORTED", st, "RCPs do not support NotAction")
	}
	if st.Actions != nil {
		for _, a := range st.Actions.Patterns {
			if a == "*" {
				l.add(SeverityError, "RCP_ACTION_STAR", st, `"*" alone is not allowed as an RCP action`)
				break
			}
		}
	}
}

func (l *linter) actions(st *model.Statement) {
	for _, ps := range []*model.PatternSet{st.Actions, st.NotActions} {
		if ps == nil {
			continue
		}
		for _, a := range ps.Patterns {
			if a != "*" {
				i := strings.IndexByte(a, ':')
				if i <= 0 || i == len(a)-1 || strings.IndexByte(a[i+1:], ':') >= 0 {
					l.add(SeverityWarning, "ACTION_FORMAT", st, "action %q is not of the form service:action", a)
				}
			}
			if hasVariable(a) {
				l.add(SeverityWarning, "VARIABLE_NOT_ALLOWED", st, "policy variables are literal text in actions: %q", a)
			}
		}
	}
}

func (l *linter) resources(st *model.Statement) {
	kind := l.doc.Kind
	for _, ps := range []*model.PatternSet{st.Resources, st.NotResources} {
		if ps == nil {
			continue
		}
		for _, r := range ps.Patterns {
			if r == "*" {
				continue
			}
			if !strings.HasPrefix(r, "arn:") {
				l.add(SeverityWarning, "RESOURCE_FORMAT", st, "resource %q is neither \"*\" nor an ARN", r)
				continue
			}
			if completed, ok := CompleteARN(r); ok {
				// AWS completes an incomplete ARN with wildcards in identity-based
				// policies, and rejects it in session policies [IAM grammar notes].
				switch {
				case kind == model.PolicySession:
					l.add(SeverityError, "INCOMPLETE_ARN", st, "session policies do not accept incomplete ARNs: %q", r)
				case kind == model.PolicySCP:
					l.add(SeverityWarning, "INCOMPLETE_ARN", st,
						"AWS does not document incomplete ARNs in SCPs; %q is evaluated as %q (ambiguity A21)", r, completed)
				case CompletesIncompleteARNs(kind):
					l.add(SeverityInfo, "INCOMPLETE_ARN", st, "AWS completes %q to %q", r, completed)
				default:
					l.add(SeverityWarning, "INCOMPLETE_ARN", st, "resource ARN %q has fewer than six segments", r)
				}
			}
			l.variableSyntax(st, r)
			if hasVariable(r) {
				if !l.doc.VariablesEnabled() {
					l.add(SeverityWarning, "VARIABLES_LITERAL", st, `policy variables in %q are literal text without "Version": "2012-10-17"`, r)
				} else if variableOutsideResourcePart(r) {
					l.add(SeverityWarning, "VARIABLE_OUTSIDE_RESOURCE_PART", st, "policy variables are allowed only in the resource part of an ARN: %q", r)
				}
			}
		}
	}
}

// arnSegments counts colon-separated segments, ignoring colons inside ${…}.
func arnSegments(s string) int {
	refs := variableRefs(s)
	n, ri := 1, 0
	for i := 0; i < len(s); i++ {
		if ri < len(refs) && i == refs[ri].start {
			i = refs[ri].end - 1
			ri++
			continue
		}
		if s[i] == ':' {
			n++
		}
	}
	return n
}

func (l *linter) principals(st *model.Statement, ps *model.PrincipalSet, elem string) {
	if ps == nil {
		return
	}
	if len(ps.Entries) == 0 {
		l.add(SeverityError, "EMPTY_LIST", st, "%s names no principals", elem)
	}
	for _, list := range []struct {
		name string
		vals []string
	}{{"AWS", ps.AWS}, {"CanonicalUser", ps.CanonicalUser}, {"Federated", ps.Federated}, {"Service", ps.Service}} {
		if list.vals != nil && len(list.vals) == 0 {
			l.add(SeverityError, "EMPTY_LIST", st, "%s.%s is an empty list", elem, list.name)
		}
	}
	for _, e := range ps.Entries {
		switch {
		case e.Kind == model.PrincipalWildcard:
		case strings.ContainsAny(e.Value, "*?"):
			l.add(SeverityError, "PARTIAL_WILDCARD_PRINCIPAL", st,
				"wildcards cannot match part of a principal (only \"*\" alone is allowed): %q", e.Value)
		case e.Kind == model.PrincipalUnrecognized:
			l.add(SeverityWarning, "INVALID_PRINCIPAL", st, "%q is not an account id, account root, user, role, session, federated-user ARN or unique id", e.Value)
		case e.Kind == model.PrincipalService && asciiLower(e.Value) != e.Value:
			// Service principal names are lower-case (§8.1) and principal
			// ARNs and names are compared case-sensitively.
			l.add(SeverityWarning, "SERVICE_PRINCIPAL_CASE", st, "service principal %q has upper-case letters; service principals are lower-case, e.g. %q", e.Value, asciiLower(e.Value))
		}
		if hasVariable(e.Value) {
			l.add(SeverityWarning, "VARIABLE_NOT_ALLOWED", st, "policy variables are literal text in %s: %q", elem, e.Value)
		}
	}
}

func (l *linter) conditions(st *model.Statement) {
	for _, a := range st.Condition {
		name := OperatorName(a)
		if a.Op == "Null" {
			if a.IfExists {
				l.add(SeverityError, "NULL_IFEXISTS", st, "the Null operator cannot be combined with IfExists")
			}
			if a.Qualifier != 0 {
				l.add(SeverityWarning, "NULL_WITH_QUALIFIER", st, "%q: a set qualifier has no meaning on Null", name)
			}
			for _, v := range a.Values {
				if !strings.EqualFold(v, "true") && !strings.EqualFold(v, "false") {
					l.add(SeverityWarning, "NULL_VALUE", st, "Null takes \"true\" or \"false\", got %q for %s", v, a.Key)
				}
			}
		}
		if len(a.Values) == 0 {
			l.add(SeverityWarning, "EMPTY_CONDITION_VALUES", st, "%s on %s has no values: %s", name, a.Key, emptyValuesMeaning(a))
		}
		if !isASCII(a.Key) {
			l.add(SeverityWarning, "NON_ASCII_CONDITION_KEY", st,
				"condition key %q has non-ASCII characters; only A–Z fold to lower case, so it never equals an ASCII key (ambiguity A22)", rawKey(a))
		}
		if hasVariable(a.Key) {
			l.add(SeverityWarning, "VARIABLE_NOT_ALLOWED", st, "policy variables are literal text in condition keys: %q", a.Key)
		}
		for _, v := range a.Values {
			if !hasVariable(v) {
				continue
			}
			l.variableSyntax(st, v)
			switch {
			case !variableOperator(a.Op):
				l.add(SeverityWarning, "VARIABLE_NOT_ALLOWED", st, "policy variables are literal text in %s values: %q", a.Op, v)
			case !l.doc.VariablesEnabled():
				l.add(SeverityWarning, "VARIABLES_LITERAL", st, `policy variables in %q are literal text without "Version": "2012-10-17"`, v)
			}
		}
	}
}

// emptyValuesMeaning says what a condition with an empty value list does
// (§9.3). There is no policy value to equal, so each request value fails a
// positive test and passes a negated one.
func emptyValuesMeaning(a authz.Atom) string {
	switch {
	case a.Op == "Null":
		return "it never matches"
	case a.Qualifier == authz.ForAllValues && !a.Negated:
		return "it matches only when the key is missing or has no values"
	case a.Qualifier == authz.ForAnyValue && a.Negated:
		return "it matches whenever the key has at least one value"
	case a.Negated:
		return "a negated operator with no values always matches"
	case a.IfExists:
		return "it matches only when the key is missing"
	default:
		return "it never matches"
	}
}

// variableSyntax flags ${…} text that the variable grammar reads differently
// from how it looks: a nested "${", or a "}" inside a quoted default.
func (l *linter) variableSyntax(st *model.Statement, s string) {
	for _, r := range variableRefs(s) {
		if r.problem != "" {
			l.add(SeverityWarning, "VARIABLE_SYNTAX", st, "%s: %q", r.problem, s)
		}
	}
}

// rawKey is the key as the policy spells it, or the folded key for atoms
// built in code.
func rawKey(a authz.Atom) string {
	if a.RawKey != "" {
		return a.RawKey
	}
	return a.Key
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isAlnum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
