// Package policy parses AWS IAM policy documents into model.PolicyDoc, lints
// them, and serializes them back to a canonical JSON form
// (docs/design/aws-effective-permission-evaluator.md §5, §6.1, §8, §9.3, §15 PR-1).
//
// Parse is strict. The document must be valid UTF-8 JSON with no duplicate
// keys and nothing after the top-level object, within Limits, and must follow
// the IAM policy grammar: the element names are the grammar's literal strings
// (case-sensitive), and unknown elements are errors. A policy that breaks the
// grammar is rejected with a *ParseError, because AWS would not accept it.
//
// Three statement-level problems are recorded as ingest anomalies instead, as
// the design requires (§8.4.3, §9.3): NotPrincipal with Allow, an invalid
// element mix, and a multivalued key used as a policy variable. The first two
// make the statement unusable, so it is dropped from Statements (keeping the
// other statements' Index values); the third keeps the statement.
//
// Case rules (§8.1): element names, Effect values, principal-map keys, ARNs and
// patterns are kept exactly as written. Condition key names are lower-cased
// (they are case-insensitive in AWS). Condition operator names are matched
// case-insensitively and stored in canonical spelling, with a lint warning
// when the spelling differs (AWS does not document operator-name case; see the
// PR description and the ambiguity register).
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// Span is the statement span type.
type Span = authz.Span

// Options describes the document being parsed.
type Options struct {
	Kind       model.PolicyKind // the zero value means "unknown": kind-specific rules are skipped
	SourceARN  string
	VersionID  string
	AWSManaged bool
	FetchedAt  time.Time
	Limits     Limits // zero fields take DefaultLimits
	// MultivaluedKey reports whether a lower-cased condition key is multivalued.
	// It defaults to IsGlobalMultivaluedKey; the catalog (PR-2) supplies the
	// service-specific ArrayOf* keys.
	MultivaluedKey func(lowerKey string) bool
}

// Result is a parsed document with its anomalies and lint findings.
type Result struct {
	Doc       *model.PolicyDoc
	Anomalies []Anomaly
	Findings  []Finding // includes one error finding per anomaly; sorted
}

// Error codes for *ParseError.
const (
	CodeInvalidJSON    = "invalid_json"
	CodeTrailingData   = "trailing_data"
	CodeDuplicateKey   = "duplicate_key"
	CodeLimitExceeded  = "limit_exceeded"
	CodeUnknownElement = "unknown_element"
	CodeInvalidType    = "invalid_type"
	CodeInvalidValue   = "invalid_value"
	CodeMissingElement = "missing_element"
)

// ParseError is a document AWS would reject outright.
type ParseError struct {
	Code   string
	Path   string // e.g. "Statement[2].Condition.StringEquals"; "" for the document
	Offset int    // byte offset in the raw document
	Line   int    // 1-based
	Col    int    // 1-based, in code points
	Msg    string
}

func (e *ParseError) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("policy: line %d col %d: %s", e.Line, e.Col, e.Msg)
	}
	return fmt.Sprintf("policy: line %d col %d: %s: %s", e.Line, e.Col, e.Path, e.Msg)
}

func newError(pos *positions, off int, code, path, msg string) *ParseError {
	l, c := pos.at(off)
	return &ParseError{Code: code, Path: path, Offset: off, Line: l, Col: c, Msg: msg}
}

// AnomalyCode names an ingest anomaly.
type AnomalyCode string

const (
	// AnomalyNotPrincipalWithAllow: NotPrincipal with Effect Allow. AWS refuses
	// to save it; the statement is ignored (§8.4.3).
	AnomalyNotPrincipalWithAllow AnomalyCode = "NOTPRINCIPAL_WITH_ALLOW"
	// AnomalyInvalidElementMix: both or neither of Action/NotAction, both
	// Resource and NotResource, or both Principal and NotPrincipal. The
	// statement is ignored.
	AnomalyInvalidElementMix AnomalyCode = "INVALID_ELEMENT_MIX"
	// AnomalyMissingResource: neither Resource nor NotResource in a policy kind
	// that requires one (only resource-based policies may omit it, §8.3). The
	// statement is ignored.
	AnomalyMissingResource AnomalyCode = "MISSING_RESOURCE"
	// AnomalyMultivaluedVariable: a multivalued key used as a policy variable.
	// The policy is invalid; the evaluator treats the pattern as literal text
	// (§9.3, [verify P-MVVAR]). The statement is kept.
	AnomalyMultivaluedVariable AnomalyCode = "MULTIVALUED_VARIABLE"
)

// Anomaly is a statement AWS would not have accepted but that we can still
// account for.
type Anomaly struct {
	Code           AnomalyCode `json:"code"`
	StatementIndex int         `json:"statement_index"`
	Sid            string      `json:"sid"`
	Span           *Span       `json:"span"`
	Detail         string      `json:"detail"`
	Dropped        bool        `json:"dropped"` // the statement was left out of Statements
}

// Parse parses and validates one policy document.
func Parse(raw []byte, opts Options) (*Result, error) {
	lim := opts.Limits.orDefault()
	pos := newPositions(raw)
	if len(raw) > lim.MaxBytes {
		return nil, newError(pos, lim.MaxBytes, CodeLimitExceeded, "", fmt.Sprintf("document larger than %d bytes", lim.MaxBytes))
	}
	root, err := readTree(raw, lim, pos)
	if err != nil {
		return nil, err
	}
	mv := opts.MultivaluedKey
	if mv == nil {
		mv = IsGlobalMultivaluedKey
	}
	p := &parser{opts: opts, lim: lim, pos: pos, multivalued: mv}
	doc := &model.PolicyDoc{
		ID:         DocumentID(opts.Kind, opts.SourceARN, opts.VersionID, raw),
		Kind:       opts.Kind,
		SourceARN:  opts.SourceARN,
		VersionID:  opts.VersionID,
		RawJSON:    bytes.Clone(raw),
		AWSManaged: opts.AWSManaged,
		FetchedAt:  opts.FetchedAt,
	}
	if err := p.document(root, doc); err != nil {
		return nil, err
	}
	res := &Result{Doc: doc, Anomalies: p.anomalies}
	res.Findings = append(res.Findings, p.findings...)
	for _, a := range p.anomalies {
		res.Findings = append(res.Findings, Finding{
			Severity: SeverityError, Code: string(a.Code), StatementIndex: a.StatementIndex,
			Span: a.Span, Message: a.Detail,
		})
	}
	res.Findings = append(res.Findings, Lint(doc)...)
	sortFindings(res.Findings)
	return res, nil
}

// DocumentID is the stable content id of a policy document:
// hex(sha256(kind | source_arn | version_id | raw bytes)) (§6.1).
func DocumentID(kind model.PolicyKind, sourceARN, versionID string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(kind.String() + "|" + sourceARN + "|" + versionID + "|"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

type parser struct {
	opts        Options
	lim         Limits
	pos         *positions
	multivalued func(string) bool
	anomalies   []Anomaly
	findings    []Finding // parse-time findings that need the raw text
}

func (p *parser) errAt(n *jnode, code, path, msg string) *ParseError {
	return newError(p.pos, n.start, code, path, msg)
}

func (p *parser) document(root *jnode, doc *model.PolicyDoc) error {
	if root.kind != jObject {
		return p.errAt(root, CodeInvalidType, "", "policy must be a JSON object, not "+root.kind.String())
	}
	var stmts *jnode
	for _, m := range root.members {
		switch m.key {
		case "Version":
			if m.val.kind != jString {
				return p.errAt(m.val, CodeInvalidType, "Version", "must be a string")
			}
			if m.val.str != model.LanguageVersion2012 && m.val.str != model.LanguageVersion2008 {
				return p.errAt(m.val, CodeInvalidValue, "Version", fmt.Sprintf("must be %q or %q, not %q",
					model.LanguageVersion2012, model.LanguageVersion2008, m.val.str))
			}
			doc.LanguageVersion = m.val.str
		case "Id":
			if m.val.kind != jString {
				return p.errAt(m.val, CodeInvalidType, "Id", "must be a string")
			}
			doc.IDElement = m.val.str
		case "Statement":
			stmts = m.val
		default:
			return newError(p.pos, m.keyStart, CodeUnknownElement, "", fmt.Sprintf("unknown policy element %q", m.key))
		}
	}
	if stmts == nil {
		return p.errAt(root, CodeMissingElement, "", `missing "Statement"`)
	}
	var list []*jnode
	switch stmts.kind {
	case jObject: // a single statement object is accepted, as in AWS's own examples
		list = []*jnode{stmts}
	case jArray:
		list = stmts.elems
	default:
		return p.errAt(stmts, CodeInvalidType, "Statement", "must be an object or an array of objects")
	}
	if len(list) > p.lim.MaxStatements {
		return p.errAt(stmts, CodeLimitExceeded, "Statement", fmt.Sprintf("more than %d statements", p.lim.MaxStatements))
	}
	doc.Statements = make([]model.Statement, 0, len(list))
	for i, n := range list {
		st, keep, err := p.statement(n, i, doc)
		if err != nil {
			return err
		}
		if keep {
			doc.Statements = append(doc.Statements, *st)
		}
	}
	return nil
}

var statementElements = map[string]bool{
	"Sid": true, "Effect": true, "Principal": true, "NotPrincipal": true, "Action": true,
	"NotAction": true, "Resource": true, "NotResource": true, "Condition": true,
}

// statement parses one statement. keep is false when an anomaly drops it.
func (p *parser) statement(n *jnode, idx int, doc *model.PolicyDoc) (*model.Statement, bool, error) {
	path := fmt.Sprintf("Statement[%d]", idx)
	if n.kind != jObject {
		return nil, false, p.errAt(n, CodeInvalidType, path, "statement must be an object, not "+n.kind.String())
	}
	span := p.pos.span(n)
	st := &model.Statement{PolicyID: doc.ID, Index: idx, Span: span}
	var condNode *jnode
	present := map[string]bool{}
	for _, m := range n.members {
		if !statementElements[m.key] {
			return nil, false, newError(p.pos, m.keyStart, CodeUnknownElement, path, fmt.Sprintf("unknown statement element %q", m.key))
		}
		present[m.key] = true
		mp := path + "." + m.key
		var err error
		switch m.key {
		case "Sid":
			if m.val.kind != jString {
				return nil, false, p.errAt(m.val, CodeInvalidType, mp, "must be a string")
			}
			st.Sid = m.val.str
		case "Effect":
			if m.val.kind != jString {
				return nil, false, p.errAt(m.val, CodeInvalidType, mp, "must be a string")
			}
			switch m.val.str {
			case "Allow":
				st.Effect = model.EffectAllow
			case "Deny":
				st.Effect = model.EffectDeny
			default:
				return nil, false, p.errAt(m.val, CodeInvalidValue, mp, fmt.Sprintf(`must be "Allow" or "Deny", not %q`, m.val.str))
			}
		case "Principal":
			st.Principals, err = p.principal(m.val, mp)
		case "NotPrincipal":
			st.NotPrincipals, err = p.principal(m.val, mp)
		case "Action":
			st.Actions, err = p.patterns(m.val, mp)
		case "NotAction":
			st.NotActions, err = p.patterns(m.val, mp)
		case "Resource":
			st.Resources, err = p.patterns(m.val, mp)
		case "NotResource":
			st.NotResources, err = p.patterns(m.val, mp)
		case "Condition":
			condNode = m.val
		}
		if err != nil {
			return nil, false, err
		}
	}
	if !present["Effect"] {
		return nil, false, p.errAt(n, CodeMissingElement, path, `missing "Effect"`)
	}
	if condNode != nil {
		ref := &authz.StmtRef{
			PolicyID: doc.ID, PolicyKind: p.opts.Kind.String(), SourceARN: p.opts.SourceARN,
			VersionID: p.opts.VersionID, StatementIndex: idx, Sid: st.Sid, Span: span,
		}
		atoms, err := p.condition(condNode, path+".Condition", idx, span, ref)
		if err != nil {
			return nil, false, err
		}
		st.Condition = atoms
	}

	// Ingest anomalies (§8.4.3, PR-1 scope).
	keep := true
	anomaly := func(code AnomalyCode, drop bool, detail string) {
		p.anomalies = append(p.anomalies, Anomaly{Code: code, StatementIndex: idx, Sid: st.Sid, Span: span, Detail: detail, Dropped: drop})
		if drop {
			keep = false
		}
	}
	switch {
	case st.Actions != nil && st.NotActions != nil:
		anomaly(AnomalyInvalidElementMix, true, "statement has both Action and NotAction")
	case st.Actions == nil && st.NotActions == nil:
		anomaly(AnomalyInvalidElementMix, true, "statement has neither Action nor NotAction")
	}
	if st.Resources != nil && st.NotResources != nil {
		anomaly(AnomalyInvalidElementMix, true, "statement has both Resource and NotResource")
	}
	if st.Principals != nil && st.NotPrincipals != nil {
		anomaly(AnomalyInvalidElementMix, true, "statement has both Principal and NotPrincipal")
	}
	if st.Resources == nil && st.NotResources == nil && p.opts.Kind != 0 && !p.opts.Kind.IsResourceBased() {
		anomaly(AnomalyMissingResource, true, fmt.Sprintf("statement has neither Resource nor NotResource, which a %s policy requires", p.opts.Kind))
	}
	if st.NotPrincipals != nil && st.Effect == model.EffectAllow {
		anomaly(AnomalyNotPrincipalWithAllow, true, "NotPrincipal is only valid with Deny; AWS refuses to save it with Allow")
	}
	if keep && doc.VariablesEnabled() { // a dropped statement is not evaluated, so only its drop reasons are reported
		for _, key := range multivaluedVariables(st, p.multivalued) {
			anomaly(AnomalyMultivaluedVariable, false, fmt.Sprintf("multivalued key %q cannot be a policy variable; it is treated as literal text", key))
		}
	}
	return st, keep, nil
}

// stringList reads a string or a list of strings (the grammar's "string or
// list" form). A one-element list and a bare string are equivalent.
func (p *parser) stringList(n *jnode, path string) ([]string, error) {
	switch n.kind {
	case jString:
		return []string{n.str}, nil
	case jArray:
		out := make([]string, 0, len(n.elems))
		for i, e := range n.elems {
			if e.kind != jString {
				return nil, p.errAt(e, CodeInvalidType, fmt.Sprintf("%s[%d]", path, i), "must be a string, not "+e.kind.String())
			}
			out = append(out, e.str)
		}
		return out, nil
	}
	return nil, p.errAt(n, CodeInvalidType, path, "must be a string or an array of strings, not "+n.kind.String())
}

func (p *parser) patterns(n *jnode, path string) (*model.PatternSet, error) {
	l, err := p.stringList(n, path)
	if err != nil {
		return nil, err
	}
	return &model.PatternSet{Patterns: l}, nil
}

// principal parses Principal or NotPrincipal: "*" or a map whose keys are
// AWS, CanonicalUser, Federated and Service (§8.4.1).
func (p *parser) principal(n *jnode, path string) (*model.PrincipalSet, error) {
	ps := &model.PrincipalSet{}
	switch n.kind {
	case jString:
		if n.str != "*" {
			return nil, p.errAt(n, CodeInvalidValue, path, `a string principal must be "*"; use a map such as {"AWS": "..."}`)
		}
		ps.Star = true
		ps.Entries = []model.PrincipalEntry{{Kind: model.PrincipalWildcard, Value: "*"}}
		return ps, nil
	case jObject:
	default:
		return nil, p.errAt(n, CodeInvalidType, path, `must be "*" or an object, not `+n.kind.String())
	}
	for _, m := range n.members {
		vals, err := p.stringList(m.val, path+"."+m.key)
		if err != nil {
			return nil, err
		}
		switch m.key {
		case "AWS":
			ps.AWS = vals
		case "CanonicalUser":
			ps.CanonicalUser = vals
		case "Federated":
			ps.Federated = vals
		case "Service":
			ps.Service = vals
		default:
			return nil, newError(p.pos, m.keyStart, CodeUnknownElement, path, fmt.Sprintf("unknown principal type %q", m.key))
		}
	}
	ps.Entries = NormalizePrincipals(ps)
	return ps, nil
}

// NormalizePrincipals computes the normalized entries of a principal set
// (§8.4.1) from its raw lists, in the order "*", AWS, CanonicalUser,
// Federated, Service.
func NormalizePrincipals(ps *model.PrincipalSet) []model.PrincipalEntry {
	var out []model.PrincipalEntry
	if ps.Star {
		out = append(out, model.PrincipalEntry{Kind: model.PrincipalWildcard, Value: "*"})
	}
	for _, v := range ps.AWS {
		out = append(out, ClassifyAWSPrincipal(v))
	}
	for _, v := range ps.CanonicalUser {
		out = append(out, model.PrincipalEntry{Kind: model.PrincipalCanonicalUser, Value: v})
	}
	for _, v := range ps.Federated {
		out = append(out, model.PrincipalEntry{Kind: model.PrincipalFederated, Value: v})
	}
	for _, v := range ps.Service {
		out = append(out, model.PrincipalEntry{Kind: model.PrincipalService, Value: v})
	}
	return out
}

// ClassifyAWSPrincipal normalizes one value of an "AWS" principal (§8.4.1):
//   - "*" is the wildcard;
//   - a 12-digit account id and arn:<partition>:iam::<account>:root are the
//     account principal;
//   - IAM user and role ARNs, STS assumed-role (session) and federated-user
//     ARNs are kept with their account;
//   - a bare AIDA…/AROA… unique id is kept as an id.
//
// Anything else, including a partial wildcard such as arn:aws:iam::*:root
// (not allowed in Principal [S5]), is unrecognized and kept literally.
func ClassifyAWSPrincipal(v string) model.PrincipalEntry {
	e := model.PrincipalEntry{Kind: model.PrincipalUnrecognized, Value: v}
	switch {
	case v == "*":
		e.Kind = model.PrincipalWildcard
		return e
	case isAccountID(v):
		e.Kind, e.AccountID = model.PrincipalAccount, v
		return e
	case isUniqueID(v):
		e.Kind = model.PrincipalUniqueID
		return e
	case !strings.HasPrefix(v, "arn:"):
		return e
	}
	parts := strings.SplitN(v, ":", 6)
	if len(parts) != 6 || parts[1] == "" || parts[3] != "" || !isAccountID(parts[4]) {
		return e
	}
	svc, acct, res := parts[2], parts[4], parts[5]
	if strings.ContainsAny(res, "*?") {
		return e
	}
	switch {
	case svc == "iam" && res == "root":
		e.Kind = model.PrincipalAccount
	case svc == "iam" && strings.HasPrefix(res, "user/") && len(res) > len("user/"):
		e.Kind = model.PrincipalIAMUser
	case svc == "iam" && strings.HasPrefix(res, "role/") && len(res) > len("role/"):
		e.Kind = model.PrincipalIAMRole
	case svc == "sts" && strings.HasPrefix(res, "assumed-role/"):
		rest := strings.TrimPrefix(res, "assumed-role/")
		if i := strings.IndexByte(rest, '/'); i > 0 && i < len(rest)-1 {
			e.Kind = model.PrincipalAssumedRole
		}
	case svc == "sts" && strings.HasPrefix(res, "federated-user/") && len(res) > len("federated-user/"):
		e.Kind = model.PrincipalFederatedUser
	}
	if e.Kind != model.PrincipalUnrecognized {
		e.AccountID = acct
	}
	if e.Kind == model.PrincipalAccount {
		e.Value = v // keep the ARN spelling; AccountID carries the id
	}
	return e
}

func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isUniqueID matches IAM user (AIDA) and role (AROA) unique ids: upper-case
// letters and digits, 16–128 characters.
func isUniqueID(s string) bool {
	if len(s) < 16 || len(s) > 128 || !(strings.HasPrefix(s, "AIDA") || strings.HasPrefix(s, "AROA")) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// Condition operators (§9.3). The base operators, in canonical spelling.
var baseOperators = []string{
	"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
	"StringLike", "StringNotLike",
	"NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals",
	"NumericGreaterThan", "NumericGreaterThanEquals",
	"DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals",
	"DateGreaterThan", "DateGreaterThanEquals",
	"Bool", "BinaryEquals", "IpAddress", "NotIpAddress",
	"ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike",
	"Null",
}

var negatedOperators = map[string]bool{
	"StringNotEquals": true, "StringNotEqualsIgnoreCase": true, "StringNotLike": true,
	"NumericNotEquals": true, "DateNotEquals": true, "NotIpAddress": true,
	"ArnNotEquals": true, "ArnNotLike": true,
}

var operatorByLower = func() map[string]string {
	m := make(map[string]string, len(baseOperators))
	for _, op := range baseOperators {
		m[asciiLower(op)] = op
	}
	return m
}()

// IsNegatedOperator reports whether a canonical base operator is negated.
func IsNegatedOperator(op string) bool { return negatedOperators[op] }

// OperatorName rebuilds the policy spelling of an atom's operator, e.g.
// "ForAllValues:StringLikeIfExists".
func OperatorName(a authz.Atom) string {
	name := a.Op
	if a.IfExists {
		name += "IfExists"
	}
	if a.Qualifier != authz.NoQualifier {
		name = a.Qualifier.String() + ":" + name
	}
	return name
}

// parseOperator splits "ForAnyValue:StringLikeIfExists" into its parts.
// Matching is ASCII case-insensitive (so no Unicode look-alike such as U+017F
// or the Kelvin sign folds into an operator name); ok is false for an unknown
// operator.
func parseOperator(name string) (op string, q authz.Qualifier, ifExists, ok bool) {
	rest := name
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		switch asciiLower(rest[:i]) {
		case "forallvalues":
			q = authz.ForAllValues
		case "foranyvalue":
			q = authz.ForAnyValue
		default:
			return "", 0, false, false
		}
		rest = rest[i+1:]
	}
	lower := asciiLower(rest)
	if op, ok = operatorByLower[lower]; ok {
		return op, q, false, true
	}
	if base, found := strings.CutSuffix(lower, "ifexists"); found {
		if op, ok = operatorByLower[base]; ok {
			return op, q, true, true
		}
	}
	return "", 0, false, false
}

// asciiLower lower-cases ASCII letters only.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// condition parses a Condition block into a conjunction of atoms, in document
// order. Operator blocks AND, keys within a block AND, and the values of one
// key OR inside the atom (§9.3).
func (p *parser) condition(n *jnode, path string, idx int, span *Span, ref *authz.StmtRef) ([]authz.Atom, error) {
	if n.kind != jObject {
		return nil, p.errAt(n, CodeInvalidType, path, "must be an object, not "+n.kind.String())
	}
	atoms := []authz.Atom{}
	seenOps := map[string]bool{}
	for _, m := range n.members {
		op, q, ifExists, ok := parseOperator(m.key)
		mp := path + "." + m.key
		if !ok {
			return nil, newError(p.pos, m.keyStart, CodeInvalidValue, path, fmt.Sprintf("unknown condition operator %q", m.key))
		}
		canon := OperatorName(authz.Atom{Op: op, Qualifier: q, IfExists: ifExists})
		if seenOps[canon] {
			return nil, newError(p.pos, m.keyStart, CodeDuplicateKey, path,
				fmt.Sprintf("condition operator %q repeats %q (operator names are compared case-insensitively)", m.key, canon))
		}
		seenOps[canon] = true
		if canon != m.key {
			p.findings = append(p.findings, Finding{
				Severity: SeverityWarning, Code: "NONCANONICAL_OPERATOR_CASE", StatementIndex: idx, Span: span,
				Message: fmt.Sprintf("condition operator %q is spelled %q in AWS's documentation", m.key, canon),
			})
		}
		if m.val.kind != jObject {
			return nil, p.errAt(m.val, CodeInvalidType, mp, "must be an object, not "+m.val.kind.String())
		}
		if len(m.val.members) == 0 {
			p.findings = append(p.findings, Finding{
				Severity: SeverityWarning, Code: "EMPTY_CONDITION_BLOCK", StatementIndex: idx, Span: span,
				Message: fmt.Sprintf("condition operator %q has no keys", m.key),
			})
		}
		seenKeys := map[string]bool{}
		for _, k := range m.val.members {
			lower := strings.ToLower(k.key)
			if seenKeys[lower] {
				return nil, newError(p.pos, k.keyStart, CodeDuplicateKey, mp,
					fmt.Sprintf("condition key %q repeats another key in this block (key names are case-insensitive)", k.key))
			}
			seenKeys[lower] = true
			vals, err := p.conditionValues(k.val, mp+"."+k.key)
			if err != nil {
				return nil, err
			}
			atoms = append(atoms, authz.Atom{
				Op: op, Key: lower, Values: vals, Qualifier: q, IfExists: ifExists,
				Negated: negatedOperators[op], Source: ref,
			})
		}
	}
	return atoms, nil
}

// conditionValues reads a condition value or list of values. Strings, numbers
// and booleans are allowed ("Quotation marks are optional for numeric and
// Boolean values"); numbers keep their literal text, booleans become
// "true"/"false". Null, objects and nested arrays are errors.
func (p *parser) conditionValues(n *jnode, path string) ([]string, error) {
	scalar := func(e *jnode, path string) (string, error) {
		switch e.kind {
		case jString, jNumber:
			return e.str, nil
		case jBool:
			if e.b {
				return "true", nil
			}
			return "false", nil
		}
		return "", p.errAt(e, CodeInvalidType, path, "condition value must be a string, number or boolean, not "+e.kind.String())
	}
	if n.kind != jArray {
		v, err := scalar(n, path)
		if err != nil {
			return nil, err
		}
		return []string{v}, nil
	}
	out := make([]string, 0, len(n.elems))
	for i, e := range n.elems {
		v, err := scalar(e, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
