package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// semantic strips the fields that legitimately differ between a document and
// its re-parsed canonical form (ids, raw bytes, spans, provenance and the raw
// spelling of condition keys, which the canonical form lower-cases).
func semantic(d *model.PolicyDoc) *model.PolicyDoc {
	c := *d
	c.ID, c.RawJSON = "", nil
	c.Statements = make([]model.Statement, len(d.Statements))
	for i, s := range d.Statements {
		s.PolicyID, s.Span, s.Index = "", nil, 0
		if s.Condition != nil {
			atoms := make([]authz.Atom, len(s.Condition))
			for j, a := range s.Condition {
				a.Source, a.RawKey = nil, ""
				atoms[j] = a
			}
			s.Condition = atoms
		}
		c.Statements[i] = s
	}
	return &c
}

// roundTrip checks parse → serialize → parse: the second parse succeeds, has
// the same statements, and serializes to the same bytes.
func roundTrip(t *testing.T, raw []byte, opts Options) {
	t.Helper()
	r1, err := Parse(raw, opts)
	if err != nil {
		return
	}
	s1, err := Serialize(r1.Doc)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// The canonical form can be a little larger than the input (a bare string
	// becomes a list, a number becomes a string), so it is re-parsed with
	// relaxed size limits.
	relaxed := opts
	lim := opts.Limits.orDefault()
	lim.MaxBytes *= 4
	lim.MaxStringBytes *= 4
	lim.MaxValues *= 4
	relaxed.Limits = lim
	r2, err := Parse(s1, relaxed)
	if err != nil {
		t.Fatalf("re-parse of canonical form failed: %v\ninput: %q\ncanonical: %s", err, raw, s1)
	}
	s2, err := Serialize(r2.Doc)
	if err != nil {
		t.Fatalf("serialize 2: %v", err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatalf("canonical form is not stable:\n1: %s\n2: %s", s1, s2)
	}
	if a, b := semantic(r1.Doc), semantic(r2.Doc); !reflect.DeepEqual(a, b) {
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		t.Fatalf("model changed across the round trip:\n1: %s\n2: %s", ja, jb)
	}
	if len(r2.Anomalies) != countKept(r1.Anomalies) {
		t.Fatalf("anomalies changed across the round trip: %+v vs %+v", r1.Anomalies, r2.Anomalies)
	}
}

func countKept(as []Anomaly) int {
	n := 0
	for _, a := range as {
		if !a.Dropped {
			n++
		}
	}
	return n
}

func TestRoundTripGolden(t *testing.T) {
	for _, g := range goldenPolicies {
		t.Run(g.id, func(t *testing.T) { roundTrip(t, []byte(g.json), Options{Kind: g.kind}) })
	}
}

func TestRoundTripCanonicalForm(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		kind           model.PolicyKind
	}{
		{"string-or-list and a single statement object", `{
  "Id": "p1",
  "Version": "2012-10-17",
  "Statement": {"Resource": "*", "Action": "s3:GetObject", "Effect": "Allow", "Sid": "One"}
}`, `{"Version":"2012-10-17","Id":"p1","Statement":[{"Sid":"One","Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`, model.PolicyResource},
		{"condition values: numbers keep their literal text, booleans become strings, keys are lower-cased", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*",
  "Condition":{"NumericLessThanEquals":{"s3:Max-Keys":10.50},"Bool":{"aws:SecureTransport":true},"stringequalsifexists":{"A:B":["x","y"]}}}]}`,
			`{"Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"],"Condition":{"NumericLessThanEquals":{"s3:max-keys":["10.50"]},"Bool":{"aws:securetransport":["true"]},"StringEqualsIfExists":{"a:b":["x","y"]}}}]}`, 0},
		{"principal forms in a fixed key order", `{"Statement":[{"Effect":"Deny","Principal":{"Service":"s3.amazonaws.com","AWS":"*","Federated":"cognito-identity.amazonaws.com","CanonicalUser":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"},"Action":"*","Resource":"*"}]}`,
			`{"Statement":[{"Effect":"Deny","Principal":{"AWS":["*"],"CanonicalUser":["79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"],"Federated":["cognito-identity.amazonaws.com"],"Service":["s3.amazonaws.com"]},"Action":["*"],"Resource":["*"]}]}`, model.PolicyResource},
		{"empty lists and empty condition survive", `{"Statement":[{"Effect":"Allow","Action":[],"Resource":"*","Condition":{}}]}`,
			`{"Statement":[{"Effect":"Allow","Action":[],"Resource":["*"],"Condition":{}}]}`, 0},
		{"HTML characters and unicode are not escaped", `{"Statement":[{"Sid":"a<b>&é","Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::b/ü x"}]}`,
			"{\"Statement\":[{\"Sid\":\"a<b>&é\",\"Effect\":\"Allow\",\"Action\":[\"*\"],\"Resource\":[\"arn:aws:s3:::b/ü\\u2028x\"]}]}", 0},
		{"dropped statements are not written", `{"Statement":[{"Effect":"Allow","Action":"a:b","NotAction":"c:d","Resource":"*"},{"Effect":"Deny","Action":"a:b","Resource":"*"}]}`,
			`{"Statement":[{"Effect":"Deny","Action":["a:b"],"Resource":["*"]}]}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Parse([]byte(tc.in), Options{Kind: tc.kind})
			if err != nil {
				t.Fatal(err)
			}
			got, err := Serialize(r.Doc)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("canonical =\n%s\nwant\n%s", got, tc.want)
			}
			roundTrip(t, []byte(tc.in), Options{Kind: tc.kind})
		})
	}
}

// malformedCases are documents AWS would reject; each must fail with a
// *ParseError of the given code. They also seed FuzzParse.
var malformedCases = []struct {
	name string
	in   string
	code string
	lim  Limits
}{
	{"empty", ``, CodeInvalidJSON, Limits{}},
	{"white space only", " \n\t ", CodeInvalidJSON, Limits{}},
	{"array root", `[]`, CodeInvalidType, Limits{}},
	{"null root", `null`, CodeInvalidType, Limits{}},
	{"string root", `"x"`, CodeInvalidType, Limits{}},
	{"second document", `{"Statement":[]} {}`, CodeTrailingData, Limits{}},
	{"trailing garbage", `{"Statement":[]} x`, CodeTrailingData, Limits{}},
	{"trailing bracket", `{"Statement":[]}]`, CodeTrailingData, Limits{}},
	{"byte-order mark", "\xef\xbb\xbf{\"Statement\":[]}", CodeInvalidJSON, Limits{}},
	{"invalid UTF-8", "{\"Statement\":[{\"Sid\":\"\xff\"}]}", CodeInvalidJSON, Limits{}},
	{"unterminated", `{"Statement":[`, CodeInvalidJSON, Limits{}},
	{"lone high surrogate", `{"Statement":[{"Sid":"\ud800","Effect":"Allow","Action":"*","Resource":"*"}]}`, CodeInvalidJSON, Limits{}},
	{"lone low surrogate", `{"Statement":[{"Sid":"a\udc00","Effect":"Allow","Action":"*","Resource":"*"}]}`, CodeInvalidJSON, Limits{}},
	{"reversed surrogate pair", `{"Statement":[{"Sid":"\udc00\ud800","Effect":"Allow","Action":"*","Resource":"*"}]}`, CodeInvalidJSON, Limits{}},
	{"trailing comma", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*",}]}`, CodeInvalidJSON, Limits{}},
	{"single quotes", `{'Statement':[]}`, CodeInvalidJSON, Limits{}},
	{"comment", `{"Statement":[] /* c */}`, CodeInvalidJSON, Limits{}},
	{"NaN", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"k":NaN}}}]}`, CodeInvalidJSON, Limits{}},
	{"leading zero", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"k":01}}}]}`, CodeInvalidJSON, Limits{}},
	{"duplicate top-level key", `{"Statement":[],"Statement":[]}`, CodeDuplicateKey, Limits{}},
	{"duplicate key via escape", `{"Statement":[],"St\u0061tement":[]}`, CodeDuplicateKey, Limits{}},
	{"duplicate Effect", `{"Statement":[{"Effect":"Allow","Effect":"Deny","Action":"*","Resource":"*"}]}`, CodeDuplicateKey, Limits{}},
	{"duplicate principal type", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"1","AWS":"2"},"Action":"*"}]}`, CodeDuplicateKey, Limits{}},
	{"duplicate condition key by case", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:SourceIp":"a","AWS:SOURCEIP":"b"}}}]}`, CodeDuplicateKey, Limits{}},
	{"duplicate operator by case", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"a":"b"},"stringequals":{"c":"d"}}}]}`, CodeDuplicateKey, Limits{}},
	{"Version not a string", `{"Version":2012,"Statement":[]}`, CodeInvalidType, Limits{}},
	{"Version unknown", `{"Version":"2012-10-18","Statement":[]}`, CodeInvalidValue, Limits{}},
	{"Version lower-case date variant", `{"Version":"2012-10-17 ","Statement":[]}`, CodeInvalidValue, Limits{}},
	{"element names are case-sensitive", `{"version":"2012-10-17","Statement":[]}`, CodeUnknownElement, Limits{}},
	{"unknown top-level element", `{"Statement":[],"Comment":"x"}`, CodeUnknownElement, Limits{}},
	{"missing Statement", `{"Version":"2012-10-17"}`, CodeMissingElement, Limits{}},
	{"Statement a string", `{"Statement":"x"}`, CodeInvalidType, Limits{}},
	{"Statement element not an object", `{"Statement":[1]}`, CodeInvalidType, Limits{}},
	{"Id not a string", `{"Id":1,"Statement":[]}`, CodeInvalidType, Limits{}},
	{"unknown statement element", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Resources":"*"}]}`, CodeUnknownElement, Limits{}},
	{"statement element case", `{"Statement":[{"effect":"Allow","Action":"*","Resource":"*"}]}`, CodeUnknownElement, Limits{}},
	{"missing Effect", `{"Statement":[{"Action":"*","Resource":"*"}]}`, CodeMissingElement, Limits{}},
	{"Effect lower-case", `{"Statement":[{"Effect":"allow","Action":"*","Resource":"*"}]}`, CodeInvalidValue, Limits{}},
	{"Effect not a string", `{"Statement":[{"Effect":true,"Action":"*","Resource":"*"}]}`, CodeInvalidType, Limits{}},
	{"Sid not a string", `{"Statement":[{"Sid":1,"Effect":"Allow","Action":"*","Resource":"*"}]}`, CodeInvalidType, Limits{}},
	{"Action a number", `{"Statement":[{"Effect":"Allow","Action":5,"Resource":"*"}]}`, CodeInvalidType, Limits{}},
	{"Action list of numbers", `{"Statement":[{"Effect":"Allow","Action":[1],"Resource":"*"}]}`, CodeInvalidType, Limits{}},
	{"Resource an object", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":{}}]}`, CodeInvalidType, Limits{}},
	{"Resource null", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":null}]}`, CodeInvalidType, Limits{}},
	{"string principal other than *", `{"Statement":[{"Effect":"Allow","Principal":"arn:aws:iam::111111111111:root","Action":"*"}]}`, CodeInvalidValue, Limits{}},
	{"principal type case", `{"Statement":[{"Effect":"Allow","Principal":{"aws":"*"},"Action":"*"}]}`, CodeUnknownElement, Limits{}},
	{"unknown principal type", `{"Statement":[{"Effect":"Allow","Principal":{"User":"x"},"Action":"*"}]}`, CodeUnknownElement, Limits{}},
	{"principal value a number", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":111111111111},"Action":"*"}]}`, CodeInvalidType, Limits{}},
	{"principal a list", `{"Statement":[{"Effect":"Allow","Principal":["*"],"Action":"*"}]}`, CodeInvalidType, Limits{}},
	{"Condition a list", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":[]}]}`, CodeInvalidType, Limits{}},
	{"operator block a string", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":"x"}}]}`, CodeInvalidType, Limits{}},
	{"unknown operator", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEqual":{"a":"b"}}}]}`, CodeInvalidValue, Limits{}},
	{"unknown qualifier", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"ForSomeValues:StringEquals":{"a":"b"}}}]}`, CodeInvalidValue, Limits{}},
	{"IfExists twice", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEqualsIfExistsIfExists":{"a":"b"}}}]}`, CodeInvalidValue, Limits{}},
	{"Unicode look-alike in operator", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEqualsIfExiſts":{"a":"b"}}}]}`, CodeInvalidValue, Limits{}},
	{"condition value null", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"a":null}}}]}`, CodeInvalidType, Limits{}},
	{"condition value object", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"a":{}}}}]}`, CodeInvalidType, Limits{}},
	{"condition value nested list", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"a":[["x"]]}}}]}`, CodeInvalidType, Limits{}},
	{"too deep", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"a":` + strings.Repeat("[", 20) + strings.Repeat("]", 20) + `}}}]}`, CodeLimitExceeded, Limits{}},
	{"too large", `{"Statement":[{"Sid":"` + strings.Repeat("a", 200) + `","Effect":"Allow","Action":"*","Resource":"*"}]}`, CodeLimitExceeded, Limits{MaxBytes: 100}},
	{"too many statements", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Allow","Action":"*","Resource":"*"}]}`, CodeLimitExceeded, Limits{MaxStatements: 2}},
	{"string too long", `{"Statement":[{"Effect":"Allow","Action":"s3:GetObjectAcl","Resource":"*"}]}`, CodeLimitExceeded, Limits{MaxStringBytes: 10}},
	{"key too long", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:principaltag/very-long-key":"x"}}}]}`, CodeLimitExceeded, Limits{MaxStringBytes: 16}},
	{"number too long", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"k":12345678901234567890}}}]}`, CodeLimitExceeded, Limits{MaxStringBytes: 16}},
	{"too many values", `{"Statement":[{"Effect":"Allow","Action":["a:a","a:b","a:c","a:d"],"Resource":"*"}]}`, CodeLimitExceeded, Limits{MaxValues: 6}},
}

func TestMalformed(t *testing.T) {
	for _, tc := range malformedCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.in), Options{Limits: tc.lim})
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want a *ParseError", err)
			}
			if pe.Code != tc.code {
				t.Errorf("code = %s (%v), want %s", pe.Code, err, tc.code)
			}
			if pe.Line < 1 || pe.Col < 1 || pe.Offset < 0 || pe.Offset > len(tc.in) {
				t.Errorf("bad position %d:%d @%d", pe.Line, pe.Col, pe.Offset)
			}
		})
	}
}

func TestParseErrorPosition(t *testing.T) {
	in := "{\n  \"Statement\": [\n    {\"Effect\": \"Allow\", \"Effect\": \"Deny\"}\n  ]\n}"
	_, err := Parse([]byte(in), Options{})
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatal(err)
	}
	if pe.Code != CodeDuplicateKey || pe.Line != 3 || pe.Col != 25 || pe.Path != "Statement[0]" {
		t.Errorf("got %+v", pe)
	}
	if want := `policy: line 3 col 25: Statement[0]: duplicate key "Effect"`; pe.Error() != want {
		t.Errorf("Error() = %q, want %q", pe.Error(), want)
	}
	_, err = Parse([]byte("{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"é\":null}}}]}"), Options{})
	if !errors.As(err, &pe) || pe.Path != "Statement[0].Condition.StringEquals.é" || pe.Col != 94 {
		t.Errorf("got %+v", pe)
	}
}

func TestEscapes(t *testing.T) {
	// A surrogate pair, an escaped backslash before "u", and other escapes are fine.
	in := `{"Statement":[{"Sid":"x","Effect":"Allow","Action":"*","Resource":["arn:aws:s3:::b/\ud83d\ude00","arn:aws:s3:::b/\\ud800","\"\/\b\f\n\r\t\u00e9"]}]}`
	r, err := Parse([]byte(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"arn:aws:s3:::b/\U0001F600", "arn:aws:s3:::b/\\ud800", "\"/\b\f\n\r\té"}
	if got := r.Doc.Statements[0].Resources.Patterns; !reflect.DeepEqual(got, want) {
		t.Errorf("patterns = %q, want %q", got, want)
	}
	if loneSurrogate([]byte(`"\ud800"`)) != 1 || loneSurrogate([]byte(`"\\ud800"`)) != -1 || loneSurrogate([]byte(`"\u12"`)) != -1 {
		t.Error("loneSurrogate")
	}
}

func TestSpans(t *testing.T) {
	in := "{\n" +
		"  \"Version\": \"2012-10-17\",\n" +
		"  \"Statement\": [\n" +
		"    {\n" +
		"      \"Sid\": \"Braces{in}Strings\",\n" +
		"      \"Effect\": \"Allow\",\n" +
		"      \"Action\": \"s3:GetObject\",\n" +
		"      \"Resource\": \"*\",\n" +
		"      \"Condition\": {\"StringEquals\": {\"aws:PrincipalTag/équipe\": \"x}\"}}\n" +
		"    },\n" +
		"    {\"Sid\": \"ünïcode\", \"Effect\": \"Deny\", \"Action\": \"*\", \"Resource\": \"*\"}, {\"Effect\": \"Allow\", \"Action\": \"*\", \"NotAction\": \"*\", \"Resource\": \"*\"},\r\n" +
		"\t{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}\n" +
		"  ]\n" +
		"}\n"
	r, err := Parse([]byte(in), Options{Kind: model.PolicyIdentity})
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		index int
		span  Span
	}{
		{0, Span{StartLine: 4, StartCol: 5, EndLine: 10, EndCol: 5}},
		// Columns count code points: "ünïcode" is 7 columns, not 9 bytes.
		{1, Span{StartLine: 11, StartCol: 5, EndLine: 11, EndCol: 72}},
		// Statement 2 (Action and NotAction) is dropped; its anomaly keeps its span.
		{3, Span{StartLine: 12, StartCol: 2, EndLine: 12, EndCol: 46}},
	}
	if len(r.Doc.Statements) != len(want) {
		t.Fatalf("statements = %d", len(r.Doc.Statements))
	}
	for i, w := range want {
		s := r.Doc.Statements[i]
		if s.Index != w.index || s.Span == nil || *s.Span != w.span {
			t.Errorf("statement %d: index %d span %+v, want index %d span %+v", i, s.Index, s.Span, w.index, w.span)
		}
	}
	if len(r.Anomalies) != 1 || r.Anomalies[0].StatementIndex != 2 ||
		*r.Anomalies[0].Span != (Span{StartLine: 11, StartCol: 75, EndLine: 11, EndCol: 143}) {
		t.Errorf("anomalies = %+v", r.Anomalies)
	}
	// The condition atom carries the statement's span as provenance.
	if a := r.Doc.Statements[0].Condition[0]; a.Source.Span != r.Doc.Statements[0].Span || a.Source.StatementIndex != 0 || a.Source.Sid != "Braces{in}Strings" {
		t.Errorf("atom source = %+v", a.Source)
	}
	// Every span covers exactly the statement's JSON object.
	for _, s := range r.Doc.Statements {
		checkSpanText(t, []byte(in), s)
	}
	// A single statement object (no array) gets a span too.
	r, err = Parse([]byte(`{"Statement": {"Effect":"Allow","Action":"*","Resource":"*"}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := *r.Doc.Statements[0].Span; got != (Span{StartLine: 1, StartCol: 15, EndLine: 1, EndCol: 60}) {
		t.Errorf("single-object span = %+v", got)
	}
}

// checkSpanText cuts the raw text at the span and checks it is the statement.
func checkSpanText(t *testing.T, raw []byte, s model.Statement) {
	t.Helper()
	text := spanText(raw, *s.Span)
	if len(text) < 2 || text[0] != '{' || text[len(text)-1] != '}' {
		t.Fatalf("statement %d span text %q is not an object", s.Index, text)
	}
	var v map[string]any
	if err := json.Unmarshal(text, &v); err != nil {
		t.Fatalf("statement %d span text %q: %v", s.Index, text, err)
	}
	if eff, _ := v["Effect"].(string); eff != s.Effect.PolicyElement() {
		t.Errorf("statement %d span text has Effect %q, want %q", s.Index, eff, s.Effect.PolicyElement())
	}
}

// spanText returns raw[start:end] for an inclusive line/column span.
func spanText(raw []byte, sp Span) []byte {
	lines := lineStarts(raw)
	offset := func(line, col int) int {
		off := lines[line-1]
		for c := 1; c < col; c++ {
			_, w := utf8.DecodeRune(raw[off:])
			off += w
		}
		return off
	}
	start := offset(sp.StartLine, sp.StartCol)
	end := offset(sp.EndLine, sp.EndCol)
	_, w := utf8.DecodeRune(raw[end:])
	return raw[start : end+w]
}

// A lone "\r" ends a line, "\r\n" is one line break, and "\n" is one too.
func TestSpansLineBreaks(t *testing.T) {
	stmt := `{"Effect":"Allow","Action":"*","Resource":"*"}`
	for name, br := range map[string]string{"LF": "\n", "CRLF": "\r\n", "CR": "\r"} {
		in := "{" + br + `  "Statement": [` + br + "    " + stmt + "," + br + br + "\t" + stmt + br + "  ]" + br + "}"
		r, err := Parse([]byte(in), Options{Kind: model.PolicyIdentity})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := []Span{
			{StartLine: 3, StartCol: 5, EndLine: 3, EndCol: 4 + len(stmt)},
			{StartLine: 5, StartCol: 2, EndLine: 5, EndCol: 1 + len(stmt)},
		}
		for i, w := range want {
			if got := *r.Doc.Statements[i].Span; got != w {
				t.Errorf("%s: statement %d span %+v, want %+v", name, i, got, w)
			}
			checkSpanText(t, []byte(in), r.Doc.Statements[i])
		}
		_, err = Parse([]byte("{"+br+br+`"Statement":[],"Statement":[]}`), Options{})
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Line != 3 || pe.Col != 16 {
			t.Errorf("%s: error position = %+v", name, pe)
		}
	}
}

// Error paths and messages embed policy keys of up to MaxStringBytes, so they
// are clipped on a rune boundary.
func TestParseErrorClipped(t *testing.T) {
	long := strings.Repeat("é", 3000) // 6,000 bytes
	for _, in := range []string{
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"` + long + `":null}}}]}`,
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","` + long + `":1}]}`,
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"` + long + `":{}}}]}`,
	} {
		_, err := Parse([]byte(in), Options{})
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Fatalf("err = %v", err)
		}
		if len(pe.Path) > maxErrorPath+len("…") || len(pe.Msg) > maxErrorMsg+len("…") || len(pe.Error()) > 1024 {
			t.Errorf("error not clipped: path %d bytes, msg %d bytes", len(pe.Path), len(pe.Msg))
		}
		if !utf8.ValidString(pe.Path) || !utf8.ValidString(pe.Msg) {
			t.Error("clipping split a rune")
		}
		if !strings.HasSuffix(pe.Path, "…") && !strings.HasSuffix(pe.Msg, "…") {
			t.Errorf("neither path nor message is marked as clipped: %v", pe)
		}
	}
	if clip("abc", 3) != "abc" || clip("abcd", 3) != "abc…" || clip("aé", 2) != "a…" {
		t.Error("clip")
	}
}

// Condition keys fold A–Z only (§8.1, A22). Unicode look-alikes do not fold
// into ASCII keys, and keys that differ only by non-ASCII case are distinct.
func TestConditionKeyFolding(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys string   // the members of one StringEquals block
		want []string // Atom.Key of each atom, in order
		raw  []string // Atom.RawKey of each atom
	}{
		{"ASCII case folds", `"aws:SourceIp":"x"`, []string{"aws:sourceip"}, []string{"aws:SourceIp"}},
		{"non-ASCII case differs (QA-1)", `"aws:PrincipalTag/É":"1","aws:PrincipalTag/é":"2"`,
			[]string{"aws:principaltag/É", "aws:principaltag/é"}, []string{"aws:PrincipalTag/É", "aws:PrincipalTag/é"}},
		{"Kelvin sign is not k", `"aws:PrincipalTag/k":"1","aws:PrincipalTag/\u212A":"2"`,
			[]string{"aws:principaltag/k", "aws:principaltag/\u212A"}, []string{"aws:PrincipalTag/k", "aws:PrincipalTag/\u212A"}},
		{"dotted capital I is not i", `"aws:SourceIp":"1","aws:Source\u0130p":"2"`,
			[]string{"aws:sourceip", "aws:source\u0130p"}, []string{"aws:SourceIp", "aws:Source\u0130p"}},
		{"look-alike alone keeps its spelling", `"AWS:SOURCE\u0130P":"1"`, []string{"aws:source\u0130p"}, []string{"AWS:SOURCE\u0130P"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{` + tc.keys + `}}}]}`
			r, err := Parse([]byte(in), Options{Kind: model.PolicyIdentity})
			if err != nil {
				t.Fatal(err)
			}
			atoms := r.Doc.Statements[0].Condition
			if len(atoms) != len(tc.want) {
				t.Fatalf("atoms = %+v", atoms)
			}
			for i, a := range atoms {
				if a.Key != tc.want[i] || a.RawKey != tc.raw[i] {
					t.Errorf("atom %d key %q raw %q, want %q raw %q", i, a.Key, a.RawKey, tc.want[i], tc.raw[i])
				}
			}
			nonASCII := false
			for _, k := range tc.want {
				nonASCII = nonASCII || !isASCII(k)
			}
			if hasFinding(r, "NON_ASCII_CONDITION_KEY") != nonASCII {
				t.Errorf("NON_ASCII_CONDITION_KEY = %v, want %v", !nonASCII, nonASCII)
			}
			roundTrip(t, []byte(in), Options{Kind: model.PolicyIdentity})
		})
	}
	// strings.ToLower would fold both look-alikes into ASCII keys.
	if asciiLower("\u212A\u0130É") != "\u212A\u0130É" || strings.ToLower("\u212A\u0130") != "ki" {
		t.Error("asciiLower must leave non-ASCII letters alone")
	}
}

func TestSpansGolden(t *testing.T) {
	for _, g := range goldenPolicies {
		r, err := Parse([]byte(g.json), Options{Kind: g.kind})
		if err != nil {
			t.Fatalf("%s: %v", g.id, err)
		}
		for _, s := range r.Doc.Statements {
			checkSpanText(t, []byte(g.json), s)
		}
	}
}

func TestAnomalies(t *testing.T) {
	type want struct {
		code    AnomalyCode
		index   int
		dropped bool
	}
	tagKeysVar := `"Resource":"arn:aws:s3:::b/${aws:TagKeys}/*"`
	for _, tc := range []struct {
		name    string
		kind    model.PolicyKind
		in      string
		opts    func(*Options)
		want    []want
		indexes []int // Index of each kept statement
	}{
		{name: "Action and NotAction", kind: model.PolicyIdentity,
			in:   `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Allow","Action":"s3:*","NotAction":"iam:*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
			want: []want{{AnomalyInvalidElementMix, 1, true}}, indexes: []int{0, 2}},
		{name: "neither Action nor NotAction", kind: model.PolicyIdentity,
			in:   `{"Statement":[{"Effect":"Allow","Resource":"*"}]}`,
			want: []want{{AnomalyInvalidElementMix, 0, true}}, indexes: []int{}},
		{name: "Resource and NotResource", kind: model.PolicyIdentity,
			in:   `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","NotResource":"arn:aws:s3:::x"}]}`,
			want: []want{{AnomalyInvalidElementMix, 0, true}}, indexes: []int{}},
		{name: "Principal and NotPrincipal", kind: model.PolicyResource,
			in:   `{"Statement":[{"Effect":"Deny","Principal":"*","NotPrincipal":{"AWS":"111111111111"},"Action":"*","Resource":"*"}]}`,
			want: []want{{AnomalyInvalidElementMix, 0, true}}, indexes: []int{}},
		{name: "two problems in one statement", kind: model.PolicyResource,
			in:   `{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"111111111111"},"Action":"*","NotAction":"*","Resource":"*"}]}`,
			want: []want{{AnomalyInvalidElementMix, 0, true}, {AnomalyNotPrincipalWithAllow, 0, true}}, indexes: []int{}},
		{name: "missing Resource in an identity policy", kind: model.PolicyIdentity,
			in:   `{"Statement":[{"Effect":"Allow","Action":"*"}]}`,
			want: []want{{AnomalyMissingResource, 0, true}}, indexes: []int{}},
		{name: "missing Resource in an SCP", kind: model.PolicySCP,
			in:   `{"Statement":[{"Effect":"Allow","Action":"*"}]}`,
			want: []want{{AnomalyMissingResource, 0, true}}, indexes: []int{}},
		{name: "missing Resource in a resource policy is implied", kind: model.PolicyResource,
			in: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*"}]}`, indexes: []int{0}},
		{name: "missing Resource with an unknown kind is kept", kind: 0,
			in: `{"Statement":[{"Effect":"Allow","Action":"*"}]}`, indexes: []int{0}},
		{name: "NotPrincipal with Allow", kind: model.PolicyResource,
			in:   `{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"111111111111"},"Action":"*","Resource":"*"}]}`,
			want: []want{{AnomalyNotPrincipalWithAllow, 0, true}}, indexes: []int{}},
		{name: "NotPrincipal with Deny is valid", kind: model.PolicyResource,
			in: `{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"111111111111"},"Action":"*","Resource":"*"}]}`, indexes: []int{0}},
		{name: "multivalued variable in Resource", kind: model.PolicyIdentity,
			in:   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*",` + tagKeysVar + `}]}`,
			want: []want{{AnomalyMultivaluedVariable, 0, false}}, indexes: []int{0}},
		{name: "multivalued variable with a default and odd case", kind: model.PolicyIdentity,
			in:   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b/${ AWS:calledVia , 'x'}"}]}`,
			want: []want{{AnomalyMultivaluedVariable, 0, false}}, indexes: []int{0}},
		{name: "multivalued variable in a String condition value", kind: model.PolicyIdentity,
			in:   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"s3:prefix":"${aws:PrincipalOrgPaths}"}}}]}`,
			want: []want{{AnomalyMultivaluedVariable, 0, false}}, indexes: []int{0}},
		{name: "a multivalued key under Version 2008 is literal text, not a variable", kind: model.PolicyIdentity,
			in: `{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:*",` + tagKeysVar + `}]}`, indexes: []int{0}},
		{name: "a variable in a Numeric value is never substituted", kind: model.PolicyIdentity,
			in: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"k":"${aws:TagKeys}"}}}]}`, indexes: []int{0}},
		{name: "escapes are not variables", kind: model.PolicyIdentity,
			in: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b/${*}${?}${$}"}]}`, indexes: []int{0}},
		{name: "catalog-supplied multivalued key", kind: model.PolicyIdentity,
			in:   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:dynamodb:*:*:table/${dynamodb:Attributes}"}]}`,
			opts: func(o *Options) { o.MultivaluedKey = func(k string) bool { return k == "dynamodb:attributes" } },
			want: []want{{AnomalyMultivaluedVariable, 0, false}}, indexes: []int{0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{Kind: tc.kind}
			if tc.opts != nil {
				tc.opts(&opts)
			}
			r, err := Parse([]byte(tc.in), opts)
			if err != nil {
				t.Fatal(err)
			}
			var got []want
			for _, a := range r.Anomalies {
				got = append(got, want{a.Code, a.StatementIndex, a.Dropped})
				if a.Span == nil || a.Detail == "" {
					t.Errorf("anomaly without span or detail: %+v", a)
				}
				if !hasFinding(r, string(a.Code)) {
					t.Errorf("anomaly %s has no error finding", a.Code)
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("anomalies = %+v, want %+v", got, tc.want)
			}
			idx := []int{}
			for _, s := range r.Doc.Statements {
				idx = append(idx, s.Index)
			}
			if !reflect.DeepEqual(idx, tc.indexes) {
				t.Errorf("kept statement indexes = %v, want %v", idx, tc.indexes)
			}
		})
	}
}

func TestParseOperator(t *testing.T) {
	for _, op := range baseOperators {
		for _, q := range []authz.Qualifier{authz.NoQualifier, authz.ForAllValues, authz.ForAnyValue} {
			for _, ifx := range []bool{false, true} {
				name := OperatorName(authz.Atom{Op: op, Qualifier: q, IfExists: ifx})
				for _, spelled := range []string{name, strings.ToLower(name), strings.ToUpper(name)} {
					gotOp, gotQ, gotIfx, ok := parseOperator(spelled)
					if !ok || gotOp != op || gotQ != q || gotIfx != ifx {
						t.Errorf("parseOperator(%q) = %s %v %v %v", spelled, gotOp, gotQ, gotIfx, ok)
					}
				}
			}
		}
	}
	for _, bad := range []string{"", "IfExists", "ForAllValues:", ":StringEquals", "ForAllValues:ForAnyValue:StringEquals",
		"StringEqualsIfExistsIfExists", "NumericEqual", "IpAddressIfExist", "Kelvin:StringEquals", "StringEquaLſ"} {
		if _, _, _, ok := parseOperator(bad); ok {
			t.Errorf("parseOperator(%q) must fail", bad)
		}
	}
	negated := 0
	for _, op := range baseOperators {
		if IsNegatedOperator(op) {
			negated++
		}
	}
	if negated != 8 {
		t.Errorf("negated operators = %d, want 8", negated)
	}
}

func TestClassifyAWSPrincipal(t *testing.T) {
	for _, tc := range []struct {
		in, acct string
		kind     model.PrincipalEntryKind
	}{
		{"*", "", model.PrincipalWildcard},
		{"123456789012", "123456789012", model.PrincipalAccount},
		{"arn:aws:iam::123456789012:root", "123456789012", model.PrincipalAccount},
		{"arn:aws-cn:iam::123456789012:root", "123456789012", model.PrincipalAccount},
		{"arn:aws-us-gov:iam::123456789012:user/division/alice", "123456789012", model.PrincipalIAMUser},
		{"arn:aws:iam::123456789012:role/aws-service-role/x.amazonaws.com/AWSServiceRoleForX", "123456789012", model.PrincipalIAMRole},
		{"arn:aws:sts::123456789012:assumed-role/app/s1", "123456789012", model.PrincipalAssumedRole},
		{"arn:aws:sts::123456789012:federated-user/bob", "123456789012", model.PrincipalFederatedUser},
		{"AIDACKCEVSQ6C2EXAMPLE", "", model.PrincipalUniqueID},
		{"AROADBQP57FF2AEXAMPLE", "", model.PrincipalUniqueID},
		// Not principals, or not in a form AWS accepts: kept literally.
		{"12345678901", "", model.PrincipalUnrecognized},
		{"1234567890123", "", model.PrincipalUnrecognized},
		{"arn:aws:iam::*:root", "", model.PrincipalUnrecognized},
		{"arn:aws:iam::123456789012:user/*", "", model.PrincipalUnrecognized},
		{"arn:aws:iam::123456789012:role/app*", "", model.PrincipalUnrecognized},
		{"arn:aws:iam::123456789012:group/eng", "", model.PrincipalUnrecognized},
		{"arn:aws:iam::123456789012:user/", "", model.PrincipalUnrecognized},
		{"arn:aws:sts::123456789012:assumed-role/app", "", model.PrincipalUnrecognized},
		{"arn:aws:sts::123456789012:assumed-role/app/", "", model.PrincipalUnrecognized},
		{"arn:aws:iam:us-east-1:123456789012:root", "", model.PrincipalUnrecognized},
		{"arn::iam::123456789012:root", "", model.PrincipalUnrecognized},
		{"arn:aws:iam::123456789012", "", model.PrincipalUnrecognized},
		{"aidackcevsq6c2example", "", model.PrincipalUnrecognized},
		{"AWS:123456789012", "", model.PrincipalUnrecognized},
		{"", "", model.PrincipalUnrecognized},
	} {
		got := ClassifyAWSPrincipal(tc.in)
		if got.Kind != tc.kind || got.AccountID != tc.acct || got.Value != tc.in {
			t.Errorf("ClassifyAWSPrincipal(%q) = %+v, want kind %v account %q", tc.in, got, tc.kind, tc.acct)
		}
	}
}

func TestDocumentFields(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Id":"q1","Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:*"}]}`)
	opts := Options{Kind: model.PolicyResource, SourceARN: "arn:aws:sqs:us-east-1:111111111111:q#policy", VersionID: "v3", AWSManaged: true}
	r, err := Parse(raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	d := r.Doc
	if d.Kind != model.PolicyResource || d.SourceARN != opts.SourceARN || d.VersionID != "v3" || !d.AWSManaged ||
		d.LanguageVersion != "2012-10-17" || d.IDElement != "q1" || !bytes.Equal(d.RawJSON, raw) {
		t.Errorf("doc = %+v", d)
	}
	if d.ID != DocumentID(opts.Kind, opts.SourceARN, opts.VersionID, raw) || len(d.ID) != 64 {
		t.Errorf("id = %q", d.ID)
	}
	if d.Statements[0].PolicyID != d.ID {
		t.Error("statement PolicyID must be the document id")
	}
	if src := d.Statements[0].Principals; src == nil || !src.Star {
		t.Error("principal")
	}
	// The id depends on every input.
	ids := map[string]bool{d.ID: true}
	for _, id := range []string{
		DocumentID(model.PolicyTrust, opts.SourceARN, opts.VersionID, raw),
		DocumentID(opts.Kind, "x", opts.VersionID, raw),
		DocumentID(opts.Kind, opts.SourceARN, "v4", raw),
		DocumentID(opts.Kind, opts.SourceARN, opts.VersionID, append([]byte(" "), raw...)),
	} {
		if ids[id] {
			t.Errorf("id collision: %s", id)
		}
		ids[id] = true
	}
	// RawJSON is a copy: the caller may reuse its buffer.
	raw[2] = 'X'
	if d.RawJSON[2] == 'X' {
		t.Error("RawJSON aliases the input")
	}
}

func TestDefaultLimitsAboveAWS(t *testing.T) {
	// AWS's largest policy documents: KMS key policies (32,768 bytes) and S3
	// bucket / Secrets Manager policies (20 KB).
	if DefaultLimits.MaxBytes < 32768*2 {
		t.Errorf("MaxBytes %d leaves too little room above AWS's 32 KiB key-policy limit", DefaultLimits.MaxBytes)
	}
	if DefaultLimits.MaxDepth < 6 {
		t.Error("the policy grammar needs depth 6")
	}
	if (Limits{}).orDefault() != DefaultLimits {
		t.Error("zero limits must take the defaults")
	}
	// A realistic large policy parses: 400 statements, ~60 KB.
	var sb strings.Builder
	sb.WriteString(`{"Version":"2012-10-17","Statement":[`)
	for i := 0; i < 400; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"Sid":"S%d","Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::bucket-%d/*"}`, i, i)
	}
	sb.WriteString("]}")
	r, err := Parse([]byte(sb.String()), Options{Kind: model.PolicyIdentity})
	if err != nil || len(r.Doc.Statements) != 400 {
		t.Fatalf("large policy: %v", err)
	}
}

// FuzzParse: the parser never panics, never exceeds its limits, and
// parse → serialize → parse is stable. Seeded with every policy in the golden
// corpus and every malformed case.
//
// When the high bit of kind is set, the document is parsed with small limits
// derived from the input, so the depth, value-count, statement and string
// limits are hit often rather than only by huge inputs.
func FuzzParse(f *testing.F) {
	for _, g := range goldenPolicies {
		f.Add([]byte(g.json), uint8(g.kind))
		f.Add([]byte(g.json), uint8(g.kind)|0x80)
	}
	for _, m := range malformedCases {
		f.Add([]byte(m.in), uint8(0))
	}
	f.Add([]byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b/${aws:TagKeys}","Condition":{"forallvalues:stringlikeifexists":{"A:B":[1,true,"x"]}}}}`), uint8(model.PolicyIdentity))
	f.Add([]byte(`{"Statement":[{"Effect":"Allow","NotPrincipal":"*","Action":"*","NotAction":"*"}]}`), uint8(model.PolicyResource))
	f.Add([]byte(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/\u00c9":"1","aws:PrincipalTag/\u00e9":"2","\u212A":"3"}}}]}`), uint8(model.PolicyIdentity))
	f.Add([]byte("{\r\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"arn:aws:sqs\"}]\r}"), uint8(model.PolicySCP)|0x80)
	f.Fuzz(func(t *testing.T, raw []byte, kind uint8) {
		opts := Options{Kind: model.PolicyKind((kind & 0x7f) % 12)}
		small := kind&0x80 != 0
		if small {
			n := len(raw)
			opts.Limits = Limits{
				MaxBytes:       1 + n,
				MaxDepth:       1 + n%7,
				MaxStatements:  1 + n%3,
				MaxStringBytes: 5 + n%32, // ≥ 5: a boolean condition value becomes "false"
				MaxValues:      1 + n%40,
			}
		}
		r, err := Parse(raw, opts)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("error is not a *ParseError: %v", err)
			}
			if len(pe.Path) > maxErrorPath+len("…") || len(pe.Msg) > maxErrorMsg+len("…") {
				t.Fatalf("error text not clipped: %d / %d bytes", len(pe.Path), len(pe.Msg))
			}
			return
		}
		lim := opts.Limits.orDefault()
		if len(raw) > lim.MaxBytes || len(r.Doc.Statements) > lim.MaxStatements {
			t.Fatalf("limits exceeded: %d bytes, %d statements", len(raw), len(r.Doc.Statements))
		}
		str := func(what, s string) {
			if len(s) > lim.MaxStringBytes {
				t.Fatalf("%s is %d bytes, longer than MaxStringBytes %d", what, len(s), lim.MaxStringBytes)
			}
		}
		str("Id", r.Doc.IDElement)
		lines := len(lineStarts(raw))
		for _, s := range r.Doc.Statements {
			if s.Span == nil || s.Span.StartLine < 1 || s.Span.EndLine > lines || s.Span.EndLine < s.Span.StartLine {
				t.Fatalf("bad span %+v (%d lines)", s.Span, lines)
			}
			str("Sid", s.Sid)
			for _, ps := range []*model.PatternSet{s.Actions, s.NotActions, s.Resources, s.NotResources} {
				if ps == nil {
					continue
				}
				for _, p := range ps.Patterns {
					str("pattern", p)
				}
				if ps.Completed != nil && len(ps.Completed) != len(ps.Patterns) {
					t.Fatalf("completed %q does not line up with patterns %q", ps.Completed, ps.Patterns)
				}
				for i, c := range ps.Completed {
					if !strings.HasPrefix(c, ps.Patterns[i]) || len(c) > len(ps.Patterns[i])+len(":*:*:*:*") {
						t.Fatalf("completed %q is not a completion of %q", c, ps.Patterns[i])
					}
				}
			}
			for _, pset := range []*model.PrincipalSet{s.Principals, s.NotPrincipals} {
				if pset == nil {
					continue
				}
				for _, list := range [][]string{pset.AWS, pset.CanonicalUser, pset.Federated, pset.Service} {
					for _, v := range list {
						str("principal", v)
					}
				}
				for _, e := range pset.Entries {
					str("principal entry", e.Value)
				}
			}
			for _, a := range s.Condition {
				str("condition key", a.Key)
				str("raw condition key", a.RawKey)
				if a.Key != asciiLower(a.RawKey) {
					t.Fatalf("key %q is not the ASCII fold of %q", a.Key, a.RawKey)
				}
				for _, v := range a.Values {
					str("condition value", v)
				}
			}
			if (s.Actions == nil) == (s.NotActions == nil) {
				t.Fatal("exactly one of Actions / NotActions must be set")
			}
			if s.Resources != nil && s.NotResources != nil || s.Principals != nil && s.NotPrincipals != nil {
				t.Fatal("invalid element mix was kept")
			}
			if s.NotPrincipals != nil && s.Effect == model.EffectAllow {
				t.Fatal("NotPrincipal with Allow was kept")
			}
		}
		if small {
			// The canonical form can need more depth than the input (a string
			// becomes a list), so the round trip uses the default limits.
			opts.Limits = Limits{}
		}
		roundTrip(t, raw, opts)
	})
}
