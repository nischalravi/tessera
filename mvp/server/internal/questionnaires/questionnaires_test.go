package questionnaires

import (
	"errors"
	"strings"
	"testing"
)

func code(err error) string {
	var qe *Error
	if errors.As(err, &qe) {
		return qe.Code
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return ""
}

func opts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = string(rune('a'+i%26)) + strings.Repeat("x", i/26)
	}
	return out
}

func TestSpecCheck(t *testing.T) {
	why := Question{Type: ShortText, Text: "Why do you need it?", Required: true}
	tests := []struct {
		name string
		spec Spec
		want string // error code; "" accepts
	}{
		{"minimal", Spec{Title: "Why", Questions: []Question{why}}, ""},
		{"no title", Spec{Title: " ", Questions: []Question{why}}, "invalid_title"},
		{"long title", Spec{Title: strings.Repeat("t", MaxTitle+1), Questions: []Question{why}}, "invalid_title"},
		{"long description", Spec{Title: "t", Description: strings.Repeat("d", MaxDescription+1), Questions: []Question{why}}, "invalid_description"},
		{"no questions", Spec{Title: "t"}, "invalid_questions"},
		{"too many questions", Spec{Title: "t", Questions: make([]Question, MaxQuestions+1)}, "invalid_questions"},
		{"unknown type", Spec{Title: "t", Questions: []Question{{Type: "number", Text: "n"}}}, "invalid_question_type"},
		{"empty text", Spec{Title: "t", Questions: []Question{{Type: YesNo, Text: " "}}}, "invalid_question_text"},
		{"bad id", Spec{Title: "t", Questions: []Question{{ID: "Q 1", Type: YesNo, Text: "x"}}}, "invalid_question_id"},
		{"duplicate id", Spec{Title: "t", Questions: []Question{{ID: "a", Type: YesNo, Text: "x"}, {ID: "a", Type: YesNo, Text: "y"}}}, "duplicate_question_id"},
		{"choice needs two options", Spec{Title: "t", Questions: []Question{{Type: SingleChoice, Text: "x", Options: []string{"one"}}}}, "invalid_options"},
		{"too many options", Spec{Title: "t", Questions: []Question{{Type: MultiChoice, Text: "x", Options: opts(MaxOptions + 1)}}}, "invalid_options"},
		{"duplicate option", Spec{Title: "t", Questions: []Question{{Type: SingleChoice, Text: "x", Options: []string{"a", " a "}}}}, "invalid_options"},
		{"options on text", Spec{Title: "t", Questions: []Question{{Type: ShortText, Text: "x", Options: []string{"a", "b"}}}}, "invalid_options"},
		{"max length on choice", Spec{Title: "t", Questions: []Question{{Type: SingleChoice, Text: "x", Options: []string{"a", "b"}, MaxLength: 5}}}, "invalid_max_length"},
		{"short text above cap", Spec{Title: "t", Questions: []Question{{Type: ShortText, Text: "x", MaxLength: CapShortText + 1}}}, "invalid_max_length"},
		{"long text at cap", Spec{Title: "t", Questions: []Question{{Type: LongText, Text: "x", MaxLength: CapLongText}}}, ""},
		{"negative max length", Spec{Title: "t", Questions: []Question{{Type: LongText, Text: "x", MaxLength: -1}}}, "invalid_max_length"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.spec.Check(); code(err) != tc.want {
				t.Errorf("Check = %q, want %q", code(err), tc.want)
			}
		})
	}
}

// A question without an id gets the next free "qN", skipping ids the editor already named.
func TestSpecCheckAssignsIDs(t *testing.T) {
	s, err := Spec{Title: " Why ", Questions: []Question{{Type: YesNo, Text: "a"}, {ID: "q1", Type: YesNo, Text: "b"}, {Type: YesNo, Text: "c"}}}.Check()
	if err != nil {
		t.Fatal(err)
	}
	if s.Title != "Why" || s.Questions[0].ID != "q2" || s.Questions[1].ID != "q1" || s.Questions[2].ID != "q3" {
		t.Errorf("ids = %q %q %q", s.Questions[0].ID, s.Questions[1].ID, s.Questions[2].ID)
	}
}

func sample() Need {
	return Need{ID: "qn", Title: "Risk", Version: 3, Questions: []Question{
		{ID: "why", Type: ShortText, Text: "Why?", Required: true, MaxLength: 20},
		{ID: "detail", Type: LongText, Text: "Detail"},
		{ID: "env", Type: SingleChoice, Text: "Env", Options: []string{"prod", "test"}},
		{ID: "tools", Type: MultiChoice, Text: "Tools", Options: []string{"cli", "ui", "api"}},
		{ID: "ack", Type: YesNo, Text: "Ack", Required: true},
		{ID: "until", Type: Date, Text: "Until"},
	}}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name  string
		given map[string]map[string]any
		want  string
	}{
		{"required only", map[string]map[string]any{"qn": {"why": "on call", "ack": false}}, ""},
		{"all types", map[string]map[string]any{"qn": {"why": "on call", "detail": "x", "env": "prod", "tools": []any{"api", "cli"}, "ack": true, "until": "2026-12-31"}}, ""},
		{"nothing given", nil, "questionnaire_required"},
		{"missing required", map[string]map[string]any{"qn": {"ack": true}}, "answer_required"},
		{"blank required", map[string]map[string]any{"qn": {"why": "   ", "ack": true}}, "answer_required"},
		{"required yes/no missing", map[string]map[string]any{"qn": {"why": "x"}}, "answer_required"},
		{"too long", map[string]map[string]any{"qn": {"why": strings.Repeat("w", 21), "ack": true}}, "invalid_answer"},
		{"wrong type text", map[string]map[string]any{"qn": {"why": 5, "ack": true}}, "invalid_answer"},
		{"choice outside options", map[string]map[string]any{"qn": {"why": "x", "ack": true, "env": "dev"}}, "invalid_answer"},
		{"multi outside options", map[string]map[string]any{"qn": {"why": "x", "ack": true, "tools": []any{"cli", "fax"}}}, "invalid_answer"},
		{"multi duplicate", map[string]map[string]any{"qn": {"why": "x", "ack": true, "tools": []any{"cli", "cli"}}}, "invalid_answer"},
		{"multi not a list", map[string]map[string]any{"qn": {"why": "x", "ack": true, "tools": "cli"}}, "invalid_answer"},
		{"yes/no as text", map[string]map[string]any{"qn": {"why": "x", "ack": "yes"}}, "invalid_answer"},
		{"bad date", map[string]map[string]any{"qn": {"why": "x", "ack": true, "until": "31/12/2026"}}, "invalid_answer"},
		{"impossible date", map[string]map[string]any{"qn": {"why": "x", "ack": true, "until": "2026-02-30"}}, "invalid_answer"},
		{"unknown question", map[string]map[string]any{"qn": {"why": "x", "ack": true, "bogus": 1}}, "unknown_question"},
		{"unasked questionnaire", map[string]map[string]any{"qn": {"why": "x", "ack": true}, "other": {}}, "unexpected_questionnaire"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Validate([]Need{sample()}, tc.given)
			if code(err) != tc.want {
				t.Fatalf("Validate = %q (%v), want %q", code(err), err, tc.want)
			}
			if tc.want == "" && (len(got) != 1 || got[0].Hash == "" || got[0].Need.Version != 3) {
				t.Errorf("checked = %+v", got)
			}
		})
	}
}

// Optional-only questionnaires may be left alone; answers are trimmed, optional blanks dropped,
// and the same answers hash the same whatever order the keys or the choices came in.
func TestValidateNormalizes(t *testing.T) {
	optional := Need{ID: "o", Questions: []Question{{ID: "a", Type: ShortText, Text: "a"}}}
	if got, err := Validate([]Need{optional}, nil); err != nil || len(got) != 0 {
		t.Errorf("optional-only, none given: %v %v", got, err)
	}
	if got, err := Validate([]Need{optional}, map[string]map[string]any{"o": {"a": "  "}}); err != nil || len(got) != 0 {
		t.Errorf("optional-only, blank: %v %v", got, err)
	}
	a, err := Validate([]Need{sample()}, map[string]map[string]any{"qn": {"why": "  on call ", "ack": true, "tools": []any{"api", "cli"}, "detail": ""}})
	if err != nil {
		t.Fatal(err)
	}
	if a[0].Answers["why"] != "on call" || len(a[0].Answers) != 3 {
		t.Errorf("normalized = %v", a[0].Answers)
	}
	b, err := Validate([]Need{sample()}, map[string]map[string]any{"qn": {"tools": []string{"cli", "api"}, "ack": true, "why": "on call"}})
	if err != nil {
		t.Fatal(err)
	}
	if a[0].Hash != b[0].Hash {
		t.Errorf("hash differs for the same answers: %s %s", a[0].Hash, b[0].Hash)
	}
	c, _ := Validate([]Need{sample()}, map[string]map[string]any{"qn": {"tools": []string{"cli"}, "ack": true, "why": "on call"}})
	if c[0].Hash == a[0].Hash {
		t.Error("different answers share a hash")
	}
}

func TestUnion(t *testing.T) {
	a, b := Need{ID: "a"}, Need{ID: "b"}
	if got := Union([]Need{a}, []Need{a, b}, nil); len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Errorf("Union = %v", got)
	}
}
