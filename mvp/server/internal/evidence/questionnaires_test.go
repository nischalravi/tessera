package evidence_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/evidence"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Answers to questionnaires given in the period are in the pack, with the version they were
// given against and their hash; answers outside the period are not (issue #298).
func TestPackHasQuestionnaireAnswers(t *testing.T) {
	st, ids := testkit.Tiny(t)
	const qid = "11111111-1111-4111-8111-111111111111"
	testkit.Write(t, st, func(c *store.TenantTx) error {
		if err := c.InsertQuestionnaire(qid, &store.QuestionnaireVersion{Title: "Why do you need this?", CreatedBy: "admin",
			Questions: `[{"id":"why","type":"short_text","text":"Why?","required":true}]`}, h(0)); err != nil {
			return err
		}
		put := func(subject string, at time.Time) error {
			return c.PutQuestionnaireAnswer(&store.QuestionnaireAnswer{QuestionnaireID: qid, Version: 1, SubjectKind: store.QSubjectRequestLine,
				SubjectID: subject, Answers: `{"why":"=cmd"}`, Hash: "abc" + subject, AnsweredBy: "Alice"}, at)
		}
		if err := put("in", h(2)); err != nil {
			return err
		}
		return put("late", h(60))
	})
	res := generate(t, st, ids, "soc2", nil)
	rows := records(t, unzip(t, res.Zip)[evidence.FileQuestionnaires])
	if len(rows) != 1 || rows[0]["subject_id"] != "in" || rows[0]["questionnaire"] != "Why do you need this?" || rows[0]["version"] != "1" ||
		rows[0]["answers_hash"] != "abcin" || rows[0]["answered_by"] != "Alice" {
		t.Fatalf("rows = %v", rows)
	}
	if got := rows[0]["answers"]; got != `{"why":"=cmd"}` { // the cell starts with {, so it is not a formula
		t.Errorf("answers = %q", got)
	}
	// the control that asks for it lists the file
	listed := false
	for _, c := range res.Manifest.Controls {
		for _, f := range c.Files {
			listed = listed || f == evidence.FileQuestionnaires
		}
	}
	if !listed {
		t.Error("no SOC 2 control lists the questionnaire answers")
	}
}
