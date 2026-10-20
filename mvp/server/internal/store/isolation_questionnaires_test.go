package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Questionnaires (schema/0450_questionnaires.sql, issue #298): definitions, versions,
// attachments and answers are read and written only through the tenant's own handle.

func TestIsolation_Questionnaires(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	const qid = "11111111-1111-4111-8111-111111111111"
	qs := `[{"id":"q1","type":"short_text","text":"Why?","required":true}]`
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.InsertQuestionnaire(qid, &store.QuestionnaireVersion{Title: "Why", Questions: qs, CreatedBy: "admin a"}, storetest.Now); err != nil {
			return err
		}
		ok, err := c.AddQuestionnaireVersion(&store.QuestionnaireVersion{QuestionnaireID: qid, Version: 2, Title: "Why 2", Questions: qs, CreatedBy: "admin a"}, storetest.Now)
		if err != nil || !ok {
			t.Fatalf("second version: %v %v", ok, err)
		}
		// a stale editor (still on version 1) is refused
		if ok, err := c.AddQuestionnaireVersion(&store.QuestionnaireVersion{QuestionnaireID: qid, Version: 2, Title: "x", Questions: qs, CreatedBy: "x"}, storetest.Now); err != nil || ok {
			t.Errorf("stale version accepted: %v %v", ok, err)
		}
		if err := c.ReplaceQuestionnaireAttachments(qid, []store.QuestionnaireAttachment{
			{Kind: store.QTargetPrivileged, TargetID: store.QPrivilegedTarget}, {Kind: store.QTargetReviewCampaign, TargetID: "7"}}); err != nil {
			return err
		}
		return c.PutQuestionnaireAnswer(&store.QuestionnaireAnswer{QuestionnaireID: qid, Version: 2, SubjectKind: store.QSubjectReviewItem,
			SubjectID: "5", Answers: `{"q1":"because"}`, Hash: "h", AnsweredBy: "rev a"}, storetest.Now)
	})
	if err != nil {
		t.Fatal(err)
	}
	inA(t, f, func(c *store.TenantTx) error {
		q, err := c.Questionnaire(qid)
		if err != nil || q.Version != 2 || q.Title != "Why 2" {
			t.Errorf("A's questionnaire: %+v %v", q, err)
		}
		if vs, err := c.QuestionnaireVersions(qid); err != nil || len(vs) != 2 || vs[0].Version != 2 {
			t.Errorf("A's versions: %v %v", vs, err)
		}
		if as, err := c.QuestionnaireAnswersFor(store.QSubjectReviewItem, "5"); err != nil || len(as) != 1 || as[0].Version != 2 {
			t.Errorf("A's answers: %v %v", as, err)
		}
		if as, err := c.QuestionnaireAnswersBetween(storetest.Now.AddDate(-1, 0, 0), storetest.Now.AddDate(1, 0, 0)); err != nil || len(as) != 1 || as[0].Title != "Why 2" {
			t.Errorf("A's answers by period: %v %v", as, err)
		}
		if as, err := c.QuestionnaireAnswersBetween(storetest.Now.AddDate(1, 0, 0), storetest.Now.AddDate(2, 0, 0)); err != nil || len(as) != 0 {
			t.Errorf("answers outside the period: %v %v", as, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.Questionnaire(qid); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's questionnaire: %v", err)
		}
		if _, err := c.QuestionnaireVersion(qid, 1); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's version: %v", err)
		}
		if l, err := c.Questionnaires(); err != nil || len(l) != 0 {
			t.Errorf("B lists A's questionnaires: %v %v", l, err)
		}
		if l, err := c.QuestionnaireAttachments(); err != nil || len(l) != 0 {
			t.Errorf("B lists A's attachments: %v %v", l, err)
		}
		if _, err := c.QuestionnaireAttachmentFor(store.QTargetPrivileged, store.QPrivilegedTarget); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's attachment: %v", err)
		}
		if l, err := c.QuestionnaireAnswersFor(store.QSubjectReviewItem, "5"); err != nil || len(l) != 0 {
			t.Errorf("B reads A's answers: %v %v", l, err)
		}
		if l, err := c.QuestionnaireAnswersBetween(storetest.Now.AddDate(-1, 0, 0), storetest.Now.AddDate(1, 0, 0)); err != nil || len(l) != 0 {
			t.Errorf("B reads A's answers by period: %v %v", l, err)
		}
		if n, err := c.QuestionnaireAnswerCount(qid); err != nil || n != 0 {
			t.Errorf("B counts A's answers: %d %v", n, err)
		}
		if ok, err := c.AddQuestionnaireVersion(&store.QuestionnaireVersion{QuestionnaireID: qid, Version: 3, Title: "B", Questions: qs, CreatedBy: "b"}, storetest.Now); ok || err != nil {
			t.Errorf("B versions A's questionnaire: %v %v", ok, err)
		}
		if ok, err := c.RetireQuestionnaire(qid, "b", storetest.Now); ok || err != nil {
			t.Errorf("B retires A's questionnaire: %v %v", ok, err)
		}
		return nil
	})
	// B cannot attach to, or answer, A's questionnaire
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.ReplaceQuestionnaireAttachments(qid, []store.QuestionnaireAttachment{{Kind: store.QTargetPrivileged, TargetID: "*"}})
	})
	if err == nil {
		t.Error("B attached A's questionnaire")
	}
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.PutQuestionnaireAnswer(&store.QuestionnaireAnswer{QuestionnaireID: qid, Version: 2, SubjectKind: store.QSubjectReviewItem,
			SubjectID: "5", Answers: `{}`, Hash: "h", AnsweredBy: "b"}, storetest.Now)
	})
	if err == nil {
		t.Error("B answered A's questionnaire")
	}
	// the same target and title are free in B: uniqueness is per tenant
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		const bid = "22222222-2222-4222-8222-222222222222"
		if err := c.InsertQuestionnaire(bid, &store.QuestionnaireVersion{Title: "Why 2", Questions: qs, CreatedBy: "admin b"}, storetest.Now); err != nil {
			return err
		}
		return c.ReplaceQuestionnaireAttachments(bid, []store.QuestionnaireAttachment{{Kind: store.QTargetPrivileged, TargetID: "*"}})
	})
	if err != nil {
		t.Errorf("B's own questionnaire: %v", err)
	}
	// within a tenant a target holds one questionnaire
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		const other = "33333333-3333-4333-8333-333333333333"
		if err := c.InsertQuestionnaire(other, &store.QuestionnaireVersion{Title: "Other", Questions: qs, CreatedBy: "a"}, storetest.Now); err != nil {
			return err
		}
		return c.ReplaceQuestionnaireAttachments(other, []store.QuestionnaireAttachment{{Kind: store.QTargetPrivileged, TargetID: "*"}})
	})
	if err == nil {
		t.Error("a target took two questionnaires")
	}
}

// questionnairesCovered lists the methods TestIsolation_Questionnaires exercises.
func questionnairesCovered() map[string]bool {
	return map[string]bool{"Questionnaires": true, "Questionnaire": true, "InsertQuestionnaire": true, "AddQuestionnaireVersion": true,
		"RetireQuestionnaire": true, "QuestionnaireVersion": true, "QuestionnaireVersions": true, "QuestionnaireAttachments": true,
		"QuestionnaireAttachmentFor": true, "ReplaceQuestionnaireAttachments": true, "PutQuestionnaireAnswer": true,
		"QuestionnaireAnswersFor": true, "QuestionnaireAnswerCount": true, "QuestionnaireAnswersBetween": true}
}
