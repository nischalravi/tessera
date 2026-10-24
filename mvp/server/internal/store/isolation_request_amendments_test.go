package store_test

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Comments and attachment metadata on a request line (schema/0911, issue #588) belong to the line's
// tenant: another tenant's handle sees none, and the rows cannot be changed or deleted.
func TestIsolation_RequestAmendments(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := seedReqRows(t, f.DB, f.A, "a")
	b := seedReqRows(t, f.DB, f.B, "b")
	uid := a.user.ID.String()
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertRequestComment(&store.RequestComment{ID: "c-a", LineID: a.line, AuthorUserID: uid, Author: "r", Body: "hello", CreatedAt: storetest.Now}); err != nil {
			t.Fatal(err)
		}
		if err := c.InsertRequestAttachment(&store.RequestAttachment{ID: "at-a", LineID: a.line, Name: "n.pdf", SizeBytes: 10, AddedBy: uid,
			AddedByName: "r", CreatedAt: storetest.Now}); err != nil {
			t.Fatal(err)
		}
		if cs, err := c.RequestComments(a.line); err != nil || len(cs) != 1 || cs[0].Body != "hello" {
			t.Errorf("A's comments: %v %v", cs, err)
		}
		if as, err := c.RequestAttachments(a.line); err != nil || len(as) != 1 || as[0].SizeBytes != 10 {
			t.Errorf("A's attachments: %v %v", as, err)
		}
		if n, err := c.RequestCommentCount(a.line); err != nil || n != 1 {
			t.Errorf("A's comment count: %d %v", n, err)
		}
		if n, err := c.RequestAttachmentCount(a.line); err != nil || n != 1 {
			t.Errorf("A's attachment count: %d %v", n, err)
		}
		// the size cap is in the schema too
		if err := c.InsertRequestAttachment(&store.RequestAttachment{ID: "at-big", LineID: a.line, Name: "big", SizeBytes: 10<<20 + 1, AddedBy: uid,
			AddedByName: "r", CreatedAt: storetest.Now}); err == nil {
			t.Error("an oversize attachment was stored")
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if cs, err := c.RequestComments(a.line); err != nil || len(cs) != 0 {
			t.Errorf("B reads A's comments: %v %v", cs, err)
		}
		if as, err := c.RequestAttachments(a.line); err != nil || len(as) != 0 {
			t.Errorf("B reads A's attachments: %v %v", as, err)
		}
		if n, err := c.RequestCommentCount(a.line); err != nil || n != 0 {
			t.Errorf("B counts A's comments: %d %v", n, err)
		}
		if n, err := c.RequestAttachmentCount(a.line); err != nil || n != 0 {
			t.Errorf("B counts A's attachments: %d %v", n, err)
		}
		// B cannot attach to A's line, nor use A's user
		if err := c.InsertRequestComment(&store.RequestComment{ID: "c-x", LineID: a.line, AuthorUserID: b.user.ID.String(), Author: "b", Body: "x", CreatedAt: storetest.Now}); err == nil {
			t.Error("B commented on A's line")
		}
		if err := c.InsertRequestComment(&store.RequestComment{ID: "c-y", LineID: b.line, AuthorUserID: uid, Author: "b", Body: "x", CreatedAt: storetest.Now}); err == nil {
			t.Error("B's comment names A's user")
		}
		if err := c.InsertRequestAttachment(&store.RequestAttachment{ID: "at-x", LineID: a.line, Name: "x", AddedBy: b.user.ID.String(), AddedByName: "b",
			CreatedAt: storetest.Now}); err == nil {
			t.Error("B attached to A's line")
		}
		return nil
	})
}

// requestAmendmentsCovered lists the methods TestIsolation_RequestAmendments exercises.
func requestAmendmentsCovered() map[string]bool {
	return map[string]bool{"InsertRequestComment": true, "RequestComments": true, "RequestCommentCount": true,
		"InsertRequestAttachment": true, "RequestAttachments": true, "RequestAttachmentCount": true}
}
