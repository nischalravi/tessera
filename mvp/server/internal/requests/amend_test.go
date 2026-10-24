package requests_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Amending a pending request: comments, attachment metadata and an added approver.
func TestAmend_CommentsAttachmentsApprovers(t *testing.T) {
	r := newRouted(t)
	lines, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := lines[0].ID
	do := func(fn func(c *store.TenantTx) error) { r.tx(func(c *store.TenantTx) error { return fn(c) }) }
	var cerr error
	run := func(fn func(c *store.TenantTx) error) error {
		do(func(c *store.TenantTx) error { cerr = fn(c); return nil })
		return cerr
	}

	// comments: the requester and the current approver may; an outsider may not (404)
	for _, who := range []requests.Actor{r.alice, r.carol} {
		if err := run(func(c *store.TenantTx) error { _, err := requests.AddComment(c, id, who, " please hurry ", r.now); return err }); err != nil {
			t.Errorf("%s comments: %v", who.Display, err)
		}
	}
	if err := run(func(c *store.TenantTx) error { _, err := requests.AddComment(c, id, r.zed, "hi", r.now); return err }); code(err) != "request_not_found" {
		t.Errorf("outsider comments: %v", err)
	}
	for name, body := range map[string]string{"empty": "  ", "long": strings.Repeat("x", requests.MaxComment+1)} {
		if err := run(func(c *store.TenantTx) error { _, err := requests.AddComment(c, id, r.alice, body, r.now); return err }); code(err) != "invalid_comment" {
			t.Errorf("%s comment: %v", name, err)
		}
	}
	do(func(c *store.TenantTx) error {
		cs, _ := c.RequestComments(id)
		if len(cs) != 2 || cs[0].Body != "please hurry" {
			t.Errorf("comments = %+v", cs)
		}
		return nil
	})

	// attachments: off by default, then metadata only with a size cap
	spec := requests.AttachmentSpec{Name: "ticket.pdf", ContentType: "application/pdf", SizeBytes: 1234, Reference: "https://tickets.example/1"}
	if err := run(func(c *store.TenantTx) error { _, err := requests.AddAttachment(c, id, r.alice, spec, r.now); return err }); code(err) != "attachments_not_allowed" {
		t.Errorf("attachments off: %v", err)
	}
	do(func(c *store.TenantTx) error {
		s, ver, _ := requests.LoadSettings(c)
		s.AttachmentsAllowed = true
		_, _, err := requests.SaveSettings(c, s, ver, r.pat, r.now)
		return err
	})
	if err := run(func(c *store.TenantTx) error { _, err := requests.AddAttachment(c, id, r.alice, spec, r.now); return err }); err != nil {
		t.Errorf("attach: %v", err)
	}
	big := spec
	big.SizeBytes = requests.MaxAttachmentBytes + 1
	if err := run(func(c *store.TenantTx) error { _, err := requests.AddAttachment(c, id, r.alice, big, r.now); return err }); code(err) != "attachment_too_large" {
		t.Errorf("oversize: %v", err)
	}
	neg := spec
	neg.SizeBytes = -1
	if err := run(func(c *store.TenantTx) error { _, err := requests.AddAttachment(c, id, r.alice, neg, r.now); return err }); code(err) != "attachment_too_large" {
		t.Errorf("negative size: %v", err)
	}
	noName := spec
	noName.Name = ""
	if err := run(func(c *store.TenantTx) error { _, err := requests.AddAttachment(c, id, r.alice, noName, r.now); return err }); code(err) != "invalid_attachment" {
		t.Errorf("no name: %v", err)
	}
	for i := 1; i < requests.MaxLineAttachments; i++ {
		if err := run(func(c *store.TenantTx) error { _, err := requests.AddAttachment(c, id, r.alice, spec, r.now); return err }); err != nil {
			t.Fatalf("attachment %d: %v", i, err)
		}
	}
	if err := run(func(c *store.TenantTx) error { _, err := requests.AddAttachment(c, id, r.alice, spec, r.now); return err }); code(err) != "too_many_attachments" {
		t.Errorf("attachment cap: %v", err)
	}

	// approvers: not the requester, not a duplicate, not the beneficiary; the manager may add zed
	add := func(who requests.Actor, ident int64) error {
		return run(func(c *store.TenantTx) error { _, err := requests.AddApprover(c, id, who, ident, "needs a second look", r.now); return err })
	}
	zedID := *r.zed.IdentityID
	if err := add(r.alice, zedID); code(err) != "self_approval" {
		t.Errorf("requester adds: %v", err)
	}
	if err := add(r.zed, zedID); code(err) != "not_an_approver" {
		t.Errorf("outsider adds: %v", err)
	}
	if err := add(r.carol, r.ids["bob"]); code(err) != "already_an_approver" {
		t.Errorf("duplicate: %v", err)
	}
	if err := add(r.carol, r.ids["alice"]); code(err) != "invalid_approver" {
		t.Errorf("beneficiary: %v", err)
	}
	if err := add(r.carol, 999999); code(err) != "invalid_approver" {
		t.Errorf("unknown: %v", err)
	}
	if err := run(func(c *store.TenantTx) error { _, err := requests.AddApprover(c, id, r.carol, zedID, " ", r.now); return err }); code(err) != "reason_required" {
		t.Errorf("no reason: %v", err)
	}
	if err := add(r.carol, zedID); err != nil {
		t.Fatalf("carol adds zed: %v", err)
	}
	if err := add(r.carol, zedID); code(err) != "already_an_approver" {
		t.Errorf("zed twice: %v", err)
	}

	// the new stage decides last: manager, owner, decider, then zed
	for _, a := range []requests.Actor{r.carol, r.bob, r.pat} {
		if l, err := r.approve(a, id, r.now); err != nil || l.Status != store.RequestPending {
			t.Fatalf("%s approves: %v %v", a.Display, l, err)
		}
	}
	if r.edge("acct:okta:alice", "group:okta:platform") != nil {
		t.Error("granted before the added approver decided")
	}
	if got := r.inbox(r.zed, r.now); len(got) != 1 || got[0] != id {
		t.Fatalf("zed's inbox = %v", got)
	}
	if l, err := r.approve(r.zed, id, r.now); err != nil || l.Status != store.RequestApproved {
		t.Fatalf("zed approves: %v %v", l, err)
	}
	if r.edge("acct:okta:alice", "group:okta:platform") == nil {
		t.Error("no grant after the last stage")
	}
	// a closed line takes no amendment
	if err := run(func(c *store.TenantTx) error { _, err := requests.AddComment(c, id, r.alice, "late", r.now); return err }); code(err) != "not_pending" {
		t.Errorf("comment on an approved line: %v", err)
	}
	if err := add(r.pat, r.ids["bob"]); code(err) != "not_pending" {
		t.Errorf("approver on an approved line: %v", err)
	}
}
