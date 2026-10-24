package api

import (
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Amending a live request (issue #588), for the people involved in a pending line:
//
//	GET  /api/requests/{request_id}/comments      {comments}
//	POST /api/requests/{request_id}/comments      {body}
//	GET  /api/requests/{request_id}/attachments   {attachments, max_bytes}
//	POST /api/requests/{request_id}/attachments   {name, content_type, size_bytes, reference}: metadata only
//	POST /api/requests/{request_id}/approvers     {identity_id, reason}: appends a stage (approvers and deciders)
//
// Approving or denying is already per line (each line is one beneficiary and one item; a batch is
// several lines). Who may read a line may read its comments and attachments.

func (s *Server) registerAmendRoutes(create Route) {
	const G, P = http.MethodGet, http.MethodPost
	s.handle(G, "/api/requests/{request_id}/comments", read, create, s.listRequestComments)
	s.handle(P, "/api/requests/{request_id}/comments", write, create, s.addRequestComment)
	s.handle(G, "/api/requests/{request_id}/attachments", read, create, s.listRequestAttachments)
	s.handle(P, "/api/requests/{request_id}/attachments", write, create, s.addRequestAttachment)
	s.handle(P, "/api/requests/{request_id}/approvers", write, create, s.addRequestApprover)
}

type commentView struct {
	ID        string `json:"id"`
	Author    string `json:"author"`
	Body      string `json:"body"`
	CreatedAt string `json:"created_at"`
}

func commentOf(c *store.RequestComment) commentView {
	return commentView{c.ID, c.Author, c.Body, c.CreatedAt.UTC().Format(time.RFC3339)}
}

type attachmentView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
	Reference   string `json:"reference"`
	AddedBy     string `json:"added_by"`
	CreatedAt   string `json:"created_at"`
}

func attachmentOf(a *store.RequestAttachment) attachmentView {
	return attachmentView{a.ID, a.Name, a.ContentType, a.SizeBytes, a.Reference, a.AddedByName, a.CreatedAt.UTC().Format(time.RFC3339)}
}

func (s *Server) listRequestComments(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	l, _, err := s.line(r, p)
	if err != nil {
		return nil, err
	}
	cs, err := store.TxFrom(r.Context()).RequestComments(l.ID)
	if err != nil {
		return nil, err
	}
	out := make([]commentView, 0, len(cs))
	for _, c := range cs {
		out = append(out, commentOf(c))
	}
	return map[string]any{"comments": out}, nil
}

func (s *Server) addRequestComment(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	l, me, err := s.line(r, p)
	if err != nil {
		return nil, err
	}
	var b struct {
		Body string `json:"body"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	c, err := requests.AddComment(store.TxFrom(r.Context()), l.ID, me, b.Body, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return statusBody{http.StatusCreated, commentOf(c)}, nil
}

func (s *Server) listRequestAttachments(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	l, _, err := s.line(r, p)
	if err != nil {
		return nil, err
	}
	as, err := store.TxFrom(r.Context()).RequestAttachments(l.ID)
	if err != nil {
		return nil, err
	}
	out := make([]attachmentView, 0, len(as))
	for _, a := range as {
		out = append(out, attachmentOf(a))
	}
	return map[string]any{"attachments": out, "max_bytes": requests.MaxAttachmentBytes}, nil
}

func (s *Server) addRequestAttachment(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	l, me, err := s.line(r, p)
	if err != nil {
		return nil, err
	}
	var b struct {
		Name        string `json:"name"`
		ContentType string `json:"content_type"`
		SizeBytes   int64  `json:"size_bytes"`
		Reference   string `json:"reference"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	a, err := requests.AddAttachment(store.TxFrom(r.Context()), l.ID, me,
		requests.AttachmentSpec{Name: b.Name, ContentType: b.ContentType, SizeBytes: b.SizeBytes, Reference: b.Reference}, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return statusBody{http.StatusCreated, attachmentOf(a)}, nil
}

func (s *Server) addRequestApprover(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	l, me, err := s.line(r, p)
	if err != nil {
		return nil, err
	}
	var b struct {
		IdentityID int64  `json:"identity_id"`
		Reason     string `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	out, err := requests.AddApprover(tx, l.ID, me, b.IdentityID, b.Reason, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return s.lineView(r, newViewer(tx), out, me, true)
}
