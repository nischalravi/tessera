package api

import (
	"errors"
	"io"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Notification and email administration (Admin > Notifications and Email delivery):
//
//	GET|PUT|DELETE /api/admin/mail-relay          the tenant's own SMTP relay (password write-only, sealed)
//	POST           /api/admin/mail-relay/test     one test message to the signed-in admin, through the saved relay
//	GET|PUT|DELETE /api/admin/chat                the Slack or Teams incoming webhook (URL write-only, sealed)
//	POST           /api/admin/chat/test           one test message through the saved webhook
//	GET|PUT        /api/admin/notification-policy reminder cadence and escalation timings
//	GET            /api/admin/notification-templates          the wording of each kind, with the placeholders
//	PUT|DELETE     /api/admin/notification-templates/{kind}   save or reset one kind
//	GET|POST       /api/email/suppressions        addresses email is not sent to; add one
//	DELETE         /api/email/suppressions/{address}          lift one
//	POST           /api/email/dsn                 a delivery status report (RFC 3464) from the relay
//
// Reading needs email.read; every change needs email.manage, and saving the relay, the webhook, the timings or a template
// also needs a fresh phishing-resistant sign-in. Every change is audited in the same transaction, without any secret.
// A version in the body (0 when nothing is saved) makes a save a compare-and-set: a stale one is 409 version_conflict.

func (s *Server) registerNotifyAdminRoutes() {
	read_ := need(auth.PermEmailRead)
	change := needStepUp(auth.PermEmailManage, auth.StepUpPolicy)
	ops := need(auth.PermEmailManage)
	s.handle(http.MethodGet, "/api/admin/mail-relay", read, read_, s.getRelay)
	s.handle(http.MethodPut, "/api/admin/mail-relay", write, change, s.putRelay)
	s.handle(http.MethodDelete, "/api/admin/mail-relay", write, change, s.deleteRelay)
	s.handle(http.MethodPost, "/api/admin/mail-relay/test", write, change, s.testRelay)
	s.handle(http.MethodGet, "/api/admin/chat", read, read_, s.getChat)
	s.handle(http.MethodPut, "/api/admin/chat", write, change, s.putChat)
	s.handle(http.MethodDelete, "/api/admin/chat", write, change, s.deleteChat)
	s.handle(http.MethodPost, "/api/admin/chat/test", write, change, s.testChat)
	s.handle(http.MethodGet, "/api/admin/notification-policy", read, read_, s.getNotifyPolicy)
	s.handle(http.MethodPut, "/api/admin/notification-policy", write, change, s.putNotifyPolicy)
	s.handle(http.MethodGet, "/api/admin/notification-templates", read, read_, s.getTemplates)
	s.handle(http.MethodPut, "/api/admin/notification-templates/{kind}", write, change, s.putTemplate)
	s.handle(http.MethodDelete, "/api/admin/notification-templates/{kind}", write, change, s.deleteTemplate)
	s.handle(http.MethodGet, "/api/email/suppressions", read, read_, s.listSuppressions)
	s.handle(http.MethodPost, "/api/email/suppressions", write, ops, s.addSuppression)
	s.handle(http.MethodDelete, "/api/email/suppressions/{address}", write, ops, s.liftSuppression)
	s.handle(http.MethodPost, "/api/email/dsn", write, Route{Perm: auth.PermEmailDSN, BodyType: "multipart/report",
		BodyTypes: []string{"message/delivery-status", "message/rfc822"}}, s.postDSN)
}

// adminErr turns the errors of the notification settings into API errors.
func adminErr(err error) error { return notifyErr(cfgErr(err)) }

func (s *Server) relayEnv() notify.RelayEnv {
	return notify.RelayEnv{Env: s.cfg.Env, AllowLoopback: s.cfg.Env == config.Dev, Sealer: s.cfg.Sealer}
}

func (s *Server) chatEnv() notify.ChatEnv {
	return notify.ChatEnv{Sealer: s.cfg.Sealer, AnyHost: s.cfg.Env == config.Dev}
}

func (s *Server) chatHTTP() *http.Client {
	if s.cfg.OutboundHTTP != nil {
		return s.cfg.OutboundHTTP
	}
	return s.cfg.Outbound
}

// ---- relay

type relayView struct {
	notify.RelayState
	CanManage bool `json:"can_manage"`
	// Server says whether the server has a relay of its own: it sends when the tenant's is off.
	Server string `json:"server_relay"`
}

func (s *Server) relayView(r *http.Request) (relayView, error) {
	st, err := notify.LoadRelay(store.TxFrom(r.Context()))
	if err != nil {
		return relayView{}, err
	}
	return relayView{RelayState: st, CanManage: s.can(r, auth.PermEmailManage), Server: s.cfg.EmailMode}, nil
}

func (s *Server) getRelay(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	return s.relayView(r)
}

type putRelayBody struct {
	Version int `json:"version"`
	notify.RelaySpec
}

func (s *Server) putRelay(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b putRelayBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if err := notify.SaveRelay(r.Context(), store.TxFrom(r.Context()), s.relayEnv(), b.RelaySpec, b.Version, principal(r).Display, s.clock().UTC()); err != nil {
		return nil, adminErr(err)
	}
	return s.relayView(r)
}

type versionBody struct {
	Version int `json:"version"`
}

func (s *Server) deleteRelay(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b versionBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if err := notify.DeleteRelay(store.TxFrom(r.Context()), b.Version, principal(r).Display, s.clock().UTC()); err != nil {
		return nil, adminErr(err)
	}
	return s.relayView(r)
}

// testRelay sends one message to the signed-in admin's own address, never to one named in the request.
func (s *Server) testRelay(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	pr, err := userPrincipal(r)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	u, err := tx.PlatformUser(*pr.UserID)
	if err != nil {
		return nil, err
	}
	if u.Email == nil || *u.Email == "" {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "no_address", Msg: "your account has no email address to send the test to"}
	}
	att, err := notify.TestRelay(r.Context(), tx, s.relayEnv(), *u.Email, pr.Display, s.clock().UTC())
	if err != nil {
		return nil, adminErr(err)
	}
	return map[string]any{"outcome": att.Outcome, "error": att.Error, "queue_id": att.QueueID, "steps": att.Steps, "tls": att.TLS, "banner": att.Banner}, nil
}

// ---- chat

type chatView struct {
	notify.ChatState
	CanManage bool              `json:"can_manage"`
	Providers []string          `json:"providers"`
	Kinds     []kindView        `json:"available_kinds"`
	Hosts     map[string]string `json:"hosts"`
}

type kindView struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

func allKinds() []kindView {
	out := make([]kindView, 0, len(notify.Kinds))
	for _, k := range notify.Kinds {
		out = append(out, kindView{k.ID, k.Label, k.Description})
	}
	return out
}

func (s *Server) chatView(r *http.Request) (chatView, error) {
	st, err := notify.LoadChat(store.TxFrom(r.Context()))
	if err != nil {
		return chatView{}, err
	}
	return chatView{ChatState: st, CanManage: s.can(r, auth.PermEmailManage), Providers: notify.Providers, Kinds: allKinds(),
		Hosts: map[string]string{"slack": "hooks.slack.com", "teams": "*.webhook.office.com or *.logic.azure.com"}}, nil
}

func (s *Server) getChat(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	return s.chatView(r)
}

type putChatBody struct {
	Version int `json:"version"`
	notify.ChatSpec
}

func (s *Server) putChat(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b putChatBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if err := notify.SaveChat(store.TxFrom(r.Context()), s.chatEnv(), b.ChatSpec, b.Version, principal(r).Display, s.clock().UTC()); err != nil {
		return nil, adminErr(err)
	}
	return s.chatView(r)
}

func (s *Server) deleteChat(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b versionBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if err := notify.DeleteChat(store.TxFrom(r.Context()), b.Version, principal(r).Display, s.clock().UTC()); err != nil {
		return nil, adminErr(err)
	}
	return s.chatView(r)
}

func (s *Server) testChat(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	product, err := tx.BrandName()
	if err != nil {
		return nil, err
	}
	if product == "" {
		product = "Tessera"
	}
	if err := notify.TestChat(r.Context(), tx, s.chatEnv(), s.chatHTTP(), product, principal(r).Display, s.clock().UTC()); err != nil {
		return nil, adminErr(err)
	}
	return map[string]any{"ok": true}, nil
}

// ---- policy

type notifyPolicyView struct {
	notify.Policy
	Version   int           `json:"version"`
	CanManage bool          `json:"can_manage"`
	Defaults  notify.Policy `json:"defaults"`
}

func (s *Server) notifyPolicyOf(r *http.Request) (notifyPolicyView, error) {
	p, ver, err := notify.LoadPolicy(store.TxFrom(r.Context()))
	if err != nil {
		return notifyPolicyView{}, err
	}
	return notifyPolicyView{Policy: p, Version: ver, CanManage: s.can(r, auth.PermEmailManage), Defaults: notify.DefaultPolicy()}, nil
}

func (s *Server) getNotifyPolicy(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	return s.notifyPolicyOf(r)
}

type putPolicyBody struct {
	Version int `json:"version"`
	notify.Policy
}

func (s *Server) putNotifyPolicy(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b putPolicyBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if _, _, err := notify.SavePolicy(store.TxFrom(r.Context()), b.Policy, b.Version, principal(r).Display, s.clock().UTC()); err != nil {
		return nil, adminErr(err)
	}
	return s.notifyPolicyOf(r)
}

// ---- templates

type templateView struct {
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Customized  bool   `json:"customized"`
	Subject     string `json:"subject_tpl"`
	Body        string `json:"body_tpl"`
	UpdatedBy   string `json:"updated_by,omitempty"`
}

type templatesView struct {
	Templates  []templateView       `json:"templates"`
	Vars       []notify.TemplateVar `json:"variables"`
	CanManage  bool                 `json:"can_manage"`
	MaxSubject int                  `json:"max_subject"`
	MaxBody    int                  `json:"max_body"`
}

func (s *Server) templatesView(r *http.Request) (templatesView, error) {
	have, err := notify.Templates(store.TxFrom(r.Context()))
	if err != nil {
		return templatesView{}, err
	}
	v := templatesView{Vars: notify.TemplateVars, CanManage: s.can(r, auth.PermEmailManage), MaxSubject: notify.MaxTemplateSubject, MaxBody: notify.MaxTemplateBody,
		Templates: make([]templateView, 0, len(notify.Kinds))}
	for _, k := range notify.Kinds {
		t := templateView{Kind: k.ID, Label: k.Label, Description: k.Description}
		if row, ok := have[k.ID]; ok {
			t.Customized, t.Subject, t.Body, t.UpdatedBy = true, row.Subject, row.Body, row.UpdatedBy
		}
		v.Templates = append(v.Templates, t)
	}
	return v, nil
}

func (s *Server) getTemplates(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	return s.templatesView(r)
}

type putTemplateBody struct {
	Subject string `json:"subject_tpl"`
	Body    string `json:"body_tpl"`
}

func (s *Server) putTemplate(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b putTemplateBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if err := notify.SaveTemplate(store.TxFrom(r.Context()), p.path["kind"], b.Subject, b.Body, principal(r).Display, s.clock().UTC()); err != nil {
		return nil, adminErr(err)
	}
	return s.templatesView(r)
}

func (s *Server) deleteTemplate(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := notify.ResetTemplate(store.TxFrom(r.Context()), p.path["kind"], principal(r).Display, s.clock().UTC()); err != nil {
		return nil, adminErr(err)
	}
	return s.templatesView(r)
}

// ---- suppressions and DSN

type suppressionView struct {
	Address   string `json:"address"`
	Reason    string `json:"reason"`
	Note      string `json:"note"`
	MessageID string `json:"message_id,omitempty"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

func (s *Server) suppressionList(r *http.Request) (map[string]any, error) {
	rows, err := store.TxFrom(r.Context()).EmailSuppressions()
	if err != nil {
		return nil, err
	}
	out := make([]suppressionView, 0, len(rows))
	for _, x := range rows {
		out = append(out, suppressionView{x.Address, x.Reason, x.Note, x.MessageID, x.CreatedBy, x.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")})
	}
	return map[string]any{"suppressions": out, "can_manage": s.can(r, auth.PermEmailManage)}, nil
}

func (s *Server) listSuppressions(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	return s.suppressionList(r)
}

type addSuppressionBody struct {
	Address string `json:"address"`
	Note    string `json:"note"`
}

func (s *Server) addSuppression(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b addSuppressionBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if _, err := notify.Suppress(store.TxFrom(r.Context()), b.Address, store.SuppressManual, b.Note, "", principal(r).Display, s.clock().UTC()); err != nil {
		return nil, adminErr(err)
	}
	return s.suppressionList(r)
}

func (s *Server) liftSuppression(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := notify.Lift(store.TxFrom(r.Context()), p.path["address"], principal(r).Display, s.clock().UTC()); err != nil {
		return nil, adminErr(err)
	}
	return s.suppressionList(r)
}

// postDSN takes a raw delivery status report: the whole multipart/report message the relay sent to the envelope sender, or
// just its message/delivery-status part.
func (s *Server) postDSN(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errBodyTooLarge
		}
		return nil, errBodyUnreadable
	}
	d, err := notify.ParseDSN(raw)
	if err != nil {
		return nil, notifyErr(err)
	}
	res, err := notify.ApplyDSN(store.TxFrom(r.Context()), d, principal(r).Display, s.clock().UTC())
	if err != nil {
		return nil, adminErr(err)
	}
	return map[string]any{"results": res}, nil
}
