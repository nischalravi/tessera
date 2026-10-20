package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Alerting (issue #168):
//
//	GET  /api/alerts?status=&severity=&rule=          alerts, newest activity first
//	GET  /api/alerts/summary                          live counts by status and severity (the bell)
//	GET  /api/alerts/rules                            built-in rules with the tenant's settings
//	PUT  /api/alerts/rules/{rule_id}                  change a rule's settings
//	GET  /api/alerts/channels                         delivery channels (targets redacted)
//	POST /api/alerts/channels                         add a channel (webhooks: the secret is shown once)
//	PUT  /api/alerts/channels/{channel_id}            change a channel
//	POST /api/alerts/channels/{channel_id}/test       send a test message now
//	GET  /api/alerts/{alert_id}                       one alert with its deliveries
//	POST /api/alerts/{alert_id}/acknowledge|resolve|assign

func (s *Server) registerAlertRoutes() {
	readA, manage := need(auth.PermAlertsRead), need(auth.PermAlertsManage)
	configure := need(auth.PermAlertsConfigure)
	configureStepUp := needStepUp(auth.PermAlertsConfigure, auth.StepUpPolicy)
	// literal paths first: the first matching route wins
	s.handle(http.MethodGet, "/api/alerts", read, readA, s.listAlerts)
	s.handle(http.MethodGet, "/api/alerts/summary", read, readA, s.alertSummary)
	s.handle(http.MethodGet, "/api/alerts/rules", read, readA, s.listAlertRules)
	s.handle(http.MethodPut, "/api/alerts/rules/{rule_id}", write, configure, s.putAlertRule)
	s.handle(http.MethodGet, "/api/alerts/channels", read, configure, s.listAlertChannels)
	s.handle(http.MethodPost, "/api/alerts/channels", write, configureStepUp, s.createAlertChannel)
	s.handle(http.MethodPut, "/api/alerts/channels/{channel_id}", write, configureStepUp, s.updateAlertChannel)
	s.handle(http.MethodPost, "/api/alerts/channels/{channel_id}/test", phased, configure, s.rd(s.testAlertChannel))
	s.handle(http.MethodGet, "/api/alerts/{alert_id}", read, readA, s.getAlert)
	s.handle(http.MethodPost, "/api/alerts/{alert_id}/acknowledge", write, manage, s.alertAction("acknowledge"))
	s.handle(http.MethodPost, "/api/alerts/{alert_id}/resolve", write, manage, s.alertAction("resolve"))
	s.handle(http.MethodPost, "/api/alerts/{alert_id}/assign", write, manage, s.alertAction("assign"))
}

func alertErr(err error) error {
	var ae *alerts.Error
	if errors.As(err, &ae) {
		return &readiness.Error{Status: ae.Status, Code: ae.Code, Msg: ae.Msg}
	}
	return err
}

// alertActor is the signed-in user; alerts record who handled them, so API
// clients without a user cannot triage.
func alertActor(r *http.Request) (alerts.Actor, error) {
	pr := principal(r)
	if pr.UserID == nil {
		return alerts.Actor{}, &readiness.Error{Status: http.StatusForbidden, Code: "user_required",
			Msg: "only a signed-in user can do this"}
	}
	return alerts.Actor{UserID: pr.UserID.String(), Display: pr.Display}, nil
}

type alertUserRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type deliveryView struct {
	ID            string     `json:"id"`
	Channel       string     `json:"channel"`
	ChannelKind   string     `json:"channel_kind"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	NextAttemptAt *time.Time `json:"next_attempt_at"`
	LastError     *string    `json:"last_error"`
	SentAt        *time.Time `json:"sent_at"`
}

type alertView struct {
	ID             string          `json:"id"`
	Rule           string          `json:"rule"`
	RuleName       string          `json:"rule_name"`
	Key            string          `json:"key"`
	Severity       string          `json:"severity"`
	Title          string          `json:"title"`
	Detail         json.RawMessage `json:"detail"`
	Status         string          `json:"status"`
	Count          int             `json:"count"`
	FirstSeenAt    time.Time       `json:"first_seen_at"`
	LastSeenAt     time.Time       `json:"last_seen_at"`
	Assignee       *alertUserRef   `json:"assignee"`
	AcknowledgedBy *alertUserRef   `json:"acknowledged_by"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at"`
	ResolvedBy     *alertUserRef   `json:"resolved_by"`
	ResolvedAt     *time.Time      `json:"resolved_at"`
	Resolution     *string         `json:"resolution"`
	Deliveries     *[]deliveryView `json:"deliveries,omitempty"`
}

type alertUserNames struct {
	tx    *store.TenantTx
	cache map[string]*alertUserRef
}

func (u *alertUserNames) ref(id *string) (*alertUserRef, error) {
	if id == nil {
		return nil, nil
	}
	if v, ok := u.cache[*id]; ok {
		return v, nil
	}
	uid, err := uuid.Parse(*id)
	if err != nil {
		return &alertUserRef{ID: *id, Name: *id}, nil
	}
	pu, err := u.tx.PlatformUser(uid)
	if errors.Is(err, store.ErrNotFound) {
		return &alertUserRef{ID: *id, Name: "unknown user"}, nil
	} else if err != nil {
		return nil, err
	}
	v := &alertUserRef{ID: *id, Name: pu.DisplayName}
	u.cache[*id] = v
	return v, nil
}

func (u *alertUserNames) view(a *store.Alert) (alertView, error) {
	v := alertView{ID: a.ID, Rule: a.RuleID, Key: a.DedupKey, Severity: a.Severity, Title: a.Title, Detail: json.RawMessage(a.Detail),
		Status: a.Status, Count: a.Count, FirstSeenAt: a.FirstSeenAt, LastSeenAt: a.LastSeenAt, AcknowledgedAt: a.AcknowledgedAt,
		ResolvedAt: a.ResolvedAt, Resolution: a.Resolution}
	if r := alerts.RuleByID(a.RuleID); r != nil {
		v.RuleName = r.Name
	}
	if len(v.Detail) == 0 {
		v.Detail = json.RawMessage("{}")
	}
	var err error
	if v.Assignee, err = u.ref(a.AssigneeUserID); err != nil {
		return v, err
	}
	if v.AcknowledgedBy, err = u.ref(a.AcknowledgedBy); err != nil {
		return v, err
	}
	v.ResolvedBy, err = u.ref(a.ResolvedBy)
	return v, err
}

func (s *Server) listAlerts(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	f := store.AlertFilter{}
	if v := p.queryOptLiteral("status", []string{"open", "acknowledged", "resolved", "live"}); v != nil {
		f.Status = *v
	}
	if v := p.queryOptLiteral("severity", alerts.Severities); v != nil {
		f.Severity = *v
	}
	if v := p.queryOptStr("rule"); v != nil {
		f.RuleID = *v
	}
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	as, err := tx.Alerts(f)
	if err != nil {
		return nil, err
	}
	u := &alertUserNames{tx, map[string]*alertUserRef{}}
	out := make([]alertView, 0, len(as))
	for _, a := range as {
		v, err := u.view(a)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) alertSummary(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	counts, err := store.TxFrom(r.Context()).AlertCounts()
	if err != nil {
		return nil, err
	}
	out := map[string]any{"open": 0, "acknowledged": 0, "by_severity": map[string]int{}}
	bySev := map[string]int{}
	for st, m := range counts {
		n := 0
		for sev, c := range m {
			n += c
			bySev[sev] += c
		}
		out[st] = n
	}
	out["by_severity"] = bySev
	return out, nil
}

func (s *Server) getAlert(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	tx := store.TxFrom(r.Context())
	a, err := tx.Alert(p.path["alert_id"])
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "alert_not_found", Msg: "alert not found"}
	} else if err != nil {
		return nil, err
	}
	v, err := (&alertUserNames{tx, map[string]*alertUserRef{}}).view(a)
	if err != nil {
		return nil, err
	}
	ds, err := tx.AlertDeliveries(a.ID)
	if err != nil {
		return nil, err
	}
	dv := make([]deliveryView, 0, len(ds))
	for _, d := range ds {
		x := deliveryView{ID: d.ID, Status: d.Status, Attempts: d.Attempts, LastError: d.LastError, SentAt: d.SentAt}
		if d.Status == "pending" {
			next := d.NextAttemptAt
			x.NextAttemptAt = &next
		}
		if c, err := tx.AlertChannel(d.ChannelID); err == nil {
			x.Channel, x.ChannelKind = c.Name, c.Kind
		}
		dv = append(dv, x)
	}
	v.Deliveries = &dv
	return v, nil
}

func (s *Server) alertAction(kind string) handlerFunc {
	return func(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
		by, err := alertActor(r)
		if err != nil {
			return nil, err
		}
		var body struct {
			Note           string  `json:"note"`
			AssigneeUserID *string `json:"assignee_user_id"`
		}
		if err := decodeBody(r, &body, true); err != nil {
			return nil, err
		}
		tx, now, id := store.TxFrom(r.Context()), s.clock().UTC(), p.path["alert_id"]
		var a *store.Alert
		switch kind {
		case "acknowledge":
			a, err = alerts.Acknowledge(tx, id, by, now)
		case "resolve":
			a, err = alerts.Resolve(tx, id, body.Note, by, now)
		default:
			a, err = alerts.Assign(tx, id, body.AssigneeUserID, by, now)
		}
		if err != nil {
			return nil, alertErr(err)
		}
		return (&alertUserNames{tx, map[string]*alertUserRef{}}).view(a)
	}
}

type alertRuleView struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Kind          string     `json:"kind"`
	Enabled       bool       `json:"enabled"`
	Severity      string     `json:"severity"`
	Threshold     int        `json:"threshold"`
	WindowMinutes int        `json:"window_minutes"`
	Customized    bool       `json:"customized"`
	UpdatedAt     *time.Time `json:"updated_at"`
	Live          int        `json:"live"`
}

func (s *Server) listAlertRules(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	rules, err := alerts.EffectiveRules(tx)
	if err != nil {
		return nil, err
	}
	out := make([]alertRuleView, 0, len(rules))
	for _, e := range rules {
		v := alertRuleView{ID: e.ID, Name: e.Name, Description: e.Description, Kind: e.Kind, Enabled: e.Enabled, Severity: e.Severity,
			Threshold: e.Threshold, WindowMinutes: int(e.Window.Minutes()), Customized: e.Setting != nil}
		if e.Setting != nil {
			at := e.Setting.UpdatedAt
			v.UpdatedAt = &at
		}
		live, err := tx.LiveAlertsOfRule(e.ID)
		if err != nil {
			return nil, err
		}
		v.Live = len(live)
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) putAlertRule(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	by, err := alertActor(r)
	if err != nil {
		return nil, err
	}
	var b struct {
		Enabled       bool   `json:"enabled"`
		Severity      string `json:"severity"`
		Threshold     int    `json:"threshold"`
		WindowMinutes int    `json:"window_minutes"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	if err := alerts.SetRule(tx, p.path["rule_id"], alerts.RuleSpec{Enabled: b.Enabled, Severity: b.Severity, Threshold: b.Threshold,
		WindowMinutes: b.WindowMinutes}, by, s.clock().UTC()); err != nil {
		return nil, alertErr(err)
	}
	return s.listAlertRules(nil, r, p)
}

type channelView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Target      string    `json:"target"` // webhook URLs are redacted
	MinSeverity string    `json:"min_severity"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	// Secret is the webhook signing secret, only in the response that created or rotated it.
	Secret string `json:"secret,omitempty"`
}

// redactTarget keeps a webhook's scheme and host and the last 4 characters
// of its path: Slack and Teams URLs carry their token in the path.
func redactTarget(c *store.AlertChannel) string {
	if c.Kind != "webhook" {
		return c.Target
	}
	return safehttp.RedactURL(c.Target) // scheme://host[:port]/… (#333)
}

func channelViewOf(c *store.AlertChannel, secret string) channelView {
	return channelView{ID: c.ID, Name: c.Name, Kind: c.Kind, Target: redactTarget(c), MinSeverity: c.MinSeverity, Enabled: c.Enabled,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, Secret: secret}
}

func (s *Server) listAlertChannels(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	cs, err := store.TxFrom(r.Context()).AlertChannels()
	if err != nil {
		return nil, err
	}
	out := make([]channelView, 0, len(cs))
	for _, c := range cs {
		out = append(out, channelViewOf(c, ""))
	}
	return out, nil
}

type channelBody struct {
	Name         string  `json:"name"`
	Kind         string  `json:"kind"`
	Target       *string `json:"target"` // omitted on update: keep the current one
	MinSeverity  string  `json:"min_severity"`
	Enabled      *bool   `json:"enabled"`
	RotateSecret bool    `json:"rotate_secret"`
}

func (b channelBody) spec(current *store.AlertChannel) alerts.ChannelSpec {
	s := alerts.ChannelSpec{Name: b.Name, Kind: b.Kind, MinSeverity: b.MinSeverity, Enabled: b.Enabled == nil || *b.Enabled,
		RotateSecret: b.RotateSecret}
	if b.Target != nil {
		s.Target = *b.Target
	} else if current != nil {
		s.Target = current.Target
	}
	if s.MinSeverity == "" {
		s.MinSeverity = "high"
		if current != nil {
			s.MinSeverity = current.MinSeverity
		}
	}
	return s
}

func (s *Server) createAlertChannel(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	by, err := alertActor(r)
	if err != nil {
		return nil, err
	}
	var b channelBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	c, secret, err := alerts.CreateChannel(tx, s.alertSealer(), b.spec(nil), s.cfg.Env == config.Dev, by, s.clock().UTC())
	if err != nil {
		return nil, alertErr(err)
	}
	return statusBody{http.StatusCreated, channelViewOf(c, secret)}, nil
}

func (s *Server) updateAlertChannel(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	by, err := alertActor(r)
	if err != nil {
		return nil, err
	}
	var b channelBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	cur, err := tx.AlertChannel(p.path["channel_id"])
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "channel_not_found", Msg: "channel not found"}
	} else if err != nil {
		return nil, err
	}
	c, secret, err := alerts.UpdateChannel(tx, s.alertSealer(), cur.ID, b.spec(cur), s.cfg.Env == config.Dev, by, s.clock().UTC())
	if err != nil {
		return nil, alertErr(err)
	}
	return channelViewOf(c, secret), nil
}

// testAlertChannel sends a test message outside any transaction, then
// records the result.
func (s *Server) testAlertChannel(r *http.Request, p *params) (int, any, error) {
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return 0, nil, err
	}
	svc := s.cfg.Alerts
	if svc == nil {
		return 0, nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "alerts_unavailable", Msg: "alert delivery is not configured"}
	}
	var c *store.AlertChannel
	if err := p.scope.Read(r.Context(), func(tx *store.TenantTx) error {
		var err error
		c, err = tx.AlertChannel(p.path["channel_id"])
		return err
	}); errors.Is(err, store.ErrNotFound) {
		return 0, nil, &readiness.Error{Status: http.StatusNotFound, Code: "channel_not_found", Msg: "channel not found"}
	} else if err != nil {
		return 0, nil, err
	}
	slug := p.scope.Tenant.String()
	if ts, err := s.store.ActiveTenants(r.Context()); err == nil {
		for _, t := range ts {
			if t.ID == p.scope.Tenant {
				slug = t.Slug
			}
		}
	}
	sendErr := svc.TestChannel(r.Context(), p.scope.Tenant, slug, c)
	result := map[string]any{"ok": sendErr == nil}
	if sendErr != nil {
		result["error"] = sendErr.Error()
	}
	now := s.clock().UTC()
	err := p.scope.Write(r.Context(), func(tx *store.TenantTx) error {
		det := ojson.Object{{Key: "channel_id", Value: c.ID}, {Key: "channel", Value: c.Name}, {Key: "ok", Value: sendErr == nil}}
		if sendErr != nil {
			det = append(det, ojson.KV{Key: "error", Value: sendErr.Error()})
		}
		return tx.Audit(now, principal(r).Display, "alert.channel.tested", det)
	})
	return http.StatusOK, result, err
}

func (s *Server) alertSealer() *seal.Sealer {
	if s.cfg.Alerts == nil {
		return nil
	}
	return s.cfg.Alerts.Sealer
}
