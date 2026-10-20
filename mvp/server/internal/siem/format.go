// Package siem streams a tenant's audit ledger to its SIEM (issue #169).
//
// A sink is a destination (RFC 5425 syslog over TLS, or an HTTPS webhook in
// Splunk HEC or plain JSON form) and a format: "json" is the hash-chained
// record that /api/audit/export writes, so the SIEM can recompute each hash
// and check the chain; "ocsf" maps each event to OCSF 1.3 Authentication
// (3002), Account Change (3001) or API Activity (6003), keeping the chain
// fields under unmapped.tessera.
//
// Delivery is at least once and in seq order: each sink has a durable
// cursor (the last seq the destination accepted) that moves only after a
// batch is accepted, so a restart resends from there and never leaves a gap.
// Failures back off; a batch the destination rejects outright (a 4xx other
// than 408 or 429) is dead-lettered after MaxAttempts so one bad event cannot
// stop the stream. Webhooks go out through internal/safehttp; syslog
// collectors get the same address checks before the TLS dial.
package siem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Formats.
const (
	FormatJSON = "json"
	FormatOCSF = "ocsf"
)

// OCSFVersion is the OCSF schema version the mapping follows.
const OCSFVersion = "1.3.0"

// Record is one event ready to send.
type Record struct {
	Seq        int64
	Action     string
	Outcome    string
	OccurredAt time.Time
	Hash       string
	Payload    []byte // one JSON object
}

// Encode renders e in a sink's format. tenant is the tenant's slug.
func Encode(format string, e *store.AuditEvent, tenant string) (Record, error) {
	r := Record{Seq: e.Seq, Action: e.Action, Outcome: e.Outcome, OccurredAt: e.OccurredAt, Hash: e.Hash}
	var err error
	switch format {
	case FormatJSON:
		var obj ojson.Object
		if obj, err = audit.ExportRecord(e); err == nil {
			r.Payload, err = ojson.Marshal(obj)
		}
	case FormatOCSF:
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err = enc.Encode(OCSF(e, tenant)); err == nil {
			r.Payload = bytes.TrimRight(b.Bytes(), "\n")
		}
	default:
		err = fmt.Errorf("siem: unknown format %q", format)
	}
	return r, err
}

// OCSF classes used.
const (
	classAccountChange  = 3001
	classAuthentication = 3002
	classAPIActivity    = 6003
)

var className = map[int]string{classAccountChange: "Account Change", classAuthentication: "Authentication",
	classAPIActivity: "API Activity"}

var categoryOf = map[int][2]any{classAccountChange: {3, "Identity & Access Management"},
	classAuthentication: {3, "Identity & Access Management"}, classAPIActivity: {6, "Application Activity"}}

type activity struct {
	id   int
	name string
}

// classify picks the OCSF class and activity of an action.
func classify(e *store.AuditEvent, d map[string]any) (int, activity) {
	a := e.Action
	switch {
	case a == "auth.login.success", a == "auth.login.failure", a == "auth.break_glass.used":
		return classAuthentication, activity{1, "Logon"}
	case a == "auth.logout", a == "auth.session.revoked", a == "auth.session.expired":
		return classAuthentication, activity{2, "Logoff"}
	case strings.HasPrefix(a, "auth.step_up."), strings.HasPrefix(a, "auth.mfa."):
		return classAuthentication, activity{99, "Other"}
	case a == "auth.user.jit_created":
		return classAccountChange, activity{1, "Create"}
	case a == "admin.user.disabled", a == "admin.users.disable":
		return classAccountChange, activity{5, "Disable"}
	case a == "auth.role.granted", a == "admin.role.granted":
		return classAccountChange, activity{7, "Attach Policy"}
	case a == "auth.role.revoked", a == "admin.role.revoked":
		return classAccountChange, activity{8, "Detach Policy"}
	case a == "admin.change.applied" && strings.HasPrefix(str(d, "kind"), "role.grant"):
		return classAccountChange, activity{7, "Attach Policy"}
	case a == "admin.change.applied" && strings.HasPrefix(str(d, "kind"), "role.revoke"):
		return classAccountChange, activity{8, "Detach Policy"}
	}
	return classAPIActivity, apiActivity(e)
}

// apiActivity is Create, Read, Update or Delete: from the HTTP method for
// http.request, from the action's verb otherwise.
func apiActivity(e *store.AuditEvent) activity {
	if e.Action == "http.request" {
		var h struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(e.HTTP, &h)
		switch h.Method {
		case "GET", "HEAD":
			return activity{2, "Read"}
		case "POST":
			return activity{1, "Create"}
		case "PUT", "PATCH":
			return activity{3, "Update"}
		case "DELETE":
			return activity{4, "Delete"}
		}
		return activity{99, "Other"}
	}
	verb := e.Action[strings.LastIndex(e.Action, ".")+1:]
	switch verb {
	case "create", "created", "request", "requested", "raised", "launch", "launched", "submit", "submitted":
		return activity{1, "Create"}
	case "read", "export", "list", "view":
		return activity{2, "Read"}
	case "update", "updated", "set", "changed", "put", "approve", "approved", "acknowledged", "assigned", "resolved",
		"applied", "activated", "rotated", "tested", "attested", "skipped", "unskipped", "merged", "unmerged":
		return activity{3, "Update"}
	case "delete", "deleted", "revoke", "revoked", "remove", "removed", "deny", "denied", "expire", "expired",
		"retired", "cancel", "cancelled":
		return activity{4, "Delete"}
	}
	return activity{99, "Other"}
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// OCSF maps an audit event to an OCSF 1.3 event object.
func OCSF(e *store.AuditEvent, tenant string) map[string]any {
	var d map[string]any
	_ = json.Unmarshal(e.Detail, &d)
	class, act := classify(e, d)
	cat := categoryOf[class]
	statusID, status := 1, "Success"
	severityID, severity := 1, "Informational"
	switch e.Outcome {
	case store.OutcomeFailure, store.OutcomeDenied:
		statusID, status, severityID, severity = 2, "Failure", 3, "Medium"
	case store.OutcomeError:
		statusID, status, severityID, severity = 2, "Failure", 4, "High"
	}
	if e.Action == "auth.break_glass.used" {
		severityID, severity = 5, "Critical"
	}
	if e.Action == "alert.raised" {
		switch str(d, "severity") {
		case "low":
			severityID, severity = 2, "Low"
		case "medium":
			severityID, severity = 3, "Medium"
		case "high":
			severityID, severity = 4, "High"
		case "critical":
			severityID, severity = 5, "Critical"
		}
	}
	actorUser := map[string]any{"type": e.ActorType}
	if e.ActorID != nil {
		actorUser["uid"] = *e.ActorID
	}
	if e.ActorDisplay != nil {
		actorUser["name"] = *e.ActorDisplay
	}
	actor := map[string]any{"user": actorUser, "app_name": "Tessera"}
	if e.SessionID != nil {
		actor["session"] = map[string]any{"uid": *e.SessionID}
	}
	tessera := map[string]any{"action": e.Action, "outcome": e.Outcome, "seq": e.Seq, "hash": e.Hash, "prev_hash": e.PrevHash,
		"tenant_id": e.TenantID.String()}
	if e.TargetType != nil {
		tessera["target_type"] = *e.TargetType
	}
	if e.TargetID != nil {
		tessera["target_id"] = *e.TargetID
	}
	if e.PolicyVersion != nil {
		tessera["policy_version"] = *e.PolicyVersion
	}
	if len(d) > 0 {
		tessera["detail"] = d
	}
	out := map[string]any{
		"class_uid": class, "class_name": className[class], "category_uid": cat[0], "category_name": cat[1],
		"activity_id": act.id, "activity_name": act.name, "type_uid": class*100 + act.id,
		"type_name": className[class] + ": " + act.name,
		"time":      e.OccurredAt.UnixMilli(), "severity_id": severityID, "severity": severity,
		"status_id": statusID, "status": status, "status_detail": e.Outcome, "message": e.Action,
		"metadata": map[string]any{"version": OCSFVersion, "uid": e.ID.String(), "sequence": e.Seq, "log_name": "tessera.audit",
			"tenant_uid": e.TenantID.String(), "original_time": e.OccurredAt.UTC().Format(time.RFC3339Nano),
			"product": map[string]any{"name": "Tessera", "vendor_name": "Tessera", "feature": map[string]any{"name": "audit"}},
			"labels":  []string{"tenant:" + tenant}},
		"actor":    actor,
		"unmapped": map[string]any{"tessera": tessera},
	}
	if e.IP != nil {
		out["src_endpoint"] = map[string]any{"ip": *e.IP}
	}
	switch class {
	case classAuthentication:
		subject := map[string]any{}
		if v := firstNonEmpty(str(d, "email"), str(d, "subject"), deref(e.ActorDisplay)); v != "" {
			subject["name"] = v
		}
		if e.ActorID != nil && e.ActorType == "user" {
			subject["uid"] = *e.ActorID
		}
		out["user"] = subject
		var authn struct {
			AAL *int `json:"aal"`
		}
		if json.Unmarshal(e.Authn, &authn) == nil && authn.AAL != nil {
			out["is_mfa"] = *authn.AAL >= 2
		}
		if r := str(d, "reason"); r != "" {
			out["status_detail"] = r
		}
	case classAccountChange:
		target := map[string]any{}
		if v := firstNonEmpty(str(d, "user"), str(d, "email"), deref(e.TargetID)); v != "" {
			target["name"] = v
		}
		if e.TargetID != nil {
			target["uid"] = *e.TargetID
		}
		out["user"] = target
		if role := firstNonEmpty(str(d, "role"), str(d, "target_role")); role != "" {
			out["policy"] = map[string]any{"name": role}
		}
	default:
		api := map[string]any{"operation": e.Action, "service": map[string]any{"name": "tessera"}}
		if e.RequestID != nil {
			api["request"] = map[string]any{"uid": *e.RequestID}
		}
		out["api"] = api
		var h struct {
			Method string  `json:"method"`
			Route  *string `json:"route"`
			Status int     `json:"status"`
		}
		if e.Action == "http.request" && json.Unmarshal(e.HTTP, &h) == nil {
			out["http_request"] = map[string]any{"http_method": h.Method, "url": map[string]any{"path": deref(h.Route)}}
			out["http_response"] = map[string]any{"code": h.Status}
		}
	}
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
