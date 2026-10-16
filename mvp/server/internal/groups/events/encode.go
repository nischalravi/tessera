package events

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"

	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// CloudEventsContentType is the media type of a structured-mode CloudEvents
// 1.0 JSON message.
const CloudEventsContentType = "application/cloudevents+json"

// cloudEvent is a CloudEvents 1.0 event in structured JSON mode
// (https://github.com/cloudevents/spec). "sequence" is the CloudEvents
// sequence extension: the per-tenant gap-free seq, so a receiver can detect a
// missed or reordered message. "tenantid" is a Tessera extension.
type cloudEvent struct {
	SpecVersion     string         `json:"specversion"`
	ID              string         `json:"id"`
	Source          string         `json:"source"`
	Type            string         `json:"type"`
	Subject         string         `json:"subject"`
	Time            string         `json:"time"`
	DataContentType string         `json:"datacontenttype"`
	Sequence        string         `json:"sequence"`
	TenantID        string         `json:"tenantid"`
	Data            cloudEventData `json:"data"`
}

type cloudEventData struct {
	ObjectType  string          `json:"object_type"`
	ObjectID    string          `json:"object_id"`
	IdentityID  *int64          `json:"identity_id,omitempty"`
	MemberGroup string          `json:"member_group_id,omitempty"`
	List        string          `json:"list_id,omitempty"`
	Cause       string          `json:"cause_type"`
	CauseRef    string          `json:"cause_ref,omitempty"`
	Details     json.RawMessage `json:"details"`
}

// ToCloudEvent encodes e as a CloudEvents 1.0 JSON message. The id is
// "<tenant>/<seq>", so a redelivery carries the same id and receivers can
// deduplicate.
func ToCloudEvent(tenant tenancy.ID, e *Event) ([]byte, error) {
	if _, ok := ObjectType(e.Type); !ok {
		return nil, fmt.Errorf("events: unknown type %q", e.Type)
	}
	details := e.Data
	if len(details) == 0 {
		details = json.RawMessage("{}")
	}
	ce := cloudEvent{
		SpecVersion:     "1.0",
		ID:              fmt.Sprintf("%s/%d", tenant, e.Seq),
		Source:          "/tessera/tenants/" + tenant.String() + "/groups",
		Type:            "io.tessera.groups." + e.Type,
		Subject:         e.ObjectID,
		Time:            canon.FormatTime(e.OccurredAt),
		DataContentType: "application/json",
		Sequence:        fmt.Sprint(e.Seq),
		TenantID:        tenant.String(),
		Data: cloudEventData{ObjectType: e.ObjectType, ObjectID: e.ObjectID, IdentityID: e.Identity, MemberGroup: e.MemberGroup,
			List: e.List, Cause: e.CauseType, CauseRef: e.CauseRef, Details: details},
	}
	return json.Marshal(ce)
}

// row is the canonical form of an event: what the daily Merkle digest hashes
// (design §10.2). Every column of grp_events is in it, so changing any of them
// changes the digest.
type row struct {
	Seq         int64           `json:"seq"`
	Type        string          `json:"type"`
	ObjectType  string          `json:"object_type"`
	ObjectID    string          `json:"object_id"`
	IdentityID  *int64          `json:"identity_id"`
	MemberGroup *string         `json:"member_group_id"`
	List        *string         `json:"list_id"`
	Data        json.RawMessage `json:"data"`
	CauseType   string          `json:"cause_type"`
	CauseRef    *string         `json:"cause_ref"`
	AuditSeq    *int64          `json:"audit_seq"`
	OccurredAt  string          `json:"occurred_at"`
}

func nz(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Canonical returns e as RFC 8785 (JCS) canonical JSON: keys sorted, no
// insignificant whitespace, numbers in their shortest form. It is the input of
// the digest's leaf hashes.
func Canonical(e *store.GrpEvent) ([]byte, error) {
	data := e.Data
	if len(data) == 0 {
		data = json.RawMessage("{}")
	}
	raw, err := json.Marshal(row{Seq: e.Seq, Type: e.Type, ObjectType: e.ObjectType, ObjectID: e.ObjectID, IdentityID: e.Identity,
		MemberGroup: nz(e.MemberGroup), List: nz(e.List), Data: data, CauseType: e.CauseType, CauseRef: nz(e.CauseRef),
		AuditSeq: e.AuditSeq, OccurredAt: canon.FormatTime(e.OccurredAt)})
	if err != nil {
		return nil, fmt.Errorf("events: canonical seq %d: %w", e.Seq, err)
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("events: canonical seq %d: %w", e.Seq, err)
	}
	return out, nil
}
