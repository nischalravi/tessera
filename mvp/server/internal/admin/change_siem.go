package admin

import (
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeSiemSinkFilter changes a SIEM sink's event filter (issue #511). Narrowing it (fewer events reach the SOC)
// removes detection, so it takes two admins: the requester proposes, a different admin approves what the payload
// hash says. Widening or clearing a filter takes one. siem.*, audit.*, admin.change.* and the break-glass and
// step-up events reach every sink whatever the filter says (siem.AlwaysDelivered).
const TypeSiemSinkFilter = "siem.sink.filter"

type siemFilterPayload struct {
	SinkID      string   `json:"sink_id"`
	EventFilter []string `json:"event_filter"` // [] is every event
}

func init() {
	changeTypes[TypeSiemSinkFilter] = typed(TypeSiemSinkFilter, nil, planSiemFilter, applySiemFilter,
		func(_ *env, v *siemFilterPayload) string { return "Change the event filter of SIEM sink " + v.SinkID })
}

// planSiemFilter checks the sink and the filter and decides who approves: two admins when the filter narrows.
func planSiemFilter(e *env, v *siemFilterPayload) (plan, error) {
	if v.EventFilter == nil {
		return plan{}, invalid("event_filter is required ([] is every event)")
	}
	k, err := e.tx.SiemSink(v.SinkID)
	if errors.Is(err, store.ErrNotFound) {
		return plan{}, invalid("no SIEM sink %s", v.SinkID)
	} else if err != nil {
		return plan{}, err
	}
	next, err := siem.NormalizeFilter(v.EventFilter)
	if err != nil {
		return plan{}, invalid("%v", err)
	}
	if siem.SameFilter(k.EventFilter, next) {
		return plan{}, invalid("the sink already has this event filter")
	}
	return plan{twoPerson: siem.Narrows(k.EventFilter, next), target: k.ID}, nil
}

func applySiemFilter(e *env, ch *store.AdminChange, v *siemFilterPayload) error {
	if _, err := planSiemFilter(e, v); err != nil {
		return err
	}
	_, err := siem.SetEventFilter(e.tx, v.SinkID, v.EventFilter, ch.ID.String(), e.now)
	return err
}
