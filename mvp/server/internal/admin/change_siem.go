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

// TypeSiemSinkTarget moves a SIEM sink to another destination (issue #520). The sink's audit feed then goes to
// wherever the admin chose and the SOC's collector stops receiving it, so a move to another origin takes two
// admins. Applying it clears the sink's token (it never follows a sink to another origin) and disables the sink;
// an admin then gives it the new destination's token and enables it (PUT /api/siem/sinks/{id}). The request and its
// approval reach the old destination while it is still the target.
const TypeSiemSinkTarget = "siem.sink.target"

// siemFilterPayload changes what a sink receives. event_filter ([] is every event) and include_http are each
// optional (omitted keeps the current value), at least one is given. Narrowing either needs two admins: a filter
// that lets fewer events through, or include_http true to false (it drops every http.request event, issue #520).
type siemFilterPayload struct {
	SinkID      string    `json:"sink_id"`
	EventFilter *[]string `json:"event_filter,omitempty"`
	IncludeHTTP *bool     `json:"include_http,omitempty"`
}

type siemTargetPayload struct {
	SinkID string `json:"sink_id"`
	Target string `json:"target"`
}

func init() {
	changeTypes[TypeSiemSinkFilter] = typed(TypeSiemSinkFilter, nil, planSiemFilter, applySiemFilter,
		func(_ *env, v *siemFilterPayload) string { return "Change what SIEM sink " + v.SinkID + " receives" })
	changeTypes[TypeSiemSinkTarget] = typed(TypeSiemSinkTarget, nil, planSiemTarget, applySiemTarget,
		func(_ *env, v *siemTargetPayload) string { return "Move SIEM sink " + v.SinkID + " to " + v.Target })
}

// planSiemFilter checks the sink and the settings and decides who approves: two admins when either narrows.
func planSiemFilter(e *env, v *siemFilterPayload) (plan, error) {
	if v.EventFilter == nil && v.IncludeHTTP == nil {
		return plan{}, invalid("give event_filter ([] is every event) or include_http")
	}
	k, err := e.tx.SiemSink(v.SinkID)
	if errors.Is(err, store.ErrNotFound) {
		return plan{}, invalid("no SIEM sink %s", v.SinkID)
	} else if err != nil {
		return plan{}, err
	}
	narrows, same := false, true
	if v.EventFilter != nil {
		next, err := siem.NormalizeFilter(*v.EventFilter)
		if err != nil {
			return plan{}, invalid("%v", err)
		}
		narrows, same = siem.Narrows(k.EventFilter, next), siem.SameFilter(k.EventFilter, next)
	}
	if v.IncludeHTTP != nil && *v.IncludeHTTP != k.IncludeHTTP {
		same = false
		narrows = narrows || !*v.IncludeHTTP
	}
	if same {
		return plan{}, invalid("the sink already has these settings")
	}
	return plan{twoPerson: narrows, target: k.ID}, nil
}

func applySiemFilter(e *env, ch *store.AdminChange, v *siemFilterPayload) error {
	if _, err := planSiemFilter(e, v); err != nil {
		return err
	}
	_, err := siem.SetFilters(e.tx, v.SinkID, v.EventFilter, v.IncludeHTTP, ch.ID.String(), e.now)
	return err
}

// planSiemTarget needs a move to another origin (a path-only change is a plain PUT) and always takes two admins.
func planSiemTarget(e *env, v *siemTargetPayload) (plan, error) {
	k, err := e.tx.SiemSink(v.SinkID)
	if errors.Is(err, store.ErrNotFound) {
		return plan{}, invalid("no SIEM sink %s", v.SinkID)
	} else if err != nil {
		return plan{}, err
	}
	target, err := siem.CheckRetarget(k, v.Target, !e.svc.Prod)
	if err != nil {
		return plan{}, invalid("%v", err)
	}
	v.Target = target
	if siem.SinkOrigin(k.Kind, k.Target) == siem.SinkOrigin(k.Kind, v.Target) {
		return plan{}, invalid("the target is on the sink's current origin: change it with PUT /api/siem/sinks/{id}")
	}
	return plan{twoPerson: true, target: k.ID}, nil
}

func applySiemTarget(e *env, ch *store.AdminChange, v *siemTargetPayload) error {
	if _, err := planSiemTarget(e, v); err != nil {
		return err
	}
	_, err := siem.Retarget(e.tx, v.SinkID, v.Target, !e.svc.Prod, ch.ID.String(), e.now)
	return err
}
