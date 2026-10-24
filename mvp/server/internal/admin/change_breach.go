package admin

import (
	"github.com/nischalravi/tessera/mvp/server/internal/breach"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeBreachAttest attests a manual item of a vendor breach plan (issue #538). One admin alone must not be able to
// close a vendor breach by typing a note, so attesting files this request and a different admin approves it; the
// item stays in progress until then. The ledger and the plan's evidence export name both admins.
const TypeBreachAttest = breach.ChangeType

type breachAttestPayload struct {
	PlanID string `json:"plan_id"`
	ItemID string `json:"item_id"`
	Note   string `json:"note"`
}

func init() {
	t := typed(TypeBreachAttest, nil, planBreachAttest, applyBreachAttest,
		func(_ *env, v *breachAttestPayload) string { return "Attest breach plan item " + v.ItemID })
	t.afterSubmit = func(e *env, ch *store.AdminChange, v any) error {
		p := v.(*breachAttestPayload)
		return breachErr(breachSvc.AwaitAttest(e.tx, p.PlanID, p.ItemID, p.Note, ch.ID.String(), e.now))
	}
	t.afterEnd = func(e *env, _ *store.AdminChange, v any) error {
		p := v.(*breachAttestPayload)
		return breachErr(breachSvc.DropAttest(e.tx, p.PlanID, p.ItemID, e.now))
	}
	changeTypes[TypeBreachAttest] = t
}

// breachSvc validates and applies attestations. Its methods use only the transaction handed to them.
var breachSvc = &breach.Service{}

func planBreachAttest(e *env, v *breachAttestPayload) (plan, error) {
	if len(v.PlanID) != 36 || len(v.ItemID) != 36 {
		return plan{}, invalid("plan_id and item_id are required")
	}
	if _, _, err := breachSvc.CheckAttest(e.tx, v.PlanID, v.ItemID, v.Note); err != nil {
		return plan{}, breachErr(err)
	}
	return plan{twoPerson: true, target: v.ItemID}, nil
}

func applyBreachAttest(e *env, ch *store.AdminChange, v *breachAttestPayload) error {
	if ch.ApprovedBy == nil {
		return conflict("invalid_state", "the attestation has no approver")
	}
	_, err := breachSvc.AttestApproved(e.tx, v.PlanID, v.ItemID, v.Note, breach.UserName(e.tx, ch.RequestedBy),
		breach.UserName(e.tx, *ch.ApprovedBy), ch.ID.String(), e.now)
	return breachErr(err)
}

// breachErr maps a breach refusal to an API error of this package.
func breachErr(err error) error {
	if be, ok := err.(*breach.Error); ok {
		return newErr(be.Status, be.Code, "%s", be.Msg)
	}
	return err
}
