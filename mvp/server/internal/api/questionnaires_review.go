package api

import (
	"errors"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// reviewAnswers validates the answers sent with a review decision against the questionnaire
// attached to the item's campaign (nil: none asked, none given). The reviewer answers once per
// decision: the model decides item by item, so the answers belong to the decision (and its audit
// event) rather than to the campaign. An item that is already decided asks nothing: the decision
// is final and a repeat writes nothing.
func reviewAnswers(tx *store.TenantTx, itemID int64, raw any) ([]questionnaires.Checked, error) {
	it, err := tx.Item(itemID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil // the decision reports the unknown item
	} else if err != nil {
		return nil, err
	}
	if it.Decision != nil && *it.Decision != "" {
		return nil, nil
	}
	needs, err := questionnaires.ForCampaign(tx, it.CampaignID)
	if err != nil {
		return nil, err
	}
	var given map[string]map[string]any
	if o, ok := raw.(ojson.Object); ok {
		if len(needs) == 0 {
			return nil, qErr(&questionnaires.Error{Status: http.StatusUnprocessableEntity, Code: "unexpected_questionnaire",
				Msg: "this campaign asks no questions"})
		}
		given = map[string]map[string]any{needs[0].ID: questionnaires.FromObject(o)}
	}
	checked, err := questionnaires.Validate(needs, given)
	return checked, qErr(err)
}
