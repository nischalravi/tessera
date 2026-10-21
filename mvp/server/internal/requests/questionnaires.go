package requests

import (
	"errors"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/workflow"
)

// Questionnaires on requests (issue #298): the items of a cart ask the questionnaires attached
// to them (and the privileged one for a privileged group). The requester answers each once for
// the whole cart; Submit validates the answers against the version in force and keeps a copy
// with every line the questionnaire applies to.

// qerr turns a questionnaire refusal into this package's.
func qerr(err error) error {
	var qe *questionnaires.Error
	if errors.As(err, &qe) {
		return &Error{Status: qe.Status, Code: qe.Code, Msg: qe.Msg}
	}
	return err
}

// checkAnswers validates the cart's answers; perLine lists the questionnaire ids each line asks:
// its item's (and the privileged one) and the ones its workflow path adds (issue #298).
func checkAnswers(tx *store.TenantTx, lines []*store.RequestLine, plans map[string]*workflow.Plan, given map[string]map[string]any) ([]questionnaires.Checked, map[string][]string, error) {
	var all []questionnaires.Need
	perLine := map[string][]string{}
	byItem := map[string][]questionnaires.Need{}
	for _, l := range lines {
		needs, done := byItem[l.CatalogItemID]
		if !done {
			var err error
			if needs, err = questionnaires.ForItem(tx, l.CatalogItemID); err != nil {
				return nil, nil, err
			}
			byItem[l.CatalogItemID] = needs
		}
		extra, err := workflowNeeds(tx, plans[l.ID])
		if err != nil {
			return nil, nil, err
		}
		own := questionnaires.Union(needs, extra)
		perLine[l.ID] = []string{}
		for _, n := range own {
			perLine[l.ID] = append(perLine[l.ID], n.ID)
		}
		all = questionnaires.Union(all, own)
	}
	checked, err := questionnaires.Validate(all, given)
	return checked, perLine, qerr(err)
}

// forItem keeps the answers to the questionnaires an item asks.
func forItem(checked []questionnaires.Checked, ids []string) []questionnaires.Checked {
	var out []questionnaires.Checked
	for _, c := range checked {
		if slices.Contains(ids, c.Need.ID) {
			out = append(out, c)
		}
	}
	return out
}
