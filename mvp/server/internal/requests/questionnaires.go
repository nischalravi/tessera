package requests

import (
	"errors"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
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

// checkAnswers validates the cart's answers; perItem lists the questionnaire ids each item asks.
func checkAnswers(tx *store.TenantTx, lines []*store.RequestLine, given map[string]map[string]any) ([]questionnaires.Checked, map[string][]string, error) {
	var all []questionnaires.Need
	perItem := map[string][]string{}
	for _, l := range lines {
		if _, done := perItem[l.CatalogItemID]; done {
			continue
		}
		needs, err := questionnaires.ForItem(tx, l.CatalogItemID)
		if err != nil {
			return nil, nil, err
		}
		perItem[l.CatalogItemID] = []string{}
		for _, n := range needs {
			perItem[l.CatalogItemID] = append(perItem[l.CatalogItemID], n.ID)
		}
		all = questionnaires.Union(all, needs)
	}
	checked, err := questionnaires.Validate(all, given)
	return checked, perItem, qerr(err)
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
