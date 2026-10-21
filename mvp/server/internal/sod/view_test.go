package sod

import (
	"errors"
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
)

func TestViewSettings_Check(t *testing.T) {
	d := DefaultView()
	if len(d.Columns) != 6 || len(d.Filters) != 6 {
		t.Fatalf("default view = %+v", d)
	}
	got, err := ViewSettings{Columns: []string{ViewMitigatingControl, ViewRisk, ViewRisk}, Filters: nil}.Check()
	if err != nil || !slices.Equal(got.Columns, []string{ViewRisk, ViewMitigatingControl}) || got.Filters == nil || len(got.Filters) != 0 {
		t.Errorf("canonical form: %+v %v", got, err)
	}
	for name, v := range map[string]ViewSettings{
		"unknown column": {Columns: []string{"risk", "payroll"}},
		"unknown filter": {Columns: []string{"risk"}, Filters: []string{"colour"}},
		"no columns":     {Columns: []string{}},
		"nil columns":    {},
	} {
		var ce *cfgerr.Error
		if _, err := v.Check(); !errors.As(err, &ce) || ce.Status != 422 {
			t.Errorf("%s: %v", name, err)
		}
	}
}
