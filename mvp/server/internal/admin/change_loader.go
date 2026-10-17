package admin

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeGroupLoaderSave creates or changes a group loader that runs a query a
// person wrote (issue #53, GR-10; design groups-grouper-parity.md §9.1). The
// payload is the whole resulting definition, so the second person approves
// exactly what will be applied. Loaders of the other types are saved directly:
// only SQL (and, when it lands, LDAP) needs two people (GRP-6311). The change
// has no cooling-off: it narrows nothing and widens nothing by itself, and the
// loader's own failsafes guard what it does.
const TypeGroupLoaderSave = "groups.loader.save"

type loaderSavePayload struct {
	// LoaderID names the loader to change; empty creates one.
	LoaderID string `json:"loader_id,omitempty"`
	// Version is the version the change was made against (applying to a loader
	// that changed since fails rather than overwriting).
	Version *int64       `json:"version,omitempty"`
	Spec    loaders.Spec `json:"spec"`
}

func init() {
	changeTypes[TypeGroupLoaderSave] = typed(TypeGroupLoaderSave, nil, planLoaderSave, applyLoaderSave,
		func(_ *env, v *loaderSavePayload) string {
			if v.LoaderID == "" {
				return fmt.Sprintf("Create %s loader %q", v.Spec.Type, v.Spec.Name)
			}
			return fmt.Sprintf("Change %s loader %q", v.Spec.Type, v.Spec.Name)
		})
}

// loaderErr turns the loaders package's refusals into the workflow's.
func loaderErr(err error) error {
	var me *model.Error
	if !errors.As(err, &me) {
		return err
	}
	status := map[model.Kind]int{model.NotFound: http.StatusNotFound, model.Conflict: http.StatusConflict,
		model.Invalid: http.StatusUnprocessableEntity}[me.Kind]
	return newErr(status, me.Code, "%s", me.Msg)
}

func planLoaderSave(e *env, v *loaderSavePayload) (plan, error) {
	var existing *store.GrpLoader
	if v.LoaderID != "" {
		l, err := e.tx.GrpLoader(v.LoaderID)
		if errors.Is(err, store.ErrNotFound) {
			return plan{}, notFound("loader")
		}
		if err != nil {
			return plan{}, err
		}
		if v.Version != nil && *v.Version != l.Version {
			return plan{}, conflict("version_conflict", "the loader changed since the request was made")
		}
		existing = l
	}
	l, err := loaders.Validate(e.tx, v.Spec, existing)
	if err != nil {
		return plan{}, loaderErr(err)
	}
	if !loaders.IsSQL(l.Type) {
		return plan{}, invalid("only a loader that runs a SQL query goes through approval: save a %s loader directly", l.Type)
	}
	if other, err := e.tx.GrpLoaderByName(l.Name); err == nil && (existing == nil || other.ID != existing.ID) {
		return plan{}, conflict("name_taken", "a loader named %q exists", l.Name)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return plan{}, err
	}
	target := v.LoaderID
	if target == "" {
		target = "new:" + l.Name
	}
	return plan{twoPerson: true, target: target}, nil
}

func applyLoaderSave(e *env, _ *store.AdminChange, v *loaderSavePayload) error {
	if _, err := planLoaderSave(e, v); err != nil {
		return err
	}
	by := e.by.String()
	se := loaders.SaveEnv{Tx: e.tx, Now: e.now, By: &by, Sealer: e.svc.Sealer}
	var err error
	if v.LoaderID == "" {
		_, err = loaders.Create(se, v.Spec, "")
	} else {
		_, err = loaders.Update(se, v.LoaderID, v.Version, v.Spec, nil)
	}
	return loaderErr(err)
}
