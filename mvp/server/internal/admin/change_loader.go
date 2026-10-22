package admin

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

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
	t := typed(TypeGroupLoaderSave, nil, planLoaderSave, applyLoaderSave,
		func(_ *env, v *loaderSavePayload) string {
			if v.LoaderID == "" {
				return fmt.Sprintf("Create %s loader %q", v.Spec.Type, v.Spec.Name)
			}
			return fmt.Sprintf("Change %s loader %q", v.Spec.Type, v.Spec.Name)
		})
	// A SQL loader on a Postgres server carries its connection string (sealed, never in
	// the payload, which the second approver reads).
	t.submitSecret = submitLoaderSecret
	changeTypes[TypeGroupLoaderSave] = t
}

// submitLoaderSecret seals the credential of a Postgres loader's request. A create
// needs one; a change keeps the stored one when none comes.
func submitLoaderSecret(e *env, v any, id uuid.UUID, secret string) ([]byte, error) {
	p := v.(*loaderSavePayload)
	cfg, err := loaders.ValidateConfig(p.Spec.Type, p.Spec.Config, p.Spec.ConnectionID != "")
	if err != nil {
		return nil, loaderErr(err)
	}
	use := loaders.SecretPolicy(p.Spec.Type, cfg)
	switch {
	case secret == "" && use == loaders.SecretRequired && p.LoaderID == "":
		return nil, invalid("a %s loader needs its credential (client_secret)", p.Spec.Type)
	case secret == "":
		return nil, nil
	case use == loaders.SecretNone:
		return nil, invalid("a %s loader with this config takes no secret", p.Spec.Type)
	case e.svc.Sealer == nil:
		return nil, newErr(503, "sealer_unavailable", "no key-encryption key is configured to seal the credential")
	}
	if err := loaders.CheckSecret(p.Spec.Type, cfg, secret, e.svc.Prod); err != nil {
		return nil, loaderErr(err)
	}
	return e.svc.Sealer.Seal([]byte(secret), secretAAD(e.tx.Tenant(), id))
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
	if !loaders.NeedsSecondApprover(l.Type) {
		return plan{}, invalid("only a SQL, SCIM or LDAP loader goes through approval: save a %s loader directly", l.Type)
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

func applyLoaderSave(e *env, ch *store.AdminChange, v *loaderSavePayload) error {
	if _, err := planLoaderSave(e, v); err != nil {
		return err
	}
	by := e.by.String()
	se := loaders.SaveEnv{Tx: e.tx, Now: e.now, By: &by, Sealer: e.svc.Sealer, Prod: e.svc.Prod}
	var secret *string
	if len(ch.SecretEnc) > 0 {
		if e.svc.Sealer == nil {
			return newErr(503, "sealer_unavailable", "no key-encryption key is configured to open the credential")
		}
		b, err := e.svc.Sealer.Open(ch.SecretEnc, secretAAD(e.tx.Tenant(), ch.ID))
		if err != nil {
			return fmt.Errorf("open the request's credential: %w", err)
		}
		s := string(b)
		secret = &s
	}
	var err error
	if v.LoaderID == "" {
		s := ""
		if secret != nil {
			s = *secret
		}
		_, err = loaders.Create(se, v.Spec, s)
	} else {
		_, err = loaders.Update(se, v.LoaderID, v.Version, v.Spec, secret)
	}
	return loaderErr(err)
}
