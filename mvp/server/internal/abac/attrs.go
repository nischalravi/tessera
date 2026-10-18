package abac

import (
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// IdentityAttrs are the identity.* attributes of a person. A field the
// identity does not have is left out (a missing attribute denies).
func IdentityAttrs(i *store.Identity, now time.Time) Attrs {
	a := Attrs{"identity.type": i.Type, "identity.status": i.Status, "identity.name": i.Name,
		"identity.has_manager": i.ManagerID != nil}
	put := func(k string, v *string) {
		if v != nil && *v != "" {
			a[k] = *v
		}
	}
	put("identity.email", i.Email)
	put("identity.department", i.Department)
	put("identity.title", i.Title)
	put("identity.source", i.Source)
	if i.ManagerID != nil {
		a["identity.manager_id"] = float64(*i.ManagerID)
	}
	if i.HiredAt != nil && !i.HiredAt.After(now) {
		a["identity.tenure_days"] = float64(int(now.Sub(*i.HiredAt) / (24 * time.Hour)))
	}
	return a
}

// ContextAttrs are the context.* attributes: the evaluation time, and the
// assurance level when there is a signed-in user (aal 0: none).
func ContextAttrs(now time.Time, aal int) Attrs {
	u := now.UTC()
	a := Attrs{"context.time": u.Format(time.RFC3339), "context.hour": float64(u.Hour()),
		"context.weekday": strings.ToLower(u.Weekday().String()[:3])}
	if aal > 0 {
		a["context.aal"] = float64(aal)
	}
	return a
}

// Merge returns the union of the sets (later sets win).
func Merge(sets ...Attrs) Attrs {
	out := Attrs{}
	for _, s := range sets {
		for k, v := range s {
			out[k] = v
		}
	}
	return out
}

// RoleAttrs are the resource.* attributes of a business role.
func RoleAttrs(r *store.BusinessRole) Attrs {
	return Attrs{"resource.name": r.Name, "resource.risk": r.Risk}
}

// ItemAttrs are the resource.* attributes of a catalog entitlement.
func ItemAttrs(it *store.CatalogItem, g *store.Group) Attrs {
	return Attrs{"resource.name": g.Name, "resource.system": g.System, "resource.risk": it.Risk,
		"resource.privileged": g.Privileged}
}
