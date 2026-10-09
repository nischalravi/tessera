package store

import (
	"regexp"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Tenant is a customer tenant (GLOBAL table). Settings and security contacts
// (design §18.3, §15.5) arrive with the PRs that use them; their columns
// already exist with empty defaults.
type Tenant struct {
	ID        tenancy.ID
	Slug      string // ^[a-z0-9][a-z0-9-]{2,39}$; "_platform" is reserved
	Name      string
	Status    string // active | suspended | recovery
	Cell      string // "local"
	MinAdmins int    // default 2
	CreatedAt time.Time
}

// PlatformSlug is the slug of the reserved tenancy.Platform tenant.
const PlatformSlug = "_platform"

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,39}$`)

// ValidSlug reports whether s may be used as a (non-reserved) tenant slug.
func ValidSlug(s string) bool { return slugRE.MatchString(s) }
