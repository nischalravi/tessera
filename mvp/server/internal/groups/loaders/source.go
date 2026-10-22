// Package loaders fills native groups from outside sources (issue #53, GR-10;
// design docs/design/groups-grouper-parity.md §9.1). A loader is a connector
// job: a GroupSource reads a source (a SQL query on a database file, a CSV
// file or URL, a connector's groups, an identity attribute, group history), the
// subjects it names are resolved to identities, and the groups' loader-owned
// members are made to match, in one transaction with the audit event and the
// membership events.
//
// Failsafes decide whether a run may apply. A run that would remove too many
// members, empty too many groups or leave too many subjects unresolved is
// held: nothing is applied, the run keeps the plan it computed and the
// downstream impact, and a person approves (the plan is applied as it was
// computed) or rejects it (K7). Subjects that match no identity are never
// dropped silently: they are listed per loader, counted in the failsafe and
// retried on every run.
//
// This package has no SQL: it reads and writes through *store.TenantTx.
package loaders

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Loader types (design §9.1). ldap_attribute, sftp_csv and hris_sis_feed are
// designed but not built yet (they need an SSH library or the HR connectors)
// and are refused with ErrTypeUnavailable.
const (
	TypeSQLSimple       = "sql_simple"
	TypeSQLGroupList    = "sql_group_list"
	TypeCSV             = "csv"
	TypeConnectorGroups = "connector_groups"
	TypeAttribute       = "attribute"
	TypeRecent          = "recent_memberships"
	TypeSCIM            = "scim"
	TypeLDAPSimple      = "ldap_simple"
	TypeLDAPGroupList   = "ldap_group_list"
)

// unavailableTypes are the designed types that are not built.
var unavailableTypes = map[string]bool{"ldap_attribute": true, "sftp_csv": true, "hris_sis_feed": true}

// Types lists the loader types that can be configured.
func Types() []string {
	return []string{TypeSQLSimple, TypeSQLGroupList, TypeCSV, TypeConnectorGroups, TypeAttribute, TypeRecent, TypeSCIM, TypeLDAPSimple, TypeLDAPGroupList}
}

// IsSQL reports whether a loader of the type runs a query a person wrote, on a
// database file or on a Postgres server: its creation and every change need a
// second approver (GRP-6311).
func IsSQL(typ string) bool { return typ == TypeSQLSimple || typ == TypeSQLGroupList }

// NeedsSecondApprover reports whether creating a loader of the type, and every
// change of its definition or credential, needs a second administrator
// (GRP-6311): a loader that runs a query a person wrote (SQL, on a file or a
// Postgres server) or that reads a directory or a provider with a credential
// (SCIM, LDAP). Turning it off, running it and previewing it do not.
func NeedsSecondApprover(typ string) bool {
	switch typ {
	case TypeSQLSimple, TypeSQLGroupList, TypeSCIM, TypeLDAPSimple, TypeLDAPGroupList:
		return true
	}
	return false
}

// SubjectRef names a person in a source: Source is "identity" (an identity's
// external id, also the empty source), "email", "tessera_id", the system of a
// connected account (a connector's system name) or the source recorded on the
// identity ("hris", "sis"); Identifier is the value in that source.
type SubjectRef struct {
	Source     string `json:"source"`
	Identifier string `json:"identifier"`
}

// LoadedGroup is a group as a source lists it. Name is relative to the
// loader's target folder, before the name template.
type LoadedGroup struct {
	Name        string
	DisplayName string
	Description string
	Members     []SubjectRef
}

// GroupChange is one change of an incremental feed.
type GroupChange struct {
	Group   string // relative name, before the name template
	Subject SubjectRef
	Remove  bool
}

// Env is what a source may use: the database for the sources that read
// Tessera's own data (they open their own read-only transactions: no
// transaction is open while a source runs), the clock, the directory the SQL
// and CSV files must be under, the SSRF-guarded HTTP client, the guarded
// dialer of Postgres sources and the opener of directory connections.
type Env struct {
	DB      *store.DB
	Tenant  tenancy.ID
	Now     time.Time
	DataDir string
	HTTP    *http.Client
	// Prod: production refuses weaker settings (a Postgres source that is not
	// sslmode=verify-full).
	Prod bool
	// PGDial is the address-checked dialer of Postgres sources; nil turns them
	// off. Directory opens LDAP connections through safedial; nil turns LDAP
	// sources off.
	PGDial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Directory DirectoryOpener
}

// SourceStats are what a source reports about what it read.
type SourceStats struct {
	// Rows is the number of source rows (or listed members) read.
	Rows int
	// Hash is the SHA-256 of the file a source read, or "".
	Hash string
}

// LoaderJob is one run's input to a source. Secret is the loader's unsealed
// credential (nil if it has none): a source must never log it or put it in an
// error.
type LoaderJob struct {
	Loader *store.GrpLoader
	Config json.RawMessage
	Secret []byte
	Env    Env
	// Stats is filled by the source.
	Stats *SourceStats
}

// GroupSource reads a source.
type GroupSource interface {
	// Full returns every group the source lists, with all its members.
	Full(ctx context.Context, job LoaderJob) ([]LoadedGroup, error)
	// Changes is optional: ok=false means the source has no incremental feed.
	// It returns the changes after cursor and the next cursor.
	Changes(ctx context.Context, job LoaderJob, cursor string) (changes []GroupChange, next string, ok bool, err error)
}

// Errors of loader configuration and of runs; the API maps Kind to 404, 409
// or 422 like the model's.
var (
	// ErrTypeUnavailable: the type is designed but not built.
	ErrTypeUnavailable = errors.New("loaders: loader type is not available yet")
)

// SourceFor returns the source of a loader type.
func SourceFor(typ string) (GroupSource, error) {
	switch typ {
	case TypeSQLSimple, TypeSQLGroupList:
		return sqlSource{}, nil
	case TypeCSV:
		return csvSource{}, nil
	case TypeConnectorGroups:
		return connectorSource{}, nil
	case TypeAttribute:
		return attributeSource{}, nil
	case TypeRecent:
		return recentSource{}, nil
	case TypeSCIM:
		return scimSource{}, nil
	case TypeLDAPSimple, TypeLDAPGroupList:
		return ldapSource{}, nil
	}
	if unavailableTypes[typ] {
		return nil, ErrTypeUnavailable
	}
	return nil, errors.New("loaders: unknown loader type " + typ)
}

// noChanges is the Changes of a source with no incremental feed.
type noChanges struct{}

func (noChanges) Changes(context.Context, LoaderJob, string) ([]GroupChange, string, bool, error) {
	return nil, "", false, nil
}
