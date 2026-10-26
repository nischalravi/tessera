package awsorg

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// InputError is a refusal the API maps to a status: Kind is "invalid",
// "conflict" or "not_found".
type InputError struct {
	Kind, Code, Msg string
}

func (e *InputError) Error() string { return e.Msg }

func invalid(code, format string, a ...any) error {
	return &InputError{Kind: "invalid", Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Service manages connectors and runs collections. Every connector write
// commits its audit event in the same transaction.
type Service struct {
	// Sealer seals the connector's credentials (required).
	Sealer *seal.Sealer
	// Client sends the AWS requests (required for Collect); its HTTP is the
	// safehttp client in production.
	Client *Client
	// CatalogVersion is the action catalog the snapshot is taken against.
	CatalogVersion string
	// Clock defaults to time.Now.
	Clock func() time.Time
	// Eval, when set, makes Collect evaluate the snapshot it stored and bring
	// the MVP's graph up to date with the result (Materialize, PR-11). Nil:
	// a collection only stores the snapshot.
	Eval *EvalConfig
	// Canonical spells an action as the action catalog does and says whether
	// the catalog has it (catalog.Catalog.CanonicalAction); the usage ingest
	// files only actions it knows. Nil: events' actions are used as named.
	Canonical func(action string) (string, bool)
	// Federation mints the web identity tokens of federated connectors
	// (required to collect from one).
	Federation *Federation
	// AllowStaticKeys lets a connector hold a sealed access key
	// (TESSERA_AWS_ALLOW_STATIC_KEYS; prod refuses it on). Off, creating one is
	// refused and a stored one is not collected from.
	AllowStaticKeys bool
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

// CreateInput is the body of a connector create.
type CreateInput struct {
	Name   string
	Config Config
	// Credentials are the access keys of a static-key connector. Leave them
	// empty (and Config.Auth empty or federated) for the default: a federated
	// connector, which stores no secret.
	Credentials Credentials
	// ExternalID, when set, is the sts:ExternalId the reader role already
	// trusts (a governed connection's probe used it); empty generates one.
	ExternalID string
}

var externalIDRE = regexp.MustCompile(`^[\w+=,.@:/-]{2,1000}$`)

// MaxNameLen bounds a connector name.
const MaxNameLen = 80

func validName(n string) error {
	if n == "" || len(n) > MaxNameLen || strings.TrimSpace(n) != n {
		return invalid("invalid_name", "name must be 1 to %d characters, without leading or trailing space", MaxNameLen)
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return invalid("invalid_name", "name must not contain control characters")
		}
	}
	return nil
}

// CreateConnector validates and stores a connector. The credentials are sealed
// (AAD bound to tenant, table, column and connector id) before they reach the
// store; the audit event names the connector and never the credentials.
func (s *Service) CreateConnector(c *store.TenantTx, in CreateInput, actor string, now time.Time) (*store.AWSConnector, error) {
	if err := validName(in.Name); err != nil {
		return nil, err
	}
	cfg := in.Config
	if err := cfg.Validate(); err != nil {
		return nil, invalid("invalid_config", "%v", err)
	}
	hasKeys := in.Credentials != Credentials{}
	if cfg.Auth == "" {
		cfg.Auth = AuthFederated
		if hasKeys {
			cfg.Auth = AuthStaticKey
		}
	}
	id := uuid.NewString()
	var sealed []byte
	var ext string
	switch cfg.Auth {
	case AuthFederated:
		if hasKeys {
			return nil, invalid("invalid_credentials", "a federated connector takes no credentials")
		}
		if in.ExternalID != "" {
			return nil, invalid("invalid_external_id", "a federated connector takes no external_id: the role trusts the token's aud and sub")
		}
		// the column is NOT NULL: nothing secret is stored, so the blob is empty
		sealed = []byte{}
	case AuthStaticKey:
		if !s.AllowStaticKeys {
			return nil, invalid("static_keys_disabled", "stored AWS access keys are disabled on this server; create a federated connector (omit credentials)")
		}
		if err := in.Credentials.Validate(); err != nil {
			return nil, invalid("invalid_credentials", "%v", err)
		}
		if in.ExternalID != "" && !externalIDRE.MatchString(in.ExternalID) {
			return nil, invalid("invalid_external_id", "external_id is not a valid sts:ExternalId")
		}
		ext = in.ExternalID
		if ext == "" {
			ext = "tessera-" + seal.RandomString(32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
		}
		var err error
		if sealed, err = SealCredentials(s.Sealer, c.Tenant(), id, in.Credentials); err != nil {
			return nil, err
		}
	}
	cb, err := jsonMarshal(cfg)
	if err != nil {
		return nil, err
	}
	k := &store.AWSConnector{ID: id, Name: in.Name, Config: cb, CredentialsEnc: sealed, CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
		// not a secret: the customer puts it in the role's trust policy (sts:ExternalId)
		ExternalID: ext}
	if err := c.InsertAWSConnector(k); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return nil, &InputError{Kind: "conflict", Code: "name_taken", Msg: "a connector with this name already exists"}
		}
		return nil, err
	}
	if err := c.Audit(now, actor, "aws.connector.created", ojson.Object{{Key: "connector_id", Value: id}, {Key: "name", Value: in.Name},
		{Key: "regions", Value: len(cfg.Regions)}, {Key: "organization", Value: cfg.ManagementAccountID != ""}, {Key: "auth", Value: cfg.Auth}}); err != nil {
		return nil, err
	}
	k.TenantID = c.Tenant()
	return k, nil
}

// DeleteConnector removes a connector and with it its sealed credentials.
// Snapshots it collected stay.
func (s *Service) DeleteConnector(c *store.TenantTx, id, actor string, now time.Time) error {
	k, err := c.AWSConnector(id)
	if err != nil {
		return notFound(err)
	}
	if err := c.DeleteAWSConnector(id); err != nil {
		return notFound(err)
	}
	return c.Audit(now, actor, "aws.connector.deleted", ojson.Object{{Key: "connector_id", Value: id}, {Key: "name", Value: k.Name}})
}

func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return &InputError{Kind: "not_found", Code: "not_found", Msg: "no such connector"}
	}
	return err
}

// Collect runs one collection for a connector and stores the snapshot. It
// holds no transaction while it talks to AWS: it reads the connector in one,
// collects, then writes the snapshot, the connector's run state and the audit
// event in another. A failed run is recorded on the connector and audited, and
// the error is returned.
func (s *Service) Collect(ctx context.Context, db *store.DB, tenant tenancy.ID, connectorID, actor string) (*store.AWSSnapshot, error) {
	hdr, _, err := s.collect(ctx, db, tenant, connectorID, actor, false)
	if err != nil {
		return hdr, err
	}
	if s.Eval != nil {
		// The snapshot is stored either way; a failed evaluation is reported
		// with it, so the caller keeps the snapshot and sees the error.
		if _, err := s.Materialize(ctx, db, tenant, hdr.ID, actor); err != nil {
			return hdr, fmt.Errorf("awsorg: snapshot %s is stored but was not evaluated: %w", hdr.ID, err)
		}
	}
	return hdr, nil
}

// collect is Collect without the evaluation. With skipUnchanged, a collection
// whose snapshot is the one the connector last collected and evaluated writes
// no snapshot rows and no audit event (unchanged is true): the connector's
// last-run time is its only write.
func (s *Service) collect(ctx context.Context, db *store.DB, tenant tenancy.ID, connectorID, actor string, skipUnchanged bool) (hdr *store.AWSSnapshot, unchanged bool, err error) {
	if s.Client == nil || s.Client.HTTP == nil {
		return nil, false, errors.New("awsorg: no HTTP client")
	}
	var k *store.AWSConnector
	if err := db.ReadTenant(ctx, tenant, func(c *store.TenantTx) (err error) {
		k, err = c.AWSConnector(connectorID)
		return err
	}); err != nil {
		return nil, false, notFound(err)
	}
	cfg, err := ParseConfig(k.Config)
	if err != nil {
		return nil, false, s.fail(ctx, db, tenant, k, actor, "bad_config", err)
	}
	coll, code, err := s.collectorFor(tenant, k, cfg)
	if err != nil {
		return nil, false, s.fail(ctx, db, tenant, k, actor, code, err)
	}
	col, err := coll.Collect(ctx)
	if err != nil {
		return nil, false, s.fail(ctx, db, tenant, k, actor, "collection_failed", err)
	}

	err = db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		now := s.now()
		created, err := Persist(c, col, PersistInput{Source: store.AWSSourceConnector, ConnectorID: k.ID, CatalogVersion: s.CatalogVersion})
		if err != nil {
			return err
		}
		// AWS has no change feed for GetAccountAuthorizationDetails, so every run
		// reads the estate; what is incremental is the write. The snapshot id is
		// the content hash, so an estate that has not changed since the run that
		// stored and evaluated it is recognized here. A snapshot that exists but
		// is not the connector's current one (the estate went back to an earlier
		// state), or whose last run did not finish, is not unchanged: the graph
		// has to be brought up to date with it.
		unchanged = skipUnchanged && !created && k.Status == store.AWSConnectorOK && k.LastSnapshotID == col.Snapshot.ID
		// A changed estate of the job is marked ok only after it is evaluated
		// (CollectAndMaterialize), so a process that stops in between leaves the
		// connector as it was and the next run evaluates the snapshot.
		if unchanged || !skipUnchanged {
			if err := c.SetAWSConnectorRun(k.ID, store.AWSConnectorOK, col.Snapshot.ID, "", now); err != nil {
				return err
			}
		}
		if hdr, err = c.AWSSnapshot(col.Snapshot.ID); err != nil {
			return err
		}
		if unchanged {
			return nil
		}
		return c.Audit(now, actor, "aws.snapshot.collected", ojson.Object{{Key: "connector_id", Value: k.ID},
			{Key: "snapshot_id", Value: col.Snapshot.ID}, {Key: "accounts", Value: len(col.AccountIDs)},
			{Key: "findings", Value: len(col.Findings)}, {Key: "new", Value: created}})
	})
	if err != nil {
		return nil, false, err
	}
	return hdr, unchanged, nil
}

// collectorFor builds the Collector of a connector: federated (a token from
// Federation) or, where the server allows it, with the connector's sealed key.
// The code names what is missing when it fails (it is recorded on the connector).
func (s *Service) collectorFor(tenant tenancy.ID, k *store.AWSConnector, cfg *Config) (*Collector, string, error) {
	coll := &Collector{Client: s.Client, Config: cfg, ExternalID: k.ExternalID, Now: s.Clock}
	switch cfg.Mode() {
	case AuthFederated:
		if s.Federation == nil {
			return nil, "federation_unavailable", errors.New("awsorg: this server cannot issue federation tokens")
		}
		coll.WebIdentity = s.Federation.Source(tenant, k.ID)
	default:
		if !s.AllowStaticKeys {
			return nil, "static_keys_disabled",
				errors.New("awsorg: stored AWS access keys are disabled on this server; recreate the connector as a federated one")
		}
		creds, err := OpenCredentials(s.Sealer, tenant, k.ID, k.CredentialsEnc)
		if err != nil {
			return nil, "credentials_unreadable", err
		}
		coll.Base = toSigV4(creds)
	}
	return coll, "", nil
}

// CollectResult is what one run of CollectAndMaterialize did.
type CollectResult struct {
	SnapshotID string `json:"snapshot_id"`
	// Changed is false when the estate is the one the connector last collected
	// and evaluated: nothing was written but the connector's last-run time.
	Changed      bool              `json:"changed"`
	Materialized *MaterializeStats `json:"materialized,omitempty"`
	// Usage is what the usage ingest did (nil when the connector has none), and
	// UsageError why it failed: the estate collection stands either way.
	Usage      *UsageStats `json:"usage,omitempty"`
	UsageError string      `json:"usage_error,omitempty"`
}

// CollectAndMaterialize is the collection job: it collects the connector's
// estate, and when the estate changed it evaluates the snapshot and brings the
// graph up to date (Materialize). An unchanged estate writes nothing (see
// collect). An evaluation that fails marks the connector failed, so the next
// run evaluates the stored snapshot again instead of taking it as done.
func (s *Service) CollectAndMaterialize(ctx context.Context, db *store.DB, tenant tenancy.ID, connectorID, actor string) (*CollectResult, error) {
	if s.Eval == nil {
		return nil, errors.New("awsorg: no evaluator is configured")
	}
	hdr, unchanged, err := s.collect(ctx, db, tenant, connectorID, actor, true)
	if err != nil {
		return nil, err
	}
	res := &CollectResult{SnapshotID: hdr.ID, Changed: !unchanged}
	// usage is read next to the estate, whether or not the estate changed, and
	// whatever happens to it the collection's own outcome stands
	withUsage := func() {
		if ctx.Err() != nil {
			return
		}
		var uerr error
		if res.Usage, uerr = s.CollectUsage(ctx, db, tenant, connectorID, actor, hdr); uerr != nil {
			res.UsageError = clip(uerr.Error(), 500)
		}
	}
	if unchanged {
		withUsage()
		return res, nil
	}
	if res.Materialized, err = s.Materialize(ctx, db, tenant, hdr.ID, actor); err != nil {
		cause := fmt.Errorf("awsorg: snapshot %s is stored but was not evaluated: %w", hdr.ID, err)
		werr := db.InTenant(context.WithoutCancel(ctx), tenant, func(c *store.TenantTx) error {
			now := s.now()
			if err := c.SetAWSConnectorRun(connectorID, store.AWSConnectorFailed, hdr.ID, clip(cause.Error(), 500), now); err != nil {
				return err
			}
			return c.Audit(now, actor, "aws.collection.failed", ojson.Object{{Key: "connector_id", Value: connectorID},
				{Key: "code", Value: "evaluation_failed"}})
		})
		return nil, errors.Join(cause, werr)
	}
	err = db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		return c.SetAWSConnectorRun(connectorID, store.AWSConnectorOK, hdr.ID, "", s.now())
	})
	if err != nil {
		return nil, err
	}
	withUsage()
	return res, nil
}

// fail records a failed run on the connector, with its audit event, and
// returns cause. The recorded text is clipped, and holds no credentials: AWS
// error messages and our own errors never include the keys.
func (s *Service) fail(ctx context.Context, db *store.DB, tenant tenancy.ID, k *store.AWSConnector, actor, code string, cause error) error {
	// a run cut off by a cancelled context is still recorded
	werr := db.InTenant(context.WithoutCancel(ctx), tenant, func(c *store.TenantTx) error {
		now := s.now()
		if err := c.SetAWSConnectorRun(k.ID, store.AWSConnectorFailed, "", clip(cause.Error(), 500), now); err != nil {
			return err
		}
		return c.Audit(now, actor, "aws.collection.failed", ojson.Object{{Key: "connector_id", Value: k.ID}, {Key: "code", Value: code}})
	})
	if werr != nil {
		return errors.Join(cause, werr)
	}
	return cause
}
