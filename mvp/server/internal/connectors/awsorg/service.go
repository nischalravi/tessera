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
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

// CreateInput is the body of a connector create.
type CreateInput struct {
	Name        string
	Config      Config
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
	if err := in.Credentials.Validate(); err != nil {
		return nil, invalid("invalid_credentials", "%v", err)
	}
	if in.ExternalID != "" && !externalIDRE.MatchString(in.ExternalID) {
		return nil, invalid("invalid_external_id", "external_id is not a valid sts:ExternalId")
	}
	ext := in.ExternalID
	if ext == "" {
		ext = "tessera-" + seal.RandomString(32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	}
	id := uuid.NewString()
	sealed, err := SealCredentials(s.Sealer, c.Tenant(), id, in.Credentials)
	if err != nil {
		return nil, err
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
		{Key: "regions", Value: len(cfg.Regions)}, {Key: "organization", Value: cfg.ManagementAccountID != ""}}); err != nil {
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
	if s.Client == nil || s.Client.HTTP == nil {
		return nil, errors.New("awsorg: no HTTP client")
	}
	var k *store.AWSConnector
	if err := db.ReadTenant(ctx, tenant, func(c *store.TenantTx) (err error) {
		k, err = c.AWSConnector(connectorID)
		return err
	}); err != nil {
		return nil, notFound(err)
	}
	cfg, err := ParseConfig(k.Config)
	if err != nil {
		return nil, s.fail(ctx, db, tenant, k, actor, "bad_config", err)
	}
	creds, err := OpenCredentials(s.Sealer, tenant, k.ID, k.CredentialsEnc)
	if err != nil {
		return nil, s.fail(ctx, db, tenant, k, actor, "credentials_unreadable", err)
	}
	col, err := (&Collector{Client: s.Client, Config: cfg, ExternalID: k.ExternalID, Now: s.Clock,
		Base: toSigV4(creds)}).Collect(ctx)
	if err != nil {
		return nil, s.fail(ctx, db, tenant, k, actor, "collection_failed", err)
	}

	var hdr *store.AWSSnapshot
	err = db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		now := s.now()
		created, err := Persist(c, col, PersistInput{Source: store.AWSSourceConnector, ConnectorID: k.ID, CatalogVersion: s.CatalogVersion})
		if err != nil {
			return err
		}
		if err := c.SetAWSConnectorRun(k.ID, store.AWSConnectorOK, col.Snapshot.ID, "", now); err != nil {
			return err
		}
		if hdr, err = c.AWSSnapshot(col.Snapshot.ID); err != nil {
			return err
		}
		return c.Audit(now, actor, "aws.snapshot.collected", ojson.Object{{Key: "connector_id", Value: k.ID},
			{Key: "snapshot_id", Value: col.Snapshot.ID}, {Key: "accounts", Value: len(col.AccountIDs)},
			{Key: "findings", Value: len(col.Findings)}, {Key: "new", Value: created}})
	})
	if err != nil {
		return nil, err
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
