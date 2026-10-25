package awsorg

import (
	"context"
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// CollectUsage ingests usage for a connector whose config has "usage": the
// CloudTrail log files since its cursor, and a slice of IAM Access Advisor
// (see usage.go). snapshot is the connector's latest snapshot: its accounts say
// whose logs to read and its users and roles whom to ask Access Advisor about.
// It returns nil, nil for a connector with no usage settings. Like Collect it
// holds no transaction while it talks to AWS. The sources are independent: one
// failing does not stop the other, and both errors are returned.
func (s *Service) CollectUsage(ctx context.Context, db *store.DB, tenant tenancy.ID, connectorID, actor string, snapshot *store.AWSSnapshot) (*UsageStats, error) {
	if s.Client == nil || s.Client.HTTP == nil {
		return nil, errors.New("awsorg: no HTTP client")
	}
	var k *store.AWSConnector
	var states []*store.AWSUsageState
	var gaps []*store.AWSUsageGap
	var principals []string
	var cfg *Config
	err := db.ReadTenant(ctx, tenant, func(c *store.TenantTx) (err error) {
		if k, err = c.AWSConnector(connectorID); err != nil {
			return err
		}
		if cfg, err = ParseConfig(k.Config); err != nil || cfg.Usage == nil {
			return err
		}
		if states, err = c.AWSUsageStates(connectorID); err != nil {
			return err
		}
		if gaps, err = c.AWSUsageGaps(connectorID, 10000); err != nil {
			return err
		}
		if cfg.Usage.AccessAdvisor && snapshot != nil {
			principals, err = advisorPrincipals(c, snapshot.ID)
		}
		return err
	})
	if err != nil {
		return nil, notFound(err)
	}
	if cfg.Usage == nil {
		return nil, nil
	}
	creds, err := OpenCredentials(s.Sealer, tenant, k.ID, k.CredentialsEnc)
	if err != nil {
		return nil, err
	}
	u := &UsageCollector{Client: s.Client, Config: cfg, Base: toSigV4(creds), ExternalID: k.ExternalID, Now: s.Clock,
		Mapper: ActionMapper{Canonical: s.Canonical}}
	prior := func(source string) *store.AWSUsageState {
		for _, st := range states {
			if st.Source == source {
				return st
			}
		}
		return nil
	}
	existing := map[string]*store.AWSUsageGap{}
	for _, g := range gaps {
		existing[g.Source+"\x00"+g.Ref] = g
	}

	out := &UsageStats{}
	var errs []error
	if t := cfg.Usage.CloudTrail; t != nil {
		var accounts []string
		if snapshot != nil {
			accounts = snapshot.AccountIDs
		}
		b, st, terr := u.collectTrail(ctx, connectorID, accounts, prior(store.AWSUsageCloudTrail))
		out.CloudTrail = st
		if terr != nil {
			errs = append(errs, terr)
		}
		if ctx.Err() == nil && b != nil {
			if err := s.persistUsage(ctx, db, tenant, actor, b, prior(store.AWSUsageCloudTrail), existing, st.Objects, st.Refused); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if cfg.Usage.AccessAdvisor && ctx.Err() == nil {
		b, st, aerr := u.collectAdvisor(ctx, connectorID, principals, prior(store.AWSUsageAccessAdvisor))
		out.Advisor = st
		if aerr != nil {
			errs = append(errs, aerr)
		}
		if ctx.Err() == nil && b != nil {
			if err := s.persistUsage(ctx, db, tenant, actor, b, prior(store.AWSUsageAccessAdvisor), existing, st.Principals, 0); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return out, errors.Join(errs...)
}

// persistUsage writes one source's batch, its cursor and its gaps in one
// transaction, with the audit event. A run that changed nothing (no rows, no new
// gap, no cursor, coverage or data-event change) writes nothing at all.
func (s *Service) persistUsage(ctx context.Context, db *store.DB, tenant tenancy.ID, actor string, b *usageBatch, prior *store.AWSUsageState,
	existing map[string]*store.AWSUsageGap, read, refused int) error {
	var newGaps []store.AWSUsageGap
	for _, g := range b.gaps {
		if e := existing[g.Source+"\x00"+g.Ref]; e != nil && e.Code == g.Code && e.Detail == g.Detail && e.Day == g.Day {
			continue
		}
		newGaps = append(newGaps, g)
	}
	var clear []string
	for _, ref := range b.clear {
		if _, ok := existing[b.state.Source+"\x00"+ref]; ok {
			clear = append(clear, ref)
		}
	}
	changed := len(b.rows) > 0 || len(newGaps) > 0 || len(clear) > 0 || prior == nil
	if !changed {
		changed = string(prior.Cursor) != string(b.state.Cursor) || prior.CoveredFrom != b.state.CoveredFrom ||
			prior.CoveredTo != b.state.CoveredTo || prior.S3DataEvents != b.state.S3DataEvents
	}
	if !changed {
		return nil
	}
	return db.InTenant(context.WithoutCancel(ctx), tenant, func(c *store.TenantTx) error {
		now := s.now()
		for _, r := range b.rows {
			var err error
			if b.set {
				err = c.SetAWSUsage(r)
			} else {
				err = c.AddAWSUsage(r)
			}
			if err != nil {
				return err
			}
		}
		for i := range newGaps {
			if err := c.PutAWSUsageGap(&newGaps[i]); err != nil {
				return err
			}
		}
		for _, ref := range clear {
			if err := c.ClearAWSUsageGap(b.state.ConnectorID, b.state.Source, ref); err != nil {
				return err
			}
		}
		st := b.state
		st.UpdatedAt = now
		if err := c.PutAWSUsageState(&st); err != nil {
			return err
		}
		if _, err := c.PruneAWSUsage(now.Add(-usageRetention).UTC().Format(dayLayout)); err != nil {
			return err
		}
		if _, err := c.PruneAWSUsageGaps(now.Add(-gapRetention)); err != nil {
			return err
		}
		return c.Audit(now, actor, "aws.usage.ingested", ojson.Object{{Key: "connector_id", Value: st.ConnectorID}, {Key: "source", Value: st.Source},
			{Key: "read", Value: read}, {Key: "refused", Value: refused}, {Key: "rows", Value: len(b.rows)}, {Key: "gaps", Value: len(newGaps)}})
	})
}
