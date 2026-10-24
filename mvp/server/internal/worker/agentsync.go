package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// agentActor is the audit actor of a sync an agent reported.
const agentActor = "directory-agent"

// AgentSyncPayload builds the sync job of a connection from its live
// revision, or ok=false when the connection does not reach its directory
// through an agent (or is not a directory the agent can read). It carries no
// secret: the credential is named, and lives on the agent.
func AgentSyncPayload(c *store.Connection, rev *store.ConnectionRevision) (agentID string, spec agent.SyncSpec, ok bool, err error) {
	if rev == nil || rev.SecretRef == nil || rev.TemplateID != "ldap" || !strings.HasPrefix(*rev.SecretRef, "agent:") {
		return "", spec, false, nil
	}
	id, cred, valid := agent.ParseRef(*rev.SecretRef)
	if !valid {
		return "", spec, false, fmt.Errorf("connection %s: the Directory Agent credential reference is malformed", c.Name)
	}
	cfg, err := readiness.DecodeConfig([]byte(rev.Config))
	if err != nil {
		return "", spec, false, err
	}
	spec = agent.SyncSpec{System: c.System, Target: agent.Target{Host: cfg.Host, Port: cfg.Port, TLSMode: cfg.TLSMode},
		Config: agent.ProbeConfig{BindDN: cfg.BindDN, CredName: cred, BaseDNs: cfg.BaseDNs, UserFilter: cfg.UserFilter,
			CABundle: cfg.CABundle, PageSize: cfg.PageSize, AttrMap: attrMap(cfg.AttrMap)}}
	if err := spec.Validate(); err != nil {
		return "", spec, false, fmt.Errorf("connection %s: %w", c.Name, err)
	}
	return id, spec, true, nil
}

// QueueAgentSyncs queues one sync job for every live connection of the tenant
// that is bound to an active Directory Agent of the tenant (the active
// revision's credential reference names it). A connection that already has an
// open job is skipped, so a schedule never stacks work behind an agent that
// is away; a connection whose agent is missing or revoked is skipped (the
// readiness checks report it). window makes the keys unique per run. It
// returns how many jobs were queued.
func QueueAgentSyncs(tx *store.TenantTx, now time.Time, window string) (int, error) {
	conns, err := tx.Connections()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range conns {
		if c.RetiredAt != nil || c.ActiveRevisionID == nil {
			continue
		}
		rev, err := tx.Revision(*c.ActiveRevisionID)
		if err != nil {
			return n, err
		}
		agentID, spec, ok, err := AgentSyncPayload(c, rev)
		if err != nil || !ok {
			if err != nil {
				return n, err
			}
			continue
		}
		a, err := tx.DirectoryAgent(agentID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && a.Status != store.AgentActive) {
			continue
		}
		if err != nil {
			return n, err
		}
		if open, err := tx.HasOpenAgentJob(c.ID, store.AgentJobSync); err != nil {
			return n, err
		} else if open {
			continue
		}
		raw, err := json.Marshal(spec)
		if err != nil {
			return n, err
		}
		key := "sync:" + c.ID + ":" + window
		created, err := tx.EnqueueAgentJob(&store.AgentJob{AgentID: a.ID, ConnectionID: c.ID, Kind: store.AgentJobSync,
			Payload: string(raw), IdempotencyKey: &key}, now)
		if err != nil {
			return n, err
		}
		if created {
			n++
		}
	}
	return n, nil
}

// RecordAgentSync is the agent.SyncRecorder: it turns an agent's typed
// listing into connector records and ingests them through the same path as
// any connector sync, inside the transaction that finishes the job. The
// records are the connection's own system (not whatever the agent says), and
// the listing was validated by the agent service before it got here.
func RecordAgentSync(tx *store.TenantTx, now time.Time, job *store.AgentJob, _ agent.SyncSpec, res *agent.SyncResult) (ojson.Object, error) {
	conn, err := tx.Connection(job.ConnectionID)
	if err != nil {
		return nil, err
	}
	dr := &connectors.DiscoveryResult{}
	for _, a := range res.Accounts {
		rec := connectors.AccountRecord{System: conn.System, ExternalID: a.ExternalID, Username: a.Username, Kind: "user", Status: a.Status}
		if a.Email != "" {
			rec.Identity = &connectors.IdentityRef{Email: a.Email}
		}
		dr.Accounts = append(dr.Accounts, rec)
	}
	for _, g := range res.Groups {
		dr.Groups = append(dr.Groups, connectors.GroupRecord{System: conn.System, ExternalID: g.ExternalID, Name: g.Name,
			Kind: "security_group", Privileged: g.Privileged})
	}
	for _, m := range res.Members {
		dr.Edges = append(dr.Edges, connectors.EdgeRecord{
			Src:      connectors.Ref{Kind: "account", System: conn.System, ExternalID: m.Account},
			Dst:      connectors.Ref{Kind: "group", System: conn.System, ExternalID: m.Group},
			Relation: "member_of"})
	}
	stats, err := ingest.Discovery(tx, now, []*connectors.DiscoveryResult{dr}, false)
	if err != nil {
		return nil, err
	}
	detail := append(ojson.Object{{Key: "connection_id", Value: conn.ID}, {Key: "system", Value: conn.System},
		{Key: "job_id", Value: job.ID}}, stats.Object()...)
	if err := tx.Audit(now, agentActor, "connectors.sync", detail); err != nil {
		return nil, err
	}
	if _, err := reconcile.RunDrift(tx, now, agentActor); err != nil {
		return nil, err
	}
	return stats.Object(), nil
}
