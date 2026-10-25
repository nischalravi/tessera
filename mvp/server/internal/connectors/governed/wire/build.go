// Package wire opens governed connections (internal/connectors/governed) with
// the existing connector packages: it builds a connector through each
// connector's own FromEnv mapping and a read-only prober over its client. It is
// separate from package governed because it imports every connector package,
// and the readiness packages (which only need the registry and the settings)
// must not: the connectors' tests import ingest, which imports readiness. The
// server hands these functions to readiness (readiness.GovOptions).
package wire

import (
	"context"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentcore"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/atlassian"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/azurerbac"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/erp"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/gcpiam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/githubscan"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/kubernetes"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/servicenow"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sftpdrop"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/successfactors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/unixssh"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vault"
)

// Connector builds the connector of a connection by the connector's own
// FromEnv, so a governed connection reads exactly what the env-configured one
// does. rt and hc are the server's (the validated runtime and the safehttp
// client); the result reports Stats so the dry run's data checks have counts.
func Connector(p governed.Params, n governed.Net) (connectors.Connector, error) {
	rt, hc, now := n.RT, n.HC, n.Now
	getenv, err := p.Env()
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	var cn connectors.Connector
	switch p.Type {
	case governed.CyberArk, governed.Delinea, governed.BeyondTrust:
		cn, err = pam.FromEnv(p.Type, getenv, rt, hc, now)
	case governed.SAP, governed.Oracle:
		cn, err = erp.FromEnv(p.Type, getenv, rt, hc, now)
	case governed.GitHubScan:
		cn, err = githubscan.FromEnv(getenv, now(), rt, hc)
	case governed.SuccessFactors:
		cn, err = successfactors.FromEnv(getenv, now(), rt, hc)
	case governed.AgentCore:
		cn, err = agentcore.FromEnv(getenv, now())
	case governed.ServiceNow:
		cn, err = servicenow.FromEnv(getenv, rt, hc, now)
	case governed.Atlassian:
		if getenv, err = n.Overrides(getenv); err != nil {
			return nil, err
		}
		cn, err = atlassian.FromEnv(getenv, rt, hc, now)
	case governed.Kubernetes:
		cn, err = kubernetes.FromEnv(getenv, rt, hc, now)
	case governed.Vault:
		cn, err = vault.FromEnv(getenv, rt, hc, now)
	case governed.UnixSSH:
		cn, err = unixssh.FromEnv(getenv, rt)
	case governed.SFTPDrop:
		cn, err = sftpdrop.FromEnv(getenv, rt)
	case governed.AzureRBAC, governed.GCPIAM:
		if getenv, err = n.Overrides(getenv); err != nil {
			return nil, err
		}
		if p.Type == governed.AzureRBAC {
			cn, err = azurerbac.FromEnv(getenv, rt, hc, now)
		} else {
			cn, err = gcpiam.FromEnv(getenv, rt, hc, now)
		}
	}
	if err != nil {
		return nil, err
	}
	return &counted{Connector: cn}, nil
}

// counted adds the class counts the readiness data checks read (the
// connector's own result is otherwise untouched): one "user" class over the
// connector's accounts, with how many carry an id, a username and a status and
// how many ids are distinct.
type counted struct{ connectors.Connector }

func (c *counted) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	res, err := c.Connector.Discover(ctx)
	if err != nil || res == nil || res.Stats != nil {
		return res, err
	}
	sys := c.System()
	var total, id, name, status int
	ids := map[string]bool{}
	for _, a := range res.Accounts {
		if a.System != sys {
			continue
		}
		total++
		if a.ExternalID != "" {
			id++
			ids[a.ExternalID] = true
		}
		if a.Username != "" {
			name++
		}
		if a.Status != "" {
			status++
		}
	}
	if total > 0 {
		res.Stats = &connectors.DiscoveryStats{Classes: map[string]*connectors.ClassStats{"user": {Total: total,
			Attributes: map[string]connectors.AttrStat{
				"id":       {Present: id, Distinct: len(ids)},
				"username": {Present: name, Distinct: name},
				"status":   {Present: status, Distinct: status},
			}}}}
	}
	return res, nil
}
