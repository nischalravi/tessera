package provision

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/scim"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// DiscoveryRecord is the stored result of reading a SCIM target's
// ServiceProviderConfig and ResourceTypes (issue #542). Error is set when a
// document could not be read; the other fields then hold what was.
type DiscoveryRecord struct {
	CheckedAt             string   `json:"checked_at"`
	AgentAdvertised       bool     `json:"agent_advertised"`
	ServiceProviderConfig bool     `json:"service_provider_config"`
	ResourceTypes         []string `json:"resource_types"`
	// Capabilities are what the service advertised; later runs use them to pick PATCH or PUT, filters and ETags.
	Capabilities *scim.Capabilities `json:"capabilities,omitempty"`
	Error        string             `json:"error,omitempty"`
}

// Discover reads the target's discovery documents and records the result in
// the target's settings. A failed read is recorded, not returned as an error:
// discovery is read-only and must never affect Users/Groups provisioning.
func (e *Engine) Discover(ctx context.Context, t tenancy.ID, connID string) (*DiscoveryRecord, error) {
	if e.HTTP == nil || e.Build != nil {
		return nil, &Error{503, "discovery_unavailable", "discovery needs the outbound client of the server"}
	}
	var pt *store.ProvTarget
	err := e.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		pt, err = tx.ProvTarget(connID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Error{404, "not_found", "the connection has no provisioning target"}
	}
	if err != nil {
		return nil, err
	}
	var s Settings
	if err := json.Unmarshal([]byte(pt.Settings), &s); err != nil {
		return nil, &Error{422, "target_unreadable", "the target's settings are unreadable"}
	}
	if pt.Kind != KindSCIM {
		return nil, &Error{422, "discovery_unavailable", "discovery is available for SCIM targets"}
	}
	if s.AgentID != "" {
		return nil, &Error{422, "discovery_unavailable", "this target is reached through a Directory Agent; the server cannot call it"}
	}
	rec := &DiscoveryRecord{ResourceTypes: []string{}}
	token, err := e.openToken(t, pt)
	hc := e.HTTP
	if err == nil {
		hc, err = e.httpFor(ctx, t, connID)
	}
	if err != nil {
		rec.Error = truncate(safehttp.ScrubError(err, pt.BaseURL), 300)
	} else {
		cctx, cancel := e.call(ctx)
		defer cancel()
		c := s.scimClient(hc, pt.BaseURL, token)
		d, derr := c.Discover(cctx)
		rec.AgentAdvertised, rec.ServiceProviderConfig, rec.ResourceTypes = d.AgentAdvertised, d.ServiceProviderConfig, d.ResourceTypes
		rec.Capabilities = d.Capabilities
		if derr != nil {
			rec.Error = truncate(safehttp.ScrubError(derr, pt.BaseURL), 300)
		}
	}
	rec.CheckedAt = timeutil.ISO(e.Clock())
	err = e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		cur, err := tx.ProvTarget(connID)
		if err != nil {
			return err
		}
		var cs Settings
		if err := json.Unmarshal([]byte(cur.Settings), &cs); err != nil {
			return err
		}
		cs.Discovery = rec
		b, err := json.Marshal(cs)
		if err != nil {
			return err
		}
		cur.Settings = string(b)
		return tx.UpsertProvTarget(cur, e.Clock())
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Error{404, "not_found", "the connection has no provisioning target"}
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
