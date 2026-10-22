package ingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The deletion threshold guard (internal/deleteguard) for a sync: a source that suddenly reports
// many active identities as ended, or many active accounts as disabled, is held past the
// threshold instead of applied. The identity or account keeps its current (active) status; the
// held item carries the record to apply when a second admin releases it.

// Kinds of the items a sync holds.
const (
	ItemIdentityStatus = "identity_status"
	ItemAccountStatus  = "account_status"
)

// identitySnap is the sync's record of an identity, kept in a held item.
type identitySnap struct {
	ExternalID   string     `json:"external_id"`
	Name         string     `json:"name"`
	Email        *string    `json:"email,omitempty"`
	Type         string     `json:"type"`
	Department   *string    `json:"department,omitempty"`
	Title        *string    `json:"title,omitempty"`
	Status       string     `json:"status"`
	Description  *string    `json:"description,omitempty"`
	HiredAt      *time.Time `json:"hired_at,omitempty"`
	TerminatedAt *time.Time `json:"terminated_at,omitempty"`
}

func (s identitySnap) identity(now time.Time) *store.Identity {
	return &store.Identity{ExternalID: s.ExternalID, Name: s.Name, Email: s.Email, Type: s.Type, Department: s.Department,
		Title: s.Title, Status: s.Status, Description: s.Description, HiredAt: s.HiredAt, TerminatedAt: s.TerminatedAt, CreatedAt: now}
}

type held struct {
	identities map[string]bool
	accounts   map[[2]string]bool
}

// sourceKeys groups the results by the connection they were read through: the result's own SourceID, or
// the connection of its System. A result with neither (a demo, a flat file, an agent listing of an
// unknown system) is in the group "", judged under the tenant's settings alone.
func sourceKeys(c *store.TenantTx, results []*connectors.DiscoveryResult) (keys []string, groups map[string][]*connectors.DiscoveryResult, err error) {
	var byName map[string]string
	groups = map[string][]*connectors.DiscoveryResult{}
	for _, r := range results {
		key := r.SourceID
		if key == "" && r.System != "" {
			if byName == nil {
				byName = map[string]string{}
				conns, err := c.Connections()
				if err != nil {
					return nil, nil, err
				}
				for _, cn := range conns {
					if cn.RetiredAt == nil {
						byName[cn.System] = cn.ID
					}
				}
			}
			key = byName[r.System]
		}
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], r)
	}
	sort.Strings(keys)
	return keys, groups, nil
}

// vet asks the guard about every active identity and account the results turn inactive. Each source
// (connection) is judged on its own: its own settings, and its record counts against its own last good run.
func vet(c *store.TenantTx, now time.Time, results []*connectors.DiscoveryResult) (held, error) {
	h := held{identities: map[string]bool{}, accounts: map[[2]string]bool{}}
	keys, groups, err := sourceKeys(c, results)
	if err != nil {
		return h, err
	}
	tenantIdentities, err := c.DeletionPopulation(deleteguard.CatIdentities)
	if err != nil {
		return h, err
	}
	all, err := c.Accounts()
	if err != nil {
		return h, err
	}
	prevAccounts := map[string]int{}
	for _, a := range all {
		if a.Status == "active" {
			prevAccounts[a.System]++
		}
	}
	seen, seenA := map[string]bool{}, map[[2]string]bool{}
	for _, key := range keys {
		ref := deleteguard.SourceRef{Kind: deleteguard.SrcConnection, ID: key}
		if err := vetIdentities(c, now, ref, groups[key], tenantIdentities, seen, &h); err != nil {
			return h, err
		}
		if err := vetAccounts(c, now, ref, groups[key], prevAccounts, seenA, &h); err != nil {
			return h, err
		}
	}
	return h, nil
}

// suffix makes a correlation id stable per source: later runs of the same source join its open hold
// (their items are not held twice) instead of opening another every run.
func suffix(base, key string) string {
	if key == "" {
		return base
	}
	return base + ":" + key
}

func vetIdentities(c *store.TenantTx, now time.Time, ref deleteguard.SourceRef, results []*connectors.DiscoveryResult,
	tenantCount int, seen map[string]bool, h *held) error {
	partial, records := "", 0
	for _, r := range results {
		if r.Partial != "" {
			partial = r.Partial
		}
		records += len(r.Identities)
	}
	var items []deleteguard.Item
	for _, r := range results {
		for _, rec := range r.Identities {
			if defaultStr(rec.Status, "active") == "active" || seen[rec.ExternalID] {
				continue
			}
			seen[rec.ExternalID] = true
			cur, err := c.IdentityByExternalID(rec.ExternalID)
			if errors.Is(err, store.ErrNotFound) {
				continue // a new identity: nothing is being ended
			}
			if err != nil {
				return err
			}
			if cur.Status != "active" {
				continue
			}
			snap, err := json.Marshal(identitySnap{ExternalID: rec.ExternalID, Name: rec.Name, Email: rec.Email, Type: rec.Type,
				Department: rec.Department, Title: rec.Title, Status: rec.Status, Description: rec.Description, HiredAt: rec.HiredAt,
				TerminatedAt: rec.TerminatedAt})
			if err != nil {
				return err
			}
			items = append(items, deleteguard.Item{Kind: ItemIdentityStatus, Ref: string(snap),
				Label: fmt.Sprintf("%s (%s) set to %s", rec.Name, rec.ExternalID, rec.Status)})
		}
	}
	if records == 0 && partial == "" {
		return nil // a result with no identity feed says nothing about the source's identities
	}
	// the source's own last good run is the basis; the tenant's active identities only until it has one
	prev, err := deleteguard.PreviousCount(c, ref, deleteguard.CatIdentities, tenantCount)
	if err != nil {
		return err
	}
	sanity, err := deleteguard.CheckFeed(c, ref, deleteguard.CatIdentities, prev, records, partial)
	if err != nil {
		return err
	}
	if len(items) > 0 {
		d, err := deleteguard.AdmitWith(c, now, deleteguard.Request{Category: deleteguard.CatIdentities, Items: items,
			Source: deleteguard.SourceConnector, SourceID: ref.ID, SourceRef: ref, Correlation: suffix("ingest:identities", ref.ID),
			SourceDriven: true, Sanity: sanity, PrevCount: prev, NewCount: records})
		if err != nil {
			return err
		}
		for _, it := range d.Held {
			var s identitySnap
			if err := json.Unmarshal([]byte(it.Ref), &s); err != nil {
				return err
			}
			h.identities[s.ExternalID] = true
		}
	}
	if len(sanity) == 0 {
		return deleteguard.RecordGoodRun(c, now, ref, deleteguard.CatIdentities, records)
	}
	return nil
}

func vetAccounts(c *store.TenantTx, now time.Time, ref deleteguard.SourceRef, results []*connectors.DiscoveryResult,
	prevAccounts map[string]int, seenA map[[2]string]bool, h *held) error {
	partial, acRecords := "", map[string]int{}
	for _, r := range results {
		if r.Partial != "" {
			partial = r.Partial
		}
		for _, a := range r.Accounts {
			acRecords[a.System]++
		}
	}
	var items []deleteguard.Item
	systems := map[string]bool{}
	for _, r := range results {
		for _, rec := range r.Accounts {
			k := [2]string{rec.System, rec.ExternalID}
			if defaultStr(rec.Status, "active") != "disabled" || seenA[k] {
				continue
			}
			seenA[k] = true
			cur, err := c.AccountByXID(rec.System, rec.ExternalID)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if cur.Status != "active" {
				continue
			}
			systems[rec.System] = true
			rf, err := json.Marshal([2]string{rec.System, rec.ExternalID})
			if err != nil {
				return err
			}
			items = append(items, deleteguard.Item{Kind: ItemAccountStatus, Ref: string(rf),
				Label: fmt.Sprintf("account %s in %s disabled", cur.Username, rec.System)})
		}
	}
	if len(items) == 0 {
		return nil
	}
	var names []string
	for s := range systems {
		names = append(names, s)
	}
	sort.Strings(names)
	joined := strings.Join(names, ",")
	var sanity []string
	prev, cur := 0, 0
	for _, sysName := range names {
		prev, cur = prev+prevAccounts[sysName], cur+acRecords[sysName]
		sc, err := deleteguard.CheckFeed(c, ref, deleteguard.CatAccounts, prevAccounts[sysName], acRecords[sysName], partial)
		if err != nil {
			return err
		}
		sanity = append(sanity, sc...)
	}
	req := deleteguard.Request{Category: deleteguard.CatAccounts, Items: items, Source: deleteguard.SourceConnector, SourceID: joined,
		Correlation: "ingest:accounts:" + joined, SourceDriven: true, Sanity: sanity, PrevCount: prev, NewCount: cur}
	if ref.ID != "" {
		req.SourceID, req.SourceRef, req.Correlation = ref.ID, ref, "ingest:accounts:"+ref.ID
	}
	d, err := deleteguard.AdmitWith(c, now, req)
	if err != nil {
		return err
	}
	for _, it := range d.Held {
		var k [2]string
		if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
			return err
		}
		h.accounts[k] = true
	}
	return nil
}

// ReleaseIdentity applies a held identity status: the sync's record is written again if the
// identity is still active.
func ReleaseIdentity(tx *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (outcome, note string, err error) {
	var s identitySnap
	if err := json.Unmarshal([]byte(it.Ref), &s); err != nil {
		return "", "", fmt.Errorf("ingest: bad held identity: %w", err)
	}
	cur, err := tx.IdentityByExternalID(s.ExternalID)
	if errors.Is(err, store.ErrNotFound) {
		return deleteguard.ItemGone, "the identity no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	if cur.Status != "active" {
		return deleteguard.ItemGone, "the identity is already " + cur.Status, nil
	}
	if err := tx.UpsertIdentity(s.identity(now)); err != nil {
		return "", "", err
	}
	return deleteguard.ItemReleased, "", nil
}

// ReleaseAccount disables a held account if it is still active.
func ReleaseAccount(tx *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (outcome, note string, err error) {
	var k [2]string
	if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
		return "", "", fmt.Errorf("ingest: bad held account: %w", err)
	}
	a, err := tx.AccountByXID(k[0], k[1])
	if errors.Is(err, store.ErrNotFound) {
		return deleteguard.ItemGone, "the account no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	if a.Status != "active" {
		return deleteguard.ItemGone, "the account is already " + a.Status, nil
	}
	if err := tx.DisableAccount(a.ID); err != nil {
		return "", "", err
	}
	return deleteguard.ItemReleased, "", nil
}
