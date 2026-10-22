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

// vet asks the guard about every active identity and account the results turn inactive.
func vet(c *store.TenantTx, now time.Time, results []*connectors.DiscoveryResult) (held, error) {
	h := held{identities: map[string]bool{}, accounts: map[[2]string]bool{}}
	// the correlation is stable per source and category: while a batch is held, later runs of the same
	// source join that hold (their items are not held twice) instead of opening another every run
	partial := ""
	idRecords, acRecords := 0, map[string]int{}
	for _, r := range results {
		if r.Partial != "" {
			partial = r.Partial
		}
		idRecords += len(r.Identities)
		for _, a := range r.Accounts {
			acRecords[a.System]++
		}
	}
	prevIdentities, err := c.DeletionPopulation(deleteguard.CatIdentities)
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

	var idItems []deleteguard.Item
	seen := map[string]bool{}
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
				return h, err
			}
			if cur.Status != "active" {
				continue
			}
			snap, err := json.Marshal(identitySnap{ExternalID: rec.ExternalID, Name: rec.Name, Email: rec.Email, Type: rec.Type,
				Department: rec.Department, Title: rec.Title, Status: rec.Status, Description: rec.Description, HiredAt: rec.HiredAt,
				TerminatedAt: rec.TerminatedAt})
			if err != nil {
				return h, err
			}
			idItems = append(idItems, deleteguard.Item{Kind: ItemIdentityStatus, Ref: string(snap),
				Label: fmt.Sprintf("%s (%s) set to %s", rec.Name, rec.ExternalID, rec.Status)})
		}
	}
	if len(idItems) > 0 {
		var sanity []string
		if idRecords > 0 || partial != "" {
			sanity = deleteguard.FeedChecks(prevIdentities, idRecords, partial)
		}
		d, err := deleteguard.AdmitWith(c, now, deleteguard.Request{Category: deleteguard.CatIdentities, Items: idItems,
			Source: deleteguard.SourceConnector, Correlation: "ingest:identities", SourceDriven: true, Sanity: sanity,
			PrevCount: prevIdentities, NewCount: idRecords})
		if err != nil {
			return h, err
		}
		for _, it := range d.Held {
			var s identitySnap
			if err := json.Unmarshal([]byte(it.Ref), &s); err != nil {
				return h, err
			}
			h.identities[s.ExternalID] = true
		}
	}

	var acItems []deleteguard.Item
	systems := map[string]bool{}
	seenA := map[[2]string]bool{}
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
				return h, err
			}
			if cur.Status != "active" {
				continue
			}
			systems[rec.System] = true
			ref, err := json.Marshal([2]string{rec.System, rec.ExternalID})
			if err != nil {
				return h, err
			}
			acItems = append(acItems, deleteguard.Item{Kind: ItemAccountStatus, Ref: string(ref),
				Label: fmt.Sprintf("account %s in %s disabled", cur.Username, rec.System)})
		}
	}
	if len(acItems) > 0 {
		var names []string
		for s := range systems {
			names = append(names, s)
		}
		sort.Strings(names)
		var sanity []string
		prev, cur := 0, 0
		for _, sysName := range names {
			prev, cur = prev+prevAccounts[sysName], cur+acRecords[sysName]
			sanity = append(sanity, deleteguard.FeedChecks(prevAccounts[sysName], acRecords[sysName], partial)...)
		}
		d, err := deleteguard.AdmitWith(c, now, deleteguard.Request{Category: deleteguard.CatAccounts, Items: acItems,
			Source: deleteguard.SourceConnector, SourceID: strings.Join(names, ","), Correlation: "ingest:accounts:" + strings.Join(names, ","),
			SourceDriven: true, Sanity: sanity, PrevCount: prev, NewCount: cur})
		if err != nil {
			return h, err
		}
		for _, it := range d.Held {
			var k [2]string
			if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
				return h, err
			}
			h.accounts[k] = true
		}
	}
	return h, nil
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
