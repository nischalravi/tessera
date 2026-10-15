package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Account correlation decisions and identity merges (schema/0204_correlation.sql).

// AccountLink is a reviewer's pinned decision about one account.
type AccountLink struct {
	AccountID          int64
	Decision           string // "link" or "not_person"
	IdentityID         *int64 // set for "link"
	PreviousIdentityID *int64 // the account's identity before the decision
	Reason             string
	DecidedBy          string
	DecidedAt          time.Time
}

// Link decisions.
const (
	LinkDecisionLink      = "link"
	LinkDecisionNotPerson = "not_person"
)

// IdentityStatusMerged is the status of an identity merged into another.
const IdentityStatusMerged = "merged"

// MergeMove is one row a merge re-pointed from the merged identity to the survivor.
type MergeMove struct {
	Table  string `json:"table"`  // accounts, identities, agent_delegations, account_links
	ID     int64  `json:"id"`     // the row (account_links: the account id)
	Column string `json:"column"` // identity_id, owner_id, manager_id, principal_id
}

// IdentityMerge is a recorded merge.
type IdentityMerge struct {
	ID            string
	SurvivorID    int64
	MergedID      int64
	MergedStatus  string
	Moves         []MergeMove
	Reason        string
	MergedBy      string
	MergedAt      time.Time
	UnmergedBy    *string
	UnmergedAt    *time.Time
	UnmergeReason *string
}

const accountLinkCols = `l.account_id, l.decision, l.identity_id, l.previous_identity_id, l.reason, l.decided_by, l.decided_at`

const mergeCols = `m.id, m.survivor_id, m.merged_id, m.merged_status, m.moves, m.reason, m.merged_by, m.merged_at,
	m.unmerged_by, m.unmerged_at, m.unmerge_reason`

var (
	accountLinksList = tq("account_links.list", `
		SELECT `+accountLinkCols+` FROM account_links l WHERE l.tenant_id = @tenant ORDER BY l.account_id`)
	accountLinksGet = tq("account_links.get", `
		SELECT `+accountLinkCols+` FROM account_links l WHERE l.tenant_id = @tenant AND l.account_id = @account_id`)
	accountLinksByIdentity = tq("account_links.by_identity", `
		SELECT `+accountLinkCols+` FROM account_links l WHERE l.tenant_id = @tenant AND l.identity_id = @identity_id
		ORDER BY l.account_id`)
	accountLinksPut = tq("account_links.put", `
		INSERT INTO account_links (tenant_id, account_id, decision, identity_id, previous_identity_id, reason, decided_by, decided_at)
		VALUES (@tenant, @account_id, @decision, @identity_id, @previous_identity_id, @reason, @decided_by, @decided_at)
		ON CONFLICT (tenant_id, account_id) DO UPDATE SET decision = excluded.decision, identity_id = excluded.identity_id,
			previous_identity_id = excluded.previous_identity_id, reason = excluded.reason,
			decided_by = excluded.decided_by, decided_at = excluded.decided_at`)
	accountLinksDelete = tq("account_links.delete", `
		DELETE FROM account_links WHERE tenant_id = @tenant AND account_id = @account_id`)
	accountLinksSetIdentity = tq("account_links.set_identity", `
		UPDATE account_links SET identity_id = @identity_id WHERE tenant_id = @tenant AND account_id = @account_id
			AND decision = 'link'`)

	accountsSetIdentity = tq("accounts.set_identity", `
		UPDATE accounts SET identity_id = @identity_id WHERE tenant_id = @tenant AND id = @id`)
	identitiesSetStatus = tq("identities.set_status", `
		UPDATE identities SET status = @status WHERE tenant_id = @tenant AND id = @id`)
	delegationsSetPrincipal = tq("agent_delegations.set_principal", `
		UPDATE agent_delegations SET principal_id = @ref WHERE tenant_id = @tenant AND id = @id`)
	delegationsByPrincipal = tq("agent_delegations.ids_by_principal", `
		SELECT d.id FROM agent_delegations d WHERE d.tenant_id = @tenant AND d.principal_id = @principal_id ORDER BY d.id`)
	delegationPrincipal = tq("agent_delegations.principal", `
		SELECT d.principal_id FROM agent_delegations d WHERE d.tenant_id = @tenant AND d.id = @id`)
	platformUsersForIdentity = tq("platform_users.count_for_identity", `
		SELECT count(u.id) FROM platform_users u WHERE u.tenant_id = @tenant AND u.identity_id = @identity_id`)

	mergesInsert = tq("identity_merges.insert", `
		INSERT INTO identity_merges (id, tenant_id, survivor_id, merged_id, merged_status, moves, reason, merged_by, merged_at)
		VALUES (@id, @tenant, @survivor_id, @merged_id, @merged_status, @moves, @reason, @merged_by, @merged_at)`)
	mergesList = tq("identity_merges.list", `
		SELECT `+mergeCols+` FROM identity_merges m WHERE m.tenant_id = @tenant ORDER BY m.merged_at DESC, m.id`)
	mergesOpen = tq("identity_merges.open", `
		SELECT `+mergeCols+` FROM identity_merges m WHERE m.tenant_id = @tenant AND m.unmerged_at IS NULL ORDER BY m.merged_at, m.id`)
	mergesGet = tq("identity_merges.get", `
		SELECT `+mergeCols+` FROM identity_merges m WHERE m.tenant_id = @tenant AND m.id = @id`)
	mergesUnmerge = tq("identity_merges.unmerge", `
		UPDATE identity_merges SET unmerged_by = @unmerged_by, unmerged_at = @unmerged_at, unmerge_reason = @unmerge_reason
		WHERE tenant_id = @tenant AND id = @id AND unmerged_at IS NULL`)
)

func scanAccountLink(s scanner) (*AccountLink, error) {
	var l AccountLink
	var iid, prev sql.NullInt64
	var at nullTime
	if err := s.Scan(&l.AccountID, &l.Decision, &iid, &prev, &l.Reason, &l.DecidedBy, &at); err != nil {
		return nil, err
	}
	l.IdentityID, l.PreviousIdentityID = intp(iid), intp(prev)
	var err error
	l.DecidedAt, err = at.val()
	return &l, err
}

func scanMerge(s scanner) (*IdentityMerge, error) {
	var m IdentityMerge
	var moves string
	var at, unAt nullTime
	var unBy, unReason sql.NullString
	if err := s.Scan(&m.ID, &m.SurvivorID, &m.MergedID, &m.MergedStatus, &moves, &m.Reason, &m.MergedBy, &at,
		&unBy, &unAt, &unReason); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(moves), &m.Moves); err != nil {
		return nil, fmt.Errorf("store: identity_merges.moves: %w", err)
	}
	var err error
	if m.MergedAt, err = at.val(); err != nil {
		return nil, err
	}
	if m.UnmergedAt, err = unAt.ptr(); err != nil {
		return nil, err
	}
	m.UnmergedBy, m.UnmergeReason = strp(unBy), strp(unReason)
	return &m, nil
}

// AccountLinks returns every pinned decision, by account id.
func (tx *TenantTx) AccountLinks() ([]*AccountLink, error) {
	return collect(tx, scanAccountLink, accountLinksList)
}

// AccountLink returns the pinned decision for an account, or ErrNotFound.
func (tx *TenantTx) AccountLink(accountID int64) (*AccountLink, error) {
	return one(tx, scanAccountLink, accountLinksGet, sql.Named("account_id", accountID))
}

// AccountLinksTo returns the "link" decisions that name identityID.
func (tx *TenantTx) AccountLinksTo(identityID int64) ([]*AccountLink, error) {
	return collect(tx, scanAccountLink, accountLinksByIdentity, sql.Named("identity_id", identityID))
}

// PutAccountLink records (or replaces) the decision for an account.
func (tx *TenantTx) PutAccountLink(l *AccountLink) error {
	_, err := tx.exec(accountLinksPut, sql.Named("account_id", l.AccountID), sql.Named("decision", l.Decision),
		sql.Named("identity_id", IP(l.IdentityID)), sql.Named("previous_identity_id", IP(l.PreviousIdentityID)),
		sql.Named("reason", l.Reason), sql.Named("decided_by", l.DecidedBy), sql.Named("decided_at", T(l.DecidedAt)))
	return err
}

// DeleteAccountLink removes an account's decision; ErrNotFound if there is none.
func (tx *TenantTx) DeleteAccountLink(accountID int64) error {
	res, err := tx.exec(accountLinksDelete, sql.Named("account_id", accountID))
	return affectedOne(res, err)
}

// SetAccountIdentity points an account at an identity (nil: no identity).
func (tx *TenantTx) SetAccountIdentity(accountID int64, identityID *int64) error {
	res, err := tx.exec(accountsSetIdentity, sql.Named("id", accountID), sql.Named("identity_id", IP(identityID)))
	return affectedOne(res, err)
}

// SetIdentityStatus sets an identity's status.
func (tx *TenantTx) SetIdentityStatus(id int64, status string) error {
	res, err := tx.exec(identitiesSetStatus, sql.Named("id", id), sql.Named("status", status))
	return affectedOne(res, err)
}

// DelegationIDsByPrincipal lists the agent delegations made by principal.
func (tx *TenantTx) DelegationIDsByPrincipal(principal int64) ([]int64, error) {
	rows, err := tx.query(delegationsByPrincipal, sql.Named("principal_id", principal))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// PlatformUsersForIdentity counts the sign-in users bound to an identity.
func (tx *TenantTx) PlatformUsersForIdentity(identityID int64) (int, error) {
	return tx.count(platformUsersForIdentity, sql.Named("identity_id", identityID))
}

// MoveRef reads the current value of a move's column (nil when NULL or the
// row is gone).
func (tx *TenantTx) MoveRef(m MergeMove) (*int64, error) {
	var v sql.NullInt64
	var err error
	switch m.Table + "." + m.Column {
	case "accounts.identity_id":
		var a *Account
		if a, err = tx.Account(m.ID); err == nil {
			return a.IdentityID, nil
		}
	case "identities.owner_id", "identities.manager_id":
		var i *Identity
		if i, err = tx.Identity(m.ID); err == nil {
			if m.Column == "owner_id" {
				return i.OwnerID, nil
			}
			return i.ManagerID, nil
		}
	case "agent_delegations.principal_id":
		err = tx.queryRow(delegationPrincipal, sql.Named("id", m.ID)).Scan(&v)
		if err == nil {
			return intp(v), nil
		}
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrNotFound
		}
	case "account_links.identity_id":
		var l *AccountLink
		if l, err = tx.AccountLink(m.ID); err == nil {
			return l.IdentityID, nil
		}
	default:
		return nil, fmt.Errorf("store: unknown merge move %s.%s", m.Table, m.Column)
	}
	return nil, err
}

// ApplyMove sets a move's column to ref.
func (tx *TenantTx) ApplyMove(m MergeMove, ref int64) error {
	var res sql.Result
	var err error
	switch m.Table + "." + m.Column {
	case "accounts.identity_id":
		res, err = tx.exec(accountsSetIdentity, sql.Named("id", m.ID), sql.Named("identity_id", ref))
	case "identities.owner_id":
		res, err = tx.exec(identitiesSetOwner, sql.Named("id", m.ID), sql.Named("owner_id", ref))
	case "identities.manager_id":
		res, err = tx.exec(identitiesSetManager, sql.Named("id", m.ID), sql.Named("manager_id", ref))
	case "agent_delegations.principal_id":
		res, err = tx.exec(delegationsSetPrincipal, sql.Named("id", m.ID), sql.Named("ref", ref))
	case "account_links.identity_id":
		res, err = tx.exec(accountLinksSetIdentity, sql.Named("account_id", m.ID), sql.Named("identity_id", ref))
	default:
		return fmt.Errorf("store: unknown merge move %s.%s", m.Table, m.Column)
	}
	return affectedOne(res, err)
}

// InsertIdentityMerge records a merge.
func (tx *TenantTx) InsertIdentityMerge(m *IdentityMerge) error {
	moves, err := JSON(m.Moves)
	if err != nil {
		return err
	}
	_, err = tx.exec(mergesInsert, sql.Named("id", m.ID), sql.Named("survivor_id", m.SurvivorID),
		sql.Named("merged_id", m.MergedID), sql.Named("merged_status", m.MergedStatus), sql.Named("moves", moves),
		sql.Named("reason", m.Reason), sql.Named("merged_by", m.MergedBy), sql.Named("merged_at", T(m.MergedAt)))
	return err
}

// IdentityMerges lists merges, newest first.
func (tx *TenantTx) IdentityMerges() ([]*IdentityMerge, error) {
	return collect(tx, scanMerge, mergesList)
}

// OpenIdentityMerges lists merges not undone, oldest first.
func (tx *TenantTx) OpenIdentityMerges() ([]*IdentityMerge, error) {
	return collect(tx, scanMerge, mergesOpen)
}

// IdentityMerge returns one merge, or ErrNotFound.
func (tx *TenantTx) IdentityMerge(id string) (*IdentityMerge, error) {
	return one(tx, scanMerge, mergesGet, sql.Named("id", id))
}

// MarkUnmerged records an unmerge; ErrNotFound if the merge is unknown or
// already undone.
func (tx *TenantTx) MarkUnmerged(id, by, reason string, at time.Time) error {
	res, err := tx.exec(mergesUnmerge, sql.Named("id", id), sql.Named("unmerged_by", by),
		sql.Named("unmerged_at", T(at)), sql.Named("unmerge_reason", reason))
	return affectedOne(res, err)
}

// MergeSurvivors maps each identity merged (and not unmerged) to its final
// survivor, following chains (a merged into b, b into c gives a → c).
func (tx *TenantTx) MergeSurvivors() (map[int64]int64, error) {
	open, err := tx.OpenIdentityMerges()
	if err != nil {
		return nil, err
	}
	next := map[int64]int64{}
	for _, m := range open {
		next[m.MergedID] = m.SurvivorID
	}
	out := make(map[int64]int64, len(next))
	for id := range next {
		s, seen := id, map[int64]bool{}
		for {
			n, ok := next[s]
			if !ok || seen[n] {
				break
			}
			seen[s] = true
			s = n
		}
		out[id] = s
	}
	return out, nil
}

// affectedOne maps an exec that changed no row to ErrNotFound.
func affectedOne(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
