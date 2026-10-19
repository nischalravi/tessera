package store

import (
	"database/sql"
	"time"
)

// Separation of duties: functions, risks, rulesets (schema/0300_sod.sql,
// issue #298).

// SoD statuses and version kinds.
const (
	SodActive  = "active"
	SodRetired = "retired"

	SodKindFunction = "function"
	SodKindRisk     = "risk"
	SodKindRuleset  = "ruleset"
)

// SodFunction is a named, reusable set of entitlements (Selectors is the JSON
// of internal/sod).
type SodFunction struct {
	ID          string
	Key         string
	Name        string
	Description string
	OwnerID     *int64
	Selectors   string
	Status      string
	Version     int
	CreatedAt   time.Time
	UpdatedBy   *string
	UpdatedAt   time.Time
}

// SodRuleset is a named group of risks, enabled or disabled per tenant.
type SodRuleset struct {
	ID          string
	Key         string
	Name        string
	Description string
	Enabled     bool
	Status      string
	Version     int
	CreatedAt   time.Time
	UpdatedBy   *string
	UpdatedAt   time.Time
}

// SodRisk is a prioritised conflict between two or more functions.
type SodRisk struct {
	ID              string
	Key             string
	Name            string
	Description     string
	Priority        string
	BusinessProcess string
	OwnerID         *int64
	RulesetID       string
	Subjects        string // JSON: identity_types, statuses, condition
	Status          string
	Version         int
	CreatedAt       time.Time
	UpdatedBy       *string
	UpdatedAt       time.Time
}

// SodRiskFunction links a risk to one of its functions (Ord is the order the
// risk lists them in).
type SodRiskFunction struct {
	RiskID     string
	FunctionID string
	Ord        int
}

// SodVersion is a snapshot of one saved change of a function, risk or ruleset.
type SodVersion struct {
	ID        int64
	Kind      string
	ObjectID  string
	Version   int
	Snapshot  string // JSON
	Note      *string
	ChangedBy *string
	Actor     string
	ChangedAt time.Time
}

const (
	sfCols = `f.id, f.key, f.name, f.description, f.owner_identity_id, f.selectors, f.status, f.version, f.created_at,
		f.updated_by, f.updated_at`
	srsCols = `s.id, s.key, s.name, s.description, s.enabled, s.status, s.version, s.created_at, s.updated_by, s.updated_at`
	srCols  = `r.id, r.key, r.name, r.description, r.priority, r.business_process, r.owner_identity_id, r.ruleset_id,
		r.subjects, r.status, r.version, r.created_at, r.updated_by, r.updated_at`
)

var (
	sfList = tq("sod_functions.list", `
		SELECT `+sfCols+` FROM sod_functions f WHERE f.tenant_id = @tenant ORDER BY f.name, f.id`)
	sfGet = tq("sod_functions.get", `
		SELECT `+sfCols+` FROM sod_functions f WHERE f.tenant_id = @tenant AND f.id = @id`)
	sfByKey = tq("sod_functions.by_key", `
		SELECT `+sfCols+` FROM sod_functions f WHERE f.tenant_id = @tenant AND f.key = @key`)
	sfByName = tq("sod_functions.by_name", `
		SELECT `+sfCols+` FROM sod_functions f WHERE f.tenant_id = @tenant AND f.name = @name`)
	sfInsert = tq("sod_functions.insert", `
		INSERT INTO sod_functions (id, tenant_id, key, name, description, owner_identity_id, selectors, status, version,
			created_at, updated_by, updated_at)
		VALUES (@id, @tenant, @key, @name, @description, @owner, @selectors, @status, @version, @created_at, @updated_by,
			@updated_at)`)
	sfSave = tq("sod_functions.save", `
		UPDATE sod_functions SET name = @name, description = @description, owner_identity_id = @owner,
			selectors = @selectors, status = @status, version = @version, updated_by = @updated_by, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND version = @from_version`)

	srsList = tq("sod_rulesets.list", `
		SELECT `+srsCols+` FROM sod_rulesets s WHERE s.tenant_id = @tenant ORDER BY s.name, s.id`)
	srsGet = tq("sod_rulesets.get", `
		SELECT `+srsCols+` FROM sod_rulesets s WHERE s.tenant_id = @tenant AND s.id = @id`)
	srsByKey = tq("sod_rulesets.by_key", `
		SELECT `+srsCols+` FROM sod_rulesets s WHERE s.tenant_id = @tenant AND s.key = @key`)
	srsByName = tq("sod_rulesets.by_name", `
		SELECT `+srsCols+` FROM sod_rulesets s WHERE s.tenant_id = @tenant AND s.name = @name`)
	srsCount  = tq("sod_rulesets.count", `SELECT COUNT(*) FROM sod_rulesets s WHERE s.tenant_id = @tenant`)
	srsInsert = tq("sod_rulesets.insert", `
		INSERT INTO sod_rulesets (id, tenant_id, key, name, description, enabled, status, version, created_at, updated_by,
			updated_at)
		VALUES (@id, @tenant, @key, @name, @description, @enabled, @status, @version, @created_at, @updated_by, @updated_at)`)
	srsSave = tq("sod_rulesets.save", `
		UPDATE sod_rulesets SET name = @name, description = @description, enabled = @enabled, status = @status,
			version = @version, updated_by = @updated_by, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND version = @from_version`)

	srList = tq("sod_risks.list", `
		SELECT `+srCols+` FROM sod_risks r WHERE r.tenant_id = @tenant ORDER BY r.name, r.id`)
	srGet = tq("sod_risks.get", `
		SELECT `+srCols+` FROM sod_risks r WHERE r.tenant_id = @tenant AND r.id = @id`)
	srByKey = tq("sod_risks.by_key", `
		SELECT `+srCols+` FROM sod_risks r WHERE r.tenant_id = @tenant AND r.key = @key`)
	srByName = tq("sod_risks.by_name", `
		SELECT `+srCols+` FROM sod_risks r WHERE r.tenant_id = @tenant AND r.name = @name`)
	srInsert = tq("sod_risks.insert", `
		INSERT INTO sod_risks (id, tenant_id, key, name, description, priority, business_process, owner_identity_id,
			ruleset_id, subjects, status, version, created_at, updated_by, updated_at)
		VALUES (@id, @tenant, @key, @name, @description, @priority, @business_process, @owner, @ruleset_id, @subjects,
			@status, @version, @created_at, @updated_by, @updated_at)`)
	srSave = tq("sod_risks.save", `
		UPDATE sod_risks SET name = @name, description = @description, priority = @priority,
			business_process = @business_process, owner_identity_id = @owner, ruleset_id = @ruleset_id,
			subjects = @subjects, status = @status, version = @version, updated_by = @updated_by, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND version = @from_version`)

	srfList = tq("sod_risk_functions.list", `
		SELECT l.risk_id, l.function_id, l.ord FROM sod_risk_functions l
		WHERE l.tenant_id = @tenant ORDER BY l.risk_id, l.ord`)
	srfDelete = tq("sod_risk_functions.delete_for_risk", `
		DELETE FROM sod_risk_functions WHERE tenant_id = @tenant AND risk_id = @risk_id`)
	srfInsert = tq("sod_risk_functions.insert", `
		INSERT INTO sod_risk_functions (tenant_id, risk_id, function_id, ord) VALUES (@tenant, @risk_id, @function_id, @ord)`)

	svInsert = tq("sod_versions.insert", `
		INSERT INTO sod_versions (tenant_id, kind, object_id, version, snapshot, note, changed_by, actor, changed_at)
		VALUES (@tenant, @kind, @object_id, @version, @snapshot, @note, @changed_by, @actor, @changed_at)`)
	svFor = tq("sod_versions.for_object", `
		SELECT v.id, v.kind, v.object_id, v.version, v.snapshot, v.note, v.changed_by, v.actor, v.changed_at
		FROM sod_versions v WHERE v.tenant_id = @tenant AND v.kind = @kind AND v.object_id = @object_id
		ORDER BY v.version DESC`)
)

func scanSodFunction(s scanner) (*SodFunction, error) {
	var f SodFunction
	var owner sql.NullInt64
	var by sql.NullString
	var created, updated nullTime
	if err := s.Scan(&f.ID, &f.Key, &f.Name, &f.Description, &owner, &f.Selectors, &f.Status, &f.Version, &created, &by,
		&updated); err != nil {
		return nil, err
	}
	f.OwnerID, f.UpdatedBy = intp(owner), strp(by)
	var err error
	if f.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	f.UpdatedAt, err = updated.val()
	return &f, err
}

func scanSodRuleset(s scanner) (*SodRuleset, error) {
	var r SodRuleset
	var enabled int
	var by sql.NullString
	var created, updated nullTime
	if err := s.Scan(&r.ID, &r.Key, &r.Name, &r.Description, &enabled, &r.Status, &r.Version, &created, &by, &updated); err != nil {
		return nil, err
	}
	r.Enabled, r.UpdatedBy = enabled == 1, strp(by)
	var err error
	if r.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	r.UpdatedAt, err = updated.val()
	return &r, err
}

func scanSodRisk(s scanner) (*SodRisk, error) {
	var r SodRisk
	var owner sql.NullInt64
	var by sql.NullString
	var created, updated nullTime
	if err := s.Scan(&r.ID, &r.Key, &r.Name, &r.Description, &r.Priority, &r.BusinessProcess, &owner, &r.RulesetID,
		&r.Subjects, &r.Status, &r.Version, &created, &by, &updated); err != nil {
		return nil, err
	}
	r.OwnerID, r.UpdatedBy = intp(owner), strp(by)
	var err error
	if r.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	r.UpdatedAt, err = updated.val()
	return &r, err
}

func scanSodRiskFunction(s scanner) (*SodRiskFunction, error) {
	var l SodRiskFunction
	err := s.Scan(&l.RiskID, &l.FunctionID, &l.Ord)
	return &l, err
}

func scanSodVersion(s scanner) (*SodVersion, error) {
	var v SodVersion
	var note, by sql.NullString
	var at nullTime
	if err := s.Scan(&v.ID, &v.Kind, &v.ObjectID, &v.Version, &v.Snapshot, &note, &by, &v.Actor, &at); err != nil {
		return nil, err
	}
	v.Note, v.ChangedBy = strp(note), strp(by)
	var err error
	v.ChangedAt, err = at.val()
	return &v, err
}

// saved reports a versioned save's outcome: ErrNotFound if the row moved on.
func saved(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ------------------------------------------------------------ functions

// SodFunctions returns every function, by name.
func (tx *TenantTx) SodFunctions() ([]*SodFunction, error) {
	return collect(tx, scanSodFunction, sfList)
}

// SodFunction returns one function, or ErrNotFound.
func (tx *TenantTx) SodFunction(id string) (*SodFunction, error) {
	return one(tx, scanSodFunction, sfGet, sql.Named("id", id))
}

// SodFunctionByKey returns the function with the key, or ErrNotFound.
func (tx *TenantTx) SodFunctionByKey(key string) (*SodFunction, error) {
	return one(tx, scanSodFunction, sfByKey, sql.Named("key", key))
}

// SodFunctionByName returns the function with the name, or ErrNotFound.
func (tx *TenantTx) SodFunctionByName(name string) (*SodFunction, error) {
	return one(tx, scanSodFunction, sfByName, sql.Named("name", name))
}

func sodFunctionArgs(f *SodFunction) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("id", f.ID), sql.Named("name", f.Name), sql.Named("description", f.Description),
		sql.Named("owner", IP(f.OwnerID)), sql.Named("selectors", f.Selectors), sql.Named("status", f.Status),
		sql.Named("version", f.Version), sql.Named("updated_by", SP(f.UpdatedBy)), sql.Named("updated_at", T(f.UpdatedAt))}
}

// InsertSodFunction creates a function.
func (tx *TenantTx) InsertSodFunction(f *SodFunction) error {
	_, err := tx.exec(sfInsert, append(sodFunctionArgs(f), sql.Named("key", f.Key), sql.Named("created_at", T(f.CreatedAt)))...)
	return err
}

// SaveSodFunction updates a function still at version from; ErrNotFound if it
// moved on or does not exist.
func (tx *TenantTx) SaveSodFunction(f *SodFunction, from int) error {
	return saved(tx.exec(sfSave, append(sodFunctionArgs(f), sql.Named("from_version", from))...))
}

// ------------------------------------------------------------ rulesets

// SodRulesets returns every ruleset, by name.
func (tx *TenantTx) SodRulesets() ([]*SodRuleset, error) { return collect(tx, scanSodRuleset, srsList) }

// SodRuleset returns one ruleset, or ErrNotFound.
func (tx *TenantTx) SodRuleset(id string) (*SodRuleset, error) {
	return one(tx, scanSodRuleset, srsGet, sql.Named("id", id))
}

// SodRulesetByKey returns the ruleset with the key, or ErrNotFound.
func (tx *TenantTx) SodRulesetByKey(key string) (*SodRuleset, error) {
	return one(tx, scanSodRuleset, srsByKey, sql.Named("key", key))
}

// SodRulesetByName returns the ruleset with the name, or ErrNotFound.
func (tx *TenantTx) SodRulesetByName(name string) (*SodRuleset, error) {
	return one(tx, scanSodRuleset, srsByName, sql.Named("name", name))
}

// CountSodRulesets is how many rulesets (of any status) the tenant has.
func (tx *TenantTx) CountSodRulesets() (int, error) { return tx.count(srsCount) }

func sodRulesetArgs(r *SodRuleset) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("id", r.ID), sql.Named("name", r.Name), sql.Named("description", r.Description),
		sql.Named("enabled", B(r.Enabled)), sql.Named("status", r.Status), sql.Named("version", r.Version),
		sql.Named("updated_by", SP(r.UpdatedBy)), sql.Named("updated_at", T(r.UpdatedAt))}
}

// InsertSodRuleset creates a ruleset.
func (tx *TenantTx) InsertSodRuleset(r *SodRuleset) error {
	_, err := tx.exec(srsInsert, append(sodRulesetArgs(r), sql.Named("key", r.Key), sql.Named("created_at", T(r.CreatedAt)))...)
	return err
}

// SaveSodRuleset updates a ruleset still at version from; ErrNotFound if it
// moved on or does not exist.
func (tx *TenantTx) SaveSodRuleset(r *SodRuleset, from int) error {
	return saved(tx.exec(srsSave, append(sodRulesetArgs(r), sql.Named("from_version", from))...))
}

// ------------------------------------------------------------ risks

// SodRisks returns every risk, by name.
func (tx *TenantTx) SodRisks() ([]*SodRisk, error) { return collect(tx, scanSodRisk, srList) }

// SodRisk returns one risk, or ErrNotFound.
func (tx *TenantTx) SodRisk(id string) (*SodRisk, error) {
	return one(tx, scanSodRisk, srGet, sql.Named("id", id))
}

// SodRiskByKey returns the risk with the key, or ErrNotFound.
func (tx *TenantTx) SodRiskByKey(key string) (*SodRisk, error) {
	return one(tx, scanSodRisk, srByKey, sql.Named("key", key))
}

// SodRiskByName returns the risk with the name, or ErrNotFound.
func (tx *TenantTx) SodRiskByName(name string) (*SodRisk, error) {
	return one(tx, scanSodRisk, srByName, sql.Named("name", name))
}

func sodRiskArgs(r *SodRisk) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("id", r.ID), sql.Named("name", r.Name), sql.Named("description", r.Description),
		sql.Named("priority", r.Priority), sql.Named("business_process", r.BusinessProcess), sql.Named("owner", IP(r.OwnerID)),
		sql.Named("ruleset_id", r.RulesetID), sql.Named("subjects", r.Subjects), sql.Named("status", r.Status),
		sql.Named("version", r.Version), sql.Named("updated_by", SP(r.UpdatedBy)), sql.Named("updated_at", T(r.UpdatedAt))}
}

// InsertSodRisk creates a risk.
func (tx *TenantTx) InsertSodRisk(r *SodRisk) error {
	_, err := tx.exec(srInsert, append(sodRiskArgs(r), sql.Named("key", r.Key), sql.Named("created_at", T(r.CreatedAt)))...)
	return err
}

// SaveSodRisk updates a risk still at version from; ErrNotFound if it moved on
// or does not exist.
func (tx *TenantTx) SaveSodRisk(r *SodRisk, from int) error {
	return saved(tx.exec(srSave, append(sodRiskArgs(r), sql.Named("from_version", from))...))
}

// SodRiskFunctions returns every risk-function link, by risk and order.
func (tx *TenantTx) SodRiskFunctions() ([]*SodRiskFunction, error) {
	return collect(tx, scanSodRiskFunction, srfList)
}

// SetSodRiskFunctions replaces a risk's functions with functionIDs, in order.
func (tx *TenantTx) SetSodRiskFunctions(riskID string, functionIDs []string) error {
	if _, err := tx.exec(srfDelete, sql.Named("risk_id", riskID)); err != nil {
		return err
	}
	for i, id := range functionIDs {
		if _, err := tx.exec(srfInsert, sql.Named("risk_id", riskID), sql.Named("function_id", id), sql.Named("ord", i)); err != nil {
			return err
		}
	}
	return nil
}

// ------------------------------------------------------------ versions

// AddSodVersion appends a version snapshot.
func (tx *TenantTx) AddSodVersion(v *SodVersion) error {
	_, err := tx.exec(svInsert, sql.Named("kind", v.Kind), sql.Named("object_id", v.ObjectID), sql.Named("version", v.Version),
		sql.Named("snapshot", v.Snapshot), sql.Named("note", SP(v.Note)), sql.Named("changed_by", SP(v.ChangedBy)),
		sql.Named("actor", v.Actor), sql.Named("changed_at", T(v.ChangedAt)))
	return err
}

// SodVersions returns an object's versions, newest first.
func (tx *TenantTx) SodVersions(kind, objectID string) ([]*SodVersion, error) {
	return collect(tx, scanSodVersion, svFor, sql.Named("kind", kind), sql.Named("object_id", objectID))
}
