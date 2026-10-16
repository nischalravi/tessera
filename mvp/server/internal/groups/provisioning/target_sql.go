package provisioning

import (
	"context"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The SQL target writes (group_name, member) rows to a SQLite database for
// applications that read group memberships from SQL (design §9.2, G-74). The
// database access is store.ExtSQLite: this package has no SQL of its own (the
// archtest keeps database/sql inside internal/store), and the file lives in
// the operator's directory, so a tenant picks a file name and nothing else.
//
// The table has no group rows: a group exists as long as it has members, so the
// target has no group objects (Capabilities.Groups is false) and deleting a
// group removes its members.

type sqlCfg struct {
	// File is the database file name inside TESSERA_GROUPS_PROV_SQL_DIR.
	File string `json:"file"`
}

func parseSQLConfig(c *Compiled, deps Deps) (sqlCfg, error) {
	var cfg sqlCfg
	if err := strictJSON(c.Target, &cfg); err != nil {
		return cfg, cfgErr("target: %v", err)
	}
	if deps.SQLDir == "" {
		return cfg, cfgErr("the SQL target is not enabled on this server (set TESSERA_GROUPS_PROV_SQL_DIR)")
	}
	if !store.ValidExtSQLiteName(cfg.File) {
		return cfg, cfgErr("target.file must be a plain file name ending in .db, .sqlite or .sqlite3")
	}
	if len(c.Attrs) > 0 {
		return cfg, cfgErr("attrs: a SQL target has no group attributes")
	}
	return cfg, nil
}

type sqlTarget struct{ db *store.ExtSQLite }

func openSQL(ctx context.Context, spec TargetSpec) (Provisioner, error) {
	cfg, err := parseSQLConfig(spec.Common, spec.Deps)
	if err != nil {
		return nil, err
	}
	db, err := store.OpenExtSQLite(ctx, spec.Deps.SQLDir, spec.Tenant, cfg.File)
	if err != nil {
		return nil, err
	}
	return &sqlTarget{db: db}, nil
}

func (t *sqlTarget) Capabilities() Capabilities {
	return Capabilities{Memberships: true, Incremental: true, MaxBatch: 500, Readable: true}
}

func (t *sqlTarget) Close() error { return t.db.Close() }

func stateOf(rows map[string][]string) TargetState {
	st := NewState()
	for g, ms := range rows {
		st.Groups[Key(g)] = &TargetGroup{Ref: TargetRef{Name: g}, Members: ms}
	}
	return st
}

func (t *sqlTarget) ReadAll(ctx context.Context, _ Scope) (TargetState, error) {
	rows, err := t.db.Members(ctx, nil)
	return stateOf(rows), err
}

func (t *sqlTarget) Read(ctx context.Context, refs []TargetRef) (TargetState, error) {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Name)
	}
	rows, err := t.db.Members(ctx, names)
	return stateOf(rows), err
}

func (t *sqlTarget) Apply(ctx context.Context, ops []Op) ([]OpResult, error) {
	var add, remove []store.ExtPair
	out := make([]OpResult, len(ops))
	for i, op := range ops {
		out[i] = OpResult{ID: op.ID, Ref: op.Ref}
		switch op.Kind {
		case OpCreate, OpMembers:
		case OpUpdate:
			continue // no attributes
		case OpDelete:
			out[i].Err = fmt.Errorf("a SQL target has no group objects to delete")
			continue
		}
		for _, m := range op.Remove {
			remove = append(remove, store.ExtPair{Group: op.Ref.Name, Member: m})
		}
		for _, m := range op.Add {
			add = append(add, store.ExtPair{Group: op.Ref.Name, Member: m})
		}
	}
	return out, t.db.Apply(ctx, add, remove)
}
