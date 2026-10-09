package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// ---------------------------------------------------------------- values

// T formats a timestamp for storage.
func T(t time.Time) string { return timeutil.DB(t) }

// TP formats an optional timestamp for storage (NULL for nil).
func TP(t *time.Time) any {
	if t == nil {
		return nil
	}
	return timeutil.DB(*t)
}

// SP stores an optional string (NULL for nil).
func SP(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// IP stores an optional integer (NULL for nil).
func IP(i *int64) any {
	if i == nil {
		return nil
	}
	return *i
}

// B stores a boolean.
func B(b bool) int {
	if b {
		return 1
	}
	return 0
}

// JSON encodes a value for a JSON column.
func JSON(v any) (string, error) {
	b, err := ojson.Marshal(v)
	return string(b), err
}

type nullTime struct {
	sql.NullString
}

func (n nullTime) ptr() (*time.Time, error) {
	if !n.Valid {
		return nil, nil
	}
	t, err := timeutil.ParseDB(n.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (n nullTime) val() (time.Time, error) {
	t, err := n.ptr()
	if err != nil || t == nil {
		return time.Time{}, errors.Join(err, errors.New("store: unexpected NULL timestamp"))
	}
	return *t, nil
}

func strp(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	s := n.String
	return &s
}

func intp(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	i := n.Int64
	return &i
}

// tenantOf parses a tenant_id column read back from a row.
func tenantOf(s string) (tenancy.ID, error) { return tenancy.Parse(s) }

func nowUTC() time.Time { return time.Now().UTC() }

func detailWhere(where string) ojson.Object { return ojson.Object{{Key: "where", Value: where}} }
