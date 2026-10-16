package store

import (
	"context"
	"database/sql"
	"reflect"
	"strings"
	"testing"
)

// TestValues_NoFloatColumns: no column of the attribute tables has REAL
// affinity, and no field of a stored attribute value is a float, so a value can
// never reach the audit hash or an event as a float (design §10.9: floating
// values are decimal strings in value_string).
func TestValues_NoFloatColumns(t *testing.T) {
	db := openTest(t)
	for _, table := range []string{"grp_attr_defs", "grp_attr_names", "grp_attr_name_implies", "grp_attr_actions",
		"grp_attr_action_implies", "grp_attr_assigns", "grp_attr_values"} {
		rows, err := db.sql.QueryContext(context.Background(), `SELECT name, type FROM pragma_table_info(@t)`, sql.Named("t", table))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for rows.Next() {
			var name, typ string
			if err := rows.Scan(&name, &typ); err != nil {
				t.Fatal(err)
			}
			n++
			up := strings.ToUpper(typ)
			if strings.Contains(up, "REAL") || strings.Contains(up, "FLOA") || strings.Contains(up, "DOUB") || strings.Contains(up, "NUMERIC") {
				t.Errorf("%s.%s is declared %s", table, name, typ)
			}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("table %s does not exist", table)
		}
	}
	for _, v := range []any{GrpAttrValue{}, GrpAttrAssign{}, GrpAttrDef{}} {
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			k := typ.Field(i).Type
			for k.Kind() == reflect.Pointer || k.Kind() == reflect.Slice {
				k = k.Elem()
			}
			if k.Kind() == reflect.Float32 || k.Kind() == reflect.Float64 {
				t.Errorf("%s.%s is a float", typ.Name(), typ.Field(i).Name)
			}
		}
	}
}
