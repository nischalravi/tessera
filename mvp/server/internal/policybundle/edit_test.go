package policybundle

import (
	"errors"
	"strings"
	"testing"
)

const editRole = `schema: tessera.role/v1
key: payroll-ops
name: Payroll ops
description: ""
owner: ""
risk: high
requestable: false
entitlements:
    - workday:AP Approver
    - workday:Payroll Administrator
`

func TestRemoveRoleEntitlement(t *testing.T) {
	out, err := RemoveRoleEntitlement([]byte(editRole), "workday:Payroll Administrator")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(editRole, "    - workday:Payroll Administrator\n", "", 1)
	if string(out) != want {
		t.Errorf("edited =\n%s\nwant\n%s", out, want)
	}
	// the result is a role the loader accepts, with the one entitlement left
	b, diags := Load(Files{ConfigFile: []byte("schema: tessera.repo/v1\ntenant: t\nmanage:\n    roles: partial\n"), "roles/payroll-ops.yaml": out}, nil)
	if len(diags) != 0 || len(b.Roles) != 1 || len(b.Roles[0].Entitlements) != 1 || b.Roles[0].Entitlements[0] != "workday:AP Approver" {
		t.Errorf("load = %+v, %v", b, diags)
	}
	// the same edit twice is the same text
	if again, _ := RemoveRoleEntitlement([]byte(editRole), "workday:Payroll Administrator"); string(again) != string(out) {
		t.Error("not deterministic")
	}
}

func TestRemoveRoleEntitlementRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		text, ent string
		want      error
	}{
		"absent":       {editRole, "workday:Other", ErrEntitlementAbsent},
		"empty file":   {"", "workday:AP Approver", nil},
		"wrong schema": {strings.Replace(editRole, "tessera.role/v1", "tessera.jit/v1", 1), "workday:AP Approver", nil},
		"unknown key":  {editRole + "extra: 1\n", "workday:AP Approver", nil},
		"anchor":       {strings.Replace(editRole, "name: Payroll ops", "name: &n Payroll ops", 1), "workday:AP Approver", nil},
		"two docs":     {editRole + "---\nkey: x\n", "workday:AP Approver", nil},
	} {
		_, err := RemoveRoleEntitlement([]byte(tc.text), tc.ent)
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// A role file the strict reader refuses is ErrRoleUnreadable, so a caller can tell it from a failure of the service that
// served it (issue #786).
func TestRemoveRoleEntitlement_UnreadableFile(t *testing.T) {
	for name, text := range map[string]string{
		"unknown field":   editRole + "extra_field: 1\n",
		"anchor":          strings.Replace(editRole, "name: Payroll ops", "name: &n Payroll ops", 1) + "alias: *n\n",
		"second document": editRole + "---\nschema: x\n",
		"empty":           "",
		"not yaml":        "key: [unclosed\n",
		"other schema":    strings.Replace(editRole, "tessera.role/v1", "tessera.other/v1", 1),
	} {
		if _, err := RemoveRoleEntitlement([]byte(text), "workday:Payroll Administrator"); !errors.Is(err, ErrRoleUnreadable) {
			t.Errorf("%s: err = %v, want ErrRoleUnreadable", name, err)
		}
	}
	// an entitlement that is not listed is still its own error
	if _, err := RemoveRoleEntitlement([]byte(editRole), "workday:Nope"); !errors.Is(err, ErrEntitlementAbsent) || errors.Is(err, ErrRoleUnreadable) {
		t.Errorf("absent entitlement: err = %v", err)
	}
}
