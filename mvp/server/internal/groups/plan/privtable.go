package plan

// The privilege names a plan may grant, by the kind of object that holds them.
// internal/groups/privs is the source of truth; the CLI does not import it
// (it would pull the store into the binary), and TestPrivTable_MatchesPrivs
// keeps this copy in step.
var (
	groupPrivs  = []string{"admin", "update", "read", "view", "optin", "optout", "group_attr_read", "group_attr_update"}
	folderPrivs = []string{"stem_admin", "create", "stem_attr_read", "stem_attr_update", "stem_view"}
	attrPrivs   = []string{"attr_admin", "attr_update", "attr_read", "attr_view", "attr_optin", "attr_optout", "attr_def_attr_read", "attr_def_attr_update"}
)

// privObject is the object type a privilege belongs to ("" for a name that is not one).
func privObject(p string) string {
	for typ, list := range map[string][]string{"group": groupPrivs, "folder": folderPrivs, "attr_def": attrPrivs} {
		for _, n := range list {
			if n == p {
				return typ
			}
		}
	}
	return ""
}

// appliesTo is what an inherited row of a privilege of this object type covers.
func appliesTo(objectType string) string {
	switch objectType {
	case "group":
		return "groups"
	case "folder":
		return "folders"
	case "attr_def":
		return "attr_defs"
	}
	return ""
}

// privRow is one row of grp_privileges as a plan means it.
type privRow struct {
	AppliesTo string
	Scope     string
}

// rowsFor lists the rows that give holders a privilege on an object of the
// given type with the plan's scope. A folder's own privilege with scope one or
// sub needs the row on the folder itself and the inherited row (an inherited
// row covers the folders below, not the folder it is on); a group privilege
// granted on a folder is inherited by the groups below it only.
func rowsFor(objectType, priv, scope string) []privRow {
	if scope == "" || scope == "self" {
		return []privRow{{"self", "self"}}
	}
	inherited := privRow{appliesTo(privObject(priv)), scope}
	if privObject(priv) == objectType {
		return []privRow{{"self", "self"}, inherited}
	}
	return []privRow{inherited}
}
