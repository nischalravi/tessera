// Package pam reads a privileged-access vault (CyberArk Privileged Access
// Manager, Delinea Secret Server, BeyondTrust Password Safe) into Tessera's
// graph, and writes safe membership back through provisioning (issue #304).
// Tessera integrates with the vault; it does not replace it: nothing is
// stored here but what the vault reports, and a change is made only when a
// provisioning operation asks for it and a re-read confirms it.
//
// Vendor-neutral model. A vault holds safes (CyberArk safes, Delinea
// folders, BeyondTrust smart rules). A safe holds vaulted accounts. A safe
// has members (users, groups, roles), each with a set of safe permissions
// named as CyberArk names them. Delinea and BeyondTrust report roles; the
// readers translate those to the same permission names, so a review or an SoD
// rule reads the same vocabulary everywhere.
//
// Mapping onto Tessera's graph (Discover):
//
//	safe              -> resource (kind vault_safe) with one permission per safe
//	                     permission, privileged where it reveals or changes secrets
//	safe x profile    -> group (kind vault_safe_access, entitlement) for each of
//	                     the profiles list, use, read and manage: group -grants-> its permissions
//	member            -> account (kind user, group or role) -member_of-> the highest
//	                     profile it holds, and -direct_grant-> any permission beyond it
//	vaulted account   -> account (kind vaulted) with a secret (its password) and
//	                     the time of its last rotation
//
// Profiles are the unit a request, a review or a leaver removal works with:
// the provisioning target (target.go) adds or removes a member at a profile.
package pam

import (
	"context"
	"sort"
	"time"
)

// Vendors.
const (
	CyberArk    = "cyberark"
	Delinea     = "delinea"
	BeyondTrust = "beyondtrust"
)

// Vendors lists every vendor.
var Vendors = []string{CyberArk, Delinea, BeyondTrust}

// Safe permissions, named as CyberArk names them.
const (
	PermList           = "list_accounts"
	PermViewMembers    = "view_safe_members"
	PermUse            = "use_accounts"
	PermRetrieve       = "retrieve_accounts"
	PermAdd            = "add_accounts"
	PermUpdateProps    = "update_account_properties"
	PermUpdateContent  = "update_account_content"
	PermRename         = "rename_accounts"
	PermDelete         = "delete_accounts"
	PermUnlock         = "unlock_accounts"
	PermManageSafe     = "manage_safe"
	PermManageMembers  = "manage_safe_members"
	PermAuditLog       = "view_audit_log"
	PermBackup         = "backup_safe"
	PermNoConfirmation = "access_without_confirmation"
	PermApprove        = "requests_authorization_level"
)

// AllPerms lists every safe permission.
var AllPerms = []string{PermList, PermViewMembers, PermUse, PermRetrieve, PermAdd, PermUpdateProps, PermUpdateContent,
	PermRename, PermDelete, PermUnlock, PermManageSafe, PermManageMembers, PermAuditLog, PermBackup, PermNoConfirmation, PermApprove}

// privileged are the permissions that reveal a secret, change what is vaulted
// or change who may: a group that grants one is privileged.
var privileged = map[string]bool{PermRetrieve: true, PermAdd: true, PermUpdateContent: true, PermDelete: true,
	PermManageSafe: true, PermManageMembers: true, PermNoConfirmation: true, PermBackup: true}

// IsPrivilegedPerm reports whether a permission reveals or changes secrets, or changes who may.
func IsPrivilegedPerm(p string) bool { return privileged[p] }

// Profiles, lowest first. Each includes the one before it.
const (
	ProfileList   = "list"   // see the safe's accounts and members
	ProfileUse    = "use"    // connect through the vault without seeing the secret
	ProfileRead   = "read"   // also retrieve (see) the secret
	ProfileManage = "manage" // also add, change, delete accounts and manage members
)

// Profiles lists the profiles, lowest first.
var Profiles = []string{ProfileList, ProfileUse, ProfileRead, ProfileManage}

var profilePerms = map[string][]string{
	ProfileList: {PermList, PermViewMembers},
	ProfileUse:  {PermList, PermViewMembers, PermUse},
	ProfileRead: {PermList, PermViewMembers, PermUse, PermRetrieve},
	ProfileManage: {PermList, PermViewMembers, PermUse, PermRetrieve, PermAdd, PermUpdateProps, PermUpdateContent, PermRename,
		PermDelete, PermUnlock, PermManageSafe, PermManageMembers, PermAuditLog},
}

// ProfilePerms returns the permissions of a profile (nil for an unknown one).
func ProfilePerms(profile string) []string { return append([]string(nil), profilePerms[profile]...) }

// ValidProfile reports whether p is a profile.
func ValidProfile(p string) bool { _, ok := profilePerms[p]; return ok }

// ProfileRank orders profiles (unknown is -1, no profile 0 is "").
func ProfileRank(p string) int {
	for i, x := range Profiles {
		if x == p {
			return i
		}
	}
	return -1
}

// TopProfile is the highest profile whose permissions the set holds entirely,
// or "" when it holds not even the lowest.
func TopProfile(perms []string) string {
	have := map[string]bool{}
	for _, p := range perms {
		have[p] = true
	}
	top := ""
	for _, pr := range Profiles {
		all := true
		for _, p := range profilePerms[pr] {
			all = all && have[p]
		}
		if all {
			top = pr
		}
	}
	return top
}

// Beyond returns the permissions of the set that its top profile does not
// include, sorted: what a member holds on top of its profile.
func Beyond(perms []string) []string {
	in := map[string]bool{}
	for _, p := range profilePerms[TopProfile(perms)] {
		in[p] = true
	}
	var out []string
	for _, p := range perms {
		if !in[p] {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// Member types.
const (
	MemberUser  = "user"
	MemberGroup = "group"
	MemberRole  = "role"
)

// Safe is a container of vaulted accounts. ID is the vendor's key (what its
// API takes in a path); Name is what people call it.
type Safe struct {
	ID, Name, Description string
}

// Account is a vaulted account: a credential the vault holds and rotates.
type Account struct {
	ID, Name, Username, Address, Platform string
	AutoManaged                           bool
	CreatedAt, LastRotatedAt              *time.Time
}

// Member is a principal with access to a safe. Perms are sorted safe permissions.
type Member struct {
	Name  string
	Type  string
	Perms []string
}

// Vault is the read and write surface of one vendor.
type Vault interface {
	Vendor() string
	Safes(ctx context.Context) ([]Safe, error)
	Accounts(ctx context.Context, s Safe) ([]Account, error)
	Members(ctx context.Context, s Safe) ([]Member, error)
	// SetMember gives a member exactly the permissions of a profile (creating
	// the member when there is none); the vendor may be unable to express the
	// profile, which is a *UnsupportedError.
	SetMember(ctx context.Context, s Safe, name, memberType, profile string) error
	// RemoveMember removes a member from a safe (nothing to do when absent).
	RemoveMember(ctx context.Context, s Safe, name string) error
}

// UnsupportedError: the vendor has no role or permission set that means the profile.
type UnsupportedError struct{ Vendor, Profile string }

func (e *UnsupportedError) Error() string {
	return e.Vendor + " cannot express the profile " + e.Profile + " (supported profiles are listed in the README)"
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
