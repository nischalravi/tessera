// Package erp reads the authorization model of an ERP (SAP and Oracle Fusion
// Applications) into Tessera's graph as fine-grained entitlements, and writes
// role assignment back through provisioning (issue #304).
//
// What is read. A role (SAP PFCG single or composite role; Oracle job, abstract
// or duty role) names the transactions it can start (SAP t-codes; Oracle
// function-security privileges) and the authorizations it carries (SAP
// authorization objects with their field values, such as F_BKPF_BUK with
// ACTVT 01,02 and BUKRS 1000; Oracle data-security policies). A user holds roles,
// optionally for a period.
//
// Mapping onto Tessera's graph (Discover):
//
//	role                  -> group (kind erp_role), requestable, privileged when it holds a critical transaction or a change authorization on a critical object
//	composite role        -> the composite group is member_of each child role's group, so whoever holds the composite
//	                         holds what the children grant (the same way a nested directory group does)
//	t-code / privilege    -> permission, Action = the t-code (FB60) or privilege code, on the resource "transactions"
//	authorization object  -> permission, Action = OBJECT[FIELD=v1,v2;FIELD2=v] with fields sorted, on the resource "authorizations"
//	role grants           -> group -grants-> permission
//	user                  -> account (kind user; disabled when locked or past its validity), correlated by e-mail; -member_of-> each role it holds now
//
// The permission actions are the vocabulary of the SoD functions of issue
// #298: a function selects entitlements by name pattern (FB60, F-53, or
// F_BKPF_BUK[*ACTVT=02*]), so "enter a vendor invoice" against "release a
// payment" is two functions over t-codes, and a violation is found for whoever
// holds both through any role, composite or not. See sod_test.go.
package erp

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Systems.
const (
	SAP    = "sap"
	Oracle = "oracle"
)

// Systems lists every ERP system.
var Systems = []string{SAP, Oracle}

// Resource ids of the two things a permission acts on.
const (
	ResTransactions   = "transactions"
	ResAuthorizations = "authorizations"
)

// AuthObject is an authorization object: its name and, per field, the values it allows.
type AuthObject struct {
	Object string
	Fields map[string][]string
}

// Action is the permission name of an authorization object: OBJECT[F1=a,b;F2=c],
// fields and values sorted, so equal authorizations have equal names.
func (a AuthObject) Action() string {
	names := make([]string, 0, len(a.Fields))
	for f := range a.Fields {
		names = append(names, f)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, f := range names {
		vs := append([]string(nil), a.Fields[f]...)
		sort.Strings(vs)
		parts = append(parts, f+"="+strings.Join(vs, ","))
	}
	return a.Object + "[" + strings.Join(parts, ";") + "]"
}

// Role is a role and what it grants.
type Role struct {
	ID, Name, Description string
	Children              []string // role ids a composite role contains
	TCodes                []string
	AuthObjects           []AuthObject
}

// Assignment is a role held by a user, for a period.
type Assignment struct {
	Role     string
	From, To *time.Time
}

// Active reports whether the assignment holds at now.
func (a Assignment) Active(now time.Time) bool {
	return (a.From == nil || !a.From.After(now)) && (a.To == nil || a.To.After(now))
}

// User is an ERP user and the roles it holds.
type User struct {
	ID, Name, Email string
	Locked          bool
	ValidTo         *time.Time
	LastLogon       *time.Time
	Roles           []Assignment
}

// System is the read and write surface of one ERP.
type System interface {
	Vendor() string
	Roles(ctx context.Context) ([]Role, error)
	Users(ctx context.Context) ([]User, error)
	// Roles of one user, for a re-read after a write.
	User(ctx context.Context, id string) (*User, error)
	AssignRole(ctx context.Context, user, role string) error
	RemoveRole(ctx context.Context, user, role string) error
}

// NotFoundError: the ERP has no such user or role.
type NotFoundError struct{ Vendor, What string }

func (e *NotFoundError) Error() string { return fmt.Sprintf("%s has no %s", e.Vendor, e.What) }

// criticalTCodes are transactions that change the system's own security or
// configuration, run code or read tables whole: a role holding one is privileged.
var criticalTCodes = map[string]bool{"SU01": true, "SU10": true, "PFCG": true, "SM59": true, "SE38": true, "SE16N": true, "SA38": true,
	"SM30": true, "SM31": true, "SE37": true, "SM49": true, "SM69": true, "STMS": true, "SCC4": true, "SE06": true, "RZ10": true}

// criticalObjects are authorization objects whose change activity (ACTVT 01, 02,
// 06, 15 or *) is privileged.
var criticalObjects = map[string]bool{"S_DEVELOP": true, "S_TABU_DIS": true, "S_TABU_NAM": true, "S_USER_GRP": true, "S_USER_AGR": true,
	"S_USER_PRO": true, "S_RFC": true, "S_ADMI_FCD": true, "S_BTCH_ADM": true, "S_SCD0_OBJ": true}

// IsCriticalTCode reports whether a transaction is privileged.
func IsCriticalTCode(t string) bool { return criticalTCodes[strings.ToUpper(t)] }

// IsPrivilegedAuth reports whether an authorization object grants change on a critical object.
func IsPrivilegedAuth(a AuthObject) bool {
	if !criticalObjects[strings.ToUpper(a.Object)] {
		return false
	}
	acts, ok := a.Fields["ACTVT"]
	if !ok {
		return true // no activity limit
	}
	for _, v := range acts {
		switch v {
		case "01", "02", "06", "15", "*", "":
			return true
		}
	}
	return false
}

// Privileged reports whether a role holds anything critical.
func (r Role) Privileged() bool {
	if strings.EqualFold(r.ID, "SAP_ALL") || strings.EqualFold(r.ID, "SAP_NEW") {
		return true
	}
	for _, t := range r.TCodes {
		if IsCriticalTCode(t) {
			return true
		}
	}
	for _, a := range r.AuthObjects {
		if IsPrivilegedAuth(a) {
			return true
		}
	}
	return false
}
