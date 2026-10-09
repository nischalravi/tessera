package model

import "github.com/nischalravi/tessera/mvp/server/internal/authz"

// Every enum here has the lower-case v1 spelling as its text form (§6).
// The zero value marshals as "" and means "unset".

func marshalEnum[T ~uint8](v T, names []string) ([]byte, error) {
	if int(v) >= len(names) {
		return nil, &enumError{v: uint8(v)}
	}
	return []byte(names[v]), nil
}

type enumError struct{ v uint8 }

func (e *enumError) Error() string { return "model: enum value out of range" }

// PrincipalKind is the kind of a requester.
type PrincipalKind uint8

const (
	IAMUser              PrincipalKind = iota + 1 // "iam_user"
	IAMRole                                       // "iam_role" (a role never makes a request itself)
	RoleSession                                   // AssumeRole / WebIdentity / SAML / EC2 / Identity Center sessions
	FederatedUserSession                          // GetFederationToken
	Root                                          // account root user (including AssumeRoot sessions)
	Service                                       // service principal, e.g. "s3.amazonaws.com"
	Anonymous
)

var principalKindNames = []string{"", "iam_user", "iam_role", "role_session", "federated_user_session", "root", "service", "anonymous"}

func (k PrincipalKind) String() string               { return authz.EnumName(k, principalKindNames) }
func (k PrincipalKind) MarshalText() ([]byte, error) { return marshalEnum(k, principalKindNames) }
func (k *PrincipalKind) UnmarshalText(b []byte) (err error) {
	*k, err = authz.ParseEnum[PrincipalKind](string(b), principalKindNames, "principal kind")
	return err
}

// PolicyKind is the type of a policy document. The constants carry a Policy
// prefix because Boundary and Resource are also struct names in this package.
type PolicyKind uint8

const (
	PolicyIdentity PolicyKind = iota + 1
	PolicyBoundary
	PolicySession
	PolicySCP
	PolicyRCP
	PolicyResource
	PolicyTrust
	PolicyKMSKey
	PolicyVPCE
	PolicyS3AccessPoint
	PolicyRAM
)

var policyKindNames = []string{"", "identity", "boundary", "session", "scp", "rcp", "resource", "trust",
	"kms_key_policy", "vpc_endpoint", "s3_access_point", "ram_synthetic"}

func (k PolicyKind) String() string               { return authz.EnumName(k, policyKindNames) }
func (k PolicyKind) MarshalText() ([]byte, error) { return marshalEnum(k, policyKindNames) }
func (k *PolicyKind) UnmarshalText(b []byte) (err error) {
	*k, err = authz.ParseEnum[PolicyKind](string(b), policyKindNames, "policy kind")
	return err
}

// IsResourceBased reports whether documents of this kind are attached to a
// resource and name principals: resource, trust, KMS key, VPC endpoint and S3
// access point policies. A statement in such a policy may omit Resource (it
// then means "this resource", §8.3) and must have Principal or NotPrincipal.
// RCPs are not included: they are organization policies with "Principal": "*".
func (k PolicyKind) IsResourceBased() bool {
	switch k {
	case PolicyResource, PolicyTrust, PolicyKMSKey, PolicyVPCE, PolicyS3AccessPoint:
		return true
	}
	return false
}

// IsIdentityBased reports whether documents of this kind attach to principals
// (identity, boundary, session). These must not contain Principal.
func (k PolicyKind) IsIdentityBased() bool {
	switch k {
	case PolicyIdentity, PolicyBoundary, PolicySession:
		return true
	}
	return false
}

// Effect is a statement's effect.
type Effect uint8

const (
	EffectAllow Effect = iota + 1 // "allow"
	EffectDeny                    // "deny"
)

var effectNames = []string{"", "allow", "deny"}

func (e Effect) String() string               { return authz.EnumName(e, effectNames) }
func (e Effect) MarshalText() ([]byte, error) { return marshalEnum(e, effectNames) }
func (e *Effect) UnmarshalText(b []byte) (err error) {
	*e, err = authz.ParseEnum[Effect](string(b), effectNames, "effect")
	return err
}

// PolicyElement returns the spelling used in policy JSON: "Allow" or "Deny".
func (e Effect) PolicyElement() string {
	switch e {
	case EffectAllow:
		return "Allow"
	case EffectDeny:
		return "Deny"
	}
	return ""
}

// AttachmentType says how a policy is attached.
type AttachmentType uint8

const (
	AttachInline AttachmentType = iota + 1
	AttachManaged
	AttachBoundary
	AttachSCP
	AttachRCP
	AttachResource
	AttachSession
	AttachTrust
)

var attachmentTypeNames = []string{"", "inline", "managed", "boundary", "scp", "rcp", "resource", "session", "trust"}

func (a AttachmentType) String() string               { return authz.EnumName(a, attachmentTypeNames) }
func (a AttachmentType) MarshalText() ([]byte, error) { return marshalEnum(a, attachmentTypeNames) }
func (a *AttachmentType) UnmarshalText(b []byte) (err error) {
	*a, err = authz.ParseEnum[AttachmentType](string(b), attachmentTypeNames, "attachment type")
	return err
}

// OrgNodeKind is the kind of an Organizations node.
type OrgNodeKind uint8

const (
	OrgRoot    OrgNodeKind = iota + 1 // "root"
	OrgOU                             // "ou"
	OrgAccount                        // "account"
)

var orgNodeKindNames = []string{"", "root", "ou", "account"}

func (k OrgNodeKind) String() string               { return authz.EnumName(k, orgNodeKindNames) }
func (k OrgNodeKind) MarshalText() ([]byte, error) { return marshalEnum(k, orgNodeKindNames) }
func (k *OrgNodeKind) UnmarshalText(b []byte) (err error) {
	*k, err = authz.ParseEnum[OrgNodeKind](string(b), orgNodeKindNames, "org node kind")
	return err
}

// TrustMechanism is how a principal can become a role.
type TrustMechanism uint8

const (
	AssumeRole TrustMechanism = iota + 1
	AssumeRoleWithWebIdentity
	AssumeRoleWithSAML
	ServiceTrust
	PassRole
)

var trustMechanismNames = []string{"", "assume_role", "assume_role_with_web_identity", "assume_role_with_saml", "service", "pass_role"}

func (m TrustMechanism) String() string               { return authz.EnumName(m, trustMechanismNames) }
func (m TrustMechanism) MarshalText() ([]byte, error) { return marshalEnum(m, trustMechanismNames) }
func (m *TrustMechanism) UnmarshalText(b []byte) (err error) {
	*m, err = authz.ParseEnum[TrustMechanism](string(b), trustMechanismNames, "trust mechanism")
	return err
}

// KeyType is a condition key's declared type, shared with the catalog (§9.1).
type KeyType uint8

const (
	KeyString KeyType = iota + 1
	KeyARN
	KeyNumeric
	KeyDate
	KeyBool
	KeyIP
	KeyBinary
)

var keyTypeNames = []string{"", "string", "arn", "numeric", "date", "bool", "ip", "binary"}

func (t KeyType) String() string               { return authz.EnumName(t, keyTypeNames) }
func (t KeyType) MarshalText() ([]byte, error) { return marshalEnum(t, keyTypeNames) }
func (t *KeyType) UnmarshalText(b []byte) (err error) {
	*t, err = authz.ParseEnum[KeyType](string(b), keyTypeNames, "key type")
	return err
}

// PrincipalEntryKind classifies one value of a policy's Principal or
// NotPrincipal element after normalization (§8.4.1).
type PrincipalEntryKind uint8

const (
	PrincipalWildcard      PrincipalEntryKind = iota + 1 // "*" or {"AWS": "*"}
	PrincipalAccount                                     // "123456789012" or arn:<p>:iam::123456789012:root
	PrincipalIAMUser                                     // arn:<p>:iam::<acct>:user/<path>name
	PrincipalIAMRole                                     // arn:<p>:iam::<acct>:role/<path>name
	PrincipalAssumedRole                                 // arn:<p>:sts::<acct>:assumed-role/<role>/<session>
	PrincipalFederatedUser                               // arn:<p>:sts::<acct>:federated-user/<name>
	PrincipalUniqueID                                    // a bare AIDA…/AROA… unique id
	PrincipalService                                     // {"Service": "s3.amazonaws.com"}
	PrincipalFederated                                   // {"Federated": provider ARN or IdP name}
	PrincipalCanonicalUser                               // {"CanonicalUser": "<64 hex>"}, mapped to an account at evaluation
	PrincipalUnrecognized                                // an AWS value of no known form; kept literally (lint finding)
)

var principalEntryKindNames = []string{"", "wildcard", "account", "iam_user", "iam_role", "assumed_role",
	"federated_user", "unique_id", "service", "federated", "canonical_user", "unrecognized"}

func (k PrincipalEntryKind) String() string { return authz.EnumName(k, principalEntryKindNames) }
func (k PrincipalEntryKind) MarshalText() ([]byte, error) {
	return marshalEnum(k, principalEntryKindNames)
}
func (k *PrincipalEntryKind) UnmarshalText(b []byte) (err error) {
	*k, err = authz.ParseEnum[PrincipalEntryKind](string(b), principalEntryKindNames, "principal entry kind")
	return err
}
