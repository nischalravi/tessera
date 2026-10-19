// Package eval evaluates AWS policy conditions against a request context and
// builds the residuals a symbolic evaluation leaves behind (design §9). It does
// no I/O and reads no clock: the current time, the snapshot facts and the
// catalog facts all come in as plain inputs.
package eval

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

// Mode is how unlisted context keys are treated (§9.4).
type Mode uint8

const (
	// Concrete: every key is present or absent. A key that is not in the
	// context is absent.
	Concrete Mode = iota
	// Symbolic: a key that is not in the context is unknown (it may be present
	// with any value, or absent).
	Symbolic
)

// KeyState is the state of one context key (§9.1).
type KeyState uint8

const (
	Absent  KeyState = iota // AWS would not put the key in the request context
	Present                 // the key has Values
	Unknown                 // symbolic mode only: present with any value, or absent
)

func (s KeyState) String() string {
	switch s {
	case Present:
		return "present"
	case Unknown:
		return "unknown"
	}
	return "absent"
}

// ContextValue is one key of the request context. Values is empty for Absent
// and Unknown; a Present key with no values is the empty set.
type ContextValue struct {
	State  KeyState
	Values []string
}

// PresentValues is a Present value.
func PresentValues(v ...string) ContextValue { return ContextValue{State: Present, Values: v} }

// AbsentValue and UnknownValue are the other two states.
var (
	AbsentValue  = ContextValue{State: Absent}
	UnknownValue = ContextValue{State: Unknown}
)

// Context is the request context: lower-cased keys (ASCII A-Z only, §8.1).
type Context struct {
	Mode   Mode
	Values map[string]ContextValue
	// AbsentPrefixes lists key namespaces that are fully known: a key under
	// one of them that is not in Values is Absent even in symbolic mode (for
	// example "aws:principaltag/" once the principal's tags are loaded).
	AbsentPrefixes []string
	// Multivalued reports whether a lower-cased key is multivalued (an ArrayOf*
	// type). Nil means the global multivalued keys only; the catalog supplies
	// the service-specific ones.
	Multivalued func(lowerKey string) bool
}

// Lookup returns the state of key (any case).
func (c *Context) Lookup(key string) ContextValue {
	k := asciiLower(key)
	if v, ok := c.Values[k]; ok {
		return v
	}
	for _, p := range c.AbsentPrefixes {
		if strings.HasPrefix(k, p) {
			return AbsentValue
		}
	}
	if c.Mode == Symbolic {
		return UnknownValue
	}
	return AbsentValue
}

func (c *Context) multivalued(lowerKey string) bool {
	if c.Multivalued != nil {
		return c.Multivalued(lowerKey)
	}
	return policy.IsGlobalMultivaluedKey(lowerKey)
}

// asciiLower lower-cases ASCII letters only, so Unicode look-alikes (the Kelvin
// sign) never equal an ASCII key (A22).
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// NetworkPath says how the request reached AWS. The path decides which of the
// network keys exist (§9.2).
type NetworkPath uint8

const (
	// PathAuto derives the path from the caller-supplied keys in concrete mode
	// (any VPC key present means a VPC endpoint) and leaves every network key
	// unknown in symbolic mode.
	PathAuto NetworkPath = iota
	PathInternet
	PathVPCE
)

// ResourceInfo is what the snapshot knows about the resource being accessed.
type ResourceInfo struct {
	Account string
	OrgID   string // "" if the resource's account is not in an organization
	// OrgPaths are the resource account's org paths.
	OrgPaths []string
	Tags     map[string]string
	// TagsSupported is false when the service does not support aws:ResourceTag
	// for this action (catalog); every resource tag key is then absent.
	TagsSupported bool
}

// DeriveInput is everything buildContext needs; all of it is plain data.
type DeriveInput struct {
	Mode      Mode
	Principal *model.Principal
	// PrincipalOrgID and PrincipalOrgPaths are the principal's account's
	// organization facts; "" means the account is not in an organization.
	PrincipalOrgID    string
	PrincipalOrgPaths []string
	// LongTermCredentials is true for an IAM user or root signing with access
	// keys: the token and MFA keys are then absent.
	LongTermCredentials bool
	// ServiceName is the principal's service name (kind Service only), such as
	// "sns.amazonaws.com".
	ServiceName string
	Resource    *ResourceInfo // nil: resource keys are left to Supplied
	Network     NetworkPath
	// DirectCall is true when the principal calls the service itself, not
	// through another service: aws:ViaAWSService and aws:CalledVia* are absent.
	DirectCall bool
	// Profile pins keys for a symbolic query (see Profile). Supplied overrides
	// it. Keys may be in any case.
	Profile  map[string]ContextValue
	Supplied map[string]ContextValue
}

// networkKeys are the keys that depend on the path.
var (
	ipKeys  = []string{"aws:sourceip"}
	vpcKeys = []string{"aws:sourcevpc", "aws:sourcevpce", "aws:vpceaccount"}
)

// DeriveContext builds the request context for one request: the keys AWS
// derives from the principal, the resource and the path (§9.2), then profile
// pins, then caller-supplied values. Absent keys are listed explicitly so that
// symbolic mode does not turn them into unknowns.
func DeriveContext(in DeriveInput) *Context {
	c := &Context{Mode: in.Mode, Values: map[string]ContextValue{}}
	set := func(k string, v ContextValue) { c.Values[k] = v }
	one := func(k, v string) { set(k, PresentValues(v)) }
	absent := func(ks ...string) {
		for _, k := range ks {
			set(k, AbsentValue)
		}
	}

	if p := in.Principal; p != nil {
		c.AbsentPrefixes = append(c.AbsentPrefixes, "aws:principaltag/")
		derivePrincipal(c, in, p, one, absent)
	}
	if r := in.Resource; r != nil {
		if r.Account != "" {
			one("aws:resourceaccount", r.Account)
		} else {
			absent("aws:resourceaccount")
		}
		if r.OrgID != "" {
			one("aws:resourceorgid", r.OrgID)
			set("aws:resourceorgpaths", PresentValues(sortedCopy(r.OrgPaths)...))
		} else {
			absent("aws:resourceorgid", "aws:resourceorgpaths")
		}
		c.AbsentPrefixes = append(c.AbsentPrefixes, "aws:resourcetag/")
		if r.TagsSupported {
			for k, v := range r.Tags {
				one("aws:resourcetag/"+asciiLower(k), v)
			}
		}
	}
	if in.DirectCall {
		absent("aws:viaawsservice", "aws:calledvia", "aws:calledviafirst", "aws:calledvialast")
	}

	for k, v := range in.Profile {
		set(asciiLower(k), v)
	}
	for k, v := range in.Supplied {
		set(asciiLower(k), v)
	}

	// The path is decided last, because in concrete mode it is derived from
	// what the caller supplied.
	path := in.Network
	if path == PathAuto && in.Mode == Concrete {
		path = PathInternet
		for _, k := range vpcKeys {
			if v, ok := c.Values[k]; ok && v.State == Present {
				path = PathVPCE
			}
		}
	}
	switch path {
	case PathVPCE:
		for _, k := range ipKeys {
			if v, ok := c.Values[k]; !ok || v.State != Present {
				set(k, AbsentValue)
			}
		}
	case PathInternet:
		for _, k := range vpcKeys {
			if v, ok := c.Values[k]; !ok || v.State != Present {
				set(k, AbsentValue)
			}
		}
	}
	return c
}

func derivePrincipal(c *Context, in DeriveInput, p *model.Principal, one func(k, v string), absent func(ks ...string)) {
	anonymous := p.Kind == model.Anonymous
	service := p.Kind == model.Service
	switch {
	case anonymous || service:
		absent("aws:principalarn", "aws:principalaccount", "aws:principalorgid", "aws:principalorgpaths")
	default:
		arn := p.ARN
		if p.Kind == model.RoleSession && p.EntityARN != "" {
			arn = p.EntityARN // the role ARN, not the session ARN
		}
		one("aws:principalarn", arn)
		one("aws:principalaccount", p.AccountID)
		if in.PrincipalOrgID != "" {
			one("aws:principalorgid", in.PrincipalOrgID)
			c.Values["aws:principalorgpaths"] = PresentValues(sortedCopy(in.PrincipalOrgPaths)...)
		} else {
			absent("aws:principalorgid", "aws:principalorgpaths")
		}
	}

	// Entity tags overlaid by session tags.
	for k, v := range p.Tags {
		one("aws:principaltag/"+asciiLower(k), v)
	}
	for k, v := range p.SessionTags {
		one("aws:principaltag/"+asciiLower(k), v)
	}
	switch p.Kind {
	case model.IAMUser:
		one("aws:principaltype", "User")
		one("aws:userid", p.UniqueID)
		one("aws:username", lastSegment(p.ARN, "/"))
	case model.RoleSession:
		one("aws:principaltype", "AssumedRole")
		one("aws:userid", p.UniqueID+":"+lastSegment(p.ARN, "/"))
		absent("aws:username")
	case model.FederatedUserSession:
		one("aws:principaltype", "FederatedUser")
		one("aws:userid", p.AccountID+":"+lastSegment(p.ARN, "/"))
		absent("aws:username")
	case model.Root:
		one("aws:principaltype", "Account")
		one("aws:userid", p.AccountID)
		absent("aws:username")
	case model.Anonymous:
		one("aws:principaltype", "Anonymous")
		one("aws:userid", "anonymous")
		absent("aws:username")
	default:
		absent("aws:principaltype", "aws:userid", "aws:username")
	}

	switch {
	case service:
		one("aws:principalisawsservice", "true")
		one("aws:principalservicename", in.ServiceName)
		c.Values["aws:principalservicenameslist"] = PresentValues(in.ServiceName)
	case anonymous:
		absent("aws:principalisawsservice", "aws:principalservicename", "aws:principalservicenameslist")
	default:
		one("aws:principalisawsservice", "false")
		absent("aws:principalservicename", "aws:principalservicenameslist")
	}

	if in.LongTermCredentials || anonymous {
		absent("aws:tokenissuetime", "aws:multifactorauthpresent", "aws:multifactorauthage")
	}
	if p.SourceIdentity != "" {
		one("aws:sourceidentity", p.SourceIdentity)
	} else {
		absent("aws:sourceidentity")
	}
	if p.FederatedProvider != "" {
		one("aws:federatedprovider", p.FederatedProvider)
	} else {
		absent("aws:federatedprovider")
	}
}

func lastSegment(s, sep string) string {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[i+len(sep):]
	}
	return s
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// ErrProfileUnsupported is returned for an assumption profile that needs a
// constrained unknown (a value known only to lie in a set).
var ErrProfileUnsupported = fmt.Errorf("assumption profile needs constrained unknowns")

// Profile returns the partial context an assumption profile pins (§9.4). now
// is the evaluation time, passed in because this package reads no clock.
//
//	any-network   SourceIp, SourceVpc and SourceVpce unknown
//	mfa-session   MultiFactorAuthPresent = true
//	now           CurrentTime and EpochTime = now
//	tls           SecureTransport = true
//
// corp-network ("SourceIp lies in the corporate CIDRs") cannot be expressed as
// a plain value and returns ErrProfileUnsupported.
func Profile(name string, now time.Time) (map[string]ContextValue, error) {
	switch name {
	case "any-network":
		return map[string]ContextValue{
			"aws:sourceip": UnknownValue, "aws:sourcevpc": UnknownValue, "aws:sourcevpce": UnknownValue,
		}, nil
	case "mfa-session":
		return map[string]ContextValue{"aws:multifactorauthpresent": PresentValues("true")}, nil
	case "now":
		u := now.UTC()
		return map[string]ContextValue{
			"aws:currenttime": PresentValues(u.Format(time.RFC3339)),
			"aws:epochtime":   PresentValues(strconv.FormatInt(u.Unix(), 10)),
		}, nil
	case "tls":
		return map[string]ContextValue{"aws:securetransport": PresentValues("true")}, nil
	case "corp-network":
		return nil, ErrProfileUnsupported
	}
	return nil, fmt.Errorf("unknown assumption profile %q", name)
}

// DefaultProfile is {now, tls}, the default for effective permissions (§9.4).
func DefaultProfile(now time.Time) map[string]ContextValue {
	out := map[string]ContextValue{}
	for _, n := range []string{"now", "tls"} {
		p, _ := Profile(n, now)
		for k, v := range p {
			out[k] = v
		}
	}
	return out
}
