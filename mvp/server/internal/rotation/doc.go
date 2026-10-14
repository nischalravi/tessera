// Package rotation orchestrates secret rotation through the customer's vaults
// and cloud APIs (issue #113).
//
// Tessera is not a password vault. For each rotation it asks the provider for
// a new credential, writes it into the customer's own vault (Vault KV v2 or
// AWS Secrets Manager) and never stores it: the new material lives in memory
// for the few calls it takes to hand it over. The only credentials Tessera
// holds are the rotation adapters' own (an AWS access key, a Vault token, a
// GitHub token), sealed under the KEK with internal/seal.
//
// A job walks created -> handed_over -> old_disabled -> verified ->
// old_deleted. The old credential is deleted only after it has been re-read
// from the provider (its age and its last use) and that observation has been
// recorded; the database refuses a job in state verified or old_deleted
// without it. old_deleted is recorded only once the provider's retirement
// condition holds (Capabilities.Retirement): the credential is observed
// absent, or, for a Secrets Manager version, no longer AWSCURRENT/AWSPENDING
// (retired, deprecated, not deleted). A step that fails is retried with a backoff while the error is
// transient and fails the job otherwise.
//
// Outbound calls all go through an *http.Client from internal/safehttp.
package rotation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Adapter types (rotation_adapters.type).
const (
	TypeAWSIAM    = "aws_iam"
	TypeAWSSM     = "aws_secretsmanager"
	TypeVault     = "vault"
	TypeGitHub    = "github"
	TypeFake      = "fake"
	hashSeparator = "#"
)

// Target is the credential to rotate, as the adapter needs to see it.
type Target struct {
	Kind    string // the secret's kind (access_key, deploy_key, ...)
	System  string
	Name    string
	Account string // the account the secret belongs to (the IAM user name for an access key)
	Ref     string // the old credential's reference (the secret's external id; see each adapter)
	NewRef  string // the new credential's reference, once Create has made it
}

// Observation is one re-read of a credential from its provider.
type Observation struct {
	Exists        bool       // the provider still has the credential
	Active        bool       // and it can still be used
	CreatedAt     *time.Time // key age
	LastUsedAt    *time.Time // nil when never used or unknown
	LastUsedKnown bool       // the provider reports last use at all
	// Stages are the version stages the old credential still carries (Secrets
	// Manager only: AWSCURRENT, AWSPENDING, AWSPREVIOUS).
	Stages []string
	Detail string
}

// Minted is a new credential. Material is secret and is never stored or logged.
type Minted struct {
	// Ref is the new credential's reference (persisted as the job's new_ref).
	Ref string
	// OldRef, when set, narrows the old credential's reference once it is
	// known (a Secrets Manager version id); the engine persists it.
	OldRef string
	// Material is the secret (access key secret, SecretID, private key); handed
	// to the destination and dropped.
	Material map[string]string
}

// Capabilities describe what a provider can do, so the plan can say what will
// and will not happen.
type Capabilities struct {
	// CanDisable: the old credential can be deactivated before it is deleted.
	CanDisable bool
	// ReportsLastUsed: the provider reports when a credential was last used.
	ReportsLastUsed bool
	// NeedsDestination: the new credential is written to a vault Tessera is told about.
	NeedsDestination bool
	// MaterialFree: no secret leaves the provider (Secrets Manager rotates in
	// place), so an interrupted hand-over can simply be resumed.
	MaterialFree bool
	// Retirement is what "done" means for the old credential once DeleteOld has
	// been accepted. The zero value, RetireDeleted, requires the provider to no
	// longer list the credential. RetireDeprecated is for providers that cannot
	// delete (Secrets Manager versions): it requires the old version to carry
	// neither AWSCURRENT nor AWSPENDING.
	Retirement string
}

// Retirement conditions (Capabilities.Retirement).
const (
	RetireDeleted    = "deleted"
	RetireDeprecated = "deprecated"
)

// Dispositions recorded when a job completes (rotation.completed old_disposition).
const (
	DispositionDeleted    = "deleted"
	DispositionDeprecated = "retired_deprecated"
)

// retired reports whether obs, read after DeleteOld, meets the provider's
// retirement condition, and what to call the outcome. Exists and inactive is
// never enough for a deletable credential: that is a stale read or a delete
// that did not take, and the engine re-reads until the credential is absent.
func retired(caps Capabilities, obs Observation) (ok bool, disposition string) {
	if caps.Retirement == RetireDeprecated {
		if !obs.Exists {
			return true, DispositionDeprecated
		}
		for _, s := range obs.Stages {
			if s == "AWSCURRENT" || s == "AWSPENDING" {
				return false, DispositionDeprecated
			}
		}
		return true, DispositionDeprecated
	}
	return !obs.Exists, DispositionDeleted
}

// Adapter rotates one kind of credential at one provider.
type Adapter interface {
	Type() string
	Capabilities() Capabilities
	// Validate checks that t has the shape this adapter can act on, before any call.
	Validate(t Target) error
	// Create makes the new credential.
	Create(ctx context.Context, t Target) (*Minted, error)
	// HandOver gives the new credential to its consumers: it writes m to dest at
	// path. Adapters that rotate in place ignore dest.
	HandOver(ctx context.Context, t Target, m *Minted, dest Destination, path string) error
	// DisableOld deactivates the old credential; ErrUnsupported when the
	// provider cannot.
	DisableOld(ctx context.Context, t Target) error
	// ObserveOld re-reads the old credential.
	ObserveOld(ctx context.Context, t Target) (Observation, error)
	// DeleteOld removes the old credential (idempotent).
	DeleteOld(ctx context.Context, t Target) error
	// DeleteNew removes a new credential that could not be handed over (idempotent).
	DeleteNew(ctx context.Context, t Target, newRef string) error
	// InventoryRef is the secret's external id once newRef has replaced oldRef.
	InventoryRef(oldRef, newRef string) string
}

// Destination is a customer vault a new credential is written to.
type Destination interface {
	Type() string
	// ValidatePath checks a destination path before any call.
	ValidatePath(path string) error
	// Put writes data at path (a new version, never a delete).
	Put(ctx context.Context, path string, data map[string]string) error
}

// ErrUnsupported: the provider cannot do this step.
var ErrUnsupported = errors.New("rotation: not supported by this provider")

// Error is an adapter failure. Transient errors (network, throttling, 5xx)
// are retried; the rest fail the job. Messages never contain secrets.
type Error struct {
	Op        string
	Code      string
	Msg       string
	Transient bool
}

func (e *Error) Error() string {
	s := e.Op
	if e.Code != "" {
		s += ": " + e.Code
	}
	if e.Msg != "" {
		s += ": " + e.Msg
	}
	return s
}

func fail(op, code, msg string, transient bool) *Error {
	return &Error{Op: op, Code: code, Msg: truncate(msg, 200), Transient: transient}
}

func truncate(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// IsTransient reports whether err is worth retrying.
func IsTransient(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Transient
}

// splitRef splits "locator#id" into its parts.
func splitRef(ref string) (locator, id string, ok bool) {
	locator, id, ok = strings.Cut(ref, hashSeparator)
	return locator, id, ok && locator != "" && id != ""
}

func badRef(adapter, want string) error {
	return fmt.Errorf("%s: the secret's external id must look like %s", adapter, want)
}

func asError(err error, target **Error) bool { return errors.As(err, target) }

// handOverToDestination writes a new credential to the customer's vault.
func handOverToDestination(ctx context.Context, t Target, m *Minted, dest Destination, path string) error {
	if dest == nil {
		return fail("hand over", "no_destination", "the policy names no destination vault", false)
	}
	if m == nil || len(m.Material) == 0 {
		return fail("hand over", "no_material", "there is no new credential to hand over", false)
	}
	if err := dest.ValidatePath(path); err != nil {
		return err
	}
	data := make(map[string]string, len(m.Material)+4)
	for k, v := range m.Material {
		data[k] = v
	}
	data["tessera_secret"] = t.Name
	data["tessera_credential_ref"] = m.Ref
	return dest.Put(ctx, path, data)
}

func asProblem(err error, target **Problem) bool { return errors.As(err, target) }
