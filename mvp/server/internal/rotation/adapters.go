package rotation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// AdapterTypes lists the types a tenant can register; "fake" only where
// Service.AllowFake is set.
func AdapterTypes(allowFake bool) []string {
	out := []string{TypeAWSIAM, TypeAWSSM, TypeVault, TypeGitHub}
	if allowFake {
		out = append(out, TypeFake)
	}
	return out
}

// kindsOf is the secret kinds an adapter type can rotate; nil means any.
func kindsOf(adapterType string) []string {
	switch adapterType {
	case TypeAWSIAM:
		return []string{"access_key"}
	case TypeGitHub:
		return []string{"deploy_key"}
	case TypeVault:
		return []string{"approle_secret_id"}
	}
	return nil
}

// Supports reports whether adapters of this type can rotate secrets of kind.
func Supports(adapterType, kind string) bool {
	k := kindsOf(adapterType)
	return k == nil || slices.Contains(k, kind)
}

// ManualReason says why Tessera cannot rotate a kind through any adapter, for
// kinds where the provider offers no API. "" means an adapter may exist.
func ManualReason(kind string) string {
	switch kind {
	case "pat":
		return "GitHub has no API to create, rotate or revoke personal access tokens (classic or fine-grained); the owner must regenerate it in GitHub"
	case "github_app":
		return "GitHub App private keys can only be generated in the GitHub UI; installation tokens last one hour and need no rotation"
	case "keypair":
		return "key-pair rotation for this system is not supported yet; the owner must rotate it"
	}
	return ""
}

// ---------------------------------------------------------------- settings and credentials

var (
	fakeFailAt  = []string{"", "create", "handover", "disable", "observe", "delete"}
	printableRE = regexp.MustCompile(`^[\x21-\x7e]+$`) // printable, no spaces
)

// validSecret: 8 to 4096 printable characters, no spaces.
func validSecret(s string) bool { return len(s) >= 8 && len(s) <= 4096 && printableRE.MatchString(s) }

// AdapterInput is what an admin submits for an adapter. Config is non-secret
// and echoed back; Credential is sealed and never returned.
type AdapterInput struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Config     map[string]string `json:"config"`
	Credential map[string]string `json:"credential"`
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// validateEndpoint accepts an http(s) base URL without user info, query or
// fragment; plain http only outside prod (safehttp still limits it to dev
// loopback at call time).
func validateEndpoint(field, raw, env string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be an http(s) URL without credentials, query or fragment", field)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && env != config.Prod) {
		return fmt.Errorf("%s must be an https URL", field)
	}
	return nil
}

// cleanConfig validates input config for a type and returns the canonical map.
func cleanConfig(typ string, in map[string]string, env string) (map[string]string, error) {
	allowed := map[string][]string{
		TypeAWSIAM: {"region", "endpoint"}, TypeAWSSM: {"region", "endpoint"},
		TypeVault: {"address", "namespace"}, TypeGitHub: {"api_url"},
		TypeFake: {"fail_at", "consumer_still_uses", "delete_lag", "retirement"},
	}[typ]
	out := map[string]string{}
	for k, v := range in {
		if !slices.Contains(allowed, k) {
			return nil, fmt.Errorf("config.%s is not a setting of %s adapters (have %s)", k, typ, strings.Join(allowed, ", "))
		}
		out[k] = strings.TrimSpace(v)
	}
	var err error
	switch typ {
	case TypeAWSIAM, TypeAWSSM:
		if r := out["region"]; r != "" && !regionRE.MatchString(r) {
			err = fmt.Errorf("config.region must be an AWS region such as eu-west-1")
		}
		if e := out["endpoint"]; err == nil && e != "" {
			err = validateEndpoint("config.endpoint", e, env)
		}
	case TypeVault:
		if out["address"] == "" {
			err = fmt.Errorf("config.address (the Vault URL) is required")
		} else {
			err = validateEndpoint("config.address", out["address"], env)
		}
		if ns := out["namespace"]; err == nil && ns != "" && !vaultNSRE.MatchString(ns) {
			err = fmt.Errorf("config.namespace contains characters Vault namespaces do not use")
		}
	case TypeGitHub:
		if e := out["api_url"]; e != "" {
			err = validateEndpoint("config.api_url", e, env)
		}
	case TypeFake:
		if !slices.Contains(fakeFailAt, out["fail_at"]) {
			err = fmt.Errorf("config.fail_at must be one of create, handover, disable, observe, delete")
		}
		if v := out["consumer_still_uses"]; err == nil && v != "" && v != "true" && v != "false" {
			err = fmt.Errorf("config.consumer_still_uses must be true or false")
		}
		if v := out["delete_lag"]; err == nil && v != "" {
			if n, perr := strconv.Atoi(v); perr != nil || n < 0 || n > 1000 {
				err = fmt.Errorf("config.delete_lag must be a number of reads from 0 to 1000")
			}
		}
		if v := out["retirement"]; err == nil && v != "" && v != RetireDeleted && v != RetireDeprecated {
			err = fmt.Errorf("config.retirement must be deleted or deprecated")
		}
	}
	for k, v := range out {
		if v == "" {
			delete(out, k)
		}
	}
	return out, err
}

// cleanCredential validates the credential fields of a type.
func cleanCredential(typ string, in map[string]string) (map[string]string, error) {
	fields := map[string][]string{
		TypeAWSIAM: {"access_key_id", "secret_access_key", "session_token"},
		TypeAWSSM:  {"access_key_id", "secret_access_key", "session_token"},
		TypeVault:  {"token"}, TypeGitHub: {"token"}, TypeFake: nil,
	}[typ]
	out := map[string]string{}
	for k, v := range in {
		if !slices.Contains(fields, k) {
			return nil, fmt.Errorf("credential.%s is not a field of %s adapters (have %s)", k, typ, strings.Join(fields, ", "))
		}
		out[k] = strings.TrimSpace(v)
	}
	switch typ {
	case TypeAWSIAM, TypeAWSSM:
		if !keyIDRE.MatchString(out["access_key_id"]) {
			return nil, fmt.Errorf("credential.access_key_id must be an AWS access key id")
		}
		if !validSecret(out["secret_access_key"]) {
			return nil, fmt.Errorf("credential.secret_access_key is required")
		}
		if t := out["session_token"]; t != "" && !validSecret(t) {
			return nil, fmt.Errorf("credential.session_token is not a valid token")
		}
	case TypeVault, TypeGitHub:
		if !validSecret(out["token"]) {
			return nil, fmt.Errorf("credential.token is required (8 to 4096 printable characters, no spaces)")
		}
	}
	for k, v := range out {
		if v == "" {
			delete(out, k)
		}
	}
	return out, nil
}

// sealAAD binds a sealed credential to its tenant, table, column and adapter.
func sealAAD(t tenancy.ID, adapterID string) []byte {
	return seal.AAD(t, "rotation_adapters", "secret_enc", adapterID)
}

// openCredential unseals an adapter row's credential.
func openCredential(s *seal.Sealer, row *store.RotationAdapter) (map[string]string, error) {
	if s == nil {
		return nil, fmt.Errorf("rotation: sealing is not configured")
	}
	plain, err := s.Open(row.SecretEnc, sealAAD(row.TenantID, row.ID))
	if err != nil {
		return nil, fmt.Errorf("rotation: adapter %q: %w", row.Name, err)
	}
	var cred map[string]string
	if err := json.Unmarshal(plain, &cred); err != nil {
		return nil, fmt.Errorf("rotation: adapter %q: unreadable credential", row.Name)
	}
	return cred, nil
}

// ---------------------------------------------------------------- building adapters

// Built is an adapter row turned into something that can call its provider.
type Built struct {
	Adapter     Adapter     // nil for a type that is only a destination
	Destination Destination // nil for a type that cannot receive credentials
}

// Factory builds adapters from their rows. HTTP must be an internal/safehttp client.
type Factory struct {
	HTTP      *http.Client
	Sealer    *seal.Sealer
	Now       func() time.Time
	AllowFake bool
	// Override replaces Build (tests).
	Override func(row *store.RotationAdapter) (*Built, error)
}

// Build opens the row's credential and builds its adapter.
func (f *Factory) Build(row *store.RotationAdapter) (*Built, error) {
	if f.Override != nil {
		return f.Override(row)
	}
	now := f.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	var cfg map[string]string
	if err := json.Unmarshal([]byte(row.Config), &cfg); err != nil {
		return nil, fmt.Errorf("rotation: adapter %q: unreadable config", row.Name)
	}
	if row.Type == TypeFake {
		if !f.AllowFake {
			return nil, fmt.Errorf("rotation: adapter %q is a simulated adapter, which this environment refuses", row.Name)
		}
		a := newFake(row.ID, cfg, now)
		return &Built{Adapter: a, Destination: a}, nil
	}
	cred, err := openCredential(f.Sealer, row)
	if err != nil {
		return nil, err
	}
	if f.HTTP == nil {
		return nil, fmt.Errorf("rotation: no outbound HTTP client configured")
	}
	switch row.Type {
	case TypeAWSIAM:
		a := newIAM(f.HTTP, awsCredsOf(cred), cfg["region"], cfg["endpoint"], now)
		return &Built{Adapter: a}, nil
	case TypeAWSSM:
		a := newSM(f.HTTP, awsCredsOf(cred), cfg["region"], cfg["endpoint"], now)
		return &Built{Adapter: a, Destination: a}, nil
	case TypeVault:
		a := newVault(f.HTTP, cfg["address"], cfg["namespace"], cred["token"])
		return &Built{Adapter: a, Destination: a}, nil
	case TypeGitHub:
		return &Built{Adapter: newGitHub(f.HTTP, cfg["api_url"], cred["token"], now)}, nil
	}
	return nil, fmt.Errorf("rotation: adapter %q has unknown type %q", row.Name, row.Type)
}

func awsCredsOf(c map[string]string) awsCreds {
	return awsCreds{AccessKeyID: c["access_key_id"], SecretAccessKey: c["secret_access_key"], SessionToken: c["session_token"]}
}
