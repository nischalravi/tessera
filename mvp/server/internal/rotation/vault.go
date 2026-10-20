package rotation

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// vaultAdapter rotates a HashiCorp Vault AppRole SecretID and is a hand-over
// destination (it writes a KV v2 secret).
//
// Target: Account is unused; Ref is "<auth mount>/<role>#<secret id accessor>"
// (for the default mount: "approle/etl-role#2f1c..."). Vault cannot deactivate
// a SecretID, so the old one stays valid until it is destroyed by accessor;
// the verification therefore records its age but no last use (Vault does not
// track one).
type vaultAdapter struct {
	http      *http.Client
	addr      string // base URL, no trailing slash
	token     string
	namespace string
}

func newVault(c *http.Client, addr, namespace, token string) *vaultAdapter {
	return &vaultAdapter{http: c, addr: strings.TrimRight(addr, "/"), namespace: namespace, token: token}
}

var (
	vaultSegRE      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	vaultKVSegRE    = regexp.MustCompile(`^[A-Za-z0-9_.@=-]{1,128}$`)
	vaultAccessorRE = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)
	vaultNSRE       = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,200}$`)
)

func (*vaultAdapter) Type() string { return TypeVault }
func (*vaultAdapter) Capabilities() Capabilities {
	return Capabilities{CanDisable: false, ReportsLastUsed: false, NeedsDestination: true}
}

// approleRef splits "<mount>/<role>#<accessor>" into the role's API path and the accessor.
func approleRef(ref string) (rolePath, accessor string, err error) {
	loc, accessor, ok := splitRef(ref)
	if !ok {
		return "", "", badRef("vault", "<auth mount>/<role>#<secret id accessor>")
	}
	i := strings.LastIndex(loc, "/")
	if i <= 0 || i == len(loc)-1 {
		return "", "", badRef("vault", "<auth mount>/<role>#<secret id accessor>")
	}
	mount, role := loc[:i], loc[i+1:]
	for _, seg := range strings.Split(mount, "/") {
		if !vaultSegRE.MatchString(seg) || seg == "." || seg == ".." {
			return "", "", badRef("vault", "<auth mount>/<role>#<secret id accessor>")
		}
	}
	if !vaultSegRE.MatchString(role) || role == "." || role == ".." || !vaultAccessorRE.MatchString(accessor) {
		return "", "", badRef("vault", "<auth mount>/<role>#<secret id accessor>")
	}
	return "auth/" + mount + "/role/" + role, accessor, nil
}

func (v *vaultAdapter) Validate(t Target) error {
	_, _, err := approleRef(t.Ref)
	return err
}

type vaultResult struct {
	status int
	body   []byte
}

func (v *vaultAdapter) call(ctx context.Context, op, method, path string, in any) (vaultResult, error) {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return vaultResult{}, fail(op, "bad_request", "", false)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, v.addr+"/v1/"+path, bytes.NewReader(body))
	if err != nil {
		return vaultResult{}, fail(op, "bad_address", "", false)
	}
	req.Header.Set("X-Vault-Token", v.token)
	if v.namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	status, resp, err := send(v.http, op, req)
	if err != nil {
		return vaultResult{}, err
	}
	return vaultResult{status, resp}, nil
}

// vaultErr turns a non-2xx response into an Error.
func vaultErr(op string, r vaultResult) error {
	var e struct {
		Errors []string `json:"errors"`
	}
	_ = json.Unmarshal(r.body, &e)
	code := http.StatusText(r.status)
	if r.status == http.StatusForbidden {
		code = "permission_denied"
	}
	return fail(op, code, strings.Join(e.Errors, "; "), transientStatus(r.status))
}

// notFound: Vault answers 404, or 400 "failed to find ..." for an accessor it does not know.
func (r vaultResult) notFound() bool {
	return r.status == http.StatusNotFound ||
		(r.status == http.StatusBadRequest && bytes.Contains(bytes.ToLower(r.body), []byte("failed to find")))
}

func (v *vaultAdapter) Create(ctx context.Context, t Target) (*Minted, error) {
	const op = "vault create secret id"
	rolePath, _, err := approleRef(t.Ref)
	if err != nil {
		return nil, err
	}
	r, err := v.call(ctx, op, http.MethodPost, rolePath+"/secret-id", map[string]any{})
	if err != nil {
		return nil, err
	}
	if r.status/100 != 2 {
		return nil, vaultErr(op, r)
	}
	var out struct {
		Data struct {
			SecretID string `json:"secret_id"`
			Accessor string `json:"secret_id_accessor"`
		} `json:"data"`
	}
	if err := json.Unmarshal(r.body, &out); err != nil || out.Data.SecretID == "" || out.Data.Accessor == "" {
		return nil, fail(op, "bad_response", "no secret id in the response", false)
	}
	loc, _, _ := splitRef(t.Ref)
	return &Minted{Ref: loc + hashSeparator + out.Data.Accessor, Material: map[string]string{
		"secret_id": out.Data.SecretID, "secret_id_accessor": out.Data.Accessor,
		"role_path": loc}}, nil
}

func (*vaultAdapter) HandOver(ctx context.Context, t Target, m *Minted, dest Destination, path string) error {
	return handOverToDestination(ctx, t, m, dest, path)
}

func (*vaultAdapter) DisableOld(context.Context, Target) error { return ErrUnsupported }

func (v *vaultAdapter) ObserveOld(ctx context.Context, t Target) (Observation, error) {
	const op = "vault lookup secret id accessor"
	rolePath, accessor, err := approleRef(t.Ref)
	if err != nil {
		return Observation{}, err
	}
	r, err := v.call(ctx, op, http.MethodPost, rolePath+"/secret-id-accessor/lookup",
		map[string]any{"secret_id_accessor": accessor})
	if err != nil {
		return Observation{}, err
	}
	if r.notFound() {
		return Observation{Detail: "the secret id accessor is not known to Vault"}, nil
	}
	if r.status/100 != 2 {
		return Observation{}, vaultErr(op, r)
	}
	var out struct {
		Data struct {
			Created string `json:"creation_time"`
			Expires string `json:"expiration_time"`
		} `json:"data"`
	}
	if err := json.Unmarshal(r.body, &out); err != nil {
		return Observation{}, fail(op, "bad_response", "", false)
	}
	obs := Observation{Exists: true, Active: true, CreatedAt: parseAWSTime(out.Data.Created),
		Detail: "vault does not report when a secret id was last used"}
	if out.Data.Expires != "" && !strings.HasPrefix(out.Data.Expires, "0001-") {
		obs.Detail += "; expires " + out.Data.Expires
	}
	return obs, nil
}

func (v *vaultAdapter) DeleteOld(ctx context.Context, t Target) error { return v.destroy(ctx, t.Ref) }

func (v *vaultAdapter) DeleteNew(ctx context.Context, _ Target, newRef string) error {
	return v.destroy(ctx, newRef)
}

func (v *vaultAdapter) destroy(ctx context.Context, ref string) error {
	const op = "vault destroy secret id accessor"
	rolePath, accessor, err := approleRef(ref)
	if err != nil {
		return err
	}
	r, err := v.call(ctx, op, http.MethodPost, rolePath+"/secret-id-accessor/destroy",
		map[string]any{"secret_id_accessor": accessor})
	if err != nil {
		return err
	}
	if r.status/100 == 2 || r.notFound() {
		return nil
	}
	return vaultErr(op, r)
}

func (*vaultAdapter) InventoryRef(_, newRef string) string { return newRef }

// ValidatePath: "<kv v2 mount>/<secret path>", each segment letters, digits and _.@=-
func (*vaultAdapter) ValidatePath(path string) error {
	segs := strings.Split(path, "/")
	if len(segs) < 2 {
		return fail("vault", "invalid_path", "a destination path is <kv mount>/<secret path>", false)
	}
	for _, s := range segs {
		if !vaultKVSegRE.MatchString(s) || s == "." || s == ".." {
			return fail("vault", "invalid_path", "a destination path uses letters, digits and _.@=- in each segment", false)
		}
	}
	return nil
}

// Put writes a new version of a KV v2 secret.
func (v *vaultAdapter) Put(ctx context.Context, path string, data map[string]string) error {
	const op = "vault kv put"
	if err := v.ValidatePath(path); err != nil {
		return err
	}
	mount, rest, _ := strings.Cut(path, "/")
	segs := strings.Split(rest, "/")
	for i := range segs {
		segs[i] = url.PathEscape(segs[i])
	}
	r, err := v.call(ctx, op, http.MethodPost, url.PathEscape(mount)+"/data/"+strings.Join(segs, "/"),
		map[string]any{"data": data})
	if err != nil {
		return err
	}
	if r.status/100 != 2 {
		return vaultErr(op, r)
	}
	return nil
}
