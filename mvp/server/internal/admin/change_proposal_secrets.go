package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Proposals that carry secrets (issue #719): connections (connector credentials), alert channels (webhook signing
// secrets and URLs, which carry a token) and SIEM sinks (HEC tokens, S3 secret access keys, webhook URLs).
//
// A secret never enters the payload, so it is in no hash, audit event, response or log. SubmitProposal takes each secret
// field out of the body (splitProposalSecrets), leaves the marker "set" in its place and seals the plaintext, one blob per
// field, under the KEK with an AAD that binds the tenant, the request id and the field's path (secretsAAD); the blobs
// live in admin_change_requests.secret_enc, apart from the payload. Every terminal transition of the request (rejected,
// cancelled, expired, applied, failed) already sets that column to NULL in the same statement, so a blob lives exactly
// as long as the request is open. The approval and the apply open the blobs in memory (openSecrets), validate again with
// them and hand the plaintext to the same domain code the admin routes call, which seals it under the object's own AAD.
//
// A field the proposal leaves out keeps its current value on an update; a proposal can replace a secret and can never read one.
const (
	KindConnection   = "connection"
	KindAlertChannel = "alert_channel"
	KindSiemSink     = "siem_sink"
)

// secretMarker stands for a sealed secret in a stored payload.
const secretMarker = "set"

// secretPath is a JSON path of a secret field of a body. urlOnly: the field is a secret only when its value is a URL (a
// webhook URL carries a token; an email address or a syslog host:port does not).
type secretPath struct {
	path    string
	urlOnly bool
}

var proposalSecretPaths = map[string][]secretPath{
	KindConnection:   {{path: "credential.secret"}},
	KindAlertChannel: {{path: "signing_secret"}, {path: "target", urlOnly: true}},
	KindSiemSink:     {{path: "token"}, {path: "target", urlOnly: true}},
}

// maxProposalSecret bounds one secret (a connection secret is at most 8 KiB, a token 4 KiB).
const maxProposalSecret = 8192

// splitProposalSecrets takes the secret fields out of a proposal body. It returns the body with the marker in their
// place (and, for a URL target, the server-derived target_origin the approver sees) and the plaintexts by path. A kind
// without secret fields is returned as it is.
func splitProposalSecrets(kind string, body json.RawMessage) (json.RawMessage, map[string]string, error) {
	paths := proposalSecretPaths[kind]
	if len(paths) == 0 {
		return body, nil, nil
	}
	if len(body) == 0 || len(body) > maxProposalBody {
		return nil, nil, invalid("body is required and at most %d bytes", maxProposalBody)
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, nil, invalid("body must be a JSON object")
	}
	secrets := map[string]string{}
	delete(m, "target_origin") // derived here, never taken from the client
	for _, sp := range paths {
		parent, key := m, sp.path
		if before, after, ok := strings.Cut(sp.path, "."); ok {
			sub, _ := m[before].(map[string]any)
			if sub == nil {
				continue
			}
			parent, key = sub, after
		}
		v, ok := parent[key]
		if !ok || v == nil {
			continue
		}
		str, ok := v.(string)
		if !ok {
			return nil, nil, invalid("%s must be a string", sp.path)
		}
		if sp.urlOnly && !strings.Contains(str, "://") {
			continue
		}
		if str == "" || len(str) > maxProposalSecret {
			return nil, nil, invalid("%s must be 1 to %d characters (leave it out to keep the current value)", sp.path, maxProposalSecret)
		}
		secrets[sp.path] = str
		parent[key] = secretMarker
		if sp.path == "target" {
			m["target_origin"] = safehttp.Origin(str)
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil, nil, invalid("body: %v", err)
	}
	return out, secrets, nil
}

// secretsAAD binds one sealed field to its tenant, request and path, so a blob cannot be moved to another tenant,
// another proposal or another field of the same one.
func secretsAAD(t tenancy.ID, id uuid.UUID, path string) []byte {
	return seal.AAD(t, "admin_change_requests", "secret_enc", id.String(), path)
}

// sealSecrets seals each secret and returns the column value: a JSON object of path to the base64 of its sealed form.
func (e *env) sealSecrets(id uuid.UUID, secrets map[string]string) ([]byte, error) {
	if e.svc.Sealer == nil {
		return nil, newErr(503, "sealer_unavailable", "no key-encryption key is configured to seal the proposal's secrets")
	}
	blobs := make(map[string]string, len(secrets))
	for path, v := range secrets {
		sealed, err := e.svc.Sealer.Seal([]byte(v), secretsAAD(e.tx.Tenant(), id, path))
		if err != nil {
			return nil, err
		}
		blobs[path] = base64.StdEncoding.EncodeToString(sealed)
	}
	return json.Marshal(blobs)
}

// OpenProposalSecrets opens the sealed fields of a request under the tenant and request id they were sealed for. Any blob
// that is not for this tenant, this request and the path it is stored under fails.
func OpenProposalSecrets(sealer *seal.Sealer, t tenancy.ID, id uuid.UUID, enc []byte) (map[string]string, error) {
	if len(enc) == 0 {
		return nil, nil
	}
	var blobs map[string]string
	if err := json.Unmarshal(enc, &blobs); err != nil {
		return nil, errors.New("admin: the sealed secrets are unreadable")
	}
	if sealer == nil {
		return nil, errors.New("admin: no sealer")
	}
	out := make(map[string]string, len(blobs))
	for path, b64 := range blobs {
		sealed, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, errors.New("admin: the sealed secrets are unreadable")
		}
		plain, err := sealer.Open(sealed, secretsAAD(t, id, path))
		if err != nil {
			return nil, err
		}
		out[path] = string(plain)
	}
	return out, nil
}

// openSecrets loads the plaintext secrets of a config.proposal into the env for the validation or the apply. A blob that
// does not open ends the request as tampered; the error carries no detail.
func (e *env) openSecrets(ch *store.AdminChange) error {
	if ch.Type != TypeConfigProposal || len(ch.SecretEnc) == 0 {
		return nil
	}
	s, err := OpenProposalSecrets(e.svc.Sealer, e.tx.Tenant(), ch.ID, ch.SecretEnc)
	if err != nil {
		return conflict(ReasonPayloadTampered, "the sealed secrets of the request do not open")
	}
	e.secrets = s
	return nil
}

// secretOf is the plaintext of a field whose stored value is the marker. A marker with no sealed secret behind it is a
// request that was altered after it was filed.
func (e *env) secretOf(path string, stored *string) (string, bool, error) {
	if stored == nil {
		return "", false, nil
	}
	if v, ok := e.secrets[path]; ok {
		return v, true, nil
	}
	if *stored == secretMarker && path != "target" {
		return "", false, conflict(ReasonPayloadTampered, "%s is marked as set but no secret is held for it", path)
	}
	return "", false, nil
}

// ---------------------------------------------------------------- bodies

// ConnectionBody is the body of a connection proposal. Without an id it creates a connection in draft (name, connector_type,
// system, role, config as POST /api/connections); with the connection's id it patches its config (as PATCH
// /api/connections/{id}/config) and/or replaces its credential (as PUT .../credential). It never activates: that stays a
// separate step by a person.
type ConnectionBody struct {
	Name          string                `json:"name"`
	ConnectorType string                `json:"connector_type"`
	System        string                `json:"system"`
	Role          string                `json:"role"`
	Config        json.RawMessage       `json:"config"`
	Credential    *ConnectionCredential `json:"credential"`
}

// ConnectionCredential is a credential: a reference (vault:..., agent:...) or a secret, which is sealed, never stored in the
// payload and never returned. Exactly one of them.
type ConnectionCredential struct {
	Secret    string `json:"secret,omitempty"`
	Reference string `json:"reference,omitempty"`
}

// AlertChannelBody is the body of an alert_channel proposal: the body of POST /api/alerts/channels, or with the channel's id
// of PUT /api/alerts/channels/{id}. A webhook's URL (it carries a token) and signing secret are sealed; TargetOrigin is the
// scheme, host and port of the sealed URL, set by the server. A webhook is created with the signing secret the proposer
// chose, because a secret the server generated could be shown to nobody.
type AlertChannelBody struct {
	Name          string  `json:"name"`
	Kind          string  `json:"kind"`
	Target        *string `json:"target"`
	TargetOrigin  string  `json:"target_origin,omitempty"`
	MinSeverity   string  `json:"min_severity"`
	Enabled       *bool   `json:"enabled"`
	SigningSecret *string `json:"signing_secret"`
}

// SiemSinkBody is the body of a siem_sink proposal: the body of POST /api/siem/sinks, or with the sink's id of PUT
// /api/siem/sinks/{id} (omitted fields keep their value). The token (an HEC token, an S3 secret access key) and a URL target
// are sealed; TargetOrigin is set by the server.
type SiemSinkBody struct {
	Name         string    `json:"name"`
	Kind         string    `json:"kind"`
	Format       string    `json:"format"`
	Target       *string   `json:"target"`
	TargetOrigin string    `json:"target_origin,omitempty"`
	Flavor       string    `json:"flavor"`
	CAPEM        *string   `json:"ca_pem"`
	Token        *string   `json:"token"`
	IncludeHTTP  *bool     `json:"include_http"`
	EventFilter  *[]string `json:"event_filter"`
	Region       *string   `json:"region"`
	AccessKeyID  *string   `json:"access_key_id"`
	Enabled      *bool     `json:"enabled"`
	Start        string    `json:"start"`
}

// ---------------------------------------------------------------- connection

func (e *env) readinessSvc() (*readiness.Service, error) {
	if e.svc.Connections == nil {
		return nil, newErr(503, "connections_unavailable", "connection proposals are not available on this server")
	}
	return e.svc.Connections, nil
}

func (b *ConnectionBody) credentialInput(e *env) (*readiness.CredentialInput, error) {
	if b.Credential == nil {
		return nil, nil
	}
	in := readiness.CredentialInput{Reference: b.Credential.Reference}
	if b.Credential.Secret != "" {
		v, _, err := e.secretOf("credential.secret", &b.Credential.Secret)
		if err != nil {
			return nil, err
		}
		if v == "" {
			return nil, conflict(ReasonPayloadTampered, "credential.secret is marked as set but no secret is held for it")
		}
		in.Secret = v
	}
	return &in, nil
}

func planConnection(e *env, id string, b *ConnectionBody) error {
	rd, err := e.readinessSvc()
	if err != nil {
		return err
	}
	cred, err := b.credentialInput(e)
	if err != nil {
		return err
	}
	if id == "" {
		in := readiness.CreateInput{Name: b.Name, ConnectorType: b.ConnectorType, System: b.System, Role: b.Role, Config: b.Config}
		if err := rd.CheckCreate(in); err != nil {
			return err
		}
		cs, err := e.tx.Connections()
		if err != nil {
			return err
		}
		for _, c := range cs {
			if strings.EqualFold(c.Name, strings.TrimSpace(b.Name)) {
				return conflict("duplicate_connection", "a connection with that name already exists")
			}
		}
		if cred != nil {
			return rd.CheckCredential(e.tx, rd.TemplateIDOf(b.ConnectorType), *cred)
		}
		return nil
	}
	if b.Name != "" || b.ConnectorType != "" || b.System != "" || b.Role != "" {
		return invalid("an update changes config and credential only: name, connector_type, system and role cannot change")
	}
	hasConfig := len(b.Config) > 0 && string(b.Config) != "null"
	if !hasConfig && cred == nil {
		return invalid("give config, credential or both")
	}
	conn, err := e.tx.Connection(id)
	if errors.Is(err, store.ErrNotFound) {
		return notFound("connection")
	} else if err != nil {
		return err
	}
	if hasConfig {
		if err := rd.CheckPatch(e.tx, id, b.Config, e.now); err != nil {
			return err
		}
	}
	if cred != nil {
		return rd.CheckCredential(e.tx, rd.TemplateIDOf(conn.ConnectorType), *cred)
	}
	return nil
}

func applyConnection(e *env, id string, b *ConnectionBody, display string) error {
	rd, err := e.readinessSvc()
	if err != nil {
		return err
	}
	cred, err := b.credentialInput(e)
	if err != nil {
		return err
	}
	hasConfig := len(b.Config) > 0 && string(b.Config) != "null"
	if id == "" {
		bun, err := rd.Create(e.tx, readiness.CreateInput{Name: b.Name, ConnectorType: b.ConnectorType, System: b.System, Role: b.Role,
			Config: b.Config}, display, e.now)
		if err != nil {
			return err
		}
		id = bun.Conn.ID
	} else if hasConfig {
		if _, err := rd.PatchConfig(e.tx, id, b.Config, display, e.now); err != nil {
			return err
		}
	}
	if cred != nil {
		// the domain code seals the secret under the connection's own AAD
		_, err = rd.SetCredential(e.tx, id, *cred, display, e.now)
	}
	return err
}

// ---------------------------------------------------------------- alert channel

func (b *AlertChannelBody) spec(e *env, cur *store.AlertChannel) (alerts.ChannelSpec, error) {
	sp := alerts.ChannelSpec{Name: b.Name, Kind: b.Kind, MinSeverity: b.MinSeverity, Enabled: true}
	if cur != nil {
		sp.Enabled = cur.Enabled
		if sp.Name == "" {
			sp.Name = cur.Name
		}
		if sp.MinSeverity == "" {
			sp.MinSeverity = cur.MinSeverity
		}
		sp.Target = cur.Target
	} else if sp.MinSeverity == "" {
		sp.MinSeverity = "high"
	}
	if b.Enabled != nil {
		sp.Enabled = *b.Enabled
	}
	if v, ok, err := e.secretOf("target", b.Target); err != nil {
		return sp, err
	} else if ok {
		sp.Target = v
	} else if b.Target != nil {
		sp.Target = *b.Target
	}
	if b.SigningSecret != nil {
		v, ok, err := e.secretOf("signing_secret", b.SigningSecret)
		if err != nil {
			return sp, err
		}
		if !ok {
			return sp, conflict(ReasonPayloadTampered, "signing_secret is marked as set but no secret is held for it")
		}
		sp.Secret = v
	}
	return sp, nil
}

func planAlertChannel(e *env, id string, b *AlertChannelBody) error {
	if id == "" {
		sp, err := b.spec(e, nil)
		if err != nil {
			return err
		}
		if sp.Kind == "webhook" && sp.Secret == "" {
			return newErr(422, "secret_required", "a webhook channel proposal needs signing_secret: the receiver must know it, and a proposal cannot show a generated one")
		}
		return alerts.CheckChannel(e.tx, "", sp, !e.svc.Prod)
	}
	cur, err := e.tx.AlertChannel(id)
	if errors.Is(err, store.ErrNotFound) {
		return notFound("channel")
	} else if err != nil {
		return err
	}
	sp, err := b.spec(e, cur)
	if err != nil {
		return err
	}
	return alerts.CheckChannel(e.tx, id, sp, !e.svc.Prod)
}

func applyAlertChannel(e *env, id string, b *AlertChannelBody, by uuid.UUID, display string) error {
	actor := alerts.Actor{UserID: by.String(), Display: display}
	if id == "" {
		sp, err := b.spec(e, nil)
		if err != nil {
			return err
		}
		_, _, err = alerts.CreateChannel(e.tx, e.svc.Sealer, sp, !e.svc.Prod, actor, e.now)
		return err
	}
	cur, err := e.tx.AlertChannel(id)
	if err != nil {
		return err
	}
	sp, err := b.spec(e, cur)
	if err != nil {
		return err
	}
	_, _, err = alerts.UpdateChannel(e.tx, e.svc.Sealer, id, sp, !e.svc.Prod, actor, e.now)
	return err
}

// ---------------------------------------------------------------- SIEM sink

func (b *SiemSinkBody) spec(e *env, cur *store.SiemSink) (siem.SinkSpec, error) {
	sp := siem.SinkSpec{Name: b.Name, Kind: b.Kind, Format: b.Format, Flavor: b.Flavor, Enabled: true, Start: b.Start}
	if cur != nil {
		sp.Enabled, sp.IncludeHTTP, sp.Target, sp.EventFilter = cur.Enabled, cur.IncludeHTTP, cur.Target, cur.EventFilter
		sp.Region, sp.AccessKeyID = cur.Region, cur.AccessKeyID
		if cur.CAPEM != nil {
			sp.CAPEM = *cur.CAPEM
		}
		if sp.Name == "" {
			sp.Name = cur.Name
		}
		if sp.Format == "" {
			sp.Format = cur.Format
		}
		if sp.Flavor == "" {
			sp.Flavor = cur.Flavor
		}
	}
	if b.Enabled != nil {
		sp.Enabled = *b.Enabled
	}
	if b.IncludeHTTP != nil {
		sp.IncludeHTTP = *b.IncludeHTTP
	}
	if b.EventFilter != nil {
		sp.EventFilter = *b.EventFilter
	}
	if b.Region != nil {
		sp.Region = *b.Region
	}
	if b.AccessKeyID != nil {
		sp.AccessKeyID = *b.AccessKeyID
	}
	if b.CAPEM != nil {
		sp.CAPEM = *b.CAPEM
	}
	if v, ok, err := e.secretOf("target", b.Target); err != nil {
		return sp, err
	} else if ok {
		sp.Target = v
	} else if b.Target != nil {
		sp.Target = *b.Target
	}
	if b.Token != nil {
		v, ok, err := e.secretOf("token", b.Token)
		if err != nil {
			return sp, err
		}
		if !ok {
			return sp, conflict(ReasonPayloadTampered, "token is marked as set but no secret is held for it")
		}
		sp.Token = &v
	}
	return sp, nil
}

func planSiemSink(e *env, id string, b *SiemSinkBody) error {
	if id == "" {
		sp, err := b.spec(e, nil)
		if err != nil {
			return err
		}
		return siem.CheckSinkCreate(sp, !e.svc.Prod)
	}
	cur, err := e.tx.SiemSink(id)
	if errors.Is(err, store.ErrNotFound) {
		return notFound("sink")
	} else if err != nil {
		return err
	}
	sp, err := b.spec(e, cur)
	if err != nil {
		return err
	}
	return siem.CheckSinkUpdate(e.tx, id, sp, !e.svc.Prod)
}

func applySiemSink(e *env, id string, b *SiemSinkBody, by uuid.UUID, display string) error {
	actor := siem.Actor{UserID: by.String(), Display: display}
	var cur *store.SiemSink
	if id != "" {
		var err error
		if cur, err = e.tx.SiemSink(id); err != nil {
			return err
		}
	}
	sp, err := b.spec(e, cur)
	if err != nil {
		return err
	}
	if id == "" {
		_, err = siem.CreateSink(e.tx, e.svc.Sealer, sp, !e.svc.Prod, actor, e.now)
	} else {
		_, err = siem.UpdateSink(e.tx, e.svc.Sealer, id, sp, !e.svc.Prod, actor, e.now)
	}
	return err
}

// ---------------------------------------------------------------- summaries and results

// secretNote says whether a secret field is held, never what it is.
func secretNote(p *string) string {
	if p == nil {
		return "unchanged"
	}
	return "set"
}

func originNote(b string) string {
	if b == "" {
		return ""
	}
	return " at " + b
}

func summarizeSecretKind(id string, body any) (string, bool) {
	verb := func(noun, name string) string {
		if id == "" {
			return fmt.Sprintf("create %s %q", noun, name)
		}
		return fmt.Sprintf("change %s %s", noun, id)
	}
	switch b := body.(type) {
	case *ConnectionBody:
		cred := "unchanged"
		if b.Credential != nil {
			cred = "reference"
			if b.Credential.Secret != "" {
				cred = "secret set"
			}
		}
		if id == "" {
			return fmt.Sprintf("create connection %q (%s, as a draft: it still needs validation and a separate activation; credential %s)",
				b.Name, b.ConnectorType, cred), true
		}
		return fmt.Sprintf("change connection %s (config %t, credential %s; activation stays a separate step)", id,
			len(b.Config) > 0 && string(b.Config) != "null", cred), true
	case *AlertChannelBody:
		return fmt.Sprintf("%s (%s%s, signing secret %s)", verb("alert channel", b.Name), b.Kind, originNote(b.TargetOrigin), secretNote(b.SigningSecret)), true
	case *SiemSinkBody:
		return fmt.Sprintf("%s (%s%s, token %s)", verb("SIEM sink", b.Name), b.Kind, originNote(b.TargetOrigin), secretNote(b.Token)), true
	}
	return "", false
}

// secretKindResult is the id of the row an applied proposal of these kinds made, found by its name.
func secretKindResult(tx *store.TenantTx, body any) string {
	switch b := body.(type) {
	case *ConnectionBody:
		if cs, err := tx.Connections(); err == nil {
			for _, c := range cs {
				if strings.EqualFold(c.Name, strings.TrimSpace(b.Name)) {
					return c.ID
				}
			}
		}
	case *AlertChannelBody:
		if cs, err := tx.AlertChannels(); err == nil {
			for _, c := range cs {
				if c.Name == strings.TrimSpace(b.Name) {
					return c.ID
				}
			}
		}
	case *SiemSinkBody:
		if ks, err := tx.SiemSinks(); err == nil {
			for _, k := range ks {
				if k.Name == strings.TrimSpace(b.Name) {
					return k.ID
				}
			}
		}
	}
	return ""
}
