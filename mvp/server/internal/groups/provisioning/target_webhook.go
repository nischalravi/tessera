package provisioning

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// The webhook target delivers each op as a signed CloudEvents 1.0 JSON message
// (G-77) and, if the receiver offers a read endpoint, reads its state back so
// ops can be verified.
//
//	POST url        one event per op, application/cloudevents+json
//	POST read_url   {"groups":["name",...]} or {"groups":null} -> {"groups":[{"name","members":[...],"attrs":{...}}]}
//
// Both requests carry X-Tessera-Signature: t=<unix seconds>,v1=<hex of
// HMAC-SHA256(signing_secret, "<t>." + body)>, so a receiver verifies the body
// and rejects a replay by checking t. X-Tessera-Delivery is the op id: a
// redelivery carries the same id, so the receiver can deduplicate. Without a
// read_url the target is not readable: its ops end "applied", never "verified".

type webhookCfg struct {
	URL     string `json:"url"`
	ReadURL string `json:"read_url"`
}

func parseWebhookConfig(c *Compiled) (webhookCfg, error) {
	var cfg webhookCfg
	if err := strictJSON(c.Target, &cfg); err != nil {
		return cfg, cfgErr("target: %v", err)
	}
	// no query string: the endpoint is shown back by the API, and a token in it
	// would be a credential in plain configuration; the signature is the credential
	if _, err := httpURL("target.url", cfg.URL, false); err != nil {
		return cfg, err
	}
	if cfg.ReadURL != "" {
		if _, err := httpURL("target.read_url", cfg.ReadURL, false); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

// SignatureHeader is the header a webhook delivery is signed in.
const SignatureHeader = "X-Tessera-Signature"

// DeliveryHeader carries the op id.
const DeliveryHeader = "X-Tessera-Delivery"

// Sign returns the signature header value of body at time t.
func Sign(secret []byte, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

type webhookTarget struct {
	cfg    webhookCfg
	secret []byte
	http   *http.Client
	source string
	now    func() time.Time
}

func openWebhook(spec TargetSpec) (Provisioner, error) {
	cfg, err := parseWebhookConfig(spec.Common)
	if err != nil {
		return nil, err
	}
	secret := spec.Secret["signing_secret"]
	if len(secret) < 16 {
		return nil, cfgErr("secret.signing_secret is required (at least 16 bytes)")
	}
	if spec.Deps.HTTP == nil {
		return nil, errors.New("no outbound HTTP client is configured")
	}
	return &webhookTarget{cfg: cfg, secret: []byte(secret), http: safehttp.WithConfiguredPorts(spec.Deps.HTTP, cfg.URL, cfg.ReadURL), now: time.Now,
		source: "/tessera/tenants/" + spec.Tenant.String() + "/groups/provisioners/" + spec.ProvisionerID}, nil
}

func (t *webhookTarget) Capabilities() Capabilities {
	return Capabilities{Groups: true, Memberships: true, MaxBatch: 100, Readable: t.cfg.ReadURL != ""}
}

func (t *webhookTarget) Close() error { return nil }

func (t *webhookTarget) post(ctx context.Context, rawURL, contentType, delivery string, body []byte) (int, []byte, error) {
	req, err := ctxReq(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("invalid URL")
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set(SignatureHeader, Sign(t.secret, t.now(), body))
	if delivery != "" {
		req.Header.Set(DeliveryHeader, delivery)
	}
	return doHTTP(t.http, req)
}

type webhookEvent struct {
	SpecVersion     string         `json:"specversion"`
	ID              string         `json:"id"`
	Source          string         `json:"source"`
	Type            string         `json:"type"`
	Subject         string         `json:"subject"`
	Time            string         `json:"time"`
	DataContentType string         `json:"datacontenttype"`
	Data            webhookEventOp `json:"data"`
}

type webhookEventOp struct {
	Op     string              `json:"op"`
	Group  string              `json:"group"`
	Attrs  map[string][]string `json:"attrs,omitempty"`
	Add    []string            `json:"add,omitempty"`
	Remove []string            `json:"remove,omitempty"`
}

func (t *webhookTarget) Apply(ctx context.Context, ops []Op) ([]OpResult, error) {
	out := make([]OpResult, len(ops))
	for i, op := range ops {
		out[i] = OpResult{ID: op.ID, Ref: op.Ref}
		body, err := json.Marshal(webhookEvent{SpecVersion: "1.0", ID: op.ID, Source: t.source,
			Type: "io.tessera.groups.provision." + string(op.Kind), Subject: op.Ref.Name, Time: t.now().UTC().Format(time.RFC3339),
			DataContentType: "application/json",
			Data:            webhookEventOp{Op: string(op.Kind), Group: op.Ref.Name, Attrs: op.Attrs, Add: op.Add, Remove: op.Remove}})
		if err != nil {
			out[i].Err = err
			continue
		}
		status, _, err := t.post(ctx, t.cfg.URL, "application/cloudevents+json", op.ID, body)
		switch {
		case err != nil:
			out[i].Err = err
		case status < 200 || status > 299:
			out[i].Err = statusErr("webhook delivery", status)
		}
	}
	return out, nil
}

type webhookRead struct {
	Groups []struct {
		Name    string              `json:"name"`
		Members []string            `json:"members"`
		Attrs   map[string][]string `json:"attrs"`
	} `json:"groups"`
}

func (t *webhookTarget) read(ctx context.Context, names []string) (TargetState, error) {
	st := NewState()
	if t.cfg.ReadURL == "" {
		return st, errors.New("the webhook has no read_url")
	}
	body, _ := json.Marshal(map[string]any{"groups": names})
	status, resp, err := t.post(ctx, t.cfg.ReadURL, "application/json", "", body)
	if err != nil {
		return st, err
	}
	if status != http.StatusOK {
		return st, statusErr("webhook read", status)
	}
	var r webhookRead
	if err := json.Unmarshal(resp, &r); err != nil {
		return st, fmt.Errorf("webhook read: the response is not the expected JSON")
	}
	for _, g := range r.Groups {
		st.Groups[Key(g.Name)] = &TargetGroup{Ref: TargetRef{Name: g.Name}, Members: g.Members, Attrs: g.Attrs}
	}
	return st, nil
}

func (t *webhookTarget) ReadAll(ctx context.Context, _ Scope) (TargetState, error) {
	return t.read(ctx, nil)
}

func (t *webhookTarget) Read(ctx context.Context, refs []TargetRef) (TargetState, error) {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Name)
	}
	st, err := t.read(ctx, names)
	if err != nil {
		return st, err
	}
	want := map[string]bool{}
	for _, n := range names {
		want[Key(n)] = true
	}
	for k := range st.Groups {
		if !want[k] {
			delete(st.Groups, k) // the receiver sent more than was asked for
		}
	}
	return st, nil
}
