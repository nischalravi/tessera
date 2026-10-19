package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DevProfile is the connection profile of the dev IdP (store.ProfileDevMock).
const DevProfile = "dev_mock"

// DevIdP registers guests with the dev IdP at runtime (POST <issuer>/_register,
// authenticated as the connection's client) and gives them a passkey. It is for
// development and tests: NewDevIdP refuses TESSERA_ENV=prod, and cmd/tessera
// wires it only outside production with a dev IdP configured. HTTP must be the
// safehttp client (loopback is allowed there in dev only).
type DevIdP struct {
	HTTP *http.Client
}

// NewDevIdP returns the dev authority; it refuses production.
func NewDevIdP(env string, h *http.Client) (*DevIdP, error) {
	if env == "prod" || env == "" {
		return nil, errors.New("credential: the dev IdP authority is for development and tests only")
	}
	if h == nil {
		return nil, errors.New("credential: the dev IdP authority needs the safehttp client")
	}
	return &DevIdP{HTTP: h}, nil
}

// Kind implements Authority.
func (*DevIdP) Kind() string { return "dev_idp" }

// Profile implements Authority.
func (*DevIdP) Profile() string { return DevProfile }

// subjectPrefix is the dev IdP's RegisterPrefix (not imported: the API must
// never import the dev IdP).
const subjectPrefix = "guest-"

// Register implements Authority.
func (d *DevIdP) Register(ctx context.Context, c Connection, g Guest) (Registration, error) {
	if g.Ref == "" || strings.ContainsAny(g.Ref, " \t\r\n\x00") || c.Issuer == "" || c.ClientID == "" {
		return Registration{}, fmt.Errorf("%w: incomplete registration", ErrUnavailable)
	}
	sub := subjectPrefix + g.Ref
	body, err := json.Marshal(map[string]any{"sub": sub, "email": g.Email, "name": g.Name, "tenant": g.Tenant,
		"authenticators": []string{"passkey"}})
	if err != nil {
		return Registration{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.Issuer, "/")+"/_register", bytes.NewReader(body))
	if err != nil {
		return Registration{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return Registration{}, fmt.Errorf("%w: %s", ErrUnavailable, "request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusNoContent {
		return Registration{}, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	return Registration{Subject: sub, LoginHint: sub}, nil
}
