package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps/oauthfake"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// devOAuthListenAddr returns the loopback host:port to serve the fake OAuth
// app providers on, from TESSERA_DEV_OAUTH_FAKE_URL.
func devOAuthListenAddr(cfg *config.Config) (string, error) {
	u, err := url.Parse(cfg.DevOAuthFakeURL)
	if err != nil || u.Scheme != "http" || u.Port() == "" || u.Path != "" {
		return "", errors.New("TESSERA_DEV_OAUTH_FAKE_URL must be a plain http://127.0.0.1:<port> origin")
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return "", errors.New("TESSERA_DEV_OAUTH_FAKE_URL must name a loopback IP address")
	}
	return u.Host, nil
}

// startOAuthFakes serves the stateful OAuth app provider fakes
// (internal/oauthapps/oauthfake) on TESSERA_DEV_OAUTH_FAKE_URL when it is set
// (config refuses it in prod), so sync, revoke and bulk revoke work in the
// local stack. Unset, nothing starts.
func startOAuthFakes(cfg *config.Config, logger *slog.Logger) (func(), error) {
	if cfg.DevOAuthFakeURL == "" {
		return func() {}, nil
	}
	if cfg.IsProd() || !cfg.OutboundAllowLoopback {
		return nil, errors.New("TESSERA_DEV_OAUTH_FAKE_URL needs TESSERA_ENV=dev with TESSERA_OUTBOUND_ALLOW_LOOPBACK on")
	}
	addr, err := devOAuthListenAddr(cfg)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: oauthfake.NewDevHandler(cfg.DevOAuthFakeURL), ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout: readTimeout, WriteTimeout: readTimeout}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("dev fake OAuth providers stopped", "err", err)
		}
	}()
	logger.Info("dev fake OAuth app providers listening", "url", cfg.DevOAuthFakeURL)
	return func() { _ = srv.Close() }, nil
}

// seedOAuthFakeDemo gives one tenant a live connection and credential for each
// OAuth app provider, pointed at the dev fakes, so POST /api/oauth-apps/sync
// finds apps and grants (one high-risk app held by several users).
func seedOAuthFakeDemo(ctx context.Context, st *store.DB, cfg *config.Config, sealer *seal.Sealer, tenant tenancy.ID,
	clock timeutil.Clock) error {
	if _, err := devOAuthListenAddr(cfg); err != nil {
		return err
	}
	reg, err := template.Default()
	if err != nil {
		return err
	}
	rs := readiness.NewService(reg, os.Getenv("TESSERA_ENV"))
	cs := &containment.Service{Sealer: sealer, Clock: clock}
	now := clock()
	// google and entra have readiness templates of their own; salesforce and github are generic app connections
	type conn struct{ name, connectorType string }
	conns := map[string]conn{oauthapps.Google: {"Google Workspace (dev fake)", "google"}, oauthapps.Entra: {"Microsoft Entra (dev fake)", "entra"},
		oauthapps.Salesforce: {"Salesforce (dev fake)", "scim_app"}, oauthapps.GitHub: {"GitHub (dev fake)", "scim_app"}}
	return st.InTenant(audit.WithSystemActor(ctx, "seed"), tenant, func(tx *store.TenantTx) error {
		for _, p := range oauthapps.Providers {
			b, err := rs.Create(tx, readiness.CreateInput{Name: conns[p].name, ConnectorType: conns[p].connectorType, System: p,
				Role: "account_source"}, "seed", now)
			if err != nil {
				return fmt.Errorf("%s connection: %w", p, err)
			}
			id := b.Conn.ID
			in := containment.CredentialInput{Token: oauthfake.Token, BaseURL: cfg.DevOAuthFakeURL + "/" + p}
			if p == oauthapps.GitHub {
				in.Org = oauthfake.DevOrg
			}
			if err := cs.PutCredential(tx, id, in, "seed", now); err != nil {
				return fmt.Errorf("%s credential: %w", p, err)
			}
		}
		return nil
	})
}
