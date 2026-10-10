// Command tessera-devidp runs Tessera's development identity provider: a mock
// OpenID Connect issuer for local sign-in without a real Okta or Entra tenant
// (docs/design/phase-0-platform-security.md §18.5). Development and tests only.
//
//	tessera-devidp [-addr 127.0.0.1:8001] [-issuer URL] [-key-dir var/devidp]
//	               [-users users.yaml] [-profile okta|entra|generic]
//	               [-client-id tessera-dev] [-client-jwks jwks.json]
//	               [-redirect-uris p1,p2] [-post-logout-redirect-uris u1,u2]
//
// Environment:
//
//	TESSERA_ENV           must be "dev" or "test"; anything else (including unset
//	                      or "prod") refuses to start
//	DEVIDP_CLIENT_SECRET  client_secret_basic secret of the client (default: the
//	                      well-known dev value tessera-dev-secret)
//	DEVIDP_FAULTS         "1" enables fault injection (fault= on /authorize, /_faults)
//
// It listens on loopback only.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
)

// devClientSecret is the default secret of the dev client. It is a published
// development value, not a credential: the dev IdP refuses to run outside
// TESSERA_ENV=dev/test and only listens on loopback.
const devClientSecret = "tessera-dev-secret" // #nosec G101 -- documented dev-only value of a mock IdP

const (
	defaultRedirects   = "http://localhost:*/api/auth/oidc/*/callback,http://127.0.0.1:*/api/auth/oidc/*/callback"
	defaultPostLogouts = "http://localhost:5173/,http://127.0.0.1:5173/"
	shutdownTimeout    = 5 * time.Second
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tessera-devidp:", err)
		os.Exit(1)
	}
}

type options struct {
	addr, issuer, keyDir, users, profile         string
	clientID, clientJWKS, redirects, postLogouts string
	printSAMLCert                                bool
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("tessera-devidp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.addr, "addr", "127.0.0.1:8001", "listen address (loopback only)")
	fs.StringVar(&o.issuer, "issuer", "", "issuer URL (default http://<addr>)")
	fs.StringVar(&o.keyDir, "key-dir", "var/devidp", "directory for the generated signing key")
	fs.StringVar(&o.users, "users", "", "users YAML file (default: the embedded users.yaml)")
	fs.StringVar(&o.profile, "profile", string(devidp.ProfileOkta), "emulation preselected on the sign-in page: okta, entra or generic")
	fs.StringVar(&o.clientID, "client-id", "tessera-dev", "client_id of the registered relying party")
	fs.StringVar(&o.clientJWKS, "client-jwks", "", "JWKS file of the client's public keys, enabling private_key_jwt")
	fs.StringVar(&o.redirects, "redirect-uris", defaultRedirects, "comma-separated redirect URI patterns (* = one port or path segment)")
	fs.StringVar(&o.postLogouts, "post-logout-redirect-uris", defaultPostLogouts, "comma-separated post-logout redirect URIs")
	fs.BoolVar(&o.printSAMLCert, "print-saml-cert", false, "print the SAML signing certificate (PEM) and exit, for pinning it in a connection")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected arguments %v", fs.Args())
	}
	if o.issuer == "" {
		o.issuer = "http://" + o.addr
	}
	return o, nil
}

// checkLoopback refuses any listen address that is not loopback.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("-addr %q: the dev IdP listens on loopback only", addr)
}

func buildConfig(o options, getenv func(string) string, logger *slog.Logger) (devidp.Config, error) {
	cfg := devidp.Config{Issuer: o.issuer, DefaultProfile: devidp.Profile(o.profile),
		Faults: getenv("DEVIDP_FAULTS") == "1", Logger: logger}
	key, err := devidp.LoadOrCreateKey(o.keyDir)
	if err != nil {
		return cfg, fmt.Errorf("signing key: %w", err)
	}
	cfg.Key = key
	if o.users != "" {
		b, err := readSmall(o.users)
		if err != nil {
			return cfg, err
		}
		if cfg.Users, err = devidp.ParseUsers(b); err != nil {
			return cfg, err
		}
	}
	secret := getenv("DEVIDP_CLIENT_SECRET")
	if secret == "" {
		secret = devClientSecret
	}
	c := devidp.Client{ID: o.clientID, Secret: secret, RedirectURIs: splitList(o.redirects),
		PostLogoutRedirectURIs: splitList(o.postLogouts)}
	if o.clientJWKS != "" {
		b, err := readSmall(o.clientJWKS)
		if err != nil {
			return cfg, err
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(b, &set); err != nil {
			return cfg, fmt.Errorf("-client-jwks: %w", err)
		}
		for _, k := range set.Keys {
			if !k.IsPublic() {
				return cfg, errors.New("-client-jwks must contain public keys only")
			}
		}
		c.JWKS = &set
	}
	cfg.Clients = []devidp.Client{c}
	return cfg, nil
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied config path of a dev-only tool
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if err := devidp.CheckEnv(getenv("TESSERA_ENV")); err != nil {
		return err
	}
	o, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}
	if err := checkLoopback(o.addr); err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := buildConfig(o, getenv, logger)
	if err != nil {
		return err
	}
	srv, err := devidp.New(cfg)
	if err != nil {
		return err
	}
	if o.printSAMLCert {
		_, err := io.WriteString(stdout, srv.SAMLCertificatePEM())
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- httpSrv.Serve(ln) }()
	logger.Info("tessera dev IdP listening (development only)", "issuer", srv.Issuer(),
		"client_id", o.clientID, "faults", cfg.Faults, "kid", srv.KeyID())
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err = httpSrv.Shutdown(shutdownCtx)
	if serveErr := <-errc; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return err
}
