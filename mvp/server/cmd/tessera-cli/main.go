// Command tessera-cli is the reference command-line client of Tessera's OAuth
// authorization server (docs/design/phase-0-platform-security.md §9.3, §19
// PR10). It signs in with the device authorization grant, binds every token to
// a DPoP key it generates, and calls the API with those tokens.
//
//	tessera-cli login  [--server URL] [--tenant SLUG] [--scope "tessera:read tessera:write"]
//	                   [--acr URN] [--max-age SECONDS]
//	tessera-cli whoami
//	tessera-cli api    [-d JSON | -d @-] METHOD /api/path
//	tessera-cli groups ls|show|members|plan|apply|export|templates   (groups.go)
//	tessera-cli config key|export|plan|apply   (config.go: signed configuration bundles for pipelines)
//	tessera-cli logout
//
// The DPoP key and the refresh token are stored in
// ~/.config/tessera/credentials.json (mode 0600; $XDG_CONFIG_HOME and
// $TESSERA_CONFIG_DIR move it).
//
// Environment:
//
//	TESSERA_URL     the server's public URL (TESSERA_PUBLIC_URL of the server); --server overrides
//	TESSERA_TENANT  the tenant to sign in to; --tenant overrides
//	TESSERA_ENV     "dev" lets the client reach http and loopback addresses; anything else is
//	                production: https only, no private or loopback addresses (internal/safehttp)
//
// Exit status: 0 success; 1 error (or an HTTP status of 400 or more from api);
// 2 usage; 3 the API wants a fresher or stronger sign-in (run login again, the
// message says how).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cliauth"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Exit statuses.
const (
	exitOK     = 0
	exitError  = 1
	exitUsage  = 2
	exitStepUp = 3
)

// runEnv is what the command runs against (tests replace it).
type runEnv struct {
	getenv         func(string) string
	stdin          io.Reader
	stdout, stderr io.Writer
	now            func() time.Time
	sleep          func(ctx context.Context, d time.Duration) error
	// http is the client; nil builds the safehttp client the environment calls for.
	http *http.Client
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], runEnv{getenv: os.Getenv, stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr})
	stop()
	os.Exit(code)
}

const usage = `usage:
  tessera-cli login  [--server URL] [--tenant SLUG] [--scope "..."] [--acr URN] [--max-age SECONDS]
  tessera-cli whoami
  tessera-cli api    [-d JSON | -d @-] METHOD /api/path
  tessera-cli groups ...   (tessera-cli groups help)
  tessera-cli config ...   (tessera-cli config help)
  tessera-cli logout
`

func run(ctx context.Context, args []string, e runEnv) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = fmt.Fprint(e.stderr, usage)
		if len(args) == 0 {
			return exitUsage
		}
		return exitOK
	}
	dir, err := cliauth.DefaultDir(e.getenv)
	if err != nil {
		return fail(e, err)
	}
	client := e.http
	if client == nil {
		if client, err = newHTTPClient(e.getenv("TESSERA_ENV")); err != nil {
			return fail(e, err)
		}
	}
	c := &cliauth.Client{HTTP: client, Store: &cliauth.Store{Dir: dir}, Now: e.now, Sleep: e.sleep, Out: e.stdout}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "login":
		return login(ctx, c, rest, e)
	case "whoami":
		return whoami(ctx, c, rest, e)
	case "api":
		return apiCmd(ctx, c, rest, e)
	case "logout":
		return logout(ctx, c, rest, e)
	case "groups":
		return groupsCmd(ctx, c, rest, e)
	case "config":
		return configCmd(ctx, c, rest, e)
	}
	_, _ = fmt.Fprintf(e.stderr, "tessera-cli: unknown command %q\n%s", cmd, usage)
	return exitUsage
}

// newHTTPClient is the SSRF-guarded client (every outbound call of the CLI
// goes through internal/safehttp). Development may use http and loopback.
func newHTTPClient(env string) (*http.Client, error) {
	return safehttp.ForCLIEnv(env, 30*time.Second, 32<<20)
}

func fail(e runEnv, err error) int {
	_, _ = fmt.Fprintf(e.stderr, "tessera-cli: %v\n", err)
	var se *cliauth.StepUpError
	if errors.As(err, &se) {
		return exitStepUp
	}
	return exitError
}

func flags(name string, e runEnv) *flag.FlagSet {
	fs := flag.NewFlagSet("tessera-cli "+name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	return fs
}

func login(ctx context.Context, c *cliauth.Client, args []string, e runEnv) int {
	fs := flags("login", e)
	server := fs.String("server", e.getenv("TESSERA_URL"), "the server's public URL (TESSERA_URL)")
	tenant := fs.String("tenant", e.getenv("TESSERA_TENANT"), "the tenant to sign in to (TESSERA_TENANT)")
	scope := fs.String("scope", cliauth.DefaultScope, "the scopes to ask for")
	acr := fs.String("acr", "", "the authentication strength to ask the approver for (a step-up asks for this)")
	maxAge := fs.Int("max-age", -1, "how recent the approver's sign-in must be, in seconds")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 || *server == "" || *tenant == "" {
		_, _ = fmt.Fprintln(e.stderr, "tessera-cli login: --server and --tenant are required (or TESSERA_URL and TESSERA_TENANT)")
		return exitUsage
	}
	o := cliauth.LoginOptions{Server: *server, Tenant: *tenant, Scope: *scope, ACR: *acr}
	if *maxAge >= 0 {
		o.MaxAge = maxAge
	}
	// signing in again replaces the stored session; the old one is revoked
	// once the new one exists (design §9.4), so a failed sign-in loses nothing
	old, _ := c.Store.Load()
	cr, err := c.Login(ctx, o)
	if err != nil {
		return fail(e, err)
	}
	_, _ = fmt.Fprintf(e.stdout, "Signed in to %s at %s (scope: %s).\n", cr.Tenant, cr.Server, cr.Scope)
	if old != nil {
		if err := c.Revoke(ctx, old); err != nil {
			_, _ = fmt.Fprintf(e.stderr, "tessera-cli: the previous session could not be revoked (it ends on its own): %v\n", err)
		}
	}
	return exitOK
}

func whoami(ctx context.Context, c *cliauth.Client, args []string, e runEnv) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(e.stderr, "usage: tessera-cli whoami")
		return exitUsage
	}
	res, err := c.Whoami(ctx)
	if err != nil {
		return failResponse(e, res, err)
	}
	if res.Status != http.StatusOK {
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli: the server answered %d\n", res.Status)
		return exitError
	}
	var doc map[string]any
	if err := json.Unmarshal(res.Body, &doc); err != nil {
		return fail(e, fmt.Errorf("the server's answer is not JSON: %w", err))
	}
	user, _ := doc["user"].(map[string]any)
	tenant, _ := doc["tenant"].(map[string]any)
	_, _ = fmt.Fprintf(e.stdout, "%s <%s>\n", str(user["display_name"]), str(user["email"]))
	_, _ = fmt.Fprintf(e.stdout, "tenant:      %s (%s)\n", str(tenant["name"]), str(tenant["slug"]))
	_, _ = fmt.Fprintf(e.stdout, "roles:       %s\n", list(doc["roles"]))
	_, _ = fmt.Fprintf(e.stdout, "active:      %s\n", list(doc["active_roles"]))
	_, _ = fmt.Fprintf(e.stdout, "permissions: %s\n", list(doc["permissions"]))
	return exitOK
}

func str(v any) string {
	s, _ := v.(string)
	return clean(s)
}

func list(v any) string {
	xs, _ := v.([]any)
	var out []string
	for _, x := range xs {
		out = append(out, str(x))
	}
	if len(out) == 0 {
		return "(none)"
	}
	return strings.Join(out, ", ")
}

// clean drops control characters from text the server sent.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func apiCmd(ctx context.Context, c *cliauth.Client, args []string, e runEnv) int {
	fs := flags("api", e)
	data := fs.String("d", "", "the JSON request body; @- reads it from standard input")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 2 {
		_, _ = fmt.Fprintln(e.stderr, "usage: tessera-cli api [-d JSON | -d @-] METHOD /api/path")
		return exitUsage
	}
	method := strings.ToUpper(fs.Arg(0))
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli api: unsupported method %q\n", fs.Arg(0))
		return exitUsage
	}
	var body []byte
	switch {
	case *data == "@-":
		b, err := io.ReadAll(io.LimitReader(e.stdin, 1<<20+1))
		if err != nil || len(b) > 1<<20 {
			_, _ = fmt.Fprintln(e.stderr, "tessera-cli api: the request body could not be read or is over 1 MiB")
			return exitError
		}
		body = b
	case *data != "":
		body = []byte(*data)
	}
	if len(body) > 0 && !json.Valid(body) {
		_, _ = fmt.Fprintln(e.stderr, "tessera-cli api: the request body is not valid JSON")
		return exitUsage
	}
	res, err := c.Do(ctx, method, fs.Arg(1), body)
	if err != nil {
		return failResponse(e, res, err)
	}
	_, _ = e.stdout.Write(res.Body)
	if len(res.Body) > 0 && res.Body[len(res.Body)-1] != '\n' {
		_, _ = fmt.Fprintln(e.stdout)
	}
	if res.Status >= 400 {
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli: HTTP %d\n", res.Status)
		return exitError
	}
	return exitOK
}

// failResponse reports an error, adding how to satisfy a step-up challenge.
func failResponse(e runEnv, res *cliauth.Response, err error) int {
	var se *cliauth.StepUpError
	if errors.As(err, &se) {
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli: %v.\n", se)
		cmd := "tessera-cli login"
		if se.ACR != "" {
			cmd += " --acr " + clean(se.ACR)
		}
		if se.MaxAge > 0 {
			cmd += fmt.Sprintf(" --max-age %d", se.MaxAge)
		}
		_, _ = fmt.Fprintf(e.stderr, "Sign in again to continue: %s\nThe command was not repeated; run it again afterwards.\n", cmd)
		return exitStepUp
	}
	_ = res
	return fail(e, err)
}

func logout(ctx context.Context, c *cliauth.Client, args []string, e runEnv) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(e.stderr, "usage: tessera-cli logout")
		return exitUsage
	}
	if err := c.Logout(ctx); err != nil {
		if errors.Is(err, cliauth.ErrNotLoggedIn) {
			_, _ = fmt.Fprintln(e.stderr, "tessera-cli: not signed in")
			return exitOK
		}
		return fail(e, err)
	}
	_, _ = fmt.Fprintln(e.stdout, "Signed out.")
	return exitOK
}
