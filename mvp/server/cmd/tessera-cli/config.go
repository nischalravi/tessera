package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/cliauth"
)

// tessera-cli config: export and import a tenant's configuration as a signed
// bundle from a pipeline (issue #497; the same calls as Admin > Export / import
// configuration, internal/transport). Every request goes through the signed-in
// session of `tessera-cli login`, so the server's permission (config.transport)
// and the fresh sign-in an apply needs hold for the CLI exactly as for the UI.

const configUsage = `usage:
  tessera-cli config key                                    this tenant's public signing key (share it to be trusted)
  tessera-cli config export [-o FILE]                       sign this tenant's configuration and write the bundle
  tessera-cli config plan   -f BUNDLE [--json]              what applying the bundle here would add, change and refuse
  tessera-cli config apply  -f BUNDLE [--prune] [--digest D]  apply it (a -f of - reads standard input)

These calls need the tessera:admin scope: tessera-cli login --scope "tessera:admin".

The bundle holds connections, readiness overlays, sign-in connections, catalog
items, review schedules, alert rules and log-streaming sinks, never a secret.
The destination must trust the exporting tenant's key (Admin > Export / import
configuration, or POST /api/config/trusted-signers). Apply plans first and
applies exactly that plan; pass --digest from an earlier plan to apply only if
nothing changed since you reviewed it. --prune also retires connections the
bundle does not have. plan and apply exit 1 when the bundle cannot be applied
here, and 3 when the server wants a fresher sign-in.
`

type bundlePlan struct {
	Hash        string   `json:"hash"`
	Digest      string   `json:"digest"`
	DigestPrune string   `json:"digest_prune"`
	Signer      string   `json:"signer"`
	Refusals    []string `json:"refusals"`
	Source      struct {
		Tenant string `json:"tenant"`
		Env    string `json:"env"`
	} `json:"source"`
	Exported string `json:"exported_at"`
	Items    []struct {
		Section string   `json:"section"`
		Name    string   `json:"name"`
		Action  string   `json:"action"`
		Fields  []string `json:"fields"`
		Notes   []string `json:"notes"`
	} `json:"items"`
	Counts map[string]int `json:"counts"`
}

func configCmd(ctx context.Context, c *cliauth.Client, args []string, e runEnv) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(e.stderr, configUsage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "key":
		return configKey(ctx, c, rest, e)
	case "export":
		return configExport(ctx, c, rest, e)
	case "plan":
		return configImport(ctx, c, rest, e, false)
	case "apply":
		return configImport(ctx, c, rest, e, true)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(e.stderr, configUsage)
		return exitOK
	}
	_, _ = fmt.Fprintf(e.stderr, "tessera-cli config: unknown command %q\n%s", cmd, configUsage)
	return exitUsage
}

// call makes one API call and returns the body of a success; any other status is an error.
func call(ctx context.Context, c *cliauth.Client, method, path string, body []byte) ([]byte, error) {
	res, err := c.Do(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	if res.Status >= 400 {
		var er struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Detail  string `json:"detail"`
		}
		_ = json.Unmarshal(res.Body, &er)
		msg := clean(strings.TrimSpace(er.Error + " " + er.Message + " " + er.Detail))
		if msg == "" {
			msg = clean(string(res.Body))
			if len(msg) > 300 {
				msg = msg[:300]
			}
		}
		if res.Status == http.StatusForbidden {
			msg += " (the session needs the tessera:admin scope and the tenant admin role: tessera-cli login --scope \"tessera:admin\")"
		}
		return nil, fmt.Errorf("HTTP %d %s", res.Status, msg)
	}
	return res.Body, nil
}

func configKey(ctx context.Context, c *cliauth.Client, args []string, e runEnv) int {
	if len(args) != 0 {
		_, _ = fmt.Fprint(e.stderr, configUsage)
		return exitUsage
	}
	b, err := call(ctx, c, http.MethodGet, "/api/config/signing-key", nil)
	if err != nil {
		return failResponse(e, nil, err)
	}
	var out struct {
		Key *struct {
			KID       string `json:"kid"`
			PublicKey string `json:"public_key"`
			Tenant    string `json:"tenant"`
		} `json:"key"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return fail(e, err)
	}
	if out.Key == nil {
		_, _ = fmt.Fprintln(e.stdout, "No signing key yet: the first export creates it.")
		return exitOK
	}
	_, _ = fmt.Fprintf(e.stdout, "kid %s\npublic_key %s\ntenant %s\n", clean(out.Key.KID), clean(out.Key.PublicKey), clean(out.Key.Tenant))
	return exitOK
}

func configExport(ctx context.Context, c *cliauth.Client, args []string, e runEnv) int {
	fs := flags("config export", e)
	outFile := fs.String("o", "", "write the bundle to FILE (default: standard output)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		_, _ = fmt.Fprint(e.stderr, configUsage)
		return exitUsage
	}
	b, err := call(ctx, c, http.MethodPost, "/api/config/export", []byte("{}"))
	if err != nil {
		return failResponse(e, nil, err)
	}
	var out struct {
		Hash     string          `json:"hash"`
		KID      string          `json:"kid"`
		Bundle   json.RawMessage `json:"bundle"`
		Excluded []struct {
			Section string `json:"section"`
			Name    string `json:"name"`
			Reason  string `json:"reason"`
		} `json:"excluded"`
	}
	if err := json.Unmarshal(b, &out); err != nil || len(out.Bundle) == 0 {
		return fail(e, fmt.Errorf("the server's answer has no bundle"))
	}
	body := append([]byte(out.Bundle), '\n')
	if *outFile == "" {
		_, _ = e.stdout.Write(body)
	} else if err := os.WriteFile(*outFile, body, 0o600); err != nil {
		return fail(e, err)
	}
	for _, x := range out.Excluded {
		_, _ = fmt.Fprintf(e.stderr, "left out: %s %s (%s)\n", clean(x.Section), clean(x.Name), clean(x.Reason))
	}
	_, _ = fmt.Fprintf(e.stderr, "exported, hash %s, signed by %s\n", clean(out.Hash), clean(out.KID))
	return exitOK
}

func readBundleFile(path string, e runEnv) ([]byte, error) {
	var r io.Reader = e.stdin
	if path != "-" {
		f, err := os.Open(path) // #nosec G304 -- the pipeline names its own bundle file
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("the bundle is over 1 MiB")
	}
	if !json.Valid(b) {
		return nil, fmt.Errorf("the bundle is not valid JSON")
	}
	return b, nil
}

func configImport(ctx context.Context, c *cliauth.Client, args []string, e runEnv, apply bool) int {
	name := "config plan"
	if apply {
		name = "config apply"
	}
	fs := flags(name, e)
	file := fs.String("f", "", "the bundle file (- reads standard input)")
	asJSON := fs.Bool("json", false, "print the plan as JSON")
	prune := fs.Bool("prune", false, "apply: also retire connections the bundle does not have")
	digest := fs.String("digest", "", "apply: only if the plan still has this digest (from `config plan --json`)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *file == "" || (!apply && (*prune || *digest != "")) {
		_, _ = fmt.Fprint(e.stderr, configUsage)
		return exitUsage
	}
	bundle, err := readBundleFile(*file, e)
	if err != nil {
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli %s: %v\n", name, err)
		return exitUsage
	}
	pb, err := call(ctx, c, http.MethodPost, "/api/config/import/plan", bundle)
	if err != nil {
		return failResponse(e, nil, err)
	}
	var p bundlePlan
	if err := json.Unmarshal(pb, &p); err != nil {
		return fail(e, err)
	}
	if *asJSON {
		_, _ = e.stdout.Write(pb)
		if len(pb) > 0 && pb[len(pb)-1] != '\n' {
			_, _ = fmt.Fprintln(e.stdout)
		}
	} else {
		printBundlePlan(e.stdout, &p)
	}
	if len(p.Refusals) > 0 {
		for _, r := range p.Refusals {
			_, _ = fmt.Fprintf(e.stderr, "refused: %s\n", clean(r))
		}
		return exitError
	}
	if !apply {
		return exitOK
	}
	want := p.Digest
	if *prune {
		want = p.DigestPrune
	}
	if *digest != "" && *digest != want {
		_, _ = fmt.Fprintln(e.stderr, "tessera-cli config apply: the plan is not the one you reviewed (the digest differs); plan it again and review it")
		return exitError
	}
	q := url.Values{"hash": {p.Hash}, "digest": {want}}
	if *prune {
		q.Set("prune", "true")
	}
	ab, err := call(ctx, c, http.MethodPost, "/api/config/import/apply?"+q.Encode(), bundle)
	if err != nil {
		return failResponse(e, nil, err)
	}
	var done struct {
		ImportID string `json:"import_id"`
	}
	_ = json.Unmarshal(ab, &done)
	_, _ = fmt.Fprintf(e.stdout, "applied (import %s)\n", clean(done.ImportID))
	return exitOK
}

func printBundlePlan(w io.Writer, p *bundlePlan) {
	_, _ = fmt.Fprintf(w, "bundle %s from %s (%s), signed by %s, exported %s\n", clean(p.Hash), clean(p.Source.Tenant), clean(p.Source.Env), clean(p.Signer), clean(p.Exported))
	for _, it := range p.Items {
		if it.Action == "unchanged" {
			continue
		}
		line := fmt.Sprintf("%-7s %-18s %s", clean(it.Action), clean(it.Section), clean(it.Name))
		if len(it.Fields) > 0 {
			var fs []string
			for _, f := range it.Fields {
				fs = append(fs, clean(f))
			}
			line += " [" + strings.Join(fs, ", ") + "]"
		}
		_, _ = fmt.Fprintln(w, line)
		for _, n := range it.Notes {
			_, _ = fmt.Fprintf(w, "        %s\n", clean(n))
		}
	}
	_, _ = fmt.Fprintf(w, "add %d, change %d, remove %d, unchanged %d, manual %d\n", p.Counts["add"], p.Counts["change"], p.Counts["remove"],
		p.Counts["unchanged"], p.Counts["manual"])
}
