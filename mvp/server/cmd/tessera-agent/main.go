// Command tessera-agent is the Tessera Directory Agent (DR-11, design
// docs/design/deployment-readiness.md §5.3). The customer runs it on a Windows
// or Linux host inside the network that holds a private directory. It connects
// outbound to Tessera over mutual TLS and runs a closed set of typed,
// read-only directory operations against the targets on its own local
// allowlist.
//
// Usage:
//
//	tessera-agent run        -config agent.json
//	tessera-agent enrol      -config agent.json    (the code is read from
//	                          TESSERA_AGENT_ENROL_CODE, else the first line of stdin)
//	tessera-agent credential -config agent.json set NAME | delete NAME | list
//	                         (set reads the secret from stdin; it is never an argument)
//	tessera-agent version
//
// The configuration file (JSON, only a local administrator may write it):
//
//	{
//	  "server_url": "https://tessera.example.com:8443",
//	  "server_ca_file": "/etc/tessera-agent/ca.pem",
//	  "state_dir": "/var/lib/tessera-agent",
//	  "allowed_targets": ["ldap.corp.example:636", "10.20.0.0/24:636"]
//	}
//
// The agent trusts only server_ca_file, refuses any target not in
// allowed_targets, and keeps directory credentials in state_dir/credentials
// (files 0600, or DPAPI-wrapped on Windows). A connection in Tessera refers to
// a credential as agent:<agent id>/<name>; the secret never leaves this host.
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tessera-agent:", err)
		os.Exit(1)
	}
}

const usage = "usage: tessera-agent run|enrol|credential|version -config agent.json"

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmd, args := args[0], args[1:]
	if cmd == "version" {
		_, err := fmt.Fprintf(stdout, "tessera-agent %s (protocol %d)\n", agent.Version, agent.ProtocolVersion)
		return err
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "agent.json", "path of the agent configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	switch cmd {
	case "run":
		return runAgent(cfg, stderr)
	case "enrol":
		return enrol(cfg, stdin, stdout)
	case "credential":
		return credential(cfg, fs.Args(), stdin, stdout)
	}
	return errors.New(usage)
}

// ldapProber is the agent's ProberFactory: the read-only LDAP prober, dialing
// through the agent-local safedial Dialer the Executor built.
func ldapProber(s agent.ProberSpec) (connectors.Prober, error) {
	return ldap.New(ldap.Config{Host: s.Target.Host, Port: s.Target.Port, BindDN: s.Config.BindDN,
		Password: ldap.Secret(s.Password), BaseDNs: s.Config.BaseDNs, UserFilter: s.Config.UserFilter,
		RootCAs: s.RootCAs, Dialer: s.Dialer})
}

// ldapSyncer is the agent's SyncerFactory product: it reads the directory's
// people, groups and memberships (read-only) for a pulled sync job.
type ldapSyncer struct{ p *ldap.Prober }

func ldapSync(s agent.ProberSpec) (agent.Syncer, error) {
	p, err := ldap.New(ldap.Config{Host: s.Target.Host, Port: s.Target.Port, BindDN: s.Config.BindDN,
		Password: ldap.Secret(s.Password), BaseDNs: s.Config.BaseDNs, UserFilter: s.Config.UserFilter,
		RootCAs: s.RootCAs, Dialer: s.Dialer})
	if err != nil {
		return nil, err
	}
	return ldapSyncer{p}, nil
}

func (l ldapSyncer) Discover(ctx context.Context, lim agent.SyncLimits) (*agent.SyncResult, error) {
	ls, err := l.p.Discover(ctx, lim.Accounts, lim.Groups, lim.Members)
	if err != nil {
		return nil, err
	}
	out := &agent.SyncResult{Accounts: make([]agent.SyncAccount, 0, len(ls.Accounts)),
		Groups: make([]agent.SyncGroup, 0, len(ls.Groups)), Members: make([]agent.SyncMember, 0, len(ls.Members))}
	for _, a := range ls.Accounts {
		st := "active"
		if a.Disabled {
			st = "disabled"
		}
		out.Accounts = append(out.Accounts, agent.SyncAccount{ExternalID: a.ExternalID, Username: a.Username, Email: a.Email, Status: st})
	}
	for _, g := range ls.Groups {
		out.Groups = append(out.Groups, agent.SyncGroup{ExternalID: g.ExternalID, Name: g.Name})
	}
	for _, m := range ls.Members {
		out.Members = append(out.Members, agent.SyncMember{Account: m.Account, Group: m.Group})
	}
	return out, nil
}

func telemetry(cfg *agent.Config) agent.Telemetry {
	host, _ := os.Hostname()
	return agent.Telemetry{Hostname: host, OS: runtime.GOOS, Version: agent.Version, AllowlistHash: cfg.AllowlistHash()}
}

func client(cfg *agent.Config) (*agent.Client, error) {
	ca, err := os.ReadFile(cfg.ServerCAFile) // #nosec G304 G703 -- the operator names their own CA file
	if err != nil {
		return nil, err
	}
	cert, err := agent.LoadOrCreateIdentity(filepath.Join(cfg.StateDir, "identity"))
	if err != nil {
		return nil, err
	}
	return agent.NewClient(cfg.ServerURL, ca, cert)
}

func credStore(cfg *agent.Config) (*agent.FileStore, error) {
	return agent.NewPlatformStore(filepath.Join(cfg.StateDir, "credentials"))
}

func runAgent(cfg *agent.Config, stderr io.Writer) error {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	c, err := client(cfg)
	if err != nil {
		return err
	}
	creds, err := credStore(cfg)
	if err != nil {
		return err
	}
	if len(cfg.Allow()) == 0 {
		log.Warn("allowed_targets is empty: every operation will be refused")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// the key a server-held credential is sealed to (pushes to private HTTPS targets); it stays here
	sealKey, err := agent.LoadOrCreateSealKey(filepath.Join(cfg.StateDir, "identity"))
	if err != nil {
		return err
	}
	var pushRoots *x509.CertPool
	if cfg.PushCAFile != "" {
		pem, err := os.ReadFile(cfg.PushCAFile) // #nosec G304 G703 -- the operator names their own CA file
		if err != nil {
			return err
		}
		if pushRoots, err = agent.LoadPushRoots(pem); err != nil {
			return err
		}
	}
	if len(cfg.AllowPush()) == 0 {
		log.Info("allowed_push_targets is empty: provisioning pushes will be refused")
	}
	r := &agent.Runner{Client: c, Telemetry: telemetry(cfg), Log: log, SealKey: sealKey,
		Exec: &agent.Executor{Allow: cfg.Allow(), Creds: creds, New: ldapProber, NewSyncer: ldapSync,
			AllowPush: cfg.AllowPush(), PushRoots: pushRoots, SealKey: sealKey}}
	log.Info("tessera-agent started", "version", agent.Version, "server", cfg.ServerURL, "allowlist_hash", cfg.AllowlistHash())
	return r.Run(ctx)
}

func enrol(cfg *agent.Config, stdin io.Reader, stdout io.Writer) error {
	code := strings.TrimSpace(os.Getenv("TESSERA_AGENT_ENROL_CODE"))
	if code == "" {
		line, _ := bufio.NewReader(io.LimitReader(stdin, 1<<10)).ReadString('\n')
		code = strings.TrimSpace(line)
	}
	if code == "" {
		return errors.New("no enrolment code: set TESSERA_AGENT_ENROL_CODE or pipe it on stdin")
	}
	c, err := client(cfg)
	if err != nil {
		return err
	}
	resp, err := c.Enrol(context.Background(), code, telemetry(cfg))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "enrolled as agent %s\nreference a credential stored here as agent:%s/<name>\n", resp.AgentID, resp.AgentID)
	return err
}

func credential(cfg *agent.Config, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(credUsage)
	}
	st, err := credStore(cfg)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		names, err := st.List()
		for _, n := range names {
			fmt.Fprintln(stdout, n)
		}
		return err
	case "set", "delete":
		if len(args) != 2 {
			return errors.New(credUsage)
		}
		if args[0] == "delete" {
			return st.Delete(args[1])
		}
		line, _ := bufio.NewReader(io.LimitReader(stdin, 16<<10)).ReadString('\n')
		secret := strings.TrimRight(line, "\r\n")
		if err := st.Set(args[1], secret); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "stored credential %q\n", args[1])
		return err
	}
	return errors.New(credUsage)
}

const credUsage = "usage: tessera-agent credential -config agent.json set NAME | delete NAME | list" // #nosec G101 -- help text, not a credential
