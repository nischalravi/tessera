# Tessera: identity governance MVP

Tessera models **who can actually do what** across an organization as a graph. It covers humans,
service accounts, API keys and AI agents. It then uses real usage data to cut access down to what
each identity needs.

```
Identity ──has──▶ Account ──member_of──▶ Group/Role ──maps_to──▶ Group/Role ──grants──▶ Permission ──on──▶ Resource
(human | service | ai_agent)  (per system)                                                (action)          (tags: pii, prod…)
```

Example path, computed rather than configured:
`Alice Okafor → okta:alice.okafor@… → okta:engineering → aws:DevAdmin → s3:GetObject on s3://customer-pii`

Everything runs locally with SQLite and a seeded demo company. No cloud credentials are needed.
The company is **Larkspur Labs** (`larkspur.example`): 60 employees, 25 service accounts and API
keys, 6 AI agents, and 90 days of usage across Workday, Okta, AWS, GitHub and Snowflake. All of
these names are made up.

## Quick start

Requirements: Go 1.27+ (the version in `server/go.mod`), Node 18+ (tested on 24), npm.

```bash
./run.sh             # first run: builds the Go server, installs UI deps, seeds the DB, starts API + UI
./run.sh --reseed    # reset the demo data
./run.sh test        # go vet + Go test suite (unit tests and the API parity replay)
./run.sh build       # build the Go server, then tsc + vite production build
./run.sh seed        # (re)seed the database only
./run.sh devidp      # run only the dev IdP (mock OIDC issuer for local sign-in)
./run.sh bench       # Go benchmarks + end-to-end latency, startup and memory of the server
./run.sh backup      # encrypted online backup now (-dir /backups; see "Backup and restore")
./run.sh restore F   # verify backup F and restore it over the database (stop the server first)
./run.sh audit-deps  # govulncheck ./... on the Go module (install with server/scripts/install-tools.sh)
```

* UI: http://localhost:5173 (Vite dev server; it proxies `/api` to the backend via `TESSERA_API`).
  Sign in to `larkspur` through the dev IdP (see [Signing in](#signing-in)), for example as Alice
  (tenant admin) or Pat (policy admin) with a passkey.
* API: http://127.0.0.1:8000. OpenAPI docs are at http://127.0.0.1:8000/docs
* Dev IdP: http://127.0.0.1:8001 (see [Signing in](#signing-in))

Ctrl+C stops all three processes. You can change the ports with `API_PORT=… UI_PORT=… DEVIDP_PORT=… ./run.sh`
(`DEVIDP=0` skips the dev IdP).
The database is `server/tessera.db` (override with `TESSERA_DB`); the binary is `server/bin/tessera`
and can also be run directly: `TESSERA_ENV=dev tessera serve -addr 127.0.0.1:8000 -db tessera.db` or `tessera seed`.
`TESSERA_ENV` must be set (`dev`, `test` or `prod`). Every API route except `GET /api/health` needs a
signed-in session, and the tenant is the session's: there is no default tenant. A database from before
sign-in is refused (`./run.sh` reseeds it; otherwise run `./run.sh --reseed`).

## What the demo shows

| Area | Where | Highlights in the seed data |
|---|---|---|
| Effective permissions with paths | Directory → a person, Insights → Access graph | Alice reaches `customer-pii` through Okta `engineering` → AWS `DevAdmin`. The graph explorer highlights upstream and downstream paths when you click a node, and "Who can access…" works in reverse from a resource. |
| Usage-based least privilege | Insights → Least privilege | Grants that are **safe to remove** (nothing they uniquely provide was used in N days). **Role trims**: no one of 17 engineers has used `DevAdmin → s3:GetObject customer-pii`. **Right-size** suggestions. Every revoke runs a dry run first that shows the blast radius: identities affected, permissions lost, which of those were used in the last 30 days, and which violations are resolved or introduced. |
| NHIs & AI agents | Directory → Machine identities & agents | Orphaned keys (`svc-legacy-etl`, `old-migration-token`), owners who have left (`jenkins-pat`, `LOOKER_SVC`), stale secrets (a 780-day-old access key). For agents: the delegation chain owner → agent → on-behalf-of, tool scopes, and "agent holds permissions its principal doesn't". |
| Just-in-time access | Access → Just-in-time, Inbox | Time-bound role grants with approve, deny and revoke. A background sweeper expires them automatically (every 30 s, and also on each request). JIT paths never count as standing access. |
| Policy-as-code + simulation | Governance → Policies & violations, Insights → SoD conflicts | YAML policies in `server/policies/`: SoD on payments, no standing prod admin, AI agents may not reach PII, NHI ownership, secret age, and leavers keep no access. The what-if simulator adds or removes grants on a copy of the graph and diffs effective permissions and violations. |
| Exception-only access reviews | Inbox, Governance → Access reviews | Out of 219 grants, about 62% are auto-certified from usage evidence. Reviewers see only unused, violating, orphaned, leaver or idle-privileged access, with usage and peer-coverage context. A revoke decision applies to the graph. |
| Joiner / mover / leaver | Inbox, Governance → Lifecycle | Simulated Workday feed. The leaver plan for Marcus disables accounts, removes grants, re-homes the AI agent and service account he owned, rotates their secrets and revokes delegations. For accounts on a connected Okta, Entra, Google or GitHub it also revokes live sessions, tokens and OAuth grants (see Identity containment). For historical leavers it shows the access the legacy process missed (Oren still has an active Okta account) and offers one-click cleanup. |

## Architecture

The backend is a single Go binary (`mvp/server`, module `github.com/nischalravi/tessera/mvp/server`)
with SQLite through the pure-Go `modernc.org/sqlite` driver, so it needs no C toolchain.

```
server/
  cmd/tessera/          main: `serve` (default), `seed`, `audit verify|checkpoint|export` and
                        `notify seal-password`; timeouts, graceful shutdown, JIT sweeper, audit
                        checkpointer, notification dispatcher
  cmd/tessera-devidp/   the dev IdP binary (development and tests only; see Dev sign-in)
  cmd/tessera/          main: `serve` (default), `seed` and `audit verify|checkpoint|export`; timeouts,
                        graceful shutdown, JIT sweeper, audit checkpointer
  cmd/tessera-devidp/   the dev IdP binary (development and tests only; see Signing in)
  cmd/tessera-cli/      the reference command-line client: `login` (device grant + DPoP), `whoami`,
                        `api`, `logout` (see Command-line sign-in)
  cmd/tessera-harness/  AWS evaluator differential harness, offline subcommands: `replay` re-runs the
                        recorded corpus with no AWS credentials or network (`go run ./cmd/tessera-harness
                        replay` from `server/`; exits 1 unless every case concludes what it expects);
                        `gate -report FILE` applies the nightly gate (Wilson bound, coverage, S1). Never
                        linked by the server (archtest). The nightly subcommand arrives with PR-9.
  internal/
    connectors/         Connector interface + normalized record types, deterministic demo company
                        (pyrand.go reproduces CPython's Mersenne Twister so seed 7 gives the same
                        company the Python backend generated), registry (TESSERA_CONNECTORS)
      connsync/         shared framework of the production connectors: checkpoints, full vs
                        incremental, bounded backoff, size-bounded retrying client, URL checks
      okta/ entra/      production read connectors (see Production connectors)
      all/              registers okta and entra (imported by cmd/tessera)
    ingest/             phased, idempotent upsert of connector output (cross-system refs resolve)
    store/              schema, row types and parameterized queries (database/sql, no ORM)
    audit/              hash-chained audit ledger: Record, the http.request middleware (fail-closed
                        reads), signed checkpoints + anchor sinks, verify, NDJSON export;
                        audit/canon is the v1 hash contract (RFC 8785 JCS + SHA-256)
    graph/              Snapshot: effective permissions + grant paths, copy for simulation,
                        expired-JIT / disabled-account handling
    usage/              last-used / 90-day usage index
    policy/             YAML policy loader + evaluators (sod, no_standing_access, forbidden_access,
                        secret_max_age, nhi_ownership, terminated_with_access)
    simulate/           what-if engine: apply edits to a snapshot copy, diff perms + violations
    leastpriv/          grant-level and role-level recommendations
    nhi/, jit/, reviews/, jml/, seed/
    notify/             notification outbox, in-app inbox, email senders (dev sink, SMTP), dispatcher
    api/                HTTP routes under /api, FastAPI-compatible validation errors, OpenAPI/docs
    config/             typed settings from TESSERA_* variables; production guard rails
    seal/               AES-256-GCM sealing under the KEK (AAD-bound), random secrets, SHA-256 helpers
    keys/               per-tenant ES256 signing keys and the platform Ed25519 key: rotation, JWKS
    safehttp/           SSRF-guarded outbound HTTP client (https only, address checks after DNS)
    connectors/scim/    read-only live prober for generic SCIM 2.0 applications (readiness DR-18)
    ratelimit/          keyed token-bucket limiter with a bounded key set
    oauth/              the OAuth authorization server (per-tenant issuer): device grant, refresh
                        rotation with reuse detection, client credentials for machine clients
                        (private_key_jwt, RFC 7523), introspection (RFC 7662), DPoP-bound JWT access
                        tokens, RFC 8414/9728 metadata; oauth/dpop validates DPoP proofs (RFC 9449)
    cliauth/            the CLI's client library: device login, credentials file, DPoP calls
    ojson/, timeutil/   ordered JSON + Python float repr; CPython-compatible time arithmetic
    testkit/            shared test fixtures (tiny world through a real Connector, seeded demo DB; each is seeded once per test binary and handed out as a private copy per test)
    devidp/             dev IdP: mock OIDC issuer, vendor emulation profiles, fault injection;
                        devidptest/ runs it in-process for tests. Never imported by the API.
    aws/harness/        differential harness: request specs, oracle clients (SimulateCustomPolicy,
                        SimulatePrincipalPolicy, Access Analyzer, probes), comparator and metrics M1-M4/C,
                        Wilson-bound gate, triage store, delta-debug minimizer, replay corpus. Does I/O, so it
                        sits outside the pure evaluator packages; only cmd/tessera-harness imports it.
    aws/awstest/        HTTP-layer cassette record and replay for AWS SDK clients (aws.HTTPClient)
  policies/*.yaml       policy-as-code (embedded in the binary; run.sh reads them from disk)
  testdata/parity/      golden request/response fixtures recorded from the original Python API
  testdata/aws/cassettes/  harness replay corpus, one JSON case per file (spec, oracle responses, expected
                        verdict). All current cases are synthetic (`"synthetic": true`); real recordings
                        come with the sandbox in PR-9.
  tools/benchcmp/       end-to-end benchmark (seed, startup, p50/p95, RSS; optionally vs Python)
  scripts/install-tools.sh  pinned govulncheck + gosec
frontend/               React 19 + Vite 8 + TypeScript, react-router, cytoscape.js, lucide-react
  src/
    api.ts              the single API client (typed responses, cached useApi hook)
    app/                shell (top bar + left rail), routes, nav model, command palette, global search, theme, persona
    components/         shared primitives: Button, Badge, DataTable, Dialog, Drawer, Menu, Toast, Page...
    features/<section>/ one folder per area (home, inbox, access, directory,
                        insights, governance, admin)
    mocks/              typed Preview data for features with no backend endpoint yet
```

Design notes:

* **One edge table.** Every grant (membership, role mapping, role→permission, direct grant, JIT)
  is a row in `grant_edges` with `src`/`dst` node keys such as `account:12` and `group:7`.
  Revoking, JIT, reviews and simulation all work on this table, so they work the same way in
  every system.
* **The graph is recomputed for each request** from SQLite. Building the graph and usage index,
  computing all effective permissions and evaluating every policy takes about 12 ms for about 90
  identities, 400 edges and 730 effective permissions (`go test -bench . ./internal/graph/`). Expired JIT edges and disabled accounts
  are excluded at build time. This is fine for an MVP. At larger scale you would cache the
  snapshot and invalidate it on writes, or update it incrementally.
* **Policies run against a `graph.Snapshot`**, not the database, so the same evaluators handle
  live state and simulated state.
* **Usage events** are stored as daily aggregates per (identity, permission). A real connector
  would map CloudTrail, Okta System Log, GitHub audit log and Snowflake `ACCESS_HISTORY` events
  onto these.

### Deployment readiness

Every customer system can be a governed **connection** with a pinned readiness checklist
(`server/internal/readiness/templates/*.yaml`; `tessera readiness lint` checks them). A revision
moves draft → ready to validate → validated → dry run reconciled → active, and the server
refuses each step (409 with the blocking items) until its gate holds: Required attestations,
read-only live checks (simulated for the demo connectors, labelled Simulated, and never enough
for a real connector type), and a dry run that stages a snapshot into `stg_*` tables and
reconciles it against the HR source. Findings RF-01 to RF-12 (orphans, leavers still enabled,
unexpected privileged members, unowned service accounts…) feed a published readiness score and
a ranked needs-attention list on Insights → Deployment health. `tessera seed` also seeds an
Okta (demo) connection for the `larkspur` tenant only (`TESSERA_READINESS_DEMO=off` skips it;
`globex` starts with no connections). Connections, checklists, runs, findings and scores are
tenant-scoped like every other table; Admin → Connections → New
connection → Active Directory (demo) walks the rest. Design: `docs/design/deployment-readiness.md`.
The routes are documented at `/api/readiness/openapi.json`.

Access control: `connections.read` (tenant admin, auditor), `connections.manage` and
`connections.activate` (tenant admin). Activating, retiring, editing the config or credential, and
changing an overlay need a phishing-resistant sign-in in the last 15 minutes (step-up); so does
accepting a **critical** finding (checked in the handler, since it depends on the finding). A
revision with `write_mode` other than `off` is **two-person**: `POST /api/connections/{id}/activate`
opens an activation request (`202 pending_approval`, valid 72 h, bound to the revision and config
hash), and a different tenant admin approves it with `POST .../activation/approve` (step-up), which
applies the activation in the same transaction. The requester and anyone who attested an item of
the revision get `403 two_person_rule`; the requester cancels and anyone else rejects with
`POST .../activation/reject`; `GET .../activation` shows the latest request. The gate itself
(blocker `activation.approval`) refuses a write-enabled revision that has no approval, so no other
caller can skip the second person. This request table stands in for the `connection.activate`
admin-change type until Phase 0's admin-change workflow (PR12) lands. Non-demo connector types are
no longer refused with `phase0_required`: the gate alone decides (simulated evidence never
satisfies it).

**Generic SCIM live checks (DR-18).** A non-demo `scim_app` connection runs its live checks
against the real application (`server/internal/connectors/scim`, results not labelled Simulated,
so they can satisfy the gate). The prober is GET only and every request goes through
`internal/safehttp`. It reads `/ServiceProviderConfig`, `/ResourceTypes` and `/Schemas`
(`scim_discovery`); walks `startIndex`/`count` and compares `totalResults` with what the pages
returned (`paging`); compares each group's members on the list call, on `GET /Groups/{id}` and by
reverse lookup through users' `groups` (`members_complete`); and records 429s, `Retry-After` and
retries (`rate_headroom`). Bounds: 10 pages, 500 objects, 120 requests, 2 retries per request and
no wait longer than 3 s per 429 (a longer `Retry-After` aborts the run as rate limited). The
bearer token is the connection's sealed credential (`connection_secrets`, opened with the KEK like
the LDAP bind password); without one the live checks report an error instead of running
unauthenticated. The client is the shared outbound one, with the connection's configured port
allowed (`safehttp.WithConfiguredPorts`). Tests use an in-process SCIM server
with misbehaviour switches (`internal/connectors/scim/fakescim_test.go`).
**After activation** (design §7.4, §7.5). Activation stores a baseline of the live revision
(`readiness_baselines`: score, item states, finding and object counts, config hash). A background
scheduler (`readiness.Scheduler`, started by `tessera serve`, a pass every 15 minutes) re-runs the
live checks of every active or degraded connection daily and reconciles it weekly in live mode (the
same staging scratch tables and findings as a dry run; it never writes the live graph), then
compares the evidence with the baseline. Drift is newly failing checks (a newly failing check on the
service account's effective rights is reported as a change made outside Tessera), finding counts
beyond ±10% or ±25 objects, object counts beyond ±5% between consecutive runs, credentials within
30 days of expiry, and a newer template minor release that adds Required items (30-day grace from
when the release is first seen). A revision moves `active → degraded` when a Required live check
fails on two consecutive scheduled runs (an administrator's on-demand re-run does not count), its
credential is within 7 days of expiry, or the template grace period ends; it recovers when none of
these hold. While degraded, reads continue and write-back stops: `Service.CanWrite` is false and
`Service.RequireWrite` refuses (409 `connection_degraded`), enforced on the server. The Inbox
shows a task per degraded connection (`tasks` in `GET /api/insights/deployment-health`), and
`GET /api/connections/{id}/health` and the dashboard carry `drift`. Settings:
`TESSERA_READINESS_LIVE_CHECK_DAYS` (1 to 7, default 1) and `TESSERA_READINESS_SCHEDULER=off`.
Not wired yet: the "sync failed for 24 hours" and "cursor lost three times in 7 days" triggers
(`readiness.ExternalSignals`; nothing records them yet), and Admin → Jobs (set `Scheduler.Hook`
to the `job_runs` wrapper of #172).
**Evidence export** (design §7.6): `GET /api/connections/{id}/readiness/evidence` and
`GET /api/insights/deployment-health/evidence` return a ZIP (`manifest.json`, `checklist.csv`,
`checks.csv`, `findings.csv`, `skipped.csv`, `score.json`). The manifest holds the SHA-256 of every
file, the template pins and config hashes, the ledger range and chain head, and the SOC 2, ISO 27001,
SOX ITGC and PCI DSS control mapping text. Findings carry sample object ids only, never names. Each
export appends `readiness.evidence.exported` (with the manifest hash) in the same transaction, and
needs `connections.read` plus `audit.read` (auditor, tenant_admin).

#### Live LDAP checks

Connections of type **OpenLDAP / 389-DS** (template `ldap`, which also covers LLDAP) run **real,
read-only** checks instead of simulated ones: TLS handshake and chain, simple bind, Who Am I
(RFC 4532), base-DN reads, a bounded people search, per-class attribute fill counts (counts only,
no values), paging past the server's size limit, the change feed (syncrepl, accesslog or the
389-DS retro changelog), the schema's custom attributes and, on 389-DS, the Get Effective Rights
control. The prober (`server/internal/connectors/ldap`) can only bind, search, ask Who Am I and
negotiate StartTLS, reads at most 500 objects per class, and sends a password only over a
connection with a verified TLS 1.2+ channel. What a server cannot answer (no Who Am I, no Get
Effective Rights, no `cn=Monitor` clock, as on LLDAP and OpenLDAP) is reported as **unsupported:
an attestation is required**, never as a pass. Other connector types keep their simulated checks.

**Attest instead of an unsupported check.** A template item may mark a live verification
`on_unsupported: attestation` (the only value; the vocabulary stays closed). The `ldap` template does
so for `ldap.svc.no_write` (effective rights) and `ldap.svc.readonly` (bind identity without Who Am I).
When that check reports unsupported, `POST /api/connections/{id}/checklist/{item}/attest-instead`
(`connections.manage`, step-up) takes `{attester, reason, evidence}`: a named attester, a reason of at
least 20 characters and evidence text of at least 10. It is stored in `readiness_live_attestations`,
bound to the item's config fields (a change to them makes it stale), expires after the live TTL (24 h)
like live results, and is audited as `readiness.item.attested_instead` in the same transaction. A
`fail` or `error` result can never be attested (422 `live_check_not_unsupported`), and a simulated
result never passes for a real connector type. In the checklist, an item whose live check is
unsupported shows an "Attest instead" form.

Network path: `server/internal/safedial` shares safehttp's address policy for raw TCP. Only ports
**636 (LDAPS)** and **389 (StartTLS required)** are dialled, private, loopback, link-local,
CGNAT and metadata addresses are refused after DNS resolution, and TLS 1.2 or later is required.
**The production path for a directory on a private network is the Directory Agent** (design
`deployment-readiness.md` §5.3, DR-11, not built yet; `safedial.Transport` is the seam it will
implement). Until then, a dev instance can reach a lab directory with an explicit allowlist.

To point a local dev instance at a real LDAP or LLDAP server (for example an LLDAP on a NAS):

1. Use **LDAPS** (port 636) and a certificate whose name matches the host name you configure.
   (LLDAP: set `[ldaps_options] enabled = true`, `port = 6360`, `cert_file` and `key_file` in `lldap_config.toml`;
   map 636 on the host if the container publishes 6360. Port 389 works only if the server offers StartTLS.)
2. Create a **read-only bind account**. In LLDAP create a user such as `svc-tessera` and add it to the
   `lldap_strict_readonly` group, not `lldap_admin` (a member of `lldap_admin` is reported as a root
   identity and fails `ldap.svc.readonly`). On OpenLDAP and 389-DS use a dedicated entry with read ACLs,
   never the rootDN or `cn=Directory Manager`.
3. Start the dev server with the lab host allowlisted (dev only; `TESSERA_ENV=prod` refuses this variable):

   ```bash
   TESSERA_SAFEDIAL_ALLOW=192.168.1.20:636 ./run.sh     # host:port, CIDR:port or name:port; 389 or 636 only
   ```

4. In Admin → Connections → New connection → **OpenLDAP / 389-DS** set the host, port 636, the
   **Bind DN** (for example `uid=svc-tessera,ou=people,dc=tessera,dc=test`) and, if the server
   certificate is not from a public CA, paste the CA certificate (PEM, certificates only). Under
   Scope set the base DNs (LLDAP: `ou=people,dc=tessera,dc=test` and `ou=groups,dc=tessera,dc=test`) and
   the user filter (`(objectClass=inetOrgPerson)`), then save the password under Credential. It is
   sealed under the KEK and never returned. Attest the base items, move to ready to validate and run
   **Validate**.
5. To check the prober against the lab outside the UI (read-only; nothing is committed, the target
   comes from the environment):

   ```bash
   cd server
   TESSERA_LDAP_TEST_URL=ldaps://192.168.1.20:636 \
   TESSERA_LDAP_TEST_BIND_DN='uid=svc-tessera,ou=people,dc=tessera,dc=test' \
   TESSERA_LDAP_TEST_PASSWORD='...' \
   TESSERA_LDAP_TEST_BASE_DN='ou=people,dc=tessera,dc=test;ou=groups,dc=tessera,dc=test' \
   TESSERA_LDAP_TEST_CA=/path/to/ca.pem \
   go test -tags ldapinteg -run TestLive -v ./internal/connectors/ldap
   ```

   It logs every check's status and message (never the password) and fails if TLS, bind, the base
   DNs or the people search do not pass.

#### Directory Agent (private directories, DR-11)

Tessera never dials a private directory in production. A small agent (`cmd/tessera-agent`, Linux or
Windows) runs inside the customer network, connects **outbound** to Tessera over mutual TLS and answers a
closed set of typed, read-only operations (the nine `connectors.Prober` operations, nothing else: no
commands, no raw LDAP, no proxying). The server sends typed jobs; the agent opens its own connection.

- **Local allowlist.** The agent refuses any target not in `allowed_targets` of its own config file
  (host:port, IP:port or CIDR:port; ports 389/636; the file must not be group/other-writable).
- **Credentials stay on the agent.** `tessera-agent credential -config agent.json set NAME` reads the
  password from stdin into a file store (0600; DPAPI-wrapped on Windows). In Tessera set the connection's
  credential reference to `agent:<agent id>/NAME`.
- **Enrolment.** Admin → Connections → Directory agents → Enrol: a single-use code (random, 15 minutes,
  stored only as a hash, audited) is shown once. On the agent host run `tessera-agent enrol -config
  agent.json` and paste it. Tessera then pins the agent's client key (SHA-256 of its public key) and the
  agent pins Tessera's CA (`server_ca_file`). Revoke from the same screen.
- **Server listener.** Set `TESSERA_AGENT_ADDR` with `TESSERA_AGENT_TLS_CERT` and `TESSERA_AGENT_TLS_KEY`
  (a separate mutual-TLS port serving only `/agent/v1/*`).
- **Agent config** (JSON): `{"server_url":"https://tessera.example:8443","server_ca_file":"ca.pem",
  "state_dir":"/var/lib/tessera-agent","allowed_targets":["ldap.corp.example:636"]}`; then
  `tessera-agent run -config agent.json`.
- API: `GET /api/agents`, `POST /api/agents` (step-up; returns the code once), `POST /api/agents/{id}/revoke`
  (step-up). Table `directory_agents`, `agent_enrolments` (schema 0250).
- The Windows DPAPI store is cross-compiled and vetted (`GOOS=windows go vet`) but not run on Windows.
### Config transport (dev → test → prod)

Admin → Export / import configuration moves a tenant's connections (config, owners, credential
*references*), readiness overlays and sign-in connections to another tenant, usually on another
instance, as a **signed bundle** (`server/internal/transport`). Export signs with the tenant's
Ed25519 key (made on first export, sealed under the KEK; a server without a KEK cannot export).
Import accepts only bundles signed by a **trusted signer**: paste the exporting tenant's public
key under Trusted signers first (a tenant does not trust its own key implicitly). The preview
lists add / change / remove / manual per item; apply is bound to the previewed plan (`digest`, or
`digest_prune` with prune: the bundle, tenant, environment, current revisions, operations and prune
mode), so a change here or a different prune choice since the preview is refused with
`409 stale_plan` before anything is written; apply needs step-up, and never activates anything: new connections are drafts, config changes make a new
draft revision, sign-in connections arrive as **pending**, and a changed existing sign-in
connection is shown as manual (change it through an admin change request). Removals retire
connections only with prune. A bundle never holds a secret: sealed credentials and client
secrets stay behind (the plan says where to set them), retired connections and the dev IdP are
left out, and a bundle whose config looks like it carries a secret is refused. On a prod server
(`TESSERA_ENV=prod`) a bundle naming a localhost target or the dev IdP, or a sign-in
connection on plain http or a private address, is refused. Applies are audited
(`config.import.applied` with the bundle hash) and listed under Imports. Permission:
`config.transport` (tenant admin); reading keys, signers and history needs `admin.read`.

**Not in a bundle yet** (each needs cross-tenant id mapping for the groups and entitlements it
names, so it is left for a follow-up rather than shipped half-checked): business roles and their
versions and members, ABAC policies and bindings, catalog items and approval policies, tenant
admin settings and security contacts (these change only through admin change requests), review
schedules, alert rules, SIEM sinks, lifecycle rules and native groups. Set them up by hand in
each environment; the bundle covers connections, readiness overlays and sign-in connections only.

### Main API endpoints

`GET /api/summary` · `GET /api/identities[?type=&q=]` · `GET /api/identities/{id}` · `GET /api/accounts[?system=]` ·
`GET /api/graph?identity_id=|resource_id=` · `GET /api/nhi` ·
`GET /api/least-privilege/recommendations?unused_days=60&kind=remove|right_size|role_trim` ·
`POST /api/least-privilege/revoke {edge_id, dry_run}` · `GET /api/policies` · `GET /api/violations` ·
`POST /api/simulate {remove_edge_ids, add_edges:[{src,dst,duration_hours?}], disable_account_ids}` ·
`GET|POST /api/jit/requests` · `POST /api/jit/requests/{id}/approve|deny|revoke` ·
`GET|POST /api/reviews/campaigns` (`name` 1-200 characters after trimming, `unused_days` 1-3650, else 422) ·
`GET /api/reviews/campaigns/{id}/population` · `GET /api/reviews/campaigns/{id}/export?format=csv|json` ·
`POST /api/reviews/qa/{id}/decision {decision, comment?}` · `PUT /api/reviews/settings {qa_sample_pct}` (see "Review populations") ·
`POST /api/reviews/items/{id}/decision {decision, comment?, rule_action?}` (a decision is final: repeating it is a 200 no-op, a different one is
`409 review_item_decided` and an audited `review.decide.refused`) ·
`GET|POST /api/hris/events` (422 for an unknown `identity_id`) · `GET /api/hris/events/{id}/plan` · `POST /api/hris/events/{id}/execute` ·
`GET /api/jml/leaver-plan/{identity_id}` · `POST /api/identities/{id}/contain` (kill switch, see "Identity containment") · `POST /api/identities/{id}/disable|enable` ·
`PUT /api/connections/{id}/containment-credential` · `GET /api/accounts[?system=]` ·
`GET|POST /api/ssf/transmitters` · `GET|PUT|DELETE /api/ssf/transmitters/{id}` · `POST /api/ssf/transmitters/{id}/verify` ·
`GET /api/ssf/events` · `POST /public/t/{slug}/ssf/{transmitter_id}/events` (SSF push, see "Shared Signals receiver") ·
`GET|POST /api/siem/sinks` · `PUT /api/siem/sinks/{id}` · `POST /api/siem/sinks/{id}/rewind {seq}` ·
`GET|POST /api/siem/sinks` · `PUT /api/siem/sinks/{id}` (moving the target to another origin, or syslog host:port, while a token is stored needs a new `token`, else 422 `credential_required`; a path-only change keeps it) · `POST /api/siem/sinks/{id}/rewind {seq}` ·
`POST /api/siem/sinks/{id}/test` · `GET /api/siem/sinks/{id}/dead-letters` ·
`GET /api/alerts[?status=open|acknowledged|resolved|live&severity=&rule=]` · `GET /api/alerts/summary` · `GET /api/alerts/{id}` ·
`POST /api/alerts/{id}/acknowledge|resolve|assign` · `GET /api/alerts/rules` · `PUT /api/alerts/rules/{rule_id}` ·
`GET|POST /api/alerts/channels` · `PUT /api/alerts/channels/{id}` (a webhook moved to another origin needs `rotate_secret: true`, else 422 `credential_required`) · `POST /api/alerts/channels/{id}/test` ·
`GET /api/ownership[?kind=app|group|resource|identity&unowned=]` · `PUT /api/ownership/{kind}/{object_key}` ·
`POST /api/ownership/bulk` ·
`GET /api/audit[?limit=&before_seq=&action=&actor_id=&target_type=&target_id=&from=&to=&include_http=]` ·
`GET /api/audit/events/{event_id}/proof` · `GET /api/audit/checkpoints[?from_seq=]` · `GET /api/audit/keys` ·
`POST /api/audit/verify {from_seq?, to_seq?}` · `GET /api/audit/export[?from_seq=&to_seq=]` (NDJSON) ·
`GET /api/auth/session` (`user.identity_id` is the directory person the sign-in is linked to) · `POST /api/auth/logout` · `GET /api/auth/sessions` · `DELETE /api/auth/sessions/{session_id}` ·
`GET /api/auth/step-up?acr=&max_age=&return_to=` ·
`GET /api/auth/discover?tenant=&email=` · `GET /api/auth/login?tenant=&connection=&return_to=` (302 to the IdP) ·
`GET /api/auth/oidc/{connection_id}/callback` · `GET /api/auth/saml/{connection_id}/metadata` ·
`POST /api/auth/saml/{connection_id}/acs` · `GET /api/auth/oauth2/{connection_id}/callback` ·
`GET /api/auth/cas/{connection_id}/callback` · `POST /api/auth/wsfed/{connection_id}/callback` ·
`GET /t/{slug}/bootstrap?code=` (public) ·
`GET|POST /api/access/policies` · `PUT|DELETE /api/access/policies/{id}` · `GET|POST /api/access/networks` ·
`PUT|DELETE /api/access/networks/{id}` · `GET /api/access/users` · `GET /api/access/device-signals` ·
`PUT|DELETE /api/access/device-signals/{user_id}` · `POST /api/access/evaluate` (conditional access, below) ·
`GET|POST /api/auth/dev-login` (dev and test only) ·
`GET /api/jobs[?status=running|succeeded|failed&kind=&connection_id=&limit=]` · `GET /api/jobs/{job_id}` ·
`POST /api/jobs/{job_id}/retry` ·
`GET /api/provisioning/targets` · `PUT|DELETE /api/provisioning/targets/{connection_id}` ·
`GET /api/provisioning/ops[?status=&kind=&connection_id=&limit=]` · `GET /api/provisioning/ops/{op_id}` ·
`POST /api/provisioning/ops/{op_id}/retry|cancel` · `POST /api/provisioning/run` ·
`GET /api/provisioning/findings[?status=open|resolved]` ·
`GET /api/catalog[?all=1]` · `PUT /api/catalog/items/{group_id}` ·
`POST /api/requests {beneficiary_ids, catalog_item_ids, justification, duration_hours}` ·
`GET /api/requests[?scope=mine|pending|all&status=]` · `GET /api/requests/{id}` ·
`POST /api/requests/{id}/approve|deny|cancel|remove {reason}` ·
`GET|POST /api/abac/policies` · `GET|PUT /api/abac/policies/{id}` · `POST /api/abac/policies/{id}/retire` ·
`POST /api/abac/simulate` · `GET /api/abac/bindings` · `PUT /api/catalog/items/{group_id}/policy` ·
`GET|POST /api/sod/functions|risks|rulesets` · `GET|PUT /api/sod/{functions|risks|rulesets}/{id}` ·
`POST /api/sod/{functions|risks|rulesets}/{id}/retire` · `GET /api/sod/rulesets/{id}/export` ·
`POST /api/sod/rulesets/import` · `POST /api/sod/import-legacy` · `GET /api/sod/violations` ·
`POST /api/sod/simulate` ·
`GET|POST /api/sod/controls` · `GET|PUT /api/sod/controls/{id}` · `POST /api/sod/controls/{id}/retire` ·
`GET|POST /api/sod/mitigations` · `POST /api/sod/mitigations/{id}/approve|reject|cancel|revoke` ·
`POST /api/sod/violations/escalate` · `POST /api/sod/violations/revoke` · `GET /api/sod/review-context` ·
`GET /api/approvals/inbox` · `GET /api/approvals/delegates` · `GET|POST /api/approvals/delegations` ·
`POST /api/approvals/delegations/{id}/revoke` ·
`GET /api/correlation/queue` · `GET /api/correlation/decisions` ·
`POST /api/accounts/{id}/link {identity_id, reason}` · `POST /api/accounts/{id}/not-person {reason}` ·
`DELETE /api/accounts/{id}/link` · `POST /api/identities/{id}/merge {into, reason}` ·
`GET /api/identity-merges` · `POST /api/identity-merges/{id}/unmerge {reason}` ·
`GET|POST /api/mcp/clients` · `PUT /api/mcp/clients/{id}` · `GET|POST /api/mcp/resources` ·
`PUT /api/mcp/resources/{id}` · `GET /api/mcp/tokens` · `POST /api/mcp/tokens/{jti}/revoke` ·
`GET /api/mcp/decisions` · `GET /api/mcp/authorizations/{id}` · `POST /api/mcp/authorizations/{id}/decision`
(agent authorization, see "MCP authorization server"; the OAuth endpoints live under `/t/{slug}/`)
`GET /api/access/as-of?resource=&date=` · `GET|POST /api/evidence/packs` ·
`GET /api/evidence/packs/{id}` · `GET /api/evidence/packs/{id}/download` (see "Point-in-time access and evidence packs")
`GET|POST /api/reviews/schedules` · `PUT /api/reviews/schedules/{id}` · `POST /api/reviews/schedules/{id}/run` (an unknown `system` is 422 `invalid_system`; a second run in the same second is 409 `already_launched`; a schedule with no grants in scope creates no campaign, audits `review.schedule.skipped` and answers 200 `{skipped, reason}`) ·
`GET /api/roles/{id}/exclusions|flags` · `POST /api/roles/{id}/exclusions/{identity_id}/remove` ·
`GET /api/identities/{id}/affiliations` · `GET /api/identities/{id}/identifiers` ·
`POST /api/identities/{id}/affiliations {type, org_unit?, population?, starts_at?, ends_at?, reason}` ·
`POST /api/affiliations/{id}/end {reason}` ·
`GET /api/catalog[?all=1]` · `PUT /api/catalog/items/{group_id}` ·
`POST /api/requests {beneficiary_ids, catalog_item_ids, justification, duration_hours}` ·
`GET /api/requests[?scope=mine|pending|all&status=]` · `GET /api/requests/{id}` ·
`POST /api/requests/{id}/approve|deny|cancel|remove {reason}` ·
`GET|POST /api/roles` · `GET|PUT /api/roles/{id}` · `GET /api/roles/{id}/versions|drift` ·
`POST /api/roles/{id}/retire|reconcile|members` · `POST /api/roles/{id}/members/{identity_id}/remove`
(changes take `?dry_run=1`) · `GET|POST /api/role-requests` · `POST /api/role-requests/{id}/approve|deny|cancel` ·
`GET /api/lifecycle[?state=upcoming|active|ending|ended]` · `GET /api/lifecycle/sponsored` · `POST /api/lifecycle/sweep` ·
`GET|PUT /api/identities/{id}/lifecycle` · `POST /api/identities/{id}/lifecycle/extend {ends_at, reason}`
`POST /api/guests/invitations` · `POST /api/guests/invitations/bulk {csv, dry_run}` ·
`GET /api/guests[?sponsor=me|all&state=&population=]` · `GET /api/sponsorships/approvals` · `GET /api/sponsorships/{id}` ·
`POST /api/sponsorships/{id}/approve|reject|renew|end|transfer|accept-transfer` ·
`POST /api/guests/{identity_id}/resend-invitation|revoke-invitation` ·
`POST /public/t/{slug}/claim/start|verify/send|verify/check|existing-account|credential|resend` ·
`GET /public/t/{slug}/claim/status` (public: the guest's claim, see Guest claim) ·
`GET /api/approvals/inbox` · `GET /api/approvals/delegates` · `GET|POST /api/approvals/delegations` ·
`POST /api/approvals/delegations/{id}/revoke` ·
`GET /api/notifications[?unread=1&limit=]` · `POST /api/notifications/read {ids}|{all:true}` ·
`GET|PUT /api/notifications/preferences {prefs:{kind:channel}}` ·
`GET /api/email/messages[?status=&kind=&recipient=&limit=]` · `GET /api/email/messages/{id}` ·
`POST /api/email/messages/{id}/retry` ·
`GET /api/admin/users` · `POST /api/admin/users/{id}/disable {reason}` · `GET /api/admin/idp-connections` ·
`POST /api/admin/idp-connections/{id}/activate` · `GET|POST /api/admin/change-requests` ·
`GET /api/admin/change-requests/{id}` · `POST /api/admin/change-requests/{id}/approve|reject|cancel|apply` ·
`GET /api/admin/notifications` · `GET /api/admin/recovery` · `POST /api/admin/recovery/{id}/cancel` ·
`GET /api/admin/api-clients` (see "Admin changes")
`GET /api/config/signing-key` · `POST /api/config/export` · `GET|POST /api/config/trusted-signers` ·
`DELETE /api/config/trusted-signers/{kid}` · `POST /api/config/import/plan` (body: the bundle file) ·
`POST /api/config/import/apply?hash=&digest=&prune=` · `GET /api/config/imports`

Each route declares the permission it needs (design §12.1, §16.2; `api.Routes()` lists them and
`internal/api/rbac_routes_test.go` holds the table). The decider of a JIT request, review item, revoke
or HRIS execution is always the signed-in user.

### Conditional access (network location and device posture)

Beyond step-up, a tenant can decide **allow, require step-up or deny** by where a request comes from and
what is known about the device (issue #163; Settings → **Conditional access**, `/admin/conditional-access`).
Policies have a **scope**: `signin` (the Tessera sign-in, at the OIDC callback and SAML ACS) or
`privileged` (every route that already needs a fresh sign-in: JIT approval, review decisions, revoking
grants, HRIS execution, connection changes). Conditions, all of which must hold:

* **Network**: `in` or `not_in` named ranges (CIDRs, IPv4 and IPv6). The address is the **trusted-proxy
  client IP**: the TCP peer, or, only when the peer is in `TESSERA_TRUSTED_PROXIES`, the rightmost
  `X-Forwarded-For` entry that is not itself a trusted proxy. A header from any other peer is ignored, so a
  client cannot name its own address (the rate limiter uses the same function). An address that cannot be
  determined is in no range.
* **Device**: `unmanaged` or `not_compliant`. Posture comes from the IdP's claims at sign-in (OIDC claims or
  SAML attributes `device_managed` and `device_compliant`, renamable per connection with
  `authn_mapping.device_managed_claim` / `device_compliant_claim`; stored on the authentication context) and
  from the user's **device-compliance signal**. "Not compliant" from either source wins; a device the IdP says
  nothing about counts as unmanaged and not compliant. Signals are set by an admin (source `manual`, optional
  expiry) through `condaccess.SignalSource`; the CAEP receiver of #114 is not built, and will write
  `caep` signals into the same table or implement that interface.

Policies are checked in priority order and **the first enforced match decides**; no match is allow. `report_only`
policies are evaluated and recorded with the outcome they would have had but never change the result;
`disabled` ones are ignored. Outcomes: `deny` refuses a sign-in (`auth.login.failure`, reason
`conditional_access_denied`) or answers `403 conditional_access_denied`; `step_up` names an ACR (aal2, phr, phrh)
and optional `max_age`. On a sign-in the authentication itself must already meet it (else
`conditional_access_step_up_required`); on a privileged route it tightens the route's own requirement, so the
client gets the usual `401 step_up_required` challenge. The permission is checked before policies, so a caller
without it learns nothing of them. The operator bootstrap sign-in and the conditional access routes themselves
are exempt (a policy cannot lock an admin out of fixing it).

Every evaluation that had a policy to check is audited with its inputs (`access.decision`, or the
`conditional_access` detail of `auth.login.success` / `auth.login.failure`): scope, outcome, deciding policy,
report-only hits, client IP and how it was resolved (`peer` or `x_forwarded_for`), device managed, compliance and
its source. When a trusted proxy does not say who the client is (`X-Forwarded-For` missing or malformed, or every hop a trusted proxy), the client is unresolved: it is never given the proxy's address, every network condition on a deny or step-up policy holds for it (`in` and `not_in` alike, so a blocklist and an off-network rule both apply) and none on an allow policy does, and the event records `client_ip_unresolved`; rate limiting still keys on the proxy. Changes to ranges, policies and signals are `access.network.*`, `access.policy.*` and
`access.device_signal.*` events in the same transaction. Reading needs `conditional_access.read` (auditor,
tenant admin); changing needs `conditional_access.manage` (tenant admin) and a fresh phishing-resistant
sign-in. A tenant is limited to 100 policies and 100 ranges. `POST /api/access/evaluate` answers what the
current policies would decide for a described request without recording anything. In the dev IdP, Alice's
device is managed and compliant and Olu's is neither (`device:` in `users.yaml`).
### Point-in-time access and evidence packs

Issue #111; packages `server/internal/evidence`, `graph.BuildAsOf`, schema `0260` and `0261`.

- **Edge history** (`edge_history`). Every write to `grant_edges` (connector sync and prune, JIT
  approve, extend, revoke and sweep, manual grants, review, leaver and least-privilege revokes) opens or
  closes a span `[valid_from, valid_to)` in the same transaction, in `store/repo_grants.go`, so no
  caller can forget it. A span is half-open: the grant holds at the instant it was added and not at the
  instant it was removed. A JIT grant also stops at its own `expires_at`, even if the sweeper deleted it
  later; extending one closes the span and opens a new one. Deleting an edge needs the removal time, so
  `DeleteEdge`, `DeleteJITEdge` and `SetEdgeExpiry` take an `at` argument. Applying the schema backfills a
  span (from `created_at`) for any grant that has none, so existing databases start with today's grants
  as of their creation time.
- **`GET /api/access/as-of?resource=<id>&date=<date or datetime>`** (`graph.read`). Who could reach the
  resource, per identity with permissions and paths. A date (`2026-03-31`) means the end of that day
  (today means now); a datetime (`2026-03-31T09:30:00`, UTC) is that instant. A future instant is 422.
  Only grants are historical: identities, accounts and the identity-account bindings are today's, so an
  account disabled by a leaver plan still shows the access it had then. The UI offers it as an *As of*
  date in Access graph → *Who can access…*.
- **Evidence packs** (`evidence_packs`, immutable). `POST /api/evidence/packs {framework, from, to}`
  with `framework` one of `soc2`, `sox_itgc`, `iso27001`, `pci_dss_v4` (`audit.read`: auditor and tenant
  admin). `from` and `to` are dates or datetimes; a date `to` includes that day, the period is capped
  at 731 days and ends no later than now. The pack, its ZIP and the ledger event
  `evidence.pack_generated` (framework, period, manifest SHA-256) commit in one transaction; the ZIP is
  written after commit. `GET /api/evidence/packs` lists them, `GET /api/evidence/packs/{id}` returns the
  manifest and `.../download` the ZIP. Contents: `users.csv` (one row per account with its source
  system; the manifest counts rows per source), `jml_leavers.csv` (per leaver event and system: hours
  from the HR termination to the last grant removal, or `access_remains`; ids only), `review_campaigns.csv`
  and `review_items.csv` (campaigns created in the period with decisions), `privileged_access.csv` (who
  held privileged access at the end of the period, with the path), `revocations.csv` (grants revoked in
  Tessera in the period, verified against Tessera's own graph, not the target system), `README.txt`,
  `manifest.json` (SHA-256 and row count of every file, control mapping from the knowledge base) and
  `manifest.sha256`. The same input gives the same bytes. CSV cells starting with `= + - @` get a leading
  apostrophe. The PCI pack notes that exception-only campaigns may not satisfy requirement 7.2.4.
  The review campaigns file is built from the campaigns and their items; there was no separate review
  export to reuse.

### SIEM streaming

`tessera serve` pushes each tenant's audit ledger to its SIEM sinks every 15 seconds (`internal/siem`, issue #169).
The pull export (`/api/audit/export`) stays available.

- **Destinations:**
  - **Splunk HEC:** newline-separated HEC envelopes, sent with `Authorization: Splunk <token>`, `sourcetype` set to `tessera:audit` or `tessera:ocsf`, and `host` set to the tenant slug.
  - **HTTPS JSON:** a JSON array of events with an optional bearer token. Use it for Microsoft Sentinel's Logs Ingestion API, Cribl or Logstash.
  - **Syslog over TLS (RFC 5425):**
    - Messages are RFC 5424 with octet-counting framing, facility 13 (log audit), and the severity taken from the event's outcome.
    - Each message carries structured data `[tessera@32473 seq=… hash=…]`.
    - The port defaults to 6514. A private CA can be given as PEM.
- **Formats:**
  - `json` is the export record. It carries `hash` and `prev_hash`, so the SIEM can recompute the chain.
  - `ocsf` is OCSF 1.3: Authentication (3002) for sign-in and sign-out, Account Change (3001) for role grants and revokes and user disables, and API Activity (6003) for everything else.
  - The chain fields go under `unmapped.tessera`.
  - The mapping is pinned by golden files in `internal/siem/testdata`.
- **Delivery:**
  - At least once, in seq order, from a durable cursor per sink. The cursor moves only after the destination accepts a batch of up to 200 events, so restarts and outages leave no gaps.
  - New sinks start at the current head by default, or can replay the whole ledger with `start: "beginning"`. **Replay** in the UI (a rewind) sends everything again.
  - `http.request` events are left out unless `include_http` is set.
  - Failures back off from 10 s up to 30 min.
  - After 3 consecutive failures the sink shows as **failing**, recorded as audit event `siem.sink.failing` (and `siem.sink.recovered` when it recovers).
  - A batch the destination rejects outright (a 4xx other than 408 or 429) is retried 5 times, then dead-lettered and skipped (`siem.sink.dead_letter`). Retryable errors are never skipped.
- **Health:** healthy, catching up, retrying, failing or paused. The lag counts the events the sink still has to send.
- **Security:**
  - Webhooks go through `internal/safehttp`.
  - Syslog collectors are checked against the same address rules after DNS resolution, and the dial goes to the checked address. Private, loopback (outside dev) and cloud-metadata addresses are refused.
  - Tokens are sealed under the KEK, never returned, and kept out of the audit log.
  - Webhook URLs are shown without their query string.
  - Creating or changing a sink needs step-up.
- **Permissions:**
  - `siem.read`: auditor and tenant_admin, plus the `tessera:audit` scope.
  - `siem.configure`: tenant_admin, plus the `tessera:admin` scope.
- **UI:** **Admin > Log streaming (SIEM)** lists each sink with its health, delivered count, dead letters, and Test, Replay and Edit actions.
- **Not yet:** S3-compatible bucket sinks.
### Alerts

The alert engine (`internal/alerts`, issue #168) runs every minute in `tessera serve`. It reads new audit
events and matches them against built-in rules; detections run every 15 minutes. A tenant's first run
starts at the current head, so history does not alert.

| Rule | Fires on | Default |
|---|---|---|
| Break-glass access used | `auth.break_glass.used`, `breakglass.action` | critical, every event |
| New administrator | `auth.role.granted`, `admin.role.granted` or an applied `role.grant*` admin change, for tenant_admin, policy_admin or break_glass | high |
| MFA bypassed | `auth.mfa.bypass*` (#109) | high |
| Repeated sign-in failures | `auth.login.failure` with the same email, subject or IP | medium, 5 in 15 min |
| Provisioning or sync job failed | a failed `connectors.*`, `connection.*`, `jml.*`, `provisioning.*` or `readiness.*` event, `job.failed` (job run history), or `admin.change.failed` | high |
| Audit anchoring failing | detection: checkpoints whose anchoring failed | critical, at 3 |
| Privileged identity without an owner | detection: an active NHI or agent with privileged access and no owner, or an owner who left | high |

- **Dedup and lifecycle.** There is one live alert per rule and subject; repeats raise its count.
  - States are open, acknowledged and resolved. A detection resolves itself when the condition clears or the rule is switched off.
  - Raising, acknowledging, assigning, resolving, rule and channel changes, deliveries and channel tests are all audited (`alert.*`).
- **Rule settings.** Tenant admins can turn a rule on or off and change its severity, threshold and window (`alerts.configure`).
- **Channels.**
  - Email: a list of addresses.
  - Webhook: an https URL. The payload has a `text` field, so Slack and Teams incoming webhooks accept it.
  - Each channel takes alerts at or above its minimum severity.
  - Webhooks go out through `internal/safehttp`, which refuses private, loopback (except in dev) and cloud-metadata addresses.
  - Each webhook is signed: `X-Tessera-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">`. The secret (`whsec_…`) is shown once, sealed under the KEK, and can be rotated.
  - Creating or changing a channel needs step-up.
  - Webhook URLs (alert channels and SIEM sinks) come back as `scheme://host[:port]/…`, because Slack, Teams and
    Sumo Logic put their token in the path or query. Send errors are scrubbed the same way before they reach
    `last_error`, a test response or the audit ledger (`safehttp.ScrubError`, #333). Ledger entries written before
    the fix keep their original text (the ledger is append-only).
- **Retries.** Deliveries wait in an outbox and are retried after 1 min, 5 min, 15 min, 1 h and 4 h, then marked failed.
- **Email.** `TESSERA_NOTIFY` controls email:
  - `log` (the default) writes each message to the server log.
  - `smtp://user:pass@host:587?from=alerts@example.com` sends with STARTTLS required; a relay without STARTTLS is refused.
  - `smtps://…` sends with implicit TLS.
  - The SMTP host is operator configuration, so it does not go through `safehttp`.
- **Permissions.**
  - `alerts.read`: operator, auditor, policy_admin, tenant_admin.
  - `alerts.manage` (triage): operator, policy_admin, tenant_admin.
  - `alerts.configure`: tenant_admin.
- **UI.** **Protection > Alerts** has three tabs: alerts with filter chips and a side panel, rules, and channels (tenant admins only). For anyone with `alerts.read`, the top-bar bell lists open alerts with a count.
### Ownership

Applications (by system name), entitlements (groups), resources and machine identities each have a
primary owner, an optional backup owner, an optional owner group and a purpose (table `ownerships`,
issue #167). Owners must be active people; the backup must differ from the primary. Setting needs
`ownership.manage` (operator, policy_admin); reading needs `graph.read`. Every change is audited as
`ownership.set`.

- For a machine identity the primary owner is also `identities.owner_id`, so the NHI flags, reviews
  and policies use it. Once set in Tessera, connector sync no longer overwrites it.
- The leaver plan gains `reassign_ownership` steps: an object the leaver owns goes to its active
  backup, else to the leaver's manager (else nobody); where the leaver is the backup, the slot is
  cleared. Plans without ownership rows are unchanged.
- UI: **Identity > Ownership** lists each kind with unowned counts, a "No owner" / "No backup" filter
  and bulk **Assign owner**; the entitlement, application and machine-identity panels show the
  owners with **Assign**/**Change**; the machine identity list has the same bulk action.

### Scheduled access reviews

**Access reviews → Schedules** (issue #166) runs campaigns on a recurrence: once, every
quarter, every six months or every year. A schedule sets:

- **Scope:** one system or all; privileged grants only, or every risky grant.
- **Review window:** how many days reviewers get, and when the reminder goes out.
- **Close-out:** what happens to items nobody decided by the due date. Either they are revoked,
  or they go to an escalation reviewer for a few days and are revoked after that.

The scheduler (`reviews.scheduler`, every 5 minutes) launches due schedules. Each period
(`2026-Q4`, `2026-H2`, `2026`) runs once, even after a restart. Periods missed while the server
was down collapse into one run. The next run is counted from the scheduled time, so it doesn't
drift. **Run now** launches outside the schedule. Reminders, escalations and close-outs are audit
events; delivery by email or chat comes with alerting (#168). Reviewers are assigned as for
manual campaigns: the manager, then the owner, then the security lead. The scheduler follows
`TESSERA_NOW` in dev.

### Role memberships in reviews

A campaign certifies what people hold *through* a business role as one item, the **membership**
(issue #214): role, member and source (rule, request or manual), with the grants the role made
listed under it in the side panel. Those grants are not separate items, so a reviewer can't revoke
a grant the role would restore. A membership appears when one of its grants is risky (the same
tests as any grant); a campaign or schedule **scoped to roles** reviews every membership of those
roles, whatever the risk, and nothing else (the system and privileged scope then do not apply).
Pick the roles in the schedule form (`role_ids`).

Revoking a membership:

- **Manual or request:** removed through `roles.Unassign`, so its removal plan takes the role's
  grants that no other role justifies. Reconcile does not bring them back.
- **Rule:** the person can't be removed while the rule matches, so the reviewer chooses
  (`rule_action` in the decision; without one the API answers 422). **exclude** puts them on the
  role's exclusion list (the membership and its grants go; birthright evaluation, every save and
  Reconcile, skips them). The list is versioned: each add or removal is a new version, history is
  kept, and `GET /api/roles/{id}/exclusions` shows it. Taking someone off (`roles.manage`) lets the
  rule assign them again at the next save or Reconcile. **flag** removes nothing and records the
  decision for the role owner (`GET /api/roles/{id}/flags`, audit `review.rule_flagged`).
- **Old campaigns** still have items for a grant a role made. Revoking one is converted into a
  revoke of the membership(s) that justify it (same choices for a rule member), rather than
  refused (that would lose the decision) or applied to the edge alone (Reconcile would undo it).
- **Close-out** of a scheduled review revokes undecided manual and request memberships and flags
  undecided rule memberships; it never removes a rule member.

Role removal, exclusion and the review decision are written, with their audit events
(`role.unassign`, `role.exclude`, `review.revoke`), in the decision's transaction.

### Intended and observed access, and drift (issue #301)

Tessera keeps what was **decided** apart from what systems **report**:

* `intended_grants` (schema 0330): identity x target entitlement, with provenance (`request`, `role`,
  `birthright`, `jit`, `review_keep`, `manual`), a validity window and an owner. Approvals, role assignment,
  JIT, a review "keep" and admin grants write it in the same transaction as their `grant_edges` write
  (`InsertEdge`, `SetEdgeExpiry`, `RevokeEdge`, `Delete*Edge`, `KeepIntent` in `internal/store/repo_access_model.go`);
  revoking or expiring closes the row (`closed_at`, `close_reason`), it is never deleted.
* `observed_runs` / `observed_entitlements`: the account -> group memberships each system reported in its latest
  connector run (one run per system; the snapshot replaces the previous one). Only `ingest.Discovery` writes them.
* `access_drift` (schema 0331): one row per difference, classes `missing` (intended, not shown), `rogue` (shown, never
  intended), `orphan` (account with no identity), `stale` (shown after the intent ended); status `open`,
  `remediating`, `resolved`, `accepted`. `internal/reconcile/drift.go` finds them after each sync and every 5 minutes
  on the sweeper (`drift_sweep`); reruns are idempotent (a row is opened, reopened, updated or resolved, never duplicated).
* `remediation_policies`: per system, or per entitlement of a system, and class: `auto_provision` (missing only) and
  `auto_revoke` (rogue, stale, orphan) go through the provisioning engine (needs a write-back target, else an owner task),
  `owner_task` puts a security alert in the Inbox of the owner (the identity's owner or manager) or of the people who decide
  access, `report_only` (the default) records only. Every action writes a `drift.remediate` audit event in the same transaction.
* `grant_edges` is unchanged and stays the live model for the graph, insights, SoD and reviews. On a deployment that predates
  the tables the first reconciliation backfills both sets from it (`BackfillAccessModel`).

Routes: `GET /api/access-drift[?class=&status=&system=&identity_id=&limit=]` (`drift.read`) · `POST /api/access-drift/run`,
`POST /api/access-drift/{drift_id}/accept` (`{"reason"}`) and `/remediate` (`{"action"}`) (`drift.remediate`, step-up) ·
`GET /api/remediation-policies` · `PUT /api/remediation-policies` and `DELETE /api/remediation-policies/{policy_id}`
(`drift.policy`, policy admin, step-up). UI: Governance, Drift.

### Job run history

Every run of a connector sync, provisioning (HRIS execute), connection validation, dry run,
deployment-health re-run and JIT sweep is recorded in `job_runs` (`internal/jobs`), plus every
audit anchoring run that did something or failed. A sweep that finds nothing is not recorded.
Each record has the kind, trigger (manual, schedule or retry), status, duration, a result summary
and a one-line error. The run row is written in its own transaction before the job and finished in
another, so a job that rolls back keeps its failed run, and `job.failed` is appended to the audit
chain for alert rules to match. A request refused before the job ran (bad input, missing
permission, a blocked gate) is not a run.

`POST /api/jobs/{id}/retry` runs the operation again as the signed-in user through a typed
dispatcher, not a replayed HTTP request: the retry request is authenticated as usual, the original
route's permission and step-up are rechecked for the caller as they are now, and the route
registered for the run's kind runs with the recorded body (a connection comes from the run's
`connection_id`). No cookie, `Authorization` or `DPoP` header is stored or forwarded. It is offered only for idempotent
kinds (sync, validation, dry run, health re-run, JIT sweep), not for provisioning. The new run
links `retry_of` and records `job.retried`. Runs still `running` after an hour are marked failed
("interrupted"), and runs are kept 30 days. Reading the history needs `jobs.read` (operator,
auditor, policy admin, tenant admin). Admin → Jobs lists the runs, with Failed, Running and job
filter chips and a side panel showing the error, the result and Retry.

### Durable job queue

`internal/queue` is the one engine for background work (issue #300). Rows live in `queue_jobs` (kind,
JSON payload, idempotency key unique per tenant and kind, `run_at`, attempts, `max_attempts`,
`last_error`, lease owner and expiry, status `queued | running | succeeded | failed | dead`) and
`queue_schedules` (name, kind, spec, `next_run_at`), both tenant-owned with RLS and cross-tenant guards.
All SQL is in `internal/store/repo_queue.go`, reached through the tenant handle; a worker finds tenants
the way the old sweepers did (active tenant list), then works each one in its own transaction.

* **Claiming.** A worker claims due rows (queued or failed with `run_at` past, or running with an expired
  lease) by setting a lease in one write transaction: `BEGIN IMMEDIATE` on SQLite, `FOR UPDATE ... SKIP
  LOCKED` on Postgres (`pgOverrides`, on top of the per-tenant advisory lock). Each claim counts an
  attempt; a handler heartbeats every lease/3 (60 s lease), and a lost lease cancels the handler. A
  job whose lease expires after its last attempt is dead, not run again. Delivery is at least once.
* **Failure.** A failed attempt becomes `failed` and runs again after `10s * 2^(n-1)` (cap 15 min, plus or
  minus 20% jitter); after `max_attempts`, or on `queue.Permanent(err)`, it is `dead` and
  `queue.job_dead` is audited. `POST /api/queue/jobs/{id}/retry` puts a dead job back with a fresh
  budget (`jobs.manage`, tenant admin, step-up; `queue.job_retried` audited).
* **Schedules.** Specs are `@every 30s` or 5-field cron (UTC). A worker that finds a schedule due moves
  `next_run_at` and enqueues the job (key `schedule:name:window`) in one transaction, so a window runs
  once however many workers poll; after downtime it fires once, not per missed window. Schedules are
  declared in code (`Server.newQueue`) and created for each tenant on first sight.
* **Workers.** `Queue.Run` polls every 2 s with 4 concurrent jobs, rotating the tenant it starts with.
  On shutdown it stops claiming, waits up to 10 s, then cancels running handlers and releases their leases
  (queued again, attempt given back). `tessera serve` runs it as `Server.RunQueue`.
* **On the queue now.** The sweepers that `RunSweeper` ran, as per-tenant schedules every 30 s:
  `jit_sweep`, `sweep_requests`, `sweep_lifecycle` (sponsorships, then lifecycle: one job so the order
  holds), `sweep_admin_changes`, and `containment_retries`, plus `job_maintenance` every 10 min (stale
  `job_runs`, retention, pruning succeeded queue jobs after 7 days). The containment retry sweep runs
  `RunRetries` under a lease; each `containment_retries` row keeps its own backoff (1m, 5m, 15m, 1h) and
  24 h give-up, which are tested domain rules, so the queue adds exclusion, not a second backoff.
* **Run history.** A job execution that returns a result or an error is recorded as a `job_runs` row
  (kind = the queue kind, trigger `schedule`, or `retry` from the second attempt), so the run history of
  #172 and Admin → Jobs show it, and a failure appends `job.failed`. A sweep that finds nothing returns no
  result and records nothing, as before. `GET /api/queue/jobs?status=&kind=` and `GET
  /api/queue/schedules` (`jobs.read`) feed the Queue section of Admin → Jobs.
* **Not on the queue yet.** The notification outbox (own dead-letter state and loop) and provisioning
  operations (`provision.Engine`) keep their loops, and the audit checkpointer its own; see Known gaps.

### Closed-loop provisioning

Until issue #103 every write Tessera made (JML execute, review revoke, JIT revoke and expiry,
least-privilege revoke) changed only its own graph. `internal/provision` is the engine that makes the
change in the target system and checks that it happened.

* **Operations.** `provisioning_ops` (schema `0225`) holds one row per change: create, update, disable
  or delete an account, add or remove an entitlement. An idempotency key names the intent
  (`jit:12:end`, `review:7:revoke`, `jml:3:0:disable_account`); submitting it twice gives one operation,
  and it is sent to the target as `Idempotency-Key`. Every connector also reads before it writes, so
  a repeated request converges.
* **Lifecycle.** `queued` → `sent` → `pending_verification` → `verified`, or `mismatch` / `failed`
  (and `cancelled` by an operator). A worker (every 5 s, `Server.RunProvisioning`; `POST
  /api/provisioning/run` runs it now and is recorded as a `provision` job run) sends each operation and
  **re-reads the target**. A send that fails for a transient reason (transport, 429, 5xx) is retried
  with exponential backoff (5 s doubling to 10 min, 5 attempts); a refusal (401/403/400) fails it at
  once. A re-read that disagrees is repeated 3 times, then the operation is a `mismatch` and a finding
  (`provisioning_findings`, `verify_mismatch`, high for a disable or removal) is raised.
* **Tessera changes only after verification.** An operation carries a completion (a graph edit, a
  review decision, a JIT end) that runs in the same transaction that marks it `verified`. A failed or
  unverified write therefore leaves the review item open, the account active and the JIT grant in place.
  Retrying (or deciding again, or the next `POST …/retry`) re-queues the same operation.
* **Write-back is per connection and off by default.** A target (`provisioning_targets`, schema
  `0224`, one per connection) has a `write_back` switch. Off: the change edits the graph at once, as
  before, and nothing reaches the target (so the parity fixtures are unchanged). On: the change goes
  through the engine. Routing is by the connection's `system` (`provision.Submit`).
* **Connectors.** `internal/provision/scim` is a SCIM 2.0 client (filtered, paginated lists; group
  members read page by page; PATCH add/replace/remove, where a member is removed with the RFC 7644
  filter path and, if the server refuses it, with a value list; `dialect: entra` sends capitalised
  operations, string booleans and the value list, and every dialect reads `"True"`/`"False"`). `internal/provision/okta` is a native
  Okta connector (users, lifecycle deactivate/delete, group membership, `Link` paging that must stay on
  the org's origin). Credentials are sealed under the KEK (`internal/seal`, AAD = tenant, table,
  column and row) and are write-only in the API. Every request goes through `internal/safehttp`.
* **Limits.** Disabling or deleting an account through SCIM does not end sessions or tokens the
  account already holds (SCIM does not imply it; knowledge base §4.6), so a verified disable is not
  yet a verified kill: that needs session revocation or CAEP/SSF, which is future work.
* **What is routed.** JML leaver/mover/joiner steps (disable, remove and add group, create account),
  review revokes of group memberships, JIT revoke and expiry (the request stays `approved` and the edge
  stays until the target confirms; the sweeper does not retry a failed removal, an operator does),
  and the least-privilege revoke. Edges to permissions have no counterpart in a target and stay direct.
* **Audit.** Each operation writes `provision.enqueued`, `provision.sent` and one of
  `provision.verified`, `provision.mismatch`, `provision.failed`, plus `provision.retried`,
  `provision.cancelled`; target changes write `provision.target_set` (with the target's origin and `credential`: `none`, `kept`, `set`, `rotated` or `cleared`, plus `previous_kind`/`previous_origin` when it moved) and `provision.target_removed`
  (never the token). A stored token never follows a target to another kind or origin (scheme, host, port): such an edit needs a new token or gets 422 `credential_required`; a path-only change on the same origin keeps it. Completions write the event the direct path wrote (`jit.expire`, `review.revoke`,
  `grant.revoke`).
* **Permissions.** `provisioning.read` (operator, auditor, policy admin, tenant admin) and
  `provisioning.manage` (policy admin, tenant admin: retry, cancel, run). Configuring a target needs
  `connections.manage` with step-up.
* **Dev fake target.** `TESSERA_DEV_FAKE_TARGET=1` (set by `run.sh`) starts an in-process fake SCIM
  service on a loopback port (`internal/provision/fake`) and enables the `fake` target kind, with a
  simulated fault: `fail_writes` (503) or `drop_writes` (accepted, never applied: a mismatch). The fake
  treats users and groups it has never seen as already provisioned. Config refuses the setting with
  `TESSERA_ENV=prod`, and an architecture test keeps the fake out of every package but `cmd/tessera`.
* **Tests.** Recorded exchanges (`internal/provision/{scim,okta}/testdata`, replayed by
  `internal/provision/replay`) pin Entra's string booleans, capitalised PATCH operations, paginated
  large groups, Okta `Link` paging and error classification; engine tests cover backoff, idempotency,
  mismatch findings, sealed credentials and tenant isolation; API and JML tests show a failed
  target write leaving the review item, account and edges open.

Admin → Provisioning lists the target systems (with the write-back switch) and the operations, with
status, change and source filter chips, a side panel with the findings, request and Retry / Cancel,
and Run now.

### Admin changes, notifications and operator recovery

Changes that widen trust or privilege go through **change requests** (design §15, issue #16;
`internal/admin`, routes in `internal/api/admin_routes.go`, UI under Settings → Admin: Users,
Authentication, Change requests, API clients, and a banner on every page while a change is pending).

| `type` | Who approves | Waits | Applies |
|---|---|---|---|
| `role.grant` of `policy_admin` or `tenant_admin` | a different `tenant_admin` | 24 h | adds the role, ends the target's sessions |
| `role.grant` of viewer, operator, auditor | one admin | none | at once |
| `role.revoke` of another user's admin role | a different admin | none | at once, never below the tenant's `min_admins` |
| `role.revoke` of a non-admin role, or your own | one admin | none | at once |
| `idp_connection.create` | a different admin | 24 h | creates the connection `pending`; it becomes `active` after the requester's successful test login (`POST …/activate`) |
| `idp_connection.update_trust` | a different admin | 24 h | updates it and revokes every session that came through it |
| `idp_connection.update_cosmetic`, `.disable` | one admin | none | at once (disable ends the connection's sessions; refused for the last active connection) |
| `tenant.settings.update` | a different admin if it **weakens** a setting | 24 h if weakening | merges the bounded settings of §18.3 and `min_admins` |
| `tenant.security_contacts.update` | a different admin | 24 h | replaces the contacts |
| `breakglass.register` | a different admin | 24 h | creates the break-glass user (or adds a key to one) and opens a 24 h window for the requester to register the key |
| `breakglass.revoke` | one admin | none | revokes the key and ends its sessions |

The test login: while signed in, the requester opens `GET /api/auth/login?connection=<id>&test=1`
(login transactions have a `test` purpose, schema `0315`; OIDC and SAML). The callback records the
test login on the requester's own session and returns to `/?test_login=ok`. It never creates a session,
a user, an external login or a role, and only the requester of that connection can run it, once.

Every submit and approve needs `STEP_UP_ADMIN` (phishing-resistant sign-in within 5 minutes). The payload
is decoded into a typed struct with unknown fields refused; the approver echoes its SHA-256 (`payload_hash`)
and a mismatch is 409. States: `pending_approval` → `cooling_off` → `applied`, or `rejected`, `cancelled`,
`expired` (72 h without approval) or `failed` (the applier raised; recorded with the reason). Applying before
`effective_at` is 409; the sweeper (the `sweep_admin_changes` queue job) applies due changes and expires old ones, using the
injected clock. A tenant with fewer than two admins can grant `tenant_admin` with one person and the 24 h;
a change that needs two people is refused (`bootstrap_restricted`) until it has two. A client secret
travels beside the payload, is sealed, and is cleared when the request ends; it never appears in the
payload, audit, a response or a list. `api_client.*` types arrive with the PRs that add their table.
Every transition writes an `admin.change.*` audit event and queues an `admin_notifications`
row for every active tenant admin and security contact, in the same transaction (delivery is the
notification outbox's job, issue #189; until then the rows and the banner are the notice).

**Break-glass** (IdP down, misconfigured or compromised, §9.6, §15.4; `internal/admin/breakglass.go`,
schema `0009_breakglass.sql`, UI **Admin → Break-glass** and `/t/<slug>/break-glass`). Needs `TESSERA_RP_ID`
(default `localhost`) and `TESSERA_PUBLIC_URL`; without them the ceremonies answer 503. go-webauthn v0.18.2
with direct attestation, cross-platform keys, no resident key, user verification required.
- **Enrol**: a `breakglass.register` request (above), then the requester calls
  `POST /api/admin/break-glass/registration/options` and `/verify` (`{change_request_id[, credential]}`,
  `STEP_UP_ADMIN`) within 24 h. Our own checks refuse a backup-eligible key (BE flag), a `none` or self
  attestation, a missing user verification and, when the tenant setting `breakglass_aaguid_allowlist`
  (set with `tenant.settings.update`; narrowing is immediate, widening needs two admins and 24 h) is not
  empty, an AAGUID that is not on it. Refusals are audited (`breakglass.registration.rejected`) and spend the challenge.
  The attestation chain is not yet checked against FIDO MDS3 (OQ11), so keys are recorded with trust `basic`.
- **Use**: `POST /api/auth/break-glass/options` and `/verify` (public, JSON, `{tenant[, credential]}`). The
  challenge is single use; a sign count that does not rise is refused and raises a critical notification.
  The session has kind `break_glass`, only the role `break_glass` (`admin.read` + `breakglass.recover`), 15 min
  idle and 60 min absolute. It writes `auth.break_glass.used` (tenant and platform chain) and a critical
  notification (`severity: critical`) to every admin, contact and `tessera-security-operations`.
- **Actions**: `POST /api/admin/break-glass/actions/{idp_connection.disable | idp_connection.update_trust | role.grant | sessions.revoke_all}`;
  the first three file the normal change request with no approver and a 1 h cooling-off any admin can cancel
  (`role.grant` only for `tenant_admin`); `sessions.revoke_all` ends every other session at once. Audited as `breakglass.action`.
- **After**: `GET /api/admin/break-glass` lists keys, open enrolments and uses (30 days); every use stays on
  the admin banner until an admin answers `POST …/uses/{use_id}/attest {reason}`.

**Operator recovery** (all admins and break-glass keys lost, §15.5): two *different* operators run
`tessera admin recover-tenant -tenant acme -operator <id> -co-operator <id> -ticket <ref> -connection <id>
-email <address> -operator-phr -co-operator-phr` (the two flags attest that each signed in to the hardened
operator host with a hardware key). The tenant moves to `status=recovery` (its admins can still sign in),
a bootstrap invitation is created that works only after **72 hours** (`not_before`) and only with a
phishing-resistant sign-in, and every admin and contact is told at once. Any existing admin cancels it
under Change requests (the invitation is spent and both operators are told); redeeming it completes the
recovery. It is audited in the tenant's chain and the platform chain.
`tessera admin revoke-signing-key -tenant acme -kid <kid> -reason "…"` revokes one of a tenant's signing
keys at once (a new one becomes active; audited as the operator).
### Review populations (auditor evidence, issue #110)

Auditors test the completeness and accuracy of a review population (IPE). When a campaign is
launched, `reviews.GenerateCampaign` freezes the **full population** in the same transaction:
every standing (non-JIT) grant edge of an active account with effective permissions, for every
identity including terminated ones, not only the risky grants that become review items.
`review_populations` (hash, row count, per-system counts, source sync timestamps, scope, rules
version, QA percent) and `review_population_rows` are immutable (triggers refuse UPDATE and DELETE),
and a `review.population_frozen` audit event carries the hash and counts. Campaigns launched before
this change have no population and answer 404 on the new routes.

Each row has: `ordinal` (1..n in ascending `edge_id`), `edge_id`, `identity_id`, `identity_ref`
(external id), `account_ref`, `system`, `entitlement` (label), `edge_src`, `edge_dst`,
`in_scope_reason` (`standing_grant`) and `disposition` (`review` or `auto_certified`).
`source_syncs` is the time of the tenant's last `connectors.sync` event (Tessera keeps no
per-system sync clock), or null.

**Hash (`tessera-review-population-v1`).** To recompute it from an export:

1. Take the rows in ascending `ordinal`.
2. Write each row as a JSON object with exactly the 11 fields above and canonicalize it with
   RFC 8785 (JCS). Strings are UTF-8, numbers are integers.
3. Join the canonical rows with a single `\n` (no trailing newline).
4. `hash = lowercase-hex SHA-256( "tessera-review-population-v1" || 0x00 || joined )`. An empty
   population hashes the domain string and the 0x00 byte.

`server/testdata/golden/review_population_v1.json` is a test vector; the audit ledger's contract is
`audit_v1.json`. The export recomputes the hash from the stored rows and reports `stored_hash`,
`recomputed_hash` and `hash_match` (a mismatch is flagged `false`).

**Auto-decisions.** A grant with no exception signal is auto-certified, and
`review_auto_decisions.decided_by_rule` records the rule (`exception_only.no_exception_signals`,
version 1) and the inputs that matched: the unused-days threshold, last-used time, days since used,
permissions and permissions used, privileged, policy violation, identity status and type.

**Sampled QA.** The tenant setting `qa_sample_pct` (default 5, 0 disables, set with
`PUT /api/reviews/settings`, `reviews.manage`) sends `ceil(pct% of n)` of the n auto-decisions
(at least 1 when n > 0 and pct > 0) to a human QA queue (the security lead). Selection is
reproducible: rank the auto-decisions by `SHA-256(population_hash ":" edge_id)` ascending (hex)
and take the first k. `POST /api/reviews/qa/{id}/decision` (`reviews.decide`, step-up) records
keep (confirm) or revoke (overturn: the grant is removed like a review revoke); both are audited
(`review.qa_confirmed`, `review.qa_overturned`). The campaign side panel's "Population & export"
shows the hash, counts, QA queue and the export buttons.

**Export.** `GET /api/reviews/campaigns/{id}/export?format=csv|json` (`reviews.export`: auditor,
operator and policy admin) returns the population (rows, hashes, counts, sync timestamps) and a
decision per grant: decision, decision source, reviewer, decided by, decided at, reason, exception
reasons, the rule (auto), `qa_sample`, QA decision and `revocation_verification`:
`not_applicable` (kept or open), `verified_removed` (revoked and the grant edge is gone from
Tessera's graph) or `pending` (revoked but still present). Provider-side verification is the
containment report (`GET /api/identities/{id}/containment`). CSV cells that start with
`= + - @` are prefixed with `'`. Each export is audited as `review.population_exported`.

### Account correlation

Connectors tie most accounts to a person. **Directory → Accounts → Account matches**
(`/directory/matches`) handles the rest (issue #160):

- **To review** lists user accounts with no person and no decision. A login that equals a
  person's email, or matches the part before the @, is shown as a *proposal*. Tessera never
  links on it by itself (self-asserted attributes, design K12).
- **Link**, **Not a person** and **Release** pin a reviewer's decision (`account_links`).
  Connector syncs keep it until someone releases it, which hands the account back to the
  connector's mapping.
- **Merge** (identity page, More actions → Merge into…) moves the merged identity's accounts,
  account decisions, owned identities, reports and agent delegations to the identity kept. The
  merged identity gets status `merged`; syncs keep it merged and resolve references to it to the
  survivor. History (usage, reviews, requests, HRIS events) is not moved. An identity bound to a
  Tessera sign-in user cannot be the merged side, because credentials never move.
- **Undo** (Merges tab) works for 180 days. It moves back every recorded row that still points
  at the survivor; rows changed since stay and are listed. Merges into an identity that was
  merged later are undone last-first.

Decisions need `identities.correlate`, merges `identities.merge` (both: policy admin), each
with a fresh phishing-resistant sign-in and a reason. Every decision is audited.

### Affiliations and identifiers

The guest-accounts design (K1, `docs/design/guest-accounts-and-claim.md`) keeps **one identity per
person with many affiliations**; issue #64 (GU-1) adds the data model and a read view. The identity
page (**Affiliations & identifiers** tab) and the identity side panel (**Affiliations** tab) show,
for a human:

- **Affiliations** (`affiliations`): each relationship (employee, contractor, guest visitor, ...)
  with its source, organization unit, population, start and end. The person's lifecycle state
  (`active`, `expiring`, `expired`, ...) is **derived** from them, not stored
  (`internal/identity/affiliations`). A person is active while any affiliation is.
- **Identifiers** (`identity_identifiers`): email, employee ID, federated subjects and so on, each
  with how it was verified. Lookups use `value_hmac`, an HMAC under a per-tenant key derived from the
  KEK, so two records with the same email collide without anyone storing a lookup table of values.
  The hash is never returned by the API.
- **Source records** (`identity_source_records`): what each system of record said about the person.
  No screen yet; matching and review arrive with GU-5.

**Add** and **End** (policy admin, `identities.affiliate`, fresh phishing-resistant sign-in, reason
required, audited) are for relationships an administrator may vouch for: guest visitor, contractor,
volunteer, partner, alum, retiree. Employee, student, applicant, admit and pre-hire come only from the HR or
student feed, so the API refuses them. Guest-like types need an end date, bounded by the population
(`guest_populations`: 365 days; a guest visitor 30). Ending a running affiliation sets `ended`; one
that had not started is `revoked`. An ended affiliation is history: the table refuses to change it.

The seed back-fills one source record, one HR affiliation and the HR identifiers (email, employee
ID) for every human, with no audit events and no change to any identity id. Identities that
connectors add later are not back-filled until the lifecycle feed (GU-4, GU-11) lands. The worker
type, sponsor and lifecycle state of a person belong to `identity_lifecycle` (issue #159), not here.
### Access requests

**Access → Request access** is the catalog (issue #164). It lists every group a policy admin has
made requestable, with its risk and durations, and the requestable business roles. A request
names one or more people and items and files one *line* per person and item, all or nothing.
The checks:

- The person is active and eligible: the item's identity types and departments.
- They don't already hold the access and have no open request for it.
- Privileged items, and items with a maximum duration, get a duration (the item's default
  unless one is chosen); a duration never exceeds the maximum.

Requesting for someone else needs `requests.create_for_others`.

A person with `requests.decide` approves (with a fresh phishing-resistant sign-in) or denies (with
a reason) each line under **Access → Requests → Approvals**. Nobody approves a line they
requested or that grants them access. Approval grants the access in Tessera at once, as a
grant edge (source `request`), until the duration ends or someone removes it. The
beneficiary can remove their own access; deciders can remove anyone's. The sweeper closes
expired lines, and lines whose grant was removed elsewhere (a review, a revoke). Each line
keeps its history (submitted, approved, denied, cancelled, expired, removed), and each change
is audited.

**Approval routing** (issue #165). Each catalog item has ordered approval stages. Each stage is
one of: the person's **manager**, the item's **owner**, or an **access approver** (anyone with
`requests.decide`). A line copies its item's stages when it is filed. The first stage waits;
each approval starts the next; the last one grants. Any stage's approver can deny.

Managers and owners decide their stage from the **Inbox** or **Requests → Approvals**, as can
anyone they delegated to (**Requests → Delegations**, up to 90 days). A stage escalates to the
access approvers after the item's escalation hours (default 48). It escalates at once when no
manager or owner signs in.

Nobody decides a line they requested or that is for them, or for whoever delegated to them. Nobody
decides two stages of the same line. The seed routes every demo item to the manager, then an access
approver. Pat signs in as Anders Zeller, Vic's (Hana's) manager, so Vic's requests reach Pat
first, then Olu or another access approver.

Policy admins edit an item under **Directory → Entitlements → (group) → Request catalog**
(`catalog.manage`). The seed puts every demo group in the catalog (privileged ones: 8 hours by
default, at most 72). It also links Olu and Vic to two demo employees, so they can request for
themselves. Not yet: provisioning into the target system (#103), manager and owner routing
(#165).

### Business roles

**Directory → Roles** (issue #161). A business role bundles entitlements (groups) from several
systems, with an owner, a description, a risk, and optionally a **birthright rule**: departments,
identity types and exact job titles. An active person matches when every list they fill in
contains their value.

- **Members** come from the rule, from an approved request, or are assigned by hand. Rule members
  follow the rule: every save and **Reconcile** add the people it now matches and remove those it
  no longer does. A rule member is removed by changing the rule, not by hand.
- **Grants.** Holding a role grants each entitlement as a grant edge (source `role`) from the
  person's account in that system (or their Okta account, as for requests). A grant made any other
  way (connector, request, JIT, manual) is never touched. A role grant is removed only when none
  of the person's roles still grants the group, so overlapping roles and direct grants are safe.
- **Every change is a plan first.** Create, edit, assign, remove, reconcile and retire show the
  plan (`?dry_run=1`): who gains or loses the role, the grants added, the role grants removed,
  the grants kept and why (another role, or granted outside roles), and people with no account
  that can receive a grant. Applying it writes the change, the grants and one audit event
  (`role.create|update|assign|unassign|reconcile|retire`) in one transaction.
- **Versions.** Each save, and retirement, appends a version (the role and its entitlements, who
  and why) under the role's *History* tab. Edits carry the version they started from, so a
  concurrent edit is refused (`version_conflict`).
- **Drift** lists members missing an entitlement (removed elsewhere, or no account in that
  system) and people who hold at least half of a role's entitlements without the role.
- **Requests.** A requestable role appears in the request catalog. A role request is one per
  person; a person with `requests.decide` approves it (with step-up) or denies it under
  **Access → Requests**. Approval assigns the role. Retiring a role removes every member and
  denies its pending requests.

Changing roles needs `roles.manage` (policy admins) and a fresh phishing-resistant sign-in.
Members, versions and drift need `graph.read`. The seed creates the demo company's six roles.
Rule members are seeded only where people already hold every entitlement, so seeding grants
nothing: reconcile a role to see the rest. Not yet: provisioning into the target system (#103)
and role mining (Phase 3).

### Attribute policies (ABAC)

**Protection → Attribute policies** (issue #162). A policy is a named, versioned condition in a
small JSON language (`internal/abac`): `all` / `any` / `not` over tests
`{"attr": "identity.department", "op": "eq", "value": "Finance"}`, with ops `eq`, `ne`, `in`,
`prefix`, `exists`, `gt`, `gte`, `lt`, `lte` (numbers or RFC 3339 times). Attributes are
`identity.*` (type, status, name, email, department, title, manager_id, has_manager, source,
tenure_days, worker_type), `resource.*` (name, risk, and for catalog items system and privileged) and `context.*`
(time, hour, weekday in UTC, and `aal` when a signed-in user acts). It is data, never code:
evaluation is a deterministic walk with limits on depth (8), size (100 parts) and lists (50).

- **Missing attributes deny.** Evaluation is three-valued: a test on an attribute the subject lacks
  is unknown, `not` of unknown is still unknown, and only a condition that is definitely true
  grants. So `not (department = Legal)` does not grant to someone with no department. `exists` is
  the one test that is never unknown.
- **Where it applies.** *Birthright rules*: a role's rule has an optional `policy` (an attribute
  policy id) that must hold on top of the department, type and title lists; the policy sees the
  person, the role (`resource.name`, `resource.risk`) and the time. *Request eligibility*:
  `PUT /api/catalog/items/{group_id}/policy {policy_id}` binds a policy to a catalog item, checked
  on top of its eligible types and departments (`409 not_eligible`), with the item as the resource
  and the requester's assurance level as `context.aal`. *SoD*: a policy file's
  `subjects.condition` (the same language, as YAML) limits which identities are checked; an
  identity that lacks a tested attribute stays in scope, because a detective control should
  over-check rather than skip. Current rules and eligibility lists work unchanged.
- **Versioning and audit.** Each save is the next version in `abac_policy_versions` (append-only,
  with who and why); create, update, retire and binding changes are audited in the same
  transaction (`abac.policy.*`, `abac.binding.*`). A role rule picks up a policy's new version at
  the role's next save or reconcile; a policy a rule or catalog item uses cannot be retired.
- **Simulate before saving.** `POST /api/abac/simulate {condition, policy_id?, resource?, context?}`
  evaluates a draft against every identity and returns who matches, who gains and who loses
  against the saved version (up to 200 each, with exact counts), and how many identities lack an
  attribute the draft tests. It writes nothing; the editor requires a simulation before saving.

Reading and simulating need `graph.read`; changing a policy needs `roles.manage` with a fresh
phishing-resistant sign-in, and binding a catalog item needs `catalog.manage` (same step-up).

`identity.worker_type` (issue #215) is the person's worker type from the lifecycle record (see
"Contractors, guests and end dates"): `employee`, `contractor`, `intern`, `partner`, `vendor` or
`guest`, so `{"attr": "identity.worker_type", "op": "in", "value": ["contractor", "vendor"]}` selects
non-employees. A person with no lifecycle record is an employee; services and AI agents have no
worker type, so a test on it is unknown for them and denies. An unrecognised value simply matches
no one. The attribute editor lists it (the list comes from the server). Attributes stored outside
the identity record are loaded by `abac.Resolver` (`internal/abac/resolver.go`), once per
transaction and tenant, and every evaluation site (roles, request eligibility, SoD subjects,
simulation) uses it, so a new one is added in one place and the attribute catalog.
Not yet: location and custom HRIS fields (the identity record does not store them, so a test on
one is always unknown and denies; they arrive with the HRIS attribute mapping).

### SoD functions, risks and rulesets

**Protection → Policies & SoD → Functions / Risks / Rulesets** (issue #298), the model behind
**Insights → SoD conflicts** (`internal/sod`, schema `0300_sod.sql`).

- **Function**: a named, reusable set of entitlements, with an owner. Each selector is a system
  (blank: any) plus a permission id or an action name pattern (`*` wildcard, `\` escapes), optionally
  narrowed by one resource attribute (`environment`, `tag`, `resource`, `privileged`): the
  fine-grained "auth object / field / value" case.
- **Risk**: name, description, priority (critical to low), business process, owner, and two or more
  conflicting functions. Optional `subjects` limit who is checked (identity types, statuses, an ABAC
  condition). A violation is one identity effectively holding at least one entitlement from each of
  two of the risk's functions, by any path (roles, groups, direct grants); the two must be distinct
  entitlements. A risk with more than two functions reports each conflicting pair.
- **Ruleset**: a named group of risks, enabled or disabled per tenant. Functions, risks and rulesets
  are versioned (`sod_versions`, append-only, with who and why); a ruleset's version holds its whole
  document, so its history is the history of everything in it. Every change is audited in the same
  transaction (`sod.function|risk|ruleset.*`). Export gives a YAML file (`schema: tessera.sod/v1`);
  `POST /api/sod/rulesets/import {yaml, prune, dry_run}` makes the ruleset match a file (by key,
  everything validated before anything is written; importing the same file changes nothing).
- **Legacy policy files.** `separation_of_duties` YAML policies are converted to a ruleset "Legacy SoD
  policies": each side of a conflict is a function, each policy a risk keyed by the policy id, so
  violation keys, messages and results are unchanged (tests compare them on the tiny world and the
  seeded larkspur tenant). `tessera seed` imports them; for any other tenant
  `POST /api/sod/import-legacy` does it once. Until a tenant has a stored ruleset its policy files
  are checked directly through the same engine.
- **Detection and simulate.** `GET /api/sod/violations` lists violations per identity, risk and
  function pair with the paths that grant each side; filters `risk`, `priority`, `ruleset`, `system`,
  `business_process`, `identity`. `POST /api/sod/simulate {beneficiary_ids, catalog_item_ids,
  duration_hours}` says which risks a request would trigger; Request access shows it as a warning
  before submit (advisory; roles in the cart are not simulated yet).

Reading is `graph.read`; changing needs `sod.manage` (policy admin) and a fresh phishing-resistant
sign-in; simulate needs `requests.create` (and `requests.create_for_others` for other people).

### Mitigating controls and remediation of SoD violations

**Protection → Mitigating controls** and the actions in the **SoD conflicts** side panel (issue #298).

- **Control library** (`sod_controls`): name, description, an owner (an identity), type (preventive,
  detective, corrective), frequency and the evidence the owner must show. Changes need `sod.manage`
  and are audited (`sod.control.*`); a control that covers a pending or active mitigation cannot be retired.
- **Mitigation** (`sod_mitigations`): one person's violation of one risk, covered by a control or
  accepted, with a justification, optional evidence references and a **mandatory end date** no
  further away than `TESSERA_SOD_MAX_MITIGATION_DAYS` (default 365). It is requested by one person
  (`sod.mitigate`) and approved or rejected by another (`sod.approve`, approval also needs a fresh
  phishing-resistant sign-in): the server refuses the requester (`403 four_eyes`). Only one request
  per person and risk is pending or active. Request, approval, rejection, withdrawal and early end
  are audited in the same transaction (`sod.mitigation.*`).
- **Status.** An active mitigation shows the violation as "Mitigated until <date>" (or "Accepted
  until"), a pending one as "Mitigation requested" (still open). Mitigated and accepted violations
  are left out of the open counts (`/api/violations`, `/api/policies`, summaries, `open` in
  `GET /api/sod/violations`) but always listed in the SoD report with their cover.
- **Remediation options.** A risk offers some of `revoke`, `mitigate`, `accept`, `escalate`
  (`remediation` on the risk and in its YAML; none stated: all four). The API refuses an option the
  risk does not offer (`409 option_not_offered`). Revoke goes through the existing revoke path
  (`POST /api/sod/violations/revoke`, dry run first, only for a grant behind the violation);
  escalate notifies the risk owner and is recorded (`sod_escalations`).
- **Expiry.** The sweeper warns the control owner and the person's manager
  `TESSERA_SOD_WARN_DAYS` (default 14) before the end date, once, through the notification outbox.
  When the end date passes the mitigation expires (`sod.mitigation.expire`), the violation is open
  again (it counts as open the moment the date passes, even before the sweeper runs) and the risk and
  control owners are told. A risk owner or an approver can end an active mitigation early
  (`POST /api/sod/mitigations/{id}/revoke`, with a reason and a fresh sign-in).
- **Reviews and evidence.** `GET /api/sod/review-context?campaign_id=` lists, for each review item,
  the SoD risks behind its grant with any mitigation; the review panel shows them and lets a reviewer
  request a mitigation or escalate. Every step is an audit event, so `GET /api/audit/export`
  carries violations' mitigations and their approvals.

### Contractors, guests and end dates

**Identity → Contractors & guests** (issue #159). Each person has a worker type: employee,
contractor, intern, partner, vendor or guest. Every type except employee has:
- a **sponsor**: an active employee accountable for them;
- an **end date**, at most a year away;
- optionally an organization and a start date.

A person without a lifecycle record is an employee with no end date. Policy admins set the
lifecycle by hand (`lifecycle.manage`, with step-up). Otherwise it comes from the HRIS: a joiner
event's `worker_type` and `end_date`, with the manager as sponsor unless
`sponsor_external_id` names someone else.

- **Warnings.** The background sweeper warns 14, 7 and 1 days before the end date. Each
  warning goes out once, as a history entry and an audit event (`lifecycle.warn`). The
  notifications outbox (#189) delivers them through `lifecycle.Notify`.
- **Extending.** The sponsor, or a lifecycle admin, moves the end date later, with a reason.
  Nobody extends their own term. An extension restarts the warnings.
- **The end.** On the end date the sweeper first **contains** the person (sessions, refresh tokens
  and OAuth grants revoked at connected providers, audited as `containment.run`). A failed step
  becomes a retry and never blocks the end; if the sweep's time budget runs out first, the person
  stays due for the next pass. Then it runs the person's **leaver plan**: accounts are
  disabled, grants removed, JIT cancelled and ownership reassigned, as the JML leaver plan lists
  them. It then terminates the identity, all in one transaction with `lifecycle.end`. The
  sweep runs in the background loop, never on a read. Admins can also run it at once.
- **Converting.** Changing the worker type is a conversion, for example contractor to employee,
  which can drop the end date. It is recorded as `lifecycle.convert`.

The Users list has a *Worker type* column and filter. The identity panel and page show the
worker type, sponsor and dates, with *Extend* and *Change*. The page has three views:
*Ending soon* (the next 14 days), *Everyone*, and *Sponsored by me*. The seed makes five demo
people contractors, an intern, a vendor and a partner, ending 3 to 120 days out.

A person with a live sponsorship (next section) has their lifecycle written by it: `PUT` and
`extend` answer `409 managed_by_sponsorship`, and renewing goes through the sponsorship.

Not yet:
- provisioning the leaver plan into target systems (#103);
- the guest claim flow (GU-6 #69 onward);
- rehiring someone whose term has ended.

### Guest sponsorships and invitations

**Access → Guests I sponsor** (issue #65, GU-2; design `docs/design/guest-accounts-and-claim.md`
§4.3, §8). A sponsor invites a visitor, contractor, volunteer or partner; the **sponsorship** records
the sponsor's decision (who, purpose, population, access bundle, term, who approved, and the
**policy version** that decided). Code: `internal/guests/sponsorship`.

- **Sponsorship drives the lifecycle.** While it is active (made without approval, or approved) it
  writes the guest's *affiliation* (`internal/identity/affiliations`, source `sponsorship`; type
  `guest_visitor`, `contractor`, `volunteer` or `partner`) and their *lifecycle*
  (`internal/lifecycle`, source `sponsorship`; worker type `guest` for visitors and volunteers,
  `contractor`, `partner`). With several live sponsorships the lifecycle takes the sponsor of the
  one that ends last and the latest end date: **a person stays active until their last sponsorship
  ends**. Ending the last one ends the person now through the lifecycle end path (the leaver plan).
  The affiliation stays `pending` until the guest completes their claim (GU-6).
- **An invitation is self-asserted intake (K3).** It always creates a **new** identity (type human,
  status `invited`, source `sponsorship`, external id `guest:<uuid>`), an unverified email
  identifier marked as asserted by the sponsor (its issuer is the one invitation, so it never
  collides with another person), a source record and an `intake_records` row (channel
  `sponsor_invite` or `bulk_invite`, match mode `self_asserted`). Tessera never links it to an existing
  person and never tells the sponsor whether the email matches one. The one exception: inviting
  yourself is `422 cannot_sponsor_self`. Linking and merging are GU-5.
- **Sponsor policy** (`internal/guests/sponsorship/default_policy.json`, evaluated in Go with the
  semantics of the design's Cedar fragment until Cedar lands). Its version is
  `<id>@<12 hex of the file's sha256>`; every decision stamps it on the sponsorship, its history and
  the audit event. Defaults: only active employees sponsor (guests, contractors, interns, partners,
  vendors and `invited` people cannot); at most 50 visitor, 25 contractor, 100 volunteer and 25
  partner sponsorships at a time per sponsor, and 50 invitations a day; a term at most
  `guest_populations.max_duration_days` (visitors 30 days); a contractor whose bundle holds a
  privileged or high-risk group needs a second approver (`sponsorships.approve`, never the sponsor,
  the guest or whoever made the request); such a bundle needs IAL 2 (`bundle_needs_ial2` if the
  sponsor asks for less, otherwise the required IAL is raised). Refusals are `422` with stable codes
  (`sponsor_not_eligible`, `sponsor_limit_reached`, `daily_invite_limit`, `exceeds_max_duration`,
  `invalid_dates`, `bundle_needs_ial2`, `bundle_item_not_requestable`, `cannot_sponsor_self`, ...).
- **Access bundle.** A list of requestable catalog items (the access catalog, #164), stored on the
  sponsorship. **Granting it is GU-12**: nothing is granted in this release.
- **Bulk invite.** CSV with the header `email,given_name,family_name,population,starts_at,ends_at,purpose`
  (an optional `bundle` column of group ids separated by `;`), at most 500 rows. `dry_run` returns
  per-row policy results and writes nothing (rows count against the limits as the real run would);
  the real run creates the rows the policy permits and reports each row. One bad row never blocks
  the others.
- **Renew** re-runs the policy, needs a fresh justification and a new end at most the population
  maximum from now. Where the policy asks for a second approver the sponsor cannot renew alone: a
  holder of `sponsorships.approve` who is not the sponsor renews it. **End** by the sponsor is
  `ended`; by an approver, or before it began, `revoked`. **Transfer** asks another eligible person to
  take over; the sponsor stays until they **accept** (policy checked again as them); if nobody accepts
  within 14 days the sponsorship ends. The sweeper (`sponsorship.sweeper`, before the lifecycle
  sweep) ends sponsorships at their end date and expired transfers.
- **Notifications** (outbox): approval needed (to holders of `sponsorships.approve`), approved or
  rejected (to the sponsor), transfer requested (to the target). Reminders before the end are the
  lifecycle warnings (#159).
- **Permissions.** `guests.sponsor` (every role but break-glass: the policy decides eligibility),
  `guests.read` (operator, auditor, policy admin, tenant admin: every guest; a sponsor always sees
  their own, and the person asked to take a sponsorship over sees it), `sponsorships.approve`
  (policy admin). Every change needs a fresh phishing-resistant sign-in. A sponsorship someone may
  not see answers `404`. Audit actions: `sponsorship.create|approve|reject|renew|end|transfer|accept_transfer|expire|transfer_expire|bulk_invite|bulk_preview`.

Not yet: granting the bundle (GU-12), sponsor-leaver transfer from JML events and the transfer task
in the Inbox (GU-11), self-registration (GU-3), and per-tenant sponsor policy editing. The invitation's
claim link, email, resend and revoke are in "Guest claim" below.

### Guest claim

Issue #69 (GU-6; design `docs/design/guest-accounts-and-claim.md` §6, §7.1, §9.2, §10). A guest turns
an invitation into a sign-in. Code: `internal/guests/claim` (links, sessions, codes, completion),
`internal/guests/credential` (the credential authority), `internal/api/claim*.go`, schema
`0228_claim.sql`, the page `frontend/src/public/claim/`. This branch merges #10's OIDC sign-in, whose
callback the claim reuses.

**Flow.** When a sponsorship becomes active (made without approval, or approved) Tessera issues a
claim link and emails it through the notification outbox (so it shows in Admin → Email delivery);
resend and revoke are `POST /api/guests/{identity_id}/resend-invitation|revoke-invitation` (the
sponsor or a holder of `sponsorships.approve`, fresh phishing-resistant sign-in) and buttons in the
Guests I sponsor side panel. The intake's `invitation_status` goes `ready` (nothing sent: the claim
needs `TESSERA_PUBLIC_URL` and the KEK) → `sent` → `claimed`, `revoked` or `expired` (a sweeper marks
the last; the panel also reads an old link as expired at once; "Guest is setting up" is a link in use).
The link is `<TESSERA_PUBLIC_URL>/claim#t=<43 characters>`. The page reads the token from the
**fragment**, removes it with `history.replaceState`, and starts the claim:

1. **start**: the token is exchanged once for a claim session (cookie `__Host-tessera_claim`; in the
   dev insecure-cookie mode `tessera_claim`, like the login cookie), 60 minutes idle and 24 hours at most.
2. **verify_contact**: a 6-digit code to the invited address (10 minutes, 5 tries, then void). It
   proves control of the address once, for the claim (A0, 800-63A contact verification); it is never an
   authenticator (`docs/knowledge/01`: email is not an acceptable out-of-band authenticator).
3. **existing_account**: "Do you already have an account with the organization?", asked of every
   claimant. "No" continues. "Yes" is recorded on the intake (`existing_account`, for the review
   queue) and the guest is told an administrator will follow up. **It never links** (K3): matching
   and linking are GU-5, whose seam is `claim.Service.OnExistingAccount`.
4. **credential**: the guest is sent to the bound credential authority to sign in. The claim
   completes only on a sign-in at the sponsorship's required AAL, as the account that was set up for
   this claim, through that authority (§7.1): then identity `invited` → `active`, the sponsorship's
   affiliation `pending` → `active`, the intake `claimed`, the sponsor told (`guest.claimed`), and a
   **new platform user with no roles**, linked to the identity, whose external login is the
   `(issuer, subject)` of that sign-in (never the email), exists. Tessera creates no session for it.
5. With no authority configured (production today) the claim stops at step 4 with "your organization
   will finish setting up your sign-in" and stays pending. An IAL above 0 (IDV, GU-7) stops at
   `verify_identity`. The step list is `claim.Steps`; terms (GU-10) go in as another step.

**Security properties.** The token is 256 bits from `crypto/rand`, stored only as
`SHA-256("tessera-claim-v1|"+tenant+"|"+token)`, single use (one atomic `UPDATE … WHERE
status='issued' AND expires_at>now`, checked by rows affected because the store's SQL lint forbids
`RETURNING`), 7 days for visitors and 14 for the others (never past the sponsorship's end), bound to
the intake and the invited address's tenant-keyed hash. A new invitation revokes the earlier tokens
and open sessions of the intake. The token is never in a log, an audit event, a notification row, the
delivery log (it never records bodies) or a URL path or query. It reaches the email without being
stored: the notification row only says "send the invitation", and `notify.Secrets` (memory) hands the
link line to the dispatcher at send time and forgets it when the message is final. A restart between
queueing and sending loses it: the message becomes a dead letter with a clear error and the sponsor
resends (the same goes for confirmation codes). Codes are stored as a keyed hash (HKDF from the KEK),
compared in constant time.
Unknown, malformed, expired, used and revoked tokens get an identical `200 {"next":"check_link"}` with
identical headers after a 300 ms floor (a dummy hash comparison keeps the path alike); `claim.start.refused`
records the real reason. `Referrer-Policy: no-referrer` and `Cache-Control: no-store` are on every
response. **Key binding (T20, implemented)**: the page makes a WebCrypto ECDSA P-256 key,
non-extractable, keeps it in IndexedDB and sends the public JWK with `start`. Every request carries
`X-Claim-Proof: <unix seconds>.<base64url r||s>`, a signature over
`"tessera-claim-proof-v2\n"+METHOD+"\n"+PATH+"\n"+seconds+"\n"+session nonce+"\n"+base64url(SHA-256(body))`;
the server verifies it with `crypto/ecdsa`, accepts ±60 s and lets each proof be used once, so a
stolen cookie is useless and a captured proof cannot carry another body (the path signed is the one
the API sees: a reverse proxy must not rewrite it). One use is keyed on the signature's `r`, so the
malleated form `(r, N−s)` of an accepted signature is a replay too, and it is recorded atomically in
the tenant's database (`claim_proof_uses`, schema `0229_claim_proofs.sql`), so it holds across
restarts and processes. Missing, bad, stale and
replayed proofs get the same `401 {"error":"session_required"}` as no cookie at all and are audited
as `claim.proof.rejected`. A session of one tenant is nothing at another.

**Public routes** (`/public/t/{slug}/claim/…`, registered `noTenant` and public; each resolves the
tenant from the slug, opens its own tenant transaction and writes its domain events in it; the
`http.request` event goes to the tenant's chain as an anonymous caller):
`POST start {token, key}` · `POST verify/send` · `POST verify/check {code}` · `GET status` (step, first
name, organization, sponsor, population, end date, nothing else) · `POST existing-account {answer}` ·
`POST credential` (answers `{redirect}`) · `POST resend {email}` ("If an invitation exists for this
address, we have sent a new link."). The design's `GET credential/callback` is the existing
`/api/auth/oidc/{connection_id}/callback` with the login purpose `claim`; it sends the browser back to
`/claim?result=complete|failed`. The Vite dev server proxies `/public/t`.

**Rate limits** (`internal/ratelimit`, in process, token buckets of N per window; throttles are
audited as `claim.throttled` without a token or code): start 10 per IP per 10 minutes (client IP as
the API's rate limiter, trusting `TESSERA_TRUSTED_PROXIES`) and 100 per tenant per minute (429; no
bot challenge yet); verify/send 3 per session per 10 minutes, 5 per address per hour, 10 per day
(the answer is the same when throttled); verify/check 5 tries per code; resend 3 per address per day.

**Audit actions:** `claim.invitation.issue|revoke|expire`, `claim.start`, `claim.start.refused`,
`claim.code.send|failed|locked`, `claim.verify_contact`, `claim.existing_account`,
`claim.credential.start|pending|failed`, `claim.complete`, `claim.throttled`, `claim.proof.rejected`.

**Dev completion path** (the only credential authority so far; GU-8 does the real ones): outside
production with the dev IdP configured, `credential.DevIdP` registers the guest with the dev IdP over
HTTP through `internal/safehttp` (loopback allowed in dev only) at the dev-only
`POST <issuer>/_register` (client authentication as `tessera-dev`; only `guest-…` subjects; users.yaml
users cannot be replaced) with a passkey, then the claim redirects to the normal OIDC sign-in with
`login_hint` and `prompt=login`; the callback binds `guest-<id>`, which is the only sign-in it accepts.
To try it: `./run.sh --reseed`; sign in at http://localhost:5173 as Pat (policy admin; his account is a
Larkspur employee) and invite a guest at Access → Guests I sponsor; the dev mail sink
(`server/var/dev-mail.jsonl`, written by the dispatcher within about 15 seconds) holds the email: open
its `/claim#t=…` link, ask for a code (also in the sink), answer the question, choose "Continue to
sign-in" and pick the passkey for the guest on the dev IdP page. Back on `/claim` the guest sees
"You are all set"; the panel shows the invitation as claimed. Checked by hand: the page is plain HTML
and CSS, no third-party scripts, works at 360 px; `npm test` covers its model and client, `go test
./internal/api -run TestClaim` the API end to end.

**Deferred:** matching and linking on "yes" (GU-5), identity verification and IAL above 0 (GU-7), real
credential authorities, passwords, MFA enrolment, the Tessera-hosted service (GU-8), terms and
consent, recovery (GU-10), SMS codes, claim codes for letters, a bot challenge, and shared (multi-node)
rate-limit state. Parity fixtures are unchanged. After pulling this change run `./run.sh --reseed`:
it adds the claim tables and three columns to `intake_records`, widens its `invitation_status` check
and allows the login purpose `claim`.
themselves. Not yet: provisioning into the target system (#103), business roles (#161).

### Notifications

Issue #189. Requests, approvals, reviews and expiring access now tell people. Each notification is a
row in the tenant's outbox (`schema/0223_notifications.sql`), written **in the same transaction** as
the event that causes it, so a rolled-back event leaves none behind. The row is the person's in-app
entry (the top-bar bell: unread count, mark as read) and, if they want it, an email.

| Kind | Who is told | When |
|---|---|---|
| `request.approval_needed` | the approvers of the waiting stage (assignee and their delegates; deciders for a decider stage or one past due) | a request is submitted, and each time the next stage starts |
| `request.approved`, `request.denied` | the requester and the beneficiary | the final decision |
| `request.expiring` | the requester and the beneficiary | approved access ends within 24 hours |
| `approval.escalated` | deciders and the stage's assignee | a stage passes its due time (not when it was due at once) |
| `approval.delegated` | the delegate | someone delegates their approvals |
| `review.launched`, `review.closed` | each reviewer of the campaign | campaign created, campaign complete |
| `review.reminder` | reviewers with open items | once a week from the campaign's seventh day |
| `jit.granted`, `jit.denied`, `jit.expiring` | the requester and the person | decision; access ends within the hour |
| `access.ending` | the person (and others you name) | `notify.Expiring`, below |
| `security.alert` | whoever the producer names | `notify.SecurityAlert`; **cannot be turned off** |

People who do not sign in (a reviewer or owner with no platform user) are reached by email at their
identity's address. Seeding and system jobs notify no one. The actor of a decision is never told of it.

**Preferences.** Each user picks a channel per kind (**Notifications** in the UI, `/api/notifications/preferences`):
`off`, `in_app`, `email`, `both` or `digest` (in the bell, plus one email a day). Defaults: `both` for
approvals needed, escalations, review launches and reminders and security alerts, `in_app` for the rest.
A user with no email address keeps an `email` choice in the bell.

**Delivery.** A background dispatcher (every 15 seconds, `notify.Dispatcher`) claims due email in a short
transaction (counting the attempt and leasing the row, so a crash retries after 5 minutes and a second
dispatcher cannot send it twice), sends outside any transaction, and records each outcome in a second one.
A failure is retried after a backoff of 30 s doubling to 1 h; after `TESSERA_NOTIFY_MAX_ATTEMPTS`
(default 6), or on a permanent failure (a 5xx reply, an invalid address), the notification is a **dead
letter**: it stays in the bell, its `delivery` is `dead` and its `last_error` says why. The
email carries the notification id as its `Message-ID`. The digest is built per recipient once a day, from
`TESSERA_NOTIFY_DIGEST_HOUR` UTC (default 8). **Every email send, retry, skip, dead letter and digest is an
audit event** (`notification.send`, `notification.digest`; the address is never in it), as are
mark-as-read and preference changes. The in-app entry itself is written with the audited event that causes it.

**Email.** `TESSERA_NOTIFY_EMAIL` is `off`, `dev` or `smtp`; the default is `smtp` when `TESSERA_SMTP_HOST` is
set, else `dev` outside production and `off` in production. The **dev sink** sends nothing: it logs and
appends each message to `server/var/dev-mail.jsonl`. SMTP uses the standard library through
`safehttp.NewDialer`, the same SSRF guard as every outbound call (private, loopback and metadata
addresses refused; loopback allowed only in dev): `TESSERA_SMTP_HOST`, `_PORT` (587), `_FROM`, `_TLS`
(`starttls` default, `tls`, `none` for dev), `_USERNAME` and `TESSERA_SMTP_PASSWORD_SEALED`. The password is
never read in clear: `echo -n 'password' | tessera notify seal-password` prints it sealed under the KEK.
Production refuses the dev sink, SMTP without TLS and a login without a sealed password. With email `off`
due email is recorded as `skipped`.

**Email delivery log.** Every email the dispatcher sends has a record (`schema/0224_email_messages.sql`),
so an operator can see what happened without the relay's dashboard (**Admin → Email delivery**, or
`GET /api/email/messages`). A record holds the message id, kind, recipient and subject (never the body),
the envelope (`MAIL FROM`, `RCPT TO`), a **status**, the relay's **queue id** parsed from the final 250
reply (`250 2.0.0 Ok: queued as ABC123`), and a list of attempts. Each attempt has start and finish
times, the server banner, the EHLO capabilities, the TLS result (version, cipher, server certificate
subject and issuer, or the error), and every command with the relay's reply, its code and its enhanced
status code. The SMTP client is a small one on `net/textproto` so it can record this; AUTH is recorded as
`AUTH PLAIN <redacted>`, the body as `<message body not recorded>`, and a transcript is capped (120 steps,
24 KiB, 300 characters a field).

| Status | Meaning | Retried |
|---|---|---|
| `queued`, `sending` | waiting for an attempt, or one is running | |
| `accepted` | the relay answered 250 at the end of DATA | final |
| `deferred` | a 4xx reply | yes, with backoff |
| `rejected` | a 5xx reply, or an address that can never work | no |
| `failed` | a network or TLS error, or a timeout | yes, with backoff |
| `bounced` | reserved for bounce and DSN processing, a later step; nothing sets it yet | |

**Accepted means accepted by the relay, not delivered to the inbox.** The UI says so. After the
attempts run out a deferred or failed message is a dead letter; `POST /api/email/messages/{id}/retry`
(audited as `email.message.retry`) queues one more attempt. Reading needs `email.read` (auditor and
tenant admin), retrying `email.manage` (tenant admin). The dev sink records its sends too, with a
one-step transcript. Not yet: bounce and DSN processing, per-tenant relay settings.

**For other producers.** Write a notification from the transaction of your event:

```go
notify.Emit(tx, now, notify.Message{Kind: notify.KindSecurityAlert, Key: "role.grant:"+id,
    Subject: "...", Body: "...", Link: "/admin"}, recipients...)   // idempotent per Key and recipient
notify.SecurityAlert(tx, now, key, subject, body, link, recipients...) // admin-change notices (#16)
notify.Expiring(tx, now, notify.Ending{Key: "identity:42", IdentityID: 42, Also: []int64{managerID},
    What: "Ada's contract", EndsAt: end})   // end dates (#159): once per Key and end date
```

`notify.Identity`, `notify.User` and `notify.Deciders` build recipients. Add a kind to `notify.Kinds`
(label, default, mandatory) and it appears in everyone's settings. Not yet: per-tenant SMTP and chat
(the settings are server-wide), templates, per-kind digests.
### Identity containment (kill switch)

A disabled account does not end its live sessions, refresh tokens or OAuth consents. Two plan
steps do (design: issue #106, package `server/internal/containment`):

- `revoke_sessions`: AWS IAM Identity Center (see "AWS IAM Identity Center revoker" below); Okta `DELETE /api/v1/users/{id}/sessions?oauthTokens=true`; Entra
  `POST /v1.0/users/{id}/revokeSignInSessions`; Google `POST .../users/{key}/signOut` plus a delete
  of each `tokens` entry.
- `revoke_grants`: Okta `DELETE /api/v1/users/{id}/grants`; Entra `oauth2PermissionGrants` of the
  principal; Google token deletes; GitHub `DELETE /orgs/{org}/credential-authorizations/{id}`.
  GitHub PATs and SSH keys that are not SSO-authorized have no API: they come back as manual tasks.

Each step re-reads the provider afterwards (Okta grants and refresh tokens, Entra
`signInSessionsValidFromDateTime` and grants, Google tokens, GitHub authorizations). A provider
refusal, an unknown user (404), a 429 that outlasts its 4 attempts, or a re-read that still finds a
session or grant **fails the step**. With no credential for the connection the step is a manual
task with instructions and is never reported as done. Run time is recorded in the audit event
`containment.run` (started, finished, `duration_ms`, outcome per provider and per step), also when
the run failed. Provider calls go through `internal/safehttp`.

- **Leaver plan.** `GET .../leaver-plan` and `POST /api/hris/events/{id}/execute` carry the two
  steps for each active account on Okta, Entra, Google (GitHub: grants only) that has a live
  connection (the demo Okta connection counts). Execute runs them first with no transaction open.
  **A failed containment step does not stop the leaver**: accounts are disabled and grants removed
  as always, each failed step becomes a retry task, and the response carries
  `containment: {status, failed, retry_id, retry_ids, ...report}` where `status` is `done`,
  `manual` (nothing failed, a person must act) or `retrying` (containment is incomplete, never
  "done"). The run is audited (`containment.run`, with timings) in its own transaction, apart from
  the leaver's `jml.leaver` event.
- **Retry tasks** (`containment_retries`, schema 0206). One open task per account and step, with
  identity, connection, step, attempts, `next_attempt_at`, last error and status `pending`,
  `succeeded` or `gave_up`. The sweeper (the 30 s `containment_retries` queue job, clock-aware like the rest)
  retries a due task, re-running the step and its verification, with backoff 1 m, 5 m, 15 m,
  1 h, then hourly, until about 24 h after the first failure; then it marks it `gave_up`. Each
  attempt is audited (`containment.retry_attempt`, plus `containment.retry_scheduled`,
  `containment.retry_succeeded`, `containment.retry_gave_up`). A `gave_up` task stays listed with
  a `manual_action` and is shown in red in the identity panel; there is no separate alert
  channel yet. `GET /api/identities/{id}/containment` (graph.read) lists an identity's tasks;
  `POST /api/containment-retries/{id}/retry-now` (`identities.contain`, step-up) runs a pending
  one now. UI: the identity panel's "Containment retrying (n)" badge and list, with Retry now.
- **Contain identity.** `POST /api/identities/{id}/contain` `{reason}` (10 to 500 characters) runs
  both steps for every account of the identity (an agent too: trigger `agent`) without disabling
  anything. `200` with the report, or `502 containment_failed` with the same report plus
  `status: "retrying"` and `retry_id` (the failed steps are queued as retry tasks). Needs
  `identities.contain` (policy admin) and a fresh phishing-resistant sign-in. UI: identity page
  More actions, and the identity side panel, "Contain".
- **Credentials.** `PUT /api/connections/{id}/containment-credential` `{token, base_url, org}`
  (connections.manage, step-up) seals the provider token with the KEK (`internal/seal`, AAD bound to
  tenant, table, column, connection and purpose) in `connection_credentials` (purpose
  `containment`; the same sealed store holds the LDAP bind secret as purpose `bind`); it
  is never returned or logged. On start, `serve` re-seals any rows left in the retired
  `connection_secrets` and `containment_credentials` tables into it and drops them, in one
  transaction, and refuses to start if a blob will not open under the KEK. Okta needs `base_url` (the org URL), GitHub `org`; Entra and Google default to
  `graph.microsoft.com` and `admin.googleapis.com`. Tokens: Okta API token (SSWS), Entra and Google
  bearer access tokens with the permission to revoke sessions (`User.RevokeSessions.All`,
  `DelegatedPermissionGrant.ReadWrite.All`; `admin.directory.user.security`), GitHub an owner's
  token with `admin:org` (SAML SSO organizations only).
- **Still manual or not covered.** Okta has no API that lists IdP sessions and Google none for
  sessions: those re-reads cover refresh tokens and say so in the step's notes. `rotate_secret`
  still only stamps a timestamp.

### MCP authorization server (agent authorization)

An OAuth 2.1 authorization server for MCP clients (MCP authorization spec 2025-11-25; issue #115;
packages `server/internal/mcpauth`, `api/mcp_oauth.go`, `api/mcp_admin.go`; schema `0356_mcp_authz.sql`).
Each tenant is its own issuer, `{TESSERA_PUBLIC_URL}/t/{slug}/mcp`: apart from the CLI and
machine-client authorization server (`internal/oauth`, issuer `/t/{slug}`), so their routes never collide
and neither accepts the other's tokens (both check `iss`; they share the tenant's signing key). Tokens are ES256 JWTs (`typ at+jwt`)
signed with the tenant's `access_token` key from `internal/keys`; there are no refresh tokens.

| Endpoint | What |
| --- | --- |
| `GET /t/{slug}/mcp/.well-known/oauth-authorization-server` | RFC 8414 metadata: PKCE `S256` only, `client_id_metadata_document_supported`, `authorization_response_iss_parameter_supported` |
| `GET /t/{slug}/mcp/.well-known/oauth-protected-resource/{id}` | RFC 9728 metadata of a registered resource server |
| `GET /t/{slug}/mcp/.well-known/jwks.json` | access-token public keys |
| `GET /t/{slug}/mcp/oauth/authorize` | needs the browser session; checks the request, stores it and sends the user to Agent authorization (`?consent=`) to approve (step-up) |
| `POST /t/{slug}/mcp/oauth/token` | `authorization_code` (PKCE S256, `resource` required, single-use code) and RFC 8693 token exchange |
| `POST /t/{slug}/mcp/oauth/introspect`, `POST /t/{slug}/mcp/oauth/decisions` | for resource servers (HTTP Basic: resource id and secret): is the token live and for me; may it call this tool |
| `POST /t/{slug}/mcp/oauth/revoke` | RFC 7009, by the token's holder |

- **Clients** are identified by a client ID metadata document URL (https, with a path). The document
  is fetched through `internal/safehttp` (no redirects, size cap 16 KiB, `application/json`, its
  `client_id` must equal the URL), validated and cached for one hour in `mcp_clients`. A client is
  `pending` and unusable until an administrator (`agents.manage`, step-up) binds it to an `ai_agent`
  identity (the agent's permissions are the ceiling) and activates it. A changed redirect list or key
  set sets an active client back to pending and revokes its tokens.
- **Scope** names a graph permission: `<system>:<action>:<resource>` (for example
  `snowflake:SELECT:snowflake/CUSTOMERS`). A token's scope is `user ∩ agent ∩ task` (and, on
  exchange, `∩` the subject token's scope), computed from the graph at issue time. An empty result
  is denied; a request is narrowed, never widened. The user must also hold an unexpired delegation
  to the agent (`agent_delegations`). A permission whose names hold spaces has no scope name and is
  never granted.
- **Token exchange** takes a Tessera user token as `subject_token` and, as `actor_token`, a JWT the
  client signed with a key in its own metadata document (`iss = sub = client_id`, `aud` the issuer,
  five minutes at most, `jti` used once). The result has `sub` = the user, `act` = the agent (nested
  after the subject token's actors, at most 3 deep, no repeats), `aud` = the one `resource`, `jti`,
  and a lifetime of 5 minutes at most. The acting agent may only re-issue a token for the same
  resource (another resource needs a different actor in the chain). The subject token's client,
  agent and user must still be active, and the client's cached metadata (its keys) is refreshed
  first when its one-hour cache has expired (`RefreshActorClient`; a failed refresh fails closed).
- **Resource servers** (`/api/mcp/resources`) must be registered; a token is only issued for one.
  Registration shows a secret once; only its SHA-256 is stored.
- **Decisions**: every issue, exchange, denial, revocation and tool-call decision is a row in
  `mcp_decisions` and an audit event (`mcp.token.issue`, `mcp.token.exchange`, `mcp.token.deny`,
  `mcp.token.revoke`, `mcp.tool_call.decision`, `mcp.authorize.*`, `mcp.client.*`, `mcp.resource.*`)
  written in the same transaction, with the policy version (a digest of the policy documents).
- **Kill switch**: `POST /api/identities/{id}/contain` first revokes every live token whose agent or
  user is that identity (`mcp.tokens.revoke_identity`), before any provider call. In the same
  transaction it marks the identity contained (`mcp_contained`, schema 0357), disables the clients
  bound to it and denies its pending and approved authorization requests, so no code redeems, no
  authorization starts and no exchange succeeds for it (as agent or as user) until an operator lifts
  the containment. Introspection also checks the token's row, the client, the agent and the user on
  every call. A client that is not active never gets an authorization redirect (400 page instead).
- **Rate limits**: every `/t/{slug}/mcp/oauth/*` path has a per-IP bucket (default burst 40, one per
  250 ms) before the audit middleware, on top of the anonymous limit.
- **UI**: Protection → Agent authorization (`/agents/authorization`): registered clients (bind and
  activate), active tokens per agent (revoke), the decision log and resource servers. In dev the
  Vite proxy forwards `/t/{slug}/mcp/oauth/*` and `/t/{slug}/mcp/.well-known/*` to the API.
- Deferred: `jwks_uri` client keys, `private_key_jwt` at the token endpoint for the browser grant,
  DPoP sender-constrained tokens, a sign-in redirect for an unauthenticated authorize request
  (the user signs in to the admin center first), re-checking the graph on every tool call, and
  root-path protected resource metadata.
### Shared Signals receiver (SSF, CAEP, RISC)

A revocation at one provider should reach the others. Tessera receives OpenID Shared Signals
Framework events from transmitters such as Okta and runs the kill switch on the subject's other
linked accounts (design: issue #114, package `server/internal/ssf`, schema `0353_ssf.sql`).

| Event (type URI) | Kill-switch steps on the identity's **other** linked accounts |
|---|---|
| CAEP `session-revoked` | `revoke_sessions` |
| CAEP `credential-change` | `revoke_sessions` and `revoke_grants` |
| RISC `account-disabled` | `revoke_sessions` and `revoke_grants` (the full contain) |
| SSF `verification` | recorded; it verifies the transmitter when it carries the state Tessera asked for |
| anything else | acknowledged, recorded as `ignored` and audited |

"Other" means every account with a live kill-switch connection except those on the transmitter's
own system (`subject_system`): the transmitter already acted there. Steps run through
`containment.BuildJob` with trigger `ssf`; a failed step becomes a `containment_retries` task like
any other (24 hours of retries). Each event row (`ssf_events`) records `received_at`, the subject,
the matched identity, the outcome, `latency_ms` (receipt to the last action done) and
`iat_latency_ms` (the SET's `iat` to the last action done).

**Setup.**
1. As a policy admin (`ssf.configure`, step-up) open Admin → Shared Signals → Add transmitter, or
   `POST /api/ssf/transmitters`: `name`, `issuer` (the SET's `iss`), `audience` (its `aud`),
   `delivery` (`push` or `poll`), `subject_system` (where subjects resolve: `okta`, `entra`, ...) or
   `connection_id`, and the signing keys as `jwks_url` or an inline `jwks` (public keys only).
   `discover: true` fills a blank JWKS URL and `verification_url` from
   `<issuer>/.well-known/ssf-configuration` (fetched through `internal/safehttp`; its `issuer` must
   equal the configured one).
2. **Push** (RFC 8935). A push stream gets a generated receiver secret, returned once as
   `receiver_secret` (stored sealed). Configure the transmitter to POST each SET to
   `https://<tessera>/public/t/<tenant-slug>/ssf/<transmitter-id>/events` with
   `Authorization: Bearer <secret>` and `Content-Type: application/secevent+jwt`. Answers: `202` when
   accepted, otherwise `400 {"err": ..., "description": ...}` with `invalid_request`, `invalid_key`,
   `authentication_failed` or `access_denied` (a paused or disabled stream). An unknown tenant, an
   unknown stream, a malformed id and a wrong or missing secret all get the same
   `authentication_failed` answer, so the endpoint reveals nothing about what exists. The secret is
   compared in constant time. The route is public but rate limited per client address with the
   anonymous bucket (`TESSERA_TRUSTED_PROXIES` applies), before anything is written. A key endpoint
   that cannot be reached is a `503`: deliver again later.
3. **Poll** (RFC 8936). Give `poll_url` and `secret` (the bearer token for that endpoint, sealed).
   The sweeper loop (30 s) sends `{"ack":[...],"returnImmediately":true,"maxEvents":25,"setErrs":{...}}`
   and follows `moreAvailable` up to 4 times per sweep. A jti is acknowledged in the **next** request
   and only after its event row is committed; a SET that fails validation is reported in `setErrs`;
   a SET that hit an error of ours is neither, so the transmitter delivers it again. Acks and errors
   wait in the transmitter row until a poll carrying them succeeds.
4. `POST /api/ssf/transmitters/{id}/verify` asks the transmitter's verification endpoint (with its
   `api_token`, or the poll token) for a verification event; the stream shows *Verified* when the
   state comes back.

**Validation** (`ssf.ParseSET`). The JWS must be in compact form and signed with RS256, ES256 or
PS256 against the transmitter's JWKS (the key named by `kid`; `alg` none, HMAC and every other
algorithm are refused before any key is tried). `iss` must equal the configured issuer, `aud` must
contain the configured audience, `iat` is required, at most 2 minutes ahead and at most 24 hours old,
`exp` is absent or in the future, `nbf` not in the future, `jti` is required, and `events` holds
exactly one event. A SET is at most 64 KiB. A `jti` is accepted once per transmitter
(`UNIQUE (tenant_id, transmitter_id, jti)`): a replay is acknowledged, audited as
`ssf.event_replayed` and not processed again; a delivery that was recorded but never finished is
resumed. Keys from `jwks_url` are cached for 10 minutes and re-fetched once (at most every 30 s)
when a SET names an unknown key. `FuzzParseSET` fuzzes the parser.

**Subjects.** `iss_sub` and `opaque` resolve against the account external id, `email` and `account`
(`acct:` URIs) against the account username or the identity's email (case-insensitive), `complex`
through its `user` (the session is kept in the event's subject label). The subject comes from the
event's `subject`, else the SET's `sub_id`, else the legacy `sub` claim. A subject that matches no
account of `subject_system`, matches an account no identity owns, or matches accounts of several
identities is recorded as **unmatched** (with the reason), audited as `ssf.event_unmatched` and
shown in the UI. It is never dropped and never acted on.

**Audit.** `ssf.event_received`, `ssf.event_actioned` (steps, failures, retries queued,
`latency_ms`, `iat_latency_ms`), `ssf.event_unmatched`, `ssf.event_ignored`, `ssf.event_replayed`,
`ssf.event_rejected` (the reason, never the token), `ssf.transmitter_created|updated|deleted`,
`ssf.verification_requested|received`, plus the `containment.*` events of the run. Audit details
carry no SET, secret or key.

**Routes and permissions.** `GET /api/ssf/transmitters`, `GET /api/ssf/transmitters/{id}` (with its
recent events), `GET /api/ssf/events[?transmitter_id=&limit=]`: `graph.read`. `POST /api/ssf/transmitters`,
`PUT|DELETE /api/ssf/transmitters/{id}`, `POST /api/ssf/transmitters/{id}/verify`: `ssf.configure`
(policy admin) with a fresh phishing-resistant sign-in. A `PUT` keeps a blank secret and blank keys;
`rotate_secret: true` issues a new push secret. Stream status is `enabled`, `paused` or
`disabled` (only `enabled` accepts or polls), with `last_event_at`, `last_error` and `last_polled_at`.
UI: Admin → Shared Signals (transmitters and events, with a side panel each).

#### AWS IAM Identity Center revoker

AWS has no API that ends a workforce user's sessions. `revoke_sessions` for an
`aws_identity_center` account follows AWS's documented procedure
([Revoke user access](https://docs.aws.amazon.com/singlesignon/latest/userguide/revoke-user-permissions.html),
[Prepare to revoke an active IAM role session](https://docs.aws.amazon.com/singlesignon/latest/userguide/prereqs-revoking-user-permissions.html))
as far as an API reaches. The account's external id is the identity store `UserId`.

1. `identitystore:DescribeUser` (a stale id fails the step).
2. The Deny policy must be attached (`organizations:ListTargetsForPolicy` returns at least one
   target) and its statement must be a dedicated deny-all (see the prerequisite below). A policy that
   is unattached, or whose `identitystore:userId` statement is narrower, fails the step: a user id in
   a statement that does not deny everything proves nothing, so the step is never reported verified.
3. The `UserId` goes into the Deny policy (`organizations:DescribePolicy`, then `UpdatePolicy`; a
   `ConcurrentModificationException` is retried from a fresh read). Edits are serialized per policy:
   a worker takes a lease on (tenant, policy id) in the database
   (`containment_policy_leases`, 60 s, released when done), merges the complete desired set (every
   user id Tessera holds for the policy, pending or active within the last 12 hours, from
   `containment_policy_denials`, plus what the policy has now), writes it, then re-reads the policy
   and checks every expected entry is there. A missing entry is added again; if it is still missing
   after 4 attempts the step fails. A worker that cannot get the lease within 25 s fails the step,
   which is queued for retry.
4. The user's permission set assignments are deleted
   (`sso-admin:ListAccountAssignmentsForPrincipal`, `DeleteAccountAssignment`, then
   `DescribeAccountAssignmentDeletionStatus` until `SUCCEEDED`), so no new role session can start.
5. Verify re-reads the attachment, the policy (the `UserId` is in the deny-all statement) and the
   assignments (none left).

**External writers.** The lease only orders Tessera's own workers; AWS offers no compare-and-set on
`UpdatePolicy`. If someone edits the Deny policy by hand or from another tool at the same moment, their
write can replace Tessera's. Tessera notices (the read-back), adds its entries again and fails the
step rather than report it verified if it cannot. Edit the policy through the console between
Tessera runs, and keep the single deny-all statement: another statement that names
`identitystore:userId` makes the policy ambiguous and is refused.

**Tessera's own sessions.** Containment also ends the identity's sessions inside Tessera, whether or
not the identity has an account on a kill-switch connection: every active session of every platform
user linked to it (`platform_users.identity_id`, or a sign-in through an IdP connection whose subject
is the external id of one of the identity's accounts), in a write transaction with a
`containment.local_sessions_revoked` audit event (users and sessions counted; written when the identity
has linked platform users, so an identity nobody signs in as adds no event). The SSF receiver,
`POST /api/identities/{id}/contain` and the leaver execution all do it, before any provider call. A
revoked session is refused with `401` on its next request. Tessera keeps no refresh tokens or OAuth
grants of its own, so the session is its only bearer credential.

Manual tasks in the report: delete the AWS access portal session in the console (no API), disable
the user at the external identity provider and remove group-based access at the source, and remove
the entry from the Deny policy after 12 hours. **Tessera never removes the Deny entry**: role
sessions last up to 12 hours, and a job that deletes entries from a policy the customer owns is a
risk for a 36-byte gain. An SCP holds 5,120 characters (about 100 user ids), so remove old ids from
time to time; a full policy fails the step with that message (nothing partial: no assignment is
deleted when the policy could not be updated).

**Prerequisite: create the Deny policy first.** In AWS Organizations create a service control policy
with this content (the condition key and placeholder are the ones AWS documents), attach it to the
accounts or organizational units whose Identity Center roles you want to be able to cut off, and
give Tessera its policy id (`p-...`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["*"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "identitystore:userId": ["Add user ID here"]
        }
      }
    }
  ]
}
```

Tessera accepts only this shape: one `Deny` statement, `Action` `"*"` (a string or `["*"]`),
`Resource` `"*"` (or none), no `NotAction`, `NotResource` or other element, and as its only condition
`StringEquals` on `identitystore:userId`. A narrower statement (some actions, one resource, a second
condition such as a source IP) would not end the user's role sessions, so a user id in it is not
proof, and the step fails with an error that says so. The policy must also be attached to a target.

The placeholder matches no user and stays in the list. Tessera adds user ids next to it. The AWS
credential is an IAM user (or role session) in the management account that may call
`organizations:DescribePolicy`, `organizations:ListTargetsForPolicy`, `organizations:UpdatePolicy` on that policy,
`identitystore:DescribeUser`, `sso:ListAccountAssignmentsForPrincipal`,
`sso:DeleteAccountAssignment` and `sso:DescribeAccountAssignmentDeletionStatus` (the sso-admin API; check the
DeleteAccountAssignment reference for anything else AWS requires of the caller, which Tessera cannot verify
in advance). Store it on the connection (system
`aws_identity_center`; connections.manage, step-up), sealed like the other provider credentials:

```
PUT /api/connections/{id}/containment-credential
{"aws": {"access_key_id": "AKIA...", "secret_access_key": "...", "session_token": "",
         "region": "us-east-1", "policy_id": "p-0a1b2c3d4e",
         "identity_store_id": "d-1234567890",
         "instance_arn": "arn:aws:sso:::instance/ssoins-7223a1b2c3d4e5f6"},
 "base_url": ""}
```

`region` is the Identity Center region (Organizations is called in `us-east-1`, the commercial
partition). `base_url` replaces every AWS endpoint (a VPC endpoint, or a test server). Requests are
SigV4 signed by `internal/containment/sigv4` (standard library only, tested against vectors of
AWS's published test suite in `testdata/suite.json`) and sent through `internal/safehttp`, so the
endpoints must be public https hosts. The fixtures in `internal/containment/testdata/aws.json`
record every call, including a throttle, a concurrent modification and a full policy.
### Flat-file import (disconnected applications)

An app with no connector is fed by CSV files (issue #105; schema `0352_flatfile.sql`, package
`internal/flatfile`). Its accounts and entitlements flow through the same ingest path as a
connector's (`ingest.Import`), so they correlate with the normal resolver (the person's id, then
email; a reviewer's pin is kept), and show in access reviews, SoD, leaver plans and the correlation
queue (orphans). An entitlement is a permission `ent:<code>` on one application resource, granted
to the account by a `direct_grant` edge. Agent delegations are left alone.

- `PUT /api/flatfile/apps/{system}/mapping` `{name, owner, accounts{account_id, username, email,
  identity_id, status}, entitlements{account_id, entitlement, name, privileged}}` saves the column
  mapping (`flatfile.manage`: tenant admin; step-up). `system` is the app's permanent name
  (`^[a-z0-9][a-z0-9_.-]{0,62}$`); one that a connection or another source already feeds is `409`.
  `GET /api/flatfile/apps` lists the mappings.
- `POST /api/flatfile/apps/{system}/uploads?kind=accounts|entitlements&filename=` takes the CSV as the
  request body (`Content-Type: text/csv`, the one non-JSON body the API accepts, declared per route)
  (`flatfile.upload`: operator, policy admin). `201` with `{upload, confirmed_tasks}` when applied;
  `422` with the same body when rejected. Upload accounts before entitlements: an entitlement row
  must name an account of the last accounts file.
- Limits: 512 KiB, 5 000 rows, 64 columns, 256 characters a cell; UTF-8 only (a byte order mark is
  dropped; NUL, other encodings and control characters in a cell are rejected). A file with **any**
  invalid row is rejected whole, with every bad row listed (row, column, code, message; the first 200
  are stored), and changes nothing but the history. A partial file must never make the delta call
  accounts removed. Row codes: `not_utf8`, `column_count`, `required`, `formula_prefix`,
  `invalid_email`, `invalid_status`, `duplicate_key`, `unknown_account`, and the file-level
  `file_too_large`, `too_many_rows`, `missing_column`, `bad_csv`, `no_header`, `duplicate_column`.
- Each upload is a full snapshot of its kind. The delta against the last applied file is *added*,
  *removed* (an account is disabled, not deleted; its imported grants go; a removed account takes its
  entitlements) and *changed* (which fields, never the values). `GET /api/flatfile/uploads[?system=]`
  and `GET /api/flatfile/uploads/{id}` (graph.read) give the history, with the per-row errors and the
  delta of each upload. The file itself is not kept: only its SHA-256, size and name.
- **Formula injection.** Identifiers (account id, person's id, entitlement, email) that start with
  `= + - @` (or tab or CR) are rejected; display values (username, entitlement name, file name) are
  stored with a leading `'`; every API view neutralises again, and the CSV export of the lists does too.
- **Manual tasks.** A leaver (the plan's `disable_account` step), a least-privilege revoke or a review
  `revoke` on an imported account or entitlement opens a task (`flatfile_tasks`, audited as
  `flatfile.task_created`): Tessera cannot do it in the app. A leaver gets one task per account, not one
  per entitlement. The task stays `open` until an upload shows it done: the account gone from (or
  disabled in) the accounts file, or the account/entitlement row gone from the entitlements file
  (`confirmed`, with the upload that confirmed it, audited as `flatfile.task_confirmed`). Until then the
  account stays disabled and revoked grants are not brought back by a file that still lists them.
  `POST /api/flatfile/tasks/{id}/close` `{reason}` (10 to 500 characters; `flatfile.close_tasks`: policy
  admin; step-up) closes one by hand (`closed`, `flatfile.task_closed`). `GET /api/flatfile/tasks[?status=]`
  lists them.
- Audit: `flatfile.mapping_saved`, `flatfile.upload` (outcome `failure` for a rejected file), and the
  task events above, each in the transaction of the change.
- **SFTP later.** `flatfile.Apply(tx, now, Input{Source: "sftp", Raw: bytes, ...})` is all an SFTP drop
  has to call; the upload row already has `source` (`api` or `sftp`). No SFTP server is built.
- UI: **Settings, Flat-file apps** (`/admin/flat-files`): the mapping editor (with column suggestions
  from a sample file's first line), Upload CSV, upload history with a side panel of per-row errors and
  the delta, and the manual task list with Close.

### Verified help-desk resets

**Identity → Help desk** (`/helpdesk`, issue #108) resets a password or MFA only after the person
is verified. A case (`helpdesk_cases`, schema 0254; also `helpdesk_verifications`,
`helpdesk_signals`, `helpdesk_findings`, all tenant-scoped with isolation tests) is opened for an
identity, collects verifications, and runs through the IdP once the policy
(`internal/helpdesk/policy.go`, a pure `Evaluate`) is satisfied. The policy is checked again inside
the transaction that claims the case (open or failed to executing, single-flight), so an
unverified case cannot execute: `409 verification_required` with the policy in the body, and the
IdP is never called.

- **Methods.** `push` (a push to an existing phishing-resistant authenticator; a push to a weaker
  one does not count), `callback` (to the number from the HR record; `number_source` must be
  `"hr"` and a note is required), `manager_approval` (only the identity's manager, by a platform
  user linked to the manager's identity, never the requester or the subject) and `idv` (privileged
  identities only).
- **Privileged identities** (an effective privileged permission in the access graph, or a platform
  admin role) need two different methods and a second approver who is not the requester or the
  subject. Nobody can open a case for their own identity.
- **Four eyes (#358).** A call-back is the operator's own word, so the requester cannot record it
  (`403 requester_cannot_verify`; one recorded by the requester or the subject never counts), and
  the requester cannot execute their own case (`403 requester_cannot_execute`): a second operator
  must. Nobody verifies, approves or executes a reset of their own identity
  (`403 self_reset_not_allowed`).
- **Routes.** `GET/POST /api/helpdesk/cases`, `GET .../{case_id}`, `POST .../{case_id}/verifications`
  `{method, evidence, number_source, session_ref}`, `.../manager-approval` and `.../second-approval`
  (`helpdesk.approve`, step-up), `.../execute` (`helpdesk.reset`, step-up), `.../cancel`,
  `GET /api/helpdesk/findings`. `helpdesk.reset` and `helpdesk.approve` go to operators and policy
  admins. Every step is audited in the same transaction (`helpdesk.case.started`,
  `.verification`, `.second_approval`, `.reset.started`, `.reset.executed`, `.reset.failed`,
  `.detection.fired`).
- **Execution** goes through the narrow `ResetExecutor` interface. Okta: `reset_factors` (MFA) or
  `reset_password` with `sendEmail=true`. Entra: delete every deletable authentication method and
  issue a single-use temporary access pass (a password reset issues the pass only). They use the
  connection's provider credential from `PUT /api/connections/{id}/containment-credential` (Okta
  needs `okta.users.manage`; Entra `UserAuthenticationMethod.ReadWrite.All`) and go through
  `internal/safehttp`. The Entra pass is returned once in the execute response
  (`Cache-Control: no-store`), never stored, audited or logged. A failed reset leaves the case
  `failed` and can be run again; a case stuck in `executing` after a crash needs a human.
- **Detection** `helpdesk.post_reset_takeover`: within 24 hours after a reset, a new MFA device
  and a sign-in from a location the identity had not signed in from before the reset. There is no
  alerts engine on `dev` yet, so it is a pure function (`helpdesk.Detect`) run whenever a signal
  is stored; a finding is raised once per case, audited and listed under Detections. Real
  signals will come from the IdP log connectors; until then `POST /api/helpdesk/signals`
  `{identity_id, kind: mfa_device_added|sign_in, location, device, occurred_at}`
  (`helpdesk.approve`) simulates the feed and is a 404 in production.
- **Simulated outside production.** The `simulated` executor (calls nothing), the push provider
  (always approves) and the IDV provider (accepts any session reference not starting with
  `fail`) exist when `TESSERA_ENV` is not `prod`. In production push and IDV answer
  `503 provider_unavailable` until real providers implement `PushProvider` and `IDVProvider`.

### Native groups (folders and groups)

Groups owned by Tessera (design `docs/design/groups-grouper-parity.md`, issue #44 GR-1; not the
connected-system `groups` table). Schema `0280_groups.sql` (`grp_*`: folders, name aliases, groups,
composite factors, lists, direct memberships, and the engine tables, which stay empty until GR-2).
Code: `server/internal/groups/naming` (`:` paths, `[A-Za-z0-9_.-]` segments of 1 to 255 characters,
case-insensitive uniqueness, aliases), `server/internal/groups/model` (create, rename, move, copy,
soft delete), `server/internal/api/groups_folders.go`. No UI yet (GR-8).

- Folders form a tree under one root per tenant (created on the first write). Folders and groups
  share one name space, unique per tenant ignoring case. Renaming or moving a folder renames its
  whole subtree; every old name is kept as an **alias**: it still resolves and stays reserved, and
  its owner can take it back. A folder is deleted only when empty; a group is soft-deleted
  (`status: deleted`, restorable, keeps its name). Copies carry fields and structure, not memberships.
- Routes (a route needs `groups.read` or `groups.write`, then the privilege of the folder or group,
  see "Group privileges (GR-4)" below; every route is audited):

  | Route | |
  |---|---|
  | `GET /api/groups/folders?parent=&scope=one\|sub&q=&limit=&offset=` | list |
  | `POST /api/groups/folders` `{parent, extension, display_extension, description, data_owner}` | create (`201`) |
  | `GET\|PATCH\|DELETE /api/groups/folders/{id}` | read, edit or rename (`extension`, optional `version`), delete |
  | `POST /api/groups/folders/{id}/move` `{parent}` and `.../copy` `{parent, extension}` | move, copy |
  | `GET /api/groups/native?folder=&scope=&q=&type=group\|role&deleted=` | list groups (`GET /api/groups` is still the connected-system list) |
  | `POST /api/groups` `{folder, extension, type, requestable, ...}` | create a basic group (`201`) |
  | `GET\|PATCH\|DELETE /api/groups/{id}` | read, edit or rename (`status` active or disabled), soft delete |
  | `POST /api/groups/{id}/move` `{folder}`, `.../copy` `{folder, extension}`, `.../restore` | move, copy, restore |

- Errors: `404 not_found`; `409` `{error, detail}` with `name_taken`, `name_reserved_by_alias`,
  `root_folder`, `move_into_self`, `copy_into_self`, `folder_not_empty` (with `folders` and `groups`
  counts), `folder_mirrored`, `group_deleted`, `not_deleted`, `version_conflict`; `422` with
  `invalid_name`, `invalid_type`, `invalid_status`, `invalid_scope`, and so on.
- Audit events `groups.folder.{created,updated,renamed,moved,copied,deleted}` and
  `groups.group.{created,updated,renamed,moved,copied,deleted,restored}`, written in the change's
  transaction with the acting user; `GET /api/audit?target_type=group&target_id=` filters by object.

#### Membership engine (GR-2, issue #45)

`server/internal/groups/engine` keeps `grp_effective` (the materialized members, with support counts)
equal to the stored inputs: direct memberships, nesting and composite-factor edges (`grp_deps`) and
composite definitions. `grp_closure` and `grp_levels` are maintained incrementally (schema
`0284_groups_engine.sql` adds `grp_engine_state`). Changes recompute the affected identities in
ascending level order from the stored rows, stopping where membership does not change. A disabled or
deleted group, or one outside its own `enabled_from`/`disabled_at`, is an empty set.

| Route (`groups.read`/`groups.write`, then the privilege; the two engine routes `groups.admin`) | |
|---|---|
| `GET /api/groups/{id}/members?filter=direct\|effective&limit=&offset=` | members (`read`); `stale` is true while a recompute is queued |
| `POST /api/groups/{id}/members` `{identity \| group, enabled_from, disabled_at, reason}` | add (`201`), update dates of an existing row (`200`), or `202` |
| `GET /api/groups/{id}/members/{identity}` | hasMember; ignores a row whose `disabled_at` passed even if the time wheel lags |
| `DELETE /api/groups/{id}/members/{identity-id \| group-id}` | remove (`200` or `202`) |
| `POST /api/groups/{id}/convert-to-composite` `{op, factors, discard_members}` | basic to composite in place; direct members are `409 has_direct_members` unless discarded |
| `PUT /api/groups/{id}/composite` `{op, factors}` | redefine a composite (`union`, `intersection` n-ary; `complement` = first minus second) |
| `POST /api/groups` with `definition: composite`, `composite_op`, `factors` | create a composite |
| `PATCH /api/groups/{id}` `enabled_from`, `disabled_at` (RFC 3339, `""` clears) | the group's own dates |
| `POST /api/groups/engine/verify`, `GET /api/groups/engine/ops/{seq}` | full recompute and repair; progress of a `202` operation |

- A composite has no direct members (`409 composite_no_members`). An edge whose parent is already a
  descendant of the child is `409 {"error":"cycle","path":[names, child down to parent]}`.
- `TESSERA_GROUPS_SYNC_BUDGET` (default 5000): the estimate is `|ancestors| x |identities affected|`.
  Under it the change is applied in the request; over it the direct change commits, a
  `grp_engine_queue` job is queued, the group is `recompute_state: pending` and the answer is `202`
  with `op`. The background `engine.Runner` (started by `cmd/tessera`) drains the queue in chunks of
  2,000 identities, runs the time wheel every 30 s (and at the next date boundary: a date takes
  effect within 60 s) and verifies each tenant nightly.
- Audit events `groups.member.{added,updated,removed}`, `groups.group.converted`,
  `groups.composite.updated` (in the request's transaction) and, from the background job,
  `groups.engine.{recomputed,verified,repaired}` and `groups.timewheel.applied`.
- Tests: `go test ./internal/groups/engine` (oracle comparison; `TESSERA_ORACLE_SEEDS=500` for a
  longer soak, `go test -fuzz=FuzzEngine_MatchesOracle` for the fuzzer);
  `go test -bench . ./internal/groups/engine` runs the 10%-of-reference-tenant benchmark
  (`TESSERA_GROUPS_BENCH_SCALE` percent, default 10).

#### Group events and point-in-time history (GR-3, issue #46)

Every change to a folder, group, direct membership or (from GR-4) privilege, and every effective
membership the engine adds or removes, writes a row to `grp_events` in the same transaction, with a
per-tenant gap-free `seq` (a counter row in `grp_event_heads`, bumped under the write lock, so a
rolled-back change gives its number back). Rows are append-only (a trigger refuses `UPDATE`).
Schema `0285_group_events.sql` (the design calls it `0103`): `grp_event_heads`, `grp_events`,
`grp_event_cursors`, `grp_pit_{objects,direct,effective,privileges,digests}`, all tenant-scoped with
cross-tenant guard triggers.

- `server/internal/groups/events`: the §10.1 catalogue, `Append`, consumer cursors (`Poll`, `Ack`,
  `Lag`) and CloudEvents 1.0 JSON encoding (`ToCloudEvent`: id `<tenant>/<seq>`, `sequence` extension).
  The groups code calls `pit.Emit`, which appends the event, applies it to the PIT tables and moves the
  `pit` cursor, all in the caller's transaction.
- `server/internal/groups/pit`: the writer closes and opens half-open intervals `[start_at, end_at)`
  (`start_seq`/`end_seq` are event seqs) for objects (a snapshot of names, folder, definition, status),
  direct rows (with their own dates), effective memberships and privileges. The tables are derived
  data: `Rebuild` replays `grp_events` (the whole tenant or one group), `CompareRebuild` rebuilds and
  compares. `MembersAt`, `MembersBetween`, `DirectAt`, `DirectBetween`, `ObjectAt` are the queries.
- Tamper evidence (K9): at 00:05 UTC `pit.Runner` writes, for each finished UTC day with events, a
  Merkle root (RFC 6962 tree; leaves are SHA-256 of `0x00` and the RFC 8785 form of the event row) and
  appends `groups.pit.digest {day, first_seq, last_seq, event_count, root}` to the audit ledger, whose
  checkpoints are anchored outside the database. `VerifyDay` recomputes the root and also checks the
  stored digest against the ledger's copy; an edited, deleted or added event of a digested day is a
  `mismatch`. A server that was down catches up on the days it missed.
- Retention: `TESSERA_GROUPS_RETENTION_DAYS` (default 2555, 7 years; 30 to 36500). Once a UTC day the
  runner deletes events older than that (never past the last digested event, as a prefix of the
  sequence) and PIT intervals that ended before it, and audits `groups.retention.pruned`. Digests are
  kept; a day whose events were pruned verifies as `pruned`; `Rebuild` refuses (`history_pruned`)
  rather than lose intervals whose events are gone. Weekly the runner rebuilds the PIT rows of a
  sample of 20 groups and compares them with what was stored; a difference is repaired and audited
  as `groups.pit.mismatch` (the schedule is in memory, so a restart postpones it by a week).

| Route (the two members reads need `read` on the group, the pit routes `groups.admin`) | |
|---|---|
| `GET /api/groups/{id}/members?as_of=T[&filter=effective\|direct]` | the members at an instant (RFC 3339, not in the future); effective by default; `group` is the group's snapshot then (name, status), null if it did not exist; deleted groups keep their history |
| `GET /api/groups/{id}/members?between=T1,T2` | everyone who was a member at any time in the window (at most 366 days); `items` are intervals |
| `GET /api/groups/pit/digests?limit=` | the daily digests, newest first |
| `GET /api/groups/pit/verify[?day=YYYY-MM-DD]` | recompute a day's root (default: the newest 100 digests); statuses `ok`, `mismatch`, `ledger_mismatch`, `no_digest`, `pruned` |
| `POST /api/groups/pit/rebuild` `{group_id?}` | rebuild the PIT rows from the events (audited as `groups.pit.rebuilt`) |

- Event causes: `api` for direct changes, `engine` for effective changes (repairs by verification carry
  `data.repair`), `timewheel` for the wheel's own runs; `cause_ref` is the request id when there is one.
- Tests: `go test ./internal/groups/pit ./internal/groups/events` (`TestPIT_AsOfMatchesReplay`,
  `TestPIT_DigestDetectsTamper`, `TestPIT_RebuildEqualsLive`, `TestEvents_GapFreeSeqUnderConcurrency`),
  `TestIsolation_GroupEventTables` in `internal/store`, `TestGroupsPITAPI` in `internal/api`.

#### Group privileges (GR-4, issue #47)

Design `docs/design/groups-grouper-parity.md` §7. Schema `0286_group_privs.sql` (the design calls it
`0102`; `0280`..`0284` are taken): `grp_privileges` and `grp_priv_settings`. Code:
`server/internal/groups/privs` (`implies.go` the implication table, `check.go` checks and dynamic
inheritance, `explain.go`, `grant.go`, `settings.go`), `server/internal/api/groups_privs.go`.

- **Privileges.** Grouper's names, lower-cased: group `admin update read view optin optout
  group_attr_read group_attr_update`; folder `stem_admin create stem_attr_read stem_attr_update
  stem_view`; attribute definition `attr_admin attr_update attr_read attr_view attr_optin attr_optout
  attr_def_attr_read attr_def_attr_update` (21 names: the design says 22 but lists 21, and the
  schema CHECK has 21). `admin`, `stem_admin` and `attr_admin` imply every privilege of their object;
  `update`, `read`, `optin`, `optout`, `create` imply the view privilege.
- **Holders.** An identity, a group (every effective member holds it; `IsMember` re-checks the
  direct rows' own dates), or `everyone`. A platform user holds its identity's privileges through
  `platform_users.identity_id` (the column came with the auth core); a user without a link, and a
  machine client, hold only what everyone holds and what their roles give.
- **Dynamic inheritance.** A row on folder `F` with `applies_to` `groups`, `folders` or `attr_defs`
  and `scope` `one` (objects whose parent is `F`) or `sub` (everything below) is applied when a
  privilege is checked, never copied. `stem_admin` on a folder, by a row on it or inherited, is every
  privilege on what is below it (the design's §7.2 example).
- **Platform roles still apply.** An active `tenant_admin` holds every privilege (Grouper's wheel),
  `auditor` the read ones (`read`, `view`, `*_attr_read`, `attr_read`, `attr_view`) everywhere, and
  `viewer` the view ones when the tenant sets `groups_viewer_can_view: true` in its settings.
- **Every group route is gated twice.** The route permission (`groups.read` for reads,
  `groups.write` for changes, by role and token scope) lets the request in; the handler then needs
  the privilege of the object. A refusal is `403 {"error":"privilege_required","privilege","object_type","object_id"}`.
  `groups.admin` (tenant admins) is for tenant-wide routes: engine verify and operations, the three
  `pit` routes, the privilege settings and identity links.

  | Operation | Privilege |
  |---|---|
  | list folders, list groups | only rows the caller may view (`stem_view`, `view`) |
  | read a folder, a group | `stem_view`, `view` |
  | create a folder or group | `create` on the parent folder (before the first folder exists, a tenant admin) |
  | edit, rename, delete a folder; edit, delete, restore a group | `stem_admin`; `admin` |
  | move | `stem_admin` or `admin` on the object, and `create` on the destination |
  | copy | `stem_admin` (folder) or `read` (group) on the source, and `create` on the destination |
  | read members, hasMember, point-in-time members | `read` |
  | add or remove a member | `update`, or `optin` / `optout` when the member is the caller; `read` on a nested group |
  | convert to composite, set a composite | `admin`, and `read` on each factor |
  | list, grant, revoke privileges | `stem_admin` / `admin` (a holder group also needs `view`) |

- **Creator and default privileges.** The creator's identity becomes `admin` of a new group and
  `stem_admin` of a new folder or copy (`source: creator_default`); a tenant admin with no identity
  link needs none. `PUT /api/groups/privileges/settings` `{everyone_allowed, defaults}` sets the
  **everyone policy** (which privileges may be granted to everyone; `admin`, `stem_admin` and
  `attr_admin` never) and the grants to everyone made on each new object. Granting to everyone
  (`holder_type: everyone`, or a default) needs an active `tenant_admin`.
- **Events and audit.** A grant or revoke writes `privilege.granted` / `privilege.revoked` (the PIT
  keeps when each privilege was held, in `grp_pit_privileges`) and `groups.privilege.{granted,revoked}`
  in the change's transaction; so do deleting a folder (its rows go with it), saving the settings
  (`groups.privilege.settings_changed`) and linking a user (`groups.user.identity_{linked,unlinked}`).

| Route | |
|---|---|
| `GET\|POST /api/groups/{id}/privileges`, `GET\|POST /api/groups/folders/{id}/privileges` | the rows on the object; grant `{privilege, holder_type: identity\|group\|everyone, identity, group, applies_to: self\|groups\|folders\|attr_defs, scope: self\|one\|sub}` (`201`, or `200` for a grant that exists) |
| `DELETE .../privileges/{privilege_id}` | revoke one row (the design has `DELETE .../privileges`; the row is in the path here) |
| `GET .../privileges/effective[?identity=]` | for each privilege of the object, every path by which the identity (default: the caller) holds it, with a sentence such as "Ivan holds UPDATE on `app:foo:g` because they are in `app:foo:admins`, which holds STEM_ADMIN on folder `app:foo` ..."; another identity's needs `admin` |
| `GET\|PUT /api/groups/privileges/settings` | the everyone policy and default privileges (`groups.admin`) |
| `PUT /api/groups/users/{id}/identity` `{identity_id \| null}` | link a platform user to an identity (`groups.admin`, fresh phishing-resistant sign-in; audited). #357: never your own user (`403 self_link_not_allowed`), only to an `active` identity (`409 identity_not_active`), and a user whose identity is terminated or disabled keeps the link so sign-in stays blocked (`409 identity_inactive`). Linking an unlinked user applies at once; changing or removing an existing link needs two admins: the first gets `202 pending_second_admin` (schema `0362`, 72 h), the same admin again `403 four_eyes_required`, and a second admin's identical change applies it and revokes the user's sessions and CLI refresh tokens |

- Tests: `go test ./internal/groups/privs` (`TestImplication` for all 21 privileges,
  `TestPrivs_InheritanceOneVsSub`, `TestPrivs_ExplainListsAllPaths`,
  `TestPrivs_EveryoneNeedsTenantAdmin`), `internal/api` (`TestGroupsRoutesRequirePrivilege` for every
  route, `TestPrivs_ViewFiltersBrowseAndSearch`, `TestPrivs_GrantsGiveAccess`, ...),
  `TestIsolation_GroupPrivilegeTables` in `internal/store`.

### Audit ledger

Every tenant has an append-only, hash-chained audit log (`audit_events`; design
`docs/design/phase-0-platform-security.md` §13). Each event's hash is SHA-256 over
`"tessera-audit-v1" 0x00` and the RFC 8785 (JCS) form of the event, and links to the previous
event; `server/testdata/golden/audit_v1.json` is a test vector for independent verifiers.
SQLite triggers refuse UPDATE and DELETE. Every API call writes one `http.request` event (the
route template, status, sorted query keys, never bodies or query values); a read whose event
cannot be written answers `503 {"error":"audit_unavailable"}` instead of the data, and so does a
POST that committed no domain event of its own (and `POST /api/simulate`, whose answer is data). Domain events
(JIT, reviews, revokes, JML, readiness attestations, skips and activation) commit in the same
transaction as their change. The actor is the signed-in user, with the session id and an
authentication summary (`authn`: AAL, phishing resistance, ACR, auth time); a request without a
session is recorded as `anonymous` with the reason, on the platform chain. The API ignores any
actor a client names (request bodies have no `actor`, `approver` or `reviewer` fields).

Every 5 minutes (or 1000 events) the server signs each chain head with the platform Ed25519 key and
appends it to the anchor sink: `TESSERA_AUDIT_ANCHOR`, by default `var/audit-anchors.jsonl` next to
the database. In production it is `s3://bucket/prefix` (see "S3 Object Lock anchor" below). To check
a database:

```bash
cd server
TESSERA_ENV=dev bin/tessera audit verify -all -db tessera.db -anchors file://$PWD/var/audit-anchors.jsonl
# exit 0 ok, 2 edited row, 3 missing or duplicated seq or a truncated tail, 4 bad checkpoint
# signature, 5 checkpoint missing from the anchors, 6 stale anchoring (with -strict)
TESSERA_ENV=dev bin/tessera audit checkpoint -tenant larkspur -db tessera.db   # checkpoint now
TESSERA_ENV=dev bin/tessera audit export -tenant larkspur -db tessera.db > larkspur.ndjson
```

`GET /api/audit/export` streams the same NDJSON (chunked, 500 events per read) outside the 30 s
handler timeout, under a 15-minute stream timeout; split longer exports with `from_seq`/`to_seq`.

Truncation (deleting the newest events) is caught when the chain ends before its head or before
the newest signed checkpoint, in the database or in the anchors. Pass `-anchors`: someone who can
write the database can also delete checkpoint rows and rewind the head, and then only the anchors
show the missing tail. Events after the newest anchored checkpoint (at most one checkpoint
interval, 5 minutes or 1000 events) are the window that cannot be proven complete.

`GET /api/audit` returns at most 1000 rows per call (`limit` is clamped; a negative `limit` is a
422); page back with `before_seq`.

The Admin → Audit log page lists the events, can include API requests, verifies the chain and
exports it.

#### S3 Object Lock anchor

`TESSERA_AUDIT_ANCHOR=s3://bucket/prefix` writes one object per checkpoint, `prefix/<tenant id>/<seq>.jws`
(the checkpoint JWS), with `ObjectLockMode=COMPLIANCE`, retention of 7 years, `If-None-Match: *` (an
existing object is never replaced) and a SHA-256 checksum. `anchor_ref` is
`s3://bucket/key?versionId=<id>`; a response without a version id is a failure, because it means the
bucket is not versioned with Object Lock enabled. The bucket must be created with Object Lock
(versioning is then on) and the server's role needs `s3:PutObject`, `s3:PutObjectRetention` and
`s3:GetObject`/`s3:GetObjectVersion` (the last two let a retried write recognise its own object).
A failed anchor is retried with backoff and flagged after 3 attempts, as with the file sink.

The AWS SDK for Go v2 client sends all of its HTTP traffic through `internal/safehttp` (the SSRF
guard): no proxy, no private, link-local or loopback addresses, which also blocks the EC2/ECS
credential endpoints, so give the process credentials through the SDK's other sources
(environment, web identity / IRSA) and set `AWS_REGION`. `AWS_CA_BUNDLE` is not supported with the
safehttp client; trust a private CA through the system roots. `tessera audit verify -anchors`
reads `file://` anchor files only; verifying against the bucket is a later step.

## Operational monitoring (issue #303)

`GET /livez` and `GET /readyz` (API listener, unauthenticated, constant-shape JSON, not audited) are the orchestrator probes. `GET /metrics` (Prometheus text) is served only on the separate internal listener `TESSERA_METRICS_ADDR` (dev default `127.0.0.1:9464`, `run.sh` uses `API_PORT+1000`; off in prod unless set to a loopback or private IP; `off` disables). `GET /api/admin/platform-health` (admin.read) backs Admin -> Platform health. `TESSERA_READY_MAX_LOOP_LAG_SECONDS` (default 300) is the loop-lag threshold of `/readyz`. Metrics, SLOs and alert rules: `docs/operations/slo.md`, `deploy/prometheus/tessera-rules.yml`.

```bash
curl -s http://127.0.0.1:9000/metrics | head      # with API_PORT=8000
curl -s http://127.0.0.1:8000/readyz
```

## Postgres

SQLite stays the default and is unchanged. Set `TESSERA_DB` (or `-db`) to a Postgres DSN to use Postgres
(design `docs/design/phase-0-platform-security.md` §14.3, §19 PR14):

```bash
export TESSERA_DB='postgres://tessera_owner:…@db.example.com:5432/tessera?sslmode=verify-full&app_role=tessera_app'
```

Two roles, created once by a DBA before the first start:

```sql
CREATE ROLE tessera_owner LOGIN PASSWORD '…' BYPASSRLS;   -- (or SUPERUSER) it owns the tables and runs the migrations
CREATE ROLE tessera_app NOLOGIN NOSUPERUSER NOBYPASSRLS;   -- never owns a table, never bypasses row-level security
GRANT tessera_app TO tessera_owner;                        -- lets the owner's connections SET ROLE tessera_app
CREATE DATABASE tessera OWNER tessera_owner;
```

* The DSN's role runs the goose migrations (`internal/store/schema/postgres/*.sql`, embedded, applied
  on every start under an advisory lock) and `rls.sql`. With `app_role` every connection that serves
  requests then runs `SET ROLE tessera_app`. `TESSERA_ENV=prod` refuses a DSN without `app_role` or
  without `sslmode=require|verify-ca|verify-full`. The owner should be a superuser or `BYPASSRLS`:
  the cross-tenant guards for graph node keys are `SECURITY DEFINER` functions that must see other
  tenants' rows. The role must exist before the migrations run (they grant it its privileges).
* **Row-level security.** Every tenant table has `ENABLE` and `FORCE ROW LEVEL SECURITY` and a
  `tenant_isolation` policy on `tenant_id = NULLIF(current_setting('app.tenant_id', true), '')`.
  `DB.InTenant`/`ReadTenant` run `set_config('app.tenant_id', …, true)` (transaction-local, so a pooled
  connection cannot carry a tenant into its next transaction); with no setting no row matches.
  `sessions` and `login_transactions` also have a SELECT-only `lookup_by_hash` policy for the two
  bearer-hash lookups (`app.lookup`). The repository's own `tenant_id = @tenant` predicates stay: RLS
  is the second layer.
* **`tessera admin gen-rls [-out path] [-check]`** renders `internal/store/schema/postgres/rls.sql` from
  the Postgres schema (no database needed). After changing a Postgres migration run
  `go run ./cmd/tessera admin gen-rls -out internal/store/schema/postgres/rls.sql`;
  `TestPostgresRLSFileCurrent` fails while the committed file is stale.
* **Foreign keys** between tenant tables are composite `(tenant_id, x_id) → (tenant_id, id)` against a
  `UNIQUE (tenant_id, id)` on the parent, so the database refuses a reference into another tenant. Graph
  node keys (`account:12`) and four "soft" references to rows that may be gone (`access_requests.edge_id`,
  `review_items.edge_id`, `hris_events.identity_id`, `readiness_item_states.check_run_id`) keep a trigger.
* **Audit tables** (`audit_events`, `audit_checkpoints`): `plpgsql` triggers refuse UPDATE, DELETE and
  TRUNCATE, and `0900_roles.sql` revokes UPDATE, DELETE and TRUNCATE from `tessera_app` (only a
  checkpoint's `anchor_*` columns stay updatable).
* **What differs from SQLite.** Statements are written once, in SQLite's dialect, and translated
  (`internal/store/dialect.go`: `@name` → `$n`, `INSERT OR IGNORE`, `instr`, a negative `LIMIT`).
  Timestamps stay sortable `TEXT`. A failing statement runs inside a savepoint, so a handled unique or
  reference violation does not abort the transaction (as in SQLite). Write transactions of one tenant
  queue on an advisory lock (SQLite serializes all writers); other tenants and all readers run in
  parallel. Integer ids come from sequences, which are not gapless (an upsert that finds its row still
  consumes a value). `schema/postgres` is kept in step with the SQLite DDL by
  `TestSchemaParity_SQLiteAndPostgres`.
* `tessera serve` seeds the demo tenants into an empty Postgres database in dev (never in prod; `-reseed`
  wipes and reseeds); production starts empty and is filled with `tessera admin create-tenant`.
  `TESSERA_DB=postgres://… ./run.sh` works the same way: it never reseeds a Postgres database unless
  you pass `--reseed`.

Run the Postgres tests against any throwaway server (not production: every test creates and drops its
own database, and the first run creates the `tessera_app` role):

```bash
export TESSERA_TEST_PG_URL='postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable'
cd server && go test ./...                      # the whole suite on Postgres, as tessera_app
TESSERA_REQUIRE_PG_TESTS=1 go test ./internal/store/   # fail instead of skipping when it is unset
```

Without `TESSERA_TEST_PG_URL` the suite runs on SQLite and the Postgres-only tests skip (the
dialect, schema-parity, DSN and `gen-rls` tests need no server and always run). With it,
`internal/store/storetest`, `testkit` and the API parity replay run on Postgres (the parity replay
accepts a different numeric `id`/`edge_id` there, see above). CI should run this with a Postgres 16
service container and `TESSERA_REQUIRE_PG_TESTS=1`.

### Backup and restore

**SQLite only for now.** On a Postgres store (`TESSERA_DB=postgres://…`) `tessera backup create` refuses with
`postgres_unsupported` and the scheduler logs that it is off; back up Postgres with `pg_dump` or your provider's
snapshots (see `docs/runbooks/disaster-recovery.md`). `tessera backup restore` always writes a SQLite file. The
backup holds every table in every schema file; the drill test `TestDrill_EverySchemaTableIsInTheBackup` checks
that against the embedded schema, so a table added later cannot be left out unnoticed.

`tessera backup create` (or `./run.sh backup`) takes an online `VACUUM INTO` snapshot while the
server keeps serving. It seals the snapshot under the KEK in authenticated 1 MiB chunks, so an edited,
reordered, truncated or extended file is refused, and writes `tessera-<UTC time>-<id>.tbak`.
With `TESSERA_BACKUP_DIR` set, `tessera serve` also writes one every
`TESSERA_BACKUP_EVERY_MINUTES` (default 360) and keeps the newest `TESSERA_BACKUP_KEEP` (default
28). `-upload <presigned PUT URL>` copies a backup to object storage through `internal/safehttp`.

`tessera backup verify -in F` and `tessera backup restore -in F [-db target] [-force]` (or
`./run.sh restore F`) decrypt to a temporary file. They then check every tenant's audit chain, the
checkpoint signatures, the anchors up to the backup's head, and the chain heads in the manifest.
A restore installs the database only when all of these pass, and keeps the previous database as
`<db>.pre-restore-<time>`. A refused backup exits 7 (`wrong_kek`, `tampered_backup`,
`verification_failed`, `target_exists`). The report also says how many anchored events are newer
than the backup, which is the data the restore loses. Backups and restores are recorded in the
platform audit chain (`platform.backup.created`, `platform.backup.restored`).

A restore also revokes the credentials the backup brings back: every active session (reason
`restore`), pending sign-in transactions, unconsumed bootstrap invitations and the `access_token`
signing keys, so users sign in again and the server mints fresh keys on start. The counts are in
the report and the audit event. `replay_cache` entries consumed after the snapshot cannot be
recovered; their SAML and DPoP windows are short.

The KEK and the anchor source are not in the backup: keep the KEK in escrow, or no backup can be
opened. RPO and RTO targets, the restore procedure, what to do after a restore (sign in again,
re-sync) and the drill are in `docs/runbooks/disaster-recovery.md`. CI runs the drill as
`TestBackupDRDrill`. HA on Postgres is a draft in `docs/design/ha-postgres.md`.

## AWS action catalog

The AWS effective-permission evaluator (design `docs/design/aws-effective-permission-evaluator.md`
§10) needs a versioned catalog of actions, resource types and condition keys. It is built offline,
never at request time. Run from `server/`:

```sh
go run ./cmd/tessera catalog refresh -dir catalog/aws            # fetch a snapshot of today's upstream data
go run ./cmd/tessera catalog compile -dir catalog/aws -report diff.md   # verify, merge overlays, write compiled/<version>.json.gz
```

`refresh` downloads the AWS Service Reference JSON (about 450 services), the RCP service list from
the Organizations guide and the iam-dataset file pinned in `catalog/aws/iam-dataset.lock` (commit
and SHA-256), all through `internal/safehttp`, into `catalog/aws/snapshots/<date>/`. Snapshots are
immutable and carry a `MANIFEST.json` of SHA-256 digests. `compile` refuses a snapshot that differs
from its manifest, merges the reviewed overlays in `catalog/aws/overlays/` (RCP services, KMS
cross-account operations, global keys, S3 ACL map, resource-policy rules, opt-in regions, S3 public
keys) and writes a deterministic artifact. It prints the catalog version, the PR title, and whether
anything changed against the previous artifact; `-report` writes the full diff as Markdown.
`internal/aws/catalog.Load(dir, version)` reads the artifact. See `catalog/aws/README.md` and
`catalog/aws/THIRD_PARTY_NOTICES`.

### AWS connector (read-only)

`internal/connectors/awsorg` collects one `model.Snapshot` of an AWS estate for the evaluator
(design §11.1): Organizations (tree, SCPs, RCPs), IAM (`GetAccountAuthorizationDetails`: users,
groups, roles, managed policies, boundaries, trust policies), and the resource policies of S3, S3
access points, KMS (and grants), SQS, SNS, Secrets Manager, Lambda, ECR and VPC endpoints, plus
Identity Center assignments. It uses **no AWS SDK**: each call is an HTTPS request signed by the
stdlib SigV4 signer (`internal/aws/sigv4`, tested against the published `get-vanilla` vector) and
sent through `internal/safehttp`. Throttling and 5xx are retried with exponential backoff and full
jitter (honouring `Retry-After`); every `List*` follows its token to the last page.

- **Credentials.** The connector holds an access key pair, sealed with `internal/seal` (AAD bound to
  tenant, table, column and connector id) and never returned by the API. It signs only
  `sts:AssumeRole` with it; everything else is read as the customer's role (default `TesseraReader`)
  in each account, with an `sts:ExternalId` the connector generates and shows (`external_id`) for
  the role's trust policy. `awsorg.ReaderPolicy()` is the role's permissions policy: only List and
  Read actions, verified against the action catalog (`CheckReadOnly`, tested).
- **Fail closed (design §3.3).** A stored policy that does not parse, a statement dropped as an
  ingest anomaly, and a read that fails (an account that refuses the role, a bucket policy that is
  denied, a list that fails) are never skipped: each is a *finding* with the scope of decisions it
  could affect. `Findings.Unsupported(Request)` returns the `POLICY_UNPARSEABLE` reasons for a
  request; the evaluator (PR-5) returns such a decision as `UNSUPPORTED`.
- **Persistence.** `schema/0319_aws_snapshots.sql` has the §6.2 tables (`aws_snapshots`,
  `aws_policy_documents`, `aws_policy_attachments`, `aws_org_nodes`, `aws_trust_edges`,
  `aws_effective_permissions`, `aws_explanations`) plus `aws_connectors`, `aws_snapshot_entities`
  and `aws_collection_findings`. The snapshot id is a content hash, per tenant; persisting an
  unchanged estate writes nothing. `awsorg.Persist` / `awsorg.Load` write and rebuild a snapshot.
- **API** (connections permissions; writes need step-up): `GET|POST /api/aws/connectors`,
  `DELETE /api/aws/connectors/{id}`, `GET /api/aws/snapshots`, `GET /api/aws/snapshots/{id}`.
  `POST /api/aws/connectors` takes `{name, config: {regions, account_ids, management_account_id,
  role_name, identity_center_region}, credentials: {access_key_id, secret_access_key}}`. Running a
  collection (`awsorg.Service.Collect`) is not a route yet: a run can outlast the request timeout.
- **Tests** use `internal/aws/awstest` (test-only): `Replay` serves recorded responses from
  `internal/connectors/awsorg/testdata/http/<service>/<operation>/<n>.<ext>`, verifies every
  signature and reports calls with no recording. It does not enforce IAM; these are collection
  tests only. Fixtures are synthetic (fake account ids).

### AWS evaluator in the MVP (`/api/aws/*`)

Issue #30 (design §11). Set `TESSERA_AWS_CATALOG_DIR` (the catalog directory above, with a compiled
artifact; `TESSERA_AWS_CATALOG_VERSION` picks a version, default the newest). Without it the
evaluator routes answer `503 aws_catalog_unavailable` and nothing else changes.

| Route | Permission | |
|---|---|---|
| `GET /api/aws/can?principal=&action=&resource=&profile=&snapshot=` | `graph.read` | one decision with its trace and `explanation_id` |
| `GET /api/aws/principals/{arn}/effective?service=&profile=&limit=&cursor=` | `graph.read` | what a principal can do, paged; a larger answer than 200,000 cells needs `service=` |
| `GET /api/aws/resources/{arn}/who-can?action=&profile=` | `graph.read` | principals that can, with decisions |
| `GET /api/aws/explanations/{id}` | `graph.read` | a trace by id (from the store, else the recent ones held in memory) |
| `POST /api/aws/simulate-policy-change` | `graph.read` | `{changes, base_snapshot?, profile?, head?, comment?: {pull_number}}`: who gains or loses what, plus the PR comment text |
| `GET\|PUT /api/aws/pr-comment` | `connections.read` / `connections.manage` + step-up | the comment settings |

`{arn}` may contain slashes. Profiles: `default` (current hour, TLS), `none`, `bare`, or a list of
`any-network,mfa-session,now,tls`. Results carry fidelity (`exact`, `approximate`, `unsupported`);
a policy the collector could not read makes the decisions it could affect `unsupported`
(`POLICY_UNPARSEABLE`) and is listed as `collection_gaps`.

`simulate-policy-change` ops (design §11.3): `put_policy_version attach detach put_inline
delete_inline put_boundary delete_boundary put_resource_policy put_trust_policy attach_scp
detach_scp put_scp attach_rcp detach_rcp put_rcp move_account create_grant retire_grant put_bpa
put_ownership_controls`. For `put_inline`/`delete_inline` `policy_arn` is the inline policy's name,
for `move_account` the new parent id, for `retire_grant` the grant id. `internal/aws/snapshot.Apply`
builds the head snapshot; `internal/aws/render` writes the comment.

**PR comment to GitHub** is off by default. `PUT /api/aws/pr-comment {enabled, repo: "owner/name",
token}` seals the token under the KEK (never returned, never logged, not in audit events). Only a
request with `comment.pull_number` posts, needs `connections.manage` and a fresh phishing-resistant
sign-in, goes through `internal/safehttp` to `api.github.com`, and is audited
(`aws.pr_comment.posted` / `.failed`).

`awsorg.Service.Materialize` (run by `Collect` when `Service.Eval` is set) evaluates a snapshot and
ingests what it confirms: accounts, role groups, permissions (action atom by resource atom) and
`grants` edges with source `evaluator`, carrying explanation, outcome and fidelity
(`schema/0321_aws_integration.sql`, a side table because there is no column migration), plus
`can_assume` trust edges and the NHI trust flags `wildcard_oidc_trust`, `missing_external_id`,
`public_trust`. Least privilege never recommends or applies a conditional, approximate or
unsupported grant (`leastpriv.VerifyAWS` checks a candidate keeps the used calls and adds nothing).
UI: Insights, AWS access.

## Web UI

The UI follows an "admin center" layout: a dark top bar, a light left rail grouped by job, list
pages with a command bar and filter chips, and details that slide in from the right so you never
lose your place in the list.

**Top bar** (48px, dark). The hamburger collapses the rail to icons (below 768px it opens the rail
as a drawer), then the Tessera mark, the global search box (`/` focuses it; `⌘K` opens the
palette), and on the right the Inbox with its count, the notification bell (unread count, the
latest notifications, mark all as read, and **All notifications and settings**), settings (theme: light, dark or match system), help (shortcuts) and the user menu with the
tenant name and the persona switcher.

**Left rail** (236px, light). Active items are white with a blue left indicator; counts sit on
the right. Arrow keys move between items.

| Group | Items |
|---|---|
| (top) | **Home**, **Inbox** (count) |
| **Identity** | Users, Machine identities & agents, Groups (with an *All entitlements* tab), Applications, Ownership, Accounts (with *Account matches*), Help desk, Roles, Organizations (live, read-only, derived from departments) |
| **Access** | Request access, My access (with *My requests*), Guests I sponsor (invite, bulk invite, renew, transfer, approvals), Just-in-time, Access reviews (with *Lifecycle* and *Workflows* tabs) |
| **Protection** | Alerts (alerts, rules, channels), Policies & SoD (violations, policies, what-if simulation, SoD functions, risks and rulesets), Attribute policies, Access graph, Insights (Risk overview, Least privilege, SoD conflicts, Deployment health) |
| **Settings** | Connections (governed connections and the setup wizard), Shared Signals (SSF transmitters and received events), Admin |
| **Protection** | Alerts (alerts, rules, channels), Policies & SoD (violations, policies, what-if simulation, SoD functions, risks and rulesets), Mitigating controls (mitigations, control library), Attribute policies, Access graph (with an *As of* date for *Who can access…*), Evidence packs, Insights (Risk overview, Least privilege, SoD conflicts, Deployment health) |
| **Settings** | Connections (governed connections and the setup wizard), Flat-file apps, Conditional access (network ranges, policies, device signals), Admin |

**Home.** For the admin & security persona: the tenant name and a sync line, then tabs
(Overview, Monitoring, Deployment health, Recommendations). Overview has the KPI cards
(identities, violations, unused permissions, deployment readiness), the top three deployment
"Needs attention" entries with Fix links, and a Recommendations card next to Basic information. The employee and manager personas keep their own Home
(what is waiting on you, your access, team approvals, review progress).

**List pages.** Every Identity list, Access reviews and Policies share one pattern: breadcrumb,
title with a muted count, a command bar (New, Bulk import, Refresh, Start review, and selection
commands such as Request access for or Disable, which enable once rows are checked), filter
chips with **+ Add filter**, saved views, CSV export and a table with checkbox selection.

**Side panel.** Clicking a row opens a 520px panel over the list; on wide screens the list makes
room so it stays visible, and the selected row stays highlighted. For a user or machine identity
the panel shows the avatar, name and risk pill, a command bar (Edit, Request access for, Reset
password or Rotate secret, Start review, Open in graph, Disable) and tabs: Overview, Access,
Groups, Activity. Groups, applications, accounts, roles, organizations, policy violations and
review items have their own panels. The panel is deep-linkable (`/directory/people?selected=16`,
`/governance/policies?selected=<key>`, `/governance/reviews?item=<id>`), traps focus, closes
with `Esc` and returns focus to the row. **Open full page** goes to the existing object page.

**Inbox.** One queue for JIT and catalog approvals, access-review items, joiner/mover/leaver
tasks and delegations, with keys: `j`/`k` move, `a` approve or keep, `d` deny, `r` revoke,
`x` select, `?` help.

Routes from the previous UI (`/identities`, `/graph`, `/nhi`, `/jit`, `/policies`, `/reviews`,
`/lifecycle`, `/least-privilege`, `/dashboard`) redirect to their new homes.

**Command palette.** Press `⌘K` (macOS) or `Ctrl+K` anywhere. It fuzzy-searches pages, people,
machine identities, roles, entitlements and apps, and runs actions such as *Request access*,
*Disable user…*, *Reset password…*, *Start access review*, *Approve pending requests*,
*Open graph for…*, *Create role* and *Bulk import users*. Search results open in the side panel. Actions ending in `…` ask for an identity
next. Choosing a person shows actions for them. Use the arrow keys, `Enter`, `Backspace` to go
back a step and `Esc` to close. `/` focuses the top-bar search.

**Live since the preview wiring.** These screens call the API (schema 0310 to 0312):

| Screen | Calls | Notes |
|---|---|---|
| Identity Disable / Enable (identity page, panel, bulk, palette) | `POST /api/identities/{id}/disable`, `.../enable`, `GET .../disables` | `identities.contain` and a fresh phishing-resistant sign-in. Disable runs the kill switch's containment (revoke sessions, tokens, OAuth grants at connected providers), then sets the active accounts and the identity to disabled in one audited transaction (`identity.disable`). A failed provider step is retried and reported. Tessera does not suspend the account inside the provider. Any Tessera user linked to the identity is signed out in the same transaction (sessions revoked with reason `identity_disabled`, counted in the event) and refused at sign-in, step-up and on every request while the identity is not active (disabled, terminated or merged: the check allows only `active`, #331). A leaver (any path that terminates the identity) revokes the linked users' sessions in the same transaction (reason `identity_terminated`); Enable cannot bring back a terminated identity, and its open disable record stays open. Disable is refused (403 `self_disable_not_allowed`, `identity.disable.refused`) for the identity linked to the caller's own user (#335). Enable (`identity.enable`) sets back only the accounts Disable disabled and that are still disabled. Enable is refused (403, `identity.enable.refused`) for a user linked to the identity (`self_enable_not_allowed`) and, when the identity is linked to a Tessera user, for the admin who disabled it (`four_eyes_required`: a second admin enables it). It cannot restore revoked sessions and grants, and says so. No Undo. |
| My access > Request removal | `POST /api/removal-requests`, `GET ?scope=mine\|approvals\|pending\|all`, `.../{id}/approve\|deny\|cancel` | Shows in My requests and the approver's Inbox (the person's manager, a delegate, or `requests.decide`). Approval needs step-up and removes the grant (through `requests.Remove` when an approved request granted it, else a revoked grant with a tombstone). Just-in-time and role-held grants are refused. |
| Request access drafts | `GET/POST /api/request-drafts`, `GET/PUT/DELETE .../{id}` | Private to the user, at most 50, checked for existence but never against policy. A draft never submits itself. |
| Directory > Organizations | `GET /api/orgs`, `GET /api/orgs/{org_id}` | Read-only and derived: a root and one organization per department. Owners are the active people at the top of a department's reporting lines who lead others in it. No cost centers (the HR data has none). |
| Home recent activity | `GET /api/activity` | The signed-in user's own audit events (action, target, outcome, time; no detail). "Your recent requests" reads real request lines. |

**Preview features.** Some screens have no backend endpoint yet: workflows, reset password, generic
object create / edit / import (accounts, machine identities, rotate secret) and most admin settings
(Identity rules, Branding & labels, Certificates, Export / import configuration). They run on typed mock data in `src/mocks/`, keep their state in the
browser's localStorage, and carry a **Preview** badge. To wire one up, add a function to
`src/api.ts` that returns the same type and remove the badge.

**Visual system and accessibility.** System fonts (Segoe UI first, then the platform UI font;
no web fonts are downloaded), one accent (`#0f6cbd`), 4px radii, 1px `#e1dfdd` borders, status
pills (critical, warning, ok, info, agent) and tabular numbers in tables. Light and dark themes
follow the OS by default, with a choice in the settings menu; dark keeps the same structure (a
darker rail and surfaces) with AA contrast. Focus rings are always visible, the rail, panel and
palette work from the keyboard, motion is reduced when the OS asks for it, and the layout works
down to about 360px wide.

**Phones and tablets (768px and below).** The rail becomes a menu behind the top-bar button.
Side panels and dialogs open as full-screen sheets with a sticky header, and the step-up
prompt is a bottom sheet. Buttons, chips, tabs, inputs, rail items and row checkboxes have
touch targets of at least 44 × 44 px, and inputs use 16px text so iOS does not zoom. When
sign-in is rate limited (429), a "Too many sign-in attempts" screen counts down the server's
`Retry-After` and then enables "Try again", instead of showing a generic error.

**Bundle.** Every route is lazy-loaded. The main chunk is about 87 kB gzipped and the stylesheet
about 8 kB; cytoscape (about 146 kB gzipped) only loads with the access graph.

## Signing in

Every API call needs a signed-in session (design `docs/design/phase-0-platform-security.md` §11, §12),
and Tessera never sees a password: users sign in through their company's identity provider (OIDC, SAML 2.0,
CAS 3.0, WS-Federation (legacy ADFS), or an OAuth 2.0-only provider such as GitHub).

1. `./run.sh` and open http://localhost:5173. The sign-in page asks for the organization (tenant):
   `larkspur` (the demo company) or `globex`.
2. **Continue** lists the tenant's sign-in connections (`GET /api/auth/discover`); **Sign in with Dev
   IdP (OIDC)** leaves for the dev IdP (below).
3. On the dev IdP's page pick a user, how they authenticate and which vendor to emulate (Okta is the
   default). You come back to the page you started from, signed in.
4. Roles follow from the method, as with a real IdP (design §12.2): admin roles (`tenant_admin`,
   `policy_admin`) are active only after a phishing-resistant method (**Passkey** or **Hardware security
   key**); other roles need MFA (**Password + OTP** or better); **Password only** activates no role.
   The user menu shows inactive roles and **Re-authenticate**, and **My sessions** (`/sessions`) lists
   and signs out your sessions.

A sign-in that fails comes back to `/login?error=login_failed&request_id=…`; the page shows the request
id, and the reason is in the audit log (`auth.login.failure`), never in the URL.

| User | Tenant | Role | What they can do |
|---|---|---|---|
| Alice (`00u-alice-admin`), Ivan | larkspur | tenant_admin | read everything, the audit log, connections and readiness; no data-plane writes (separation of duties) |
| Ivan (`00u-ivan-admin2`) | larkspur | also policy_admin | the second holder of `identities.contain`, so an identity Pat disabled can be enabled under four eyes (#335) |
| Pat (`00u-pat-policy`) | larkspur | policy_admin | read, JIT and review decisions, revoke grants, run HRIS plans, sync connectors |
| Olu (`00u-olu-operator`) | larkspur | operator | read, request and decide JIT, review decisions |
| Vic (`00u-vic-viewer`) | larkspur | viewer | read (with MFA; his only authenticator in the dev IdP is a password) |
| Gina (`00u-gina-globex`) | globex | tenant_admin | the second tenant |

Approvals, review decisions, HRIS execution, applying a revoke and editing a connection's config or
credential also need a phishing-resistant sign-in in the last 15 minutes (step-up, §10.2). Nobody can
approve a JIT request they made, or one that grants access to their own identity (403 `self_approval`).
When the sign-in is too old or too weak the API answers `401 step_up_required` with the RFC 9470
challenge (`WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values=…, max_age=…`)
and a `step_up_url`. The UI explains why and, on **Continue**, re-authenticates at the IdP
(`GET /api/auth/step-up?acr=&max_age=&return_to=`: `prompt=login`, `max_age=0`); back on the page it offers
to resume the action (kept in `sessionStorage` for ten minutes: the request only, never a token).
Tessera requires the same person (else `auth.step_up.subject_mismatch`), an `auth_time` after the step-up
started (the IdP really re-authenticated) and the required ACR (else `auth.step_up.insufficient`); on
success the session's authentication is replaced, its cookie and CSRF token rotate, and
`auth.step_up.success` records what was required and what was presented.

Unauthenticated traffic is rate-limited per client IP before it reaches the audit ledger: every
`/api/auth/*` request (burst 30, then one per 2 s) and every request without a valid session (burst
120, then one per 500 ms) answer `429 rate_limited` with `Retry-After` beyond that. Behind a load
balancer, list it in `TESSERA_TRUSTED_PROXIES` so the limit applies to the `X-Forwarded-For` client.

A tenant's `require_phr_for_all` setting (`tenants.settings`, §18.3) makes every role need a
phishing-resistant sign-in in that tenant. Other session routes: `GET /api/auth/session`,
`POST /api/auth/logout`, `GET /api/auth/sessions`, `DELETE /api/auth/sessions/{session_id}`.

### Sign-in through the IdP (OIDC)

`GET /api/auth/login?tenant=larkspur` starts a sign-in through the tenant's default OIDC connection
(design §9.1): Tessera creates a login transaction (10 minutes, bound to the `__Host-tessera_login`
cookie, state and cookie stored only as hashes, the PKCE verifier sealed), asks the IdP for phishing
resistance (`acr_values=phr` for Okta, the configured `claims` for Entra, the tenant's `login_acr`) and
`max_age=43200`, and redirects. The callback (`/api/auth/oidc/{connection_id}/callback`, the redirect
URI to register at the IdP) consumes the transaction once, redeems the code with PKCE through
`internal/safehttp`, validates the ID token (`internal/auth/oidcrp`: algorithm allow-list, no
`jku`/`x5u`/`jwk`/`x5c`/`crit`, `iss`, `aud`/`azp`, `exp`, `iat` window, `nonce`, `auth_time` and
`max_age`, and the RFC 9207 `iss` parameter), normalizes the authentication, finds the user by
(connection, subject), never by email, and sets the session cookie. A connection with
`jit_provisioning` creates unknown users with its `default_role`; `group_role_mapping` adds viewer,
operator or auditor from IdP groups and never an admin role. Every refusal is audited as
`auth.login.failure` with a reason and shows a generic page with the request id.

With `./run.sh`, the sign-in page (or http://localhost:5173/api/auth/login?tenant=larkspur) goes through the dev IdP (the
seed seals its client secret, `DEVIDP_CLIENT_SECRET`, default `tessera-dev-secret`, into the `dev_mock`
connections). The UI's sign-in page uses this flow.

### Sign-in through the IdP (SAML 2.0)

A SAML connection (design §9.2, SP-initiated only) starts at the same `/api/auth/login?tenant=&connection=`:
Tessera stores the AuthnRequest ID in the login transaction and redirects with a signed AuthnRequest
(HTTP-Redirect binding, RelayState = the transaction id; a step-up adds `ForceAuthn` and the requested
class refs). The IdP posts to the ACS, `/api/auth/saml/{connection_id}/acs` (body at most 256 KiB),
which `internal/auth/samlsp` checks before and after gosaml2: XML round-trip safety, exactly one
`Assertion`, a direct child with its own enveloped signature by a pinned certificate (never `KeyInfo`
or metadata), no encrypted assertion, no comment in `NameID`, issuer, `InResponseTo`, destination and
recipient, audience (the SP entity ID, which is the metadata URL), a ±60 s window and `AuthnInstant`.
Each assertion ID is accepted once (`replay_cache`, until `NotOnOrAfter`). The subject is the
persistent NameID or `subject_source: attribute:<name>`, never the email.

The IdP's POST is cross-site, so the `SameSite=Lax` login cookie does not come with it: the ACS answers
that first POST with a page (CSP nonce, `form-action 'self'`) that posts the same form again from
Tessera's origin, where the cookie is sent. The cookie never needs `SameSite=None`.

`./run.sh` seeds a second `dev_mock` connection, **Dev IdP (SAML)**, pinning the dev IdP's SAML
certificate (`tessera-devidp -print-saml-cert`, derived from its key) with a sealed SP key, so the sign-in
page offers both. Its SP metadata is at `/api/auth/saml/<id>/metadata`.

### Sign-in through an OAuth 2.0-only provider (GitHub)

Some providers speak only OAuth 2.0 and issue no ID token (issue #151). A `protocol: oauth2`
connection (`github`, or `generic_oauth2` with configured endpoints) uses the authorization code flow
with PKCE S256 and `state` through the same login transaction and cookie. The callback,
`/api/auth/oauth2/{connection_id}/callback`, redeems the code at the pinned token endpoint and asks the
user API who signed in (`internal/auth/oauth2rp`, through `internal/safehttp`). The user is keyed on
an immutable id (GitHub's numeric `id`, or `subject_field`), never a login name or email; email is the
primary verified address when `user:email` is granted, for display only.

Nothing signed proves the factor or when the user authenticated, so these sessions are **AAL1 and
never phishing resistant**: admin roles stay inactive, step-up answers `409 step_up_unavailable`,
bootstrap invitations cannot use the connection, and `assume_phishing_resistant` is refused (and
ignored). `auth_time` is the callback time. Admins sign in through OIDC or SAML.

`./run.sh` also seeds **Dev IdP (GitHub OAuth)**, which uses the dev IdP's GitHub emulation
(`/github/login/oauth/authorize`, `/github/login/oauth/access_token`, `/github/user`; faults
`github_token_error`, `github_token_type`, `github_user_error`, `github_no_id`, `github_string_id`).

### Sign-in through CAS 3.0

A `protocol: cas` connection (issue #152; most Apereo CAS servers also speak SAML and OIDC, which are
preferred) redirects to `{cas_server_url}/login?service=…` with the transaction's `state` inside the
service URL, `/api/auth/cas/{connection_id}/callback?state=`. CAS sends back only a ticket, so the
callback rebuilds that exact service URL and validates the ticket at `{cas_server_url}/p3/serviceValidate`
through `internal/safehttp` (`internal/auth/casclient`): service tickets (`ST-`) only, no proxy tickets or
proxy granting, a size cap, XML round-trip check, exactly one `cas:user`, and any markup inside the user
or an attribute (a comment splitting the name, a nested element) refused. Each ticket is also used once
here (`replay_cache`). The user is `cas:user` or `subject_source: attribute:<name>`, never the email.

`authenticationDate` must be released: it is `auth_time` (max_age at sign-in). Phishing resistance comes
only from a configured amr-style attribute (`authn_mapping.amr_attribute` + `phr_amr`, for example
`successfulAuthenticationHandlers: [[WebAuthnAuthenticationHandler]]`); otherwise sessions are AAL1.
Step-up sends `renew=true`, validates with `renew=true`, and needs an `authenticationDate` after the
step-up started and `isFromNewLogin` not false.

`./run.sh` seeds **Dev IdP (CAS)** against the dev IdP's `/cas` server (`/cas/login` with single
sign-on unless `renew`, `/cas/p3/serviceValidate`; faults `cas_failure`, `cas_no_user`,
`cas_two_users`, `cas_comment_user`, `cas_proxied`, `cas_stale_auth`, `cas_ticket_reuse`).

### Sign-in through WS-Federation (legacy ADFS)

A `protocol: wsfed` connection (issue #153; ADFS and Entra also speak SAML and OIDC, which are preferred)
redirects to the passive endpoint with `wa=wsignin1.0`, `wtrealm` (Tessera's realm,
`/api/auth/wsfed/{connection_id}`, the token audience), `wreply` (`…/callback`) and `wctx` (the login
transaction's state); a step-up adds `wfresh=0`, and `wauth` asks for the configured class ref. The IdP
posts `wresult`, a WS-Trust 2005/02 RequestSecurityTokenResponse, to the callback (cross-site, so it is
re-posted from Tessera's origin as for SAML). `samlsp.ValidateWSFed` applies the SAML ACS checks to the
SAML 2.0 assertion inside it (the document's only assertion, its own enveloped signature by a pinned
certificate, verified detached and only the verified element read, no comment in NameID, issuer,
audience = realm, Recipient when present, time window, AuthnInstant), plus AppliesTo = realm.
WS-Federation has no request ID: the transaction is bound by the cookie and `wctx`, and each assertion
ID is accepted once (`replay_cache`). SAML 1.1 tokens are refused. The user is the persistent NameID or
`subject_source: attribute:<claim type>` (for example objectGUID), never the UPN or email.

`./run.sh` seeds **Dev IdP (WS-Federation)** against the dev IdP's `/wsfed` endpoint, which wraps the
SAML assertion it signs (faults: the SAML assertion faults, XSW1–8 included, plus `wsfed_saml11`,
`wsfed_wrong_applies_to`, `wsfed_tampered`).

**A new tenant** is created by an operator (design §15.3); every step is audited as the OS user:

```bash
cd server
TESSERA_ENV=dev go run ./cmd/tessera admin create-tenant -slug acme -name "Acme Corp"
TESSERA_ENV=dev go run ./cmd/tessera admin add-idp -tenant acme -file okta.yaml -client-secret-file okta.secret
TESSERA_ENV=dev go run ./cmd/tessera admin invite-admin -tenant acme -connection <id> -email jane@acme.example
TESSERA_ENV=dev go run ./cmd/tessera admin add-client -tenant acme -name "ETL" -owner jane@acme.example -jwks-file etl.pub.jwks -scope tessera:read -roles viewer   # see Machine clients
```

`add-idp` reads a connection file (§18.2; unknown keys are refused, secrets are never in it). OIDC uses
`client_secret_basic` for now and prints the redirect URI. `protocol: saml` with `profile: generic_saml`
needs `idp_entity_id`, `idp_sso_url` and `idp_signing_certs` (pinned), takes `subject_source` and
`attribute_map` (`email`, `name`, `groups`), generates and seals an SP key, and prints the SP entity
ID/metadata and ACS URLs to register at the IdP. `protocol: oauth2` takes `profile: github` (GitHub's
endpoints and `id` by default) or `generic_oauth2` with `authorization_endpoint`, `token_endpoint`,
`userinfo_endpoint` and `subject_field` (never a name or email), needs `-client-secret-file`, and
prints the redirect URI. `protocol: cas` with `profile: generic_cas` needs `cas_server_url`, takes
`subject_source` (`cas_user` or `attribute:<name>`), `attribute_map` and `authn_mapping`, and prints the
service URL pattern to register at the CAS server. `protocol: wsfed` with `profile: adfs` needs
`idp_entity_id` (the token issuer), `wsfed_endpoint` and `idp_signing_certs`, takes `subject_source`,
`attribute_map`, `step_up_request` and `authn_mapping`, and prints the realm and reply URL for the
relying party trust. `invite-admin` prints a one-time
`/t/acme/bootstrap?code=tbi_…` URL valid for at most 24 hours (only its hash is stored): redeeming it
with a phishing-resistant sign-in through that connection, as that email, makes the user `tenant_admin`
(source `bootstrap`), once.

### Dev IdP

Tessera's sign-in through an identity provider is tested against a **dev IdP**: a small mock OpenID
Connect issuer in pure Go (`server/internal/devidp`, binary `server/cmd/tessera-devidp`). It replaces a
real Okta or Entra tenant; nothing it issues is a real identity. Design:
`docs/design/phase-0-platform-security.md` §8.2 and §18.5.

`./run.sh` starts it on http://127.0.0.1:8001 (`DEVIDP_PORT` to change, `DEVIDP=0` to skip) and
exports `TESSERA_DEV_IDP_URL` (seeding points the `dev_mock` connections at it). Besides Tessera's own
sign-in (above), you can drive the IdP directly with any OIDC client:

| | |
|---|---|
| Discovery | http://127.0.0.1:8001/.well-known/openid-configuration |
| Client | `client_id=tessera-dev`, `client_secret_basic` with `tessera-dev-secret` (override with `DEVIDP_CLIENT_SECRET`), or `private_key_jwt` with `-client-jwks file.json` (`aud` must be exactly the token endpoint) |
| Redirect URIs | `http://localhost:*/api/auth/oidc/*/callback` and the same on `127.0.0.1` (`-redirect-uris` to change) |
| Flow | authorization code with **PKCE S256 required**; `state` and `nonce` required; ID tokens are RS256 |

**Signing in.** `/authorize` shows a page where you pick a user, how they authenticate and which
vendor to emulate:

* Users come from `server/internal/devidp/users.yaml` (embedded; `-users file.yaml` to replace):
  Alice and Ivan (tenant admins; Ivan is also a policy admin), Pat (policy admin), Olu (operator), Vic (viewer) in `larkspur`,
  and Gina (admin) in `globex`. Each lists the authenticators they own.
* Authenticators: **Passkey** (phishing-resistant), **Hardware security key** (phishing-resistant,
  device-bound), **Password + OTP**, **Password only**.
* Emulation: **Okta** returns `acr=phr` only if `acr_values` asked for `phr` and a passkey was used
  (`phrh` needs the hardware key); every other `acr_values` entry is ignored silently, as Okta does,
  so the `acr` is `urn:okta:loa:2fa:any` or `urn:okta:loa:1fa:pwd`. Unlike real Okta, which enforces a
  supported value it cannot meet, the dev IdP then returns the weaker `acr`, so the "IdP returned a
  weaker context" path can be tested. **Entra** ignores `acr_values`,
  returns a requested Conditional Access context (`claims={"id_token":{"acrs":…}}`) in `acrs` for
  passkeys, says `amr:["fido","mfa"]`, and identifies users by `oid` + `tid` with a pairwise `sub`.
  **Generic** returns the first requested `acr` the method satisfies (`phrh`, `phr`, `mfa`, `pwd`).

**Step-up.** The IdP keeps its own session cookie, so a second sign-in is silent single sign-on and
keeps the original `auth_time`. `prompt=login`, `max_age=0` or an exceeded `max_age` show the page
again and set a new `auth_time`; `prompt=none` never shows it (`login_required` instead);
`login_hint` (sub, email or Entra `oid`) lists that user first and forces the page if the session
belongs to someone else; it does not stop another user signing in. `/logout` ends the session.

**Faults** (negative tests only). Start it with `DEVIDP_FAULTS=1`, then add `fault=<name>` to the
authorization request or `POST /_faults {"fault":"<name>"}` (empty clears). Each fault changes one
thing: `wrong_iss`, `wrong_aud`, `alg_none`, `hs256_with_pubkey`, `bad_signature`, `expired`,
`future_iat`, `nonce_mismatch`, `missing_auth_time`, `stale_auth_time`, `kid_unknown`, `jku_header`,
`sub_change_on_stepup`, `acr_unrequested`, `no_iss_param`. `jku_header` signs with a second key
served at the `jku` URL under the real `kid`, so an RP that follows `jku` accepts it and one that
ignores it rejects the signature. Two faults are expectations for normalization and step-up rather
than login refusals, and are refused where they would not be defects: `acr_unrequested` (only when
`phr`/`phrh`/`acrs` were not requested) and `sub_change_on_stepup` (only with `prompt=login` or
`max_age`).

**Tests** run it in-process: `devidptest.Start(t, devidp.Config{})` returns a loopback server
with a registered test client and faults enabled.

**SAML**: `/saml/metadata` (entity ID `<issuer>/saml/metadata`) and `/saml/sso` (HTTP-Redirect
AuthnRequests from an ACS matching `http://127.0.0.1:*/api/auth/saml/*/acs` or localhost; the request
signature is not checked, dev only). It answers with a signed assertion (exclusive c14n, RSA-SHA256)
whose class ref follows the method (`urn:devidp:ac:phrh`, `urn:devidp:ac:phr`, MobileTwoFactorContract,
PasswordProtectedTransport), and attributes `email`, `displayName`, `groups`. SAML faults
(`&fault=` on the SSO URL): `unsigned_assertion`, `signed_response_unsigned_assertion`, `xsw1`–`xsw8`,
`comment_in_nameid`, `wrong_audience`, `wrong_recipient`, `saml_expired`, `unsolicited`,
`wrong_in_response_to`, `replay`.

**Safety.** The binary refuses to start unless `TESSERA_ENV` is `dev` or `test`, listens on loopback
only, and keeps its signing key in `server/var/devidp/` (mode 0600, git-ignored), separate from
Tessera's keys. `devidp.New` refuses `TESSERA_ENV=prod`. `TestIsolation_DevIdPNotImportedByAPI`
(`internal/archtest`) proves from the import graph that `cmd/tessera` and `internal/api` never link
the dev IdP.

## Production connectors: Okta and Entra ID

`TESSERA_CONNECTORS=okta`, `entra` or `okta,entra` (also mixed with `demo-*` names) runs the real
read connectors instead of the demo ones. The default stays `demo`. Both are read-only (every
request is a GET, except the OAuth token request), send every call through `internal/safehttp`
(https only, private and link-local addresses refused, redirects and page links pinned to the
configured host), and never log or audit tokens, secrets, keys or response bodies. Errors carry the
HTTP status and the provider's short error code only.

Credentials are references, never literals: `env:NAME` (an environment variable) or
`file:/absolute/path` (a mounted secret file). A literal in the variable is refused. The sealed and
vault references of the connection credential store plug into the same resolver when that store lands.

| Variable | Meaning |
|---|---|
| `TESSERA_OKTA_ORG_URL` | `https://<org>.okta.com` (a custom domain also works): https, a well-formed domain, no path |
| `TESSERA_OKTA_CLIENT_ID`, `TESSERA_OKTA_PRIVATE_KEY`, `TESSERA_OKTA_KEY_ID` | OAuth 2.0 service app with `private_key_jwt` (preferred): client id, key reference (PEM, RSA 2048+ or P-256), the key's `kid` |
| `TESSERA_OKTA_API_TOKEN` | reference to an SSWS token, instead of OAuth (set one or the other, not both) |
| `TESSERA_OKTA_EMIT_IDENTITIES` | `true` (default): also create an identity per user. `false` when an HR system is authoritative |
| `TESSERA_OKTA_MAX_INCREMENTAL_AGE` | default `24h`: a full read repairs deletions at least this often |
| `TESSERA_ENTRA_TENANT_ID`, `TESSERA_ENTRA_CLIENT_ID` | directory (tenant) GUID and application (client) id |
| `TESSERA_ENTRA_CLIENT_SECRET` | reference to the client secret |
| `TESSERA_ENTRA_GRAPH_URL`, `TESSERA_ENTRA_AUTHORITY_URL` | default `https://graph.microsoft.com` and `https://login.microsoftonline.com`; set for national clouds |
| `TESSERA_ENTRA_EMIT_IDENTITIES`, `TESSERA_ENTRA_SIGNIN_ACTIVITY` | both default `true` (the second reads last sign-in) |
| `TESSERA_ENTRA_MAX_INCREMENTAL_AGE` | default none (delta queries report deletions) |

Minimum read-only permissions:

* **Okta.** OAuth scopes `okta.users.read`, `okta.groups.read`, `okta.apps.read`, `okta.roles.read`
  and `okta.logs.read` (usage events), and the service app needs the **Read-only Administrator**
  admin role. For SSWS, a token of a Read-only Administrator. Without `okta.roles.read` role data is
  skipped, without `okta.logs.read` no usage events are produced; neither fails the sync.
* **Entra ID** (application permissions, admin consent): `User.Read.All`, `Group.Read.All`,
  `GroupMember.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory`, and optionally
  `AuditLog.Read.All` (last sign-in and usage events; needs Entra ID P1/P2). If Graph refuses
  `signInActivity` (403) the sync goes on without last sign-in. Entra needs no write permission.

What is mapped: users become accounts (Okta `lastLogin`, Entra `signInActivity`) and, unless turned
off, identities keyed by `employeeNumber`/`employeeId` (else `okta:<id>`/`entra:<id>`) with the
e-mail address for correlation; groups and memberships (Entra nested groups become group-in-group
`member_of` edges; Okta has no nested groups); apps (Okta apps, Entra enterprise apps and apps the
tenant owns) as resources with an `access` permission and one per Entra app role, user and group
assignments as `direct_grant` and `grants` edges; administrator roles (Okta roles on users and
groups, Entra directory roles) as privileged `role` groups; Entra service principals the tenant owns
as `service` accounts. Usage events are app sign-ins aggregated per user, app and day (Okta System
Log, Entra sign-in log). Okta group role assignments are re-read with the group, so a role granted
to an unchanged group appears at the next full read (within `MaxIncrementalAge`).

Sync modes. Checkpoints live in `connector_checkpoints` (tenant-scoped, same transaction as the
ingest, so a failed ingest rolls the checkpoint back). The first sync, a missing or unreadable
checkpoint, `POST /api/connectors/sync?mode=full`, and a chain older than `MaxIncrementalAge` read
everything. Otherwise Okta reads users and groups changed since the watermark (`search=lastUpdated
gt ...`) and Entra follows the stored `deltaLink`s of `users/delta` and `groups/delta` (an expired
token, HTTP 410 or `syncStateNotFound`, falls back to a full read). Apps, assignments and roles are
re-read on every sync. Rate limits: 429 and 502/503/504 are retried with `Retry-After`
(or Okta's `X-Rate-Limit-Reset`), bounded to 60 seconds a wait and 5 tries, and the client pauses
when `X-Rate-Limit-Remaining` hits 0. Ingest does not delete accounts and groups that vanish from a
source; it prunes only connector edges.

Tests run on synthetic recorded fixtures (`okta/testdata`, `entra/testdata`) through an `httptest`
TLS server. Live tests are skipped unless set (needs-human, never run in CI): `go test
./internal/connectors/okta -run Integration -v` with `TESSERA_OKTA_DEV_ORG_URL` and
`TESSERA_OKTA_DEV_API_TOKEN` (or `TESSERA_OKTA_DEV_CLIENT_ID` + `TESSERA_OKTA_DEV_PRIVATE_KEY_FILE`
[+ `TESSERA_OKTA_DEV_KEY_ID`]); `go test ./internal/connectors/entra -run Integration -v` with
`TESSERA_ENTRA_DEV_TENANT_ID`, `TESSERA_ENTRA_DEV_CLIENT_ID`, `TESSERA_ENTRA_DEV_CLIENT_SECRET`.
`internal/connectors/connsync` is what Google Workspace and Workday reuse.
## Command-line sign-in (`tessera-cli`)

The CLI and other non-browser clients use OAuth 2.0, not cookies (design §9.3, §10): Tessera is an
authorization server for each tenant (issuer `TESSERA_PUBLIC_URL/t/{slug}`), with the **device
authorization grant** (RFC 8628) and **refresh tokens**. Every token is sender-constrained with **DPoP**
(RFC 9449): the CLI generates an ES256 key, and an access token (an RFC 9068 `at+jwt`, ES256, signed with
the tenant's own key, 10 minutes, 5 minutes with `tessera:admin`) carries `cnf.jkt`, so a stolen token is
useless without the key. Roles are not in the token: the API reads them on every request, and what a
token may do is the intersection of the user's active roles and its scopes.

**Dev flow.** `./run.sh` serves everything on the UI port (the dev server proxies `/api`, `/t/*/oauth/*`
and `/.well-known/*`), and `TESSERA_PUBLIC_URL` defaults to `http://localhost:$UI_PORT`: that is the
CLI's server URL, because DPoP proofs are bound to it.

```bash
cd server && go build -o /tmp/tessera-cli ./cmd/tessera-cli     # or: go run ./cmd/tessera-cli ...
export TESSERA_ENV=dev                                             # lets the CLI use http and loopback
tessera-cli login --server http://localhost:5173 --tenant larkspur
#   To sign in to larkspur, open  http://localhost:5173/device  and enter the code  KDQV-TMWB
tessera-cli whoami
tessera-cli api GET /api/summary
tessera-cli api -d '{"identity_id":1,"group_id":2,"justification":"on call"}' POST /api/jit/requests
tessera-cli logout
```

Open `/device` in the browser as Pat, Alice or Ivan (the dev IdP users with a passkey: approving needs a
phishing-resistant sign-in, and Olu and Vic have none), type the code, check who is asking, and approve.
The CLI then acts as that user: with Pat the JIT example above works, with Alice (a tenant admin) only
reads do. Approval needs the passkey sign-in within the last 5 minutes (`max_age` 300, step-up; the page
sends you to re-authenticate and offers to resume).
There is no pre-filled link or QR code: the user types the code. `--scope` asks for fewer scopes
(default `tessera:read tessera:write`; `tessera:audit` and `tessera:admin` exist), and `--acr`,
`--max-age` ask the approver for a stronger or fresher sign-in. Exit status: 0 ok, 1 error or an HTTP
status of 400 or more, 2 usage, 3 the API wants a fresher sign-in (the message prints the `login`
command that satisfies it; nothing is repeated on its own).

**Credentials** are one file, `~/.config/tessera/credentials.json` (`$XDG_CONFIG_HOME/tessera`, or
`$TESSERA_CONFIG_DIR`): the DPoP private key, the current refresh token and the cached access token,
mode 0600 in a 0700 directory (the CLI refuses a file others can read; an OS keychain comes later).
Refreshing is serialized with a lock file, because presenting one refresh token twice is treated as
theft. `api` only takes paths on the signed-in server, so a token is never sent elsewhere. All of the
CLI's HTTP goes through `internal/safehttp` (https only, no private addresses; `TESSERA_ENV=dev` adds
http and loopback).

| Route | Purpose |
|---|---|
| `GET /t/{slug}/.well-known/oauth-authorization-server` | RFC 8414 metadata of the tenant's issuer |
| `GET /t/{slug}/.well-known/jwks.json` | the tenant's public access-token keys |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 metadata of the API (`authorization_servers` is the `/t/{slug}` template) |
| `POST /t/{slug}/oauth/device_authorization` | start a device grant (10 per minute per IP); no `verification_uri_complete` |
| `POST /t/{slug}/oauth/token` | `device_code` and `refresh_token` grants, DPoP proof and server nonce required (and `client_credentials`: see Machine clients) |
| `POST /t/{slug}/oauth/revoke` | RFC 7009: revokes the refresh token's family and the CLI session |
| `POST /api/auth/device/lookup` | session; who is asking (client, address, time, scope); 5 wrong codes lock the session out of lookups for 10 minutes (`oauth.device.lookup_bruteforce`) |
| `POST /api/auth/device/approve` | session and step-up (`max_age` 300, phishing-resistant); `{user_code, decision}` |

API requests carry `Authorization: DPoP <token>` and a `DPoP` proof bound to the method, the URL
(`TESSERA_PUBLIC_URL` + path), and the token (`ath`); a bound token under `Bearer` is refused. A refusal
is `401 login_required` with `WWW-Authenticate: DPoP error=…`; a token session that needs a fresher
sign-in gets `401 step_up_required` with `WWW-Authenticate: DPoP error="insufficient_user_authentication"`.
No CSRF header is needed for a token (no ambient credential), and the request is audited as the user,
through client `tessera-cli`.

**Refresh tokens** rotate on every use (idle 12 hours, absolute 24 hours, or 12 with an active admin
role: the CLI session's). A used token presented again revokes the whole family and the session and
writes a critical `oauth.refresh.reuse_detected`; presenting a token with another DPoP key is
`invalid_grant` and changes nothing. The first-party client `tessera-cli` exists in every tenant
(created at seed and server start); a tenant can turn the device grant off with
`tenants.settings.device_grant_enabled=false`.

The authorization server is hand-written on go-jose (the design's §6 fallback), not on zitadel/oidc: see
`internal/oauth/oauth.go` for why. Tests: `internal/oauth` (flow, refresh, tokens, metadata, fuzzing),
`internal/oauth/dpop`, `internal/cliauth`, `internal/api/oauth_routes_test.go` and the CLI against an
in-process server in `cmd/tessera-cli/e2e_test.go`. Fuzz targets: `FuzzValidateProof`,
`FuzzVerifyAccessToken` (`go test -fuzz=FuzzValidateProof -fuzztime=30s ./internal/oauth/dpop`).
`internal/oauth/oauth.go` for why. Tests: `internal/oauth` (flow, refresh, tokens, metadata, machine
clients, fuzzing), `internal/oauth/dpop`, `internal/cliauth`, `internal/api/oauth_routes_test.go`,
`internal/api/admin_clients_test.go` and the CLI against an in-process server in
`cmd/tessera-cli/e2e_test.go`. Fuzz targets: `FuzzValidateProof`, `FuzzVerifyAccessToken`,
`FuzzParseClientAssertion` (`go test -fuzz=FuzzValidateProof -fuzztime=30s ./internal/oauth/dpop`;
`go test -run xxx -fuzz=FuzzParseClientAssertion -fuzztime=30s ./internal/oauth`).

### Machine clients (client credentials)

A service, pipeline or agent that has no person behind it is a **machine client** (design §9.5): it has
its own key pair, gets its own tokens with the `client_credentials` grant, and is audited as an
`api_client`. There is no client secret. The client keeps a private key (EC P-256 or Ed25519) and the
tenant registers the public key; the client proves itself on every token request with a short-lived signed
JWT (**RFC 7523 `private_key_jwt`**, `internal/oauth/clientauth.go`):

- `alg` is `ES256` or `EdDSA`, nothing else (HS256, RS256 and `none` are refused), and the header has no
  `jku`, `x5u`, `jwk`, `x5c` or `crit`; the signature must verify with a key registered for that client.
- `iss` = `sub` = the `client_id`; `aud` is exactly the URL of the endpoint it is sent to (for example
  `https://tessera.example.com/t/acme/oauth/token`, as one string); `exp` is in the future and at most 300
  seconds after `iat`; `jti` is unique and is accepted once (in `replay_cache`, until `exp`).
- A failed authentication is `401 invalid_client` with no reason; the reason is in the audit event
  `oauth.client_auth.failed`.

```bash
# register: a PUBLIC key set (each key needs a kid), an accountable owner, roles and scopes
TESSERA_ENV=dev go run ./cmd/tessera admin add-client -tenant acme -name "Nightly ETL" \
  -owner jane@acme.example -jwks-file etl.pub.jwks -scope "tessera:read tessera:audit" -roles viewer,auditor
#   added machine client tsc_… ; token endpoint https://…/t/acme/oauth/token

# a token (DPoP proof header and the server's DPoP-Nonce as for the CLI; scope is optional)
curl -X POST "$TESSERA_PUBLIC_URL/t/acme/oauth/token" -H "DPoP: $PROOF" \
  -d grant_type=client_credentials -d client_id=tsc_… -d scope=tessera:read \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer -d client_assertion=$JWT
```

`add-client` takes only public keys, is audited as the operator (`oauth.client.created`), and refuses admin
roles: a machine client may hold `viewer`, `operator` and `auditor` only, and its `roles` are read on every
request like a user's. `-dpop=false` registers a client that may skip DPoP (it then gets a `Bearer` token and
the command warns; sending a proof anyway still binds the token). Creating and changing clients moves to
the change-request workflow in PR12. The token is an `at+jwt` of 10 minutes (5 with `tessera:admin`),
`sub` = `cli_<client row id>`, with no `sid`, no refresh token, and `cnf.jkt` when DPoP-bound.

What a machine principal may do is the intersection of its roles and its scopes (the scope is the subset of
the client's registered `allowed_scopes` it asked for, all of them if it asked for none). It can never
satisfy step-up: every route that needs a fresh sign-in (approvals, policy changes, device approval) is
`403 interactive_authentication_required`, and `/api/auth/session`, `logout`, `sessions` are for users only.
A disabled client, or one whose roles or scopes are narrowed, is cut off on the next request.

| Route | Purpose |
|---|---|
| `POST /t/{slug}/oauth/token` | also `client_credentials`: `client_assertion_type`, `client_assertion`, optional `scope`; DPoP proof and nonce when the client requires DPoP |
| `POST /t/{slug}/oauth/introspect` | RFC 7662: the same client authentication (`aud` = the introspect URL) for a client registered with the `tessera:introspect` scope; `{"active": false}` for anything that is not an active token of this tenant (expired, revoked session, other tenant, malformed) |
| `GET /api/admin/api-clients` · `/{client_id}` | `admin.read`: the tenant's clients with their public keys (kid, alg, thumbprint), roles, scopes, owner, last use. Read-only |

The RFC 8414 metadata advertises `client_credentials`, `private_key_jwt` (`ES256`, `EdDSA`) and the
`introspection_endpoint`.

## Adding a real connector

1. Implement `connectors.Connector` (`internal/connectors/connector.go`):

   ```go
   type OktaConnector struct{ orgURL, token string; http *http.Client }

   func (o *OktaConnector) System() string      { return "okta" }
   func (o *OktaConnector) DisplayName() string { return "Okta" }
   func (o *OktaConnector) TypeName() string    { return "OktaConnector" }

   func (o *OktaConnector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
       r := &connectors.DiscoveryResult{}
       for _, u := range o.users(ctx) { // paged /api/v1/users
           r.Accounts = append(r.Accounts, connectors.AccountRecord{System: "okta", ExternalID: u.ID,
               Username: u.Login, Identity: &connectors.IdentityRef{Email: u.Email}, Status: u.Status})
       }
       // groups -> GroupRecord, memberships -> EdgeRecord{Src: Ref{"account","okta",id}, Dst: Ref{"group","okta",gid}, Relation: "member_of"}
       return r, nil
   }

   func (o *OktaConnector) StreamEvents(ctx context.Context, since *time.Time, yield func(connectors.Event) error) error {
       // System Log -> yield(&connectors.UsageRecord{...})
       return nil
   }
   ```

2. Identities are correlated by `IdentityRef.ExternalID` first and then by email. Cross-system
   edges, for example an Okta group mapped to an AWS role through SAML, are emitted by whichever
   connector can see them, using `Ref{Kind, System, ExternalID}`. Ingestion runs in phases, so
   the order of connectors does not matter.
3. Register a factory in `connectors.Factories` from `internal/connectors/all` (a connector imports
   package `connectors`, so it cannot be registered there) and run with, for example,
   `TESSERA_CONNECTORS=demo-workday,okta,demo-aws,...`. You can replace demo connectors one system at
   a time. Read credentials through `connsync.ResolveSecret`, use
   the server's shared outbound client (`safehttp.ForConfig`, passed in through `all.Register`) instead of building your own, and never log them. Use `connsync` for checkpoints and backoff.
4. `internal/testkit.TinyConnector` is a minimal working connector you can use as a template.

## Testing and quality gates

```bash
cd server
go vet ./... && TESSERA_ENV=test go test -race -timeout 25m ./...
scripts/install-tools.sh && gosec ./... && govulncheck ./...
cd ../frontend && npm run build && npm test   # npm test: node:test, no extra dependencies
```

* **Unit tests** are table-driven Go tests per package: every test of the former pytest suite was
  ported, plus focused tests for effective-permission paths, policy evaluation, unused-access
  detection, the JIT lifecycle and leaver plans.
* **API parity.** `internal/api/parity_test.go` replays 160 golden request/response pairs, in order
  (reads, then simulation, JIT, review, revoke, HRIS/JML and sync mutations), against a freshly
  seeded server and requires identical JSON, including key order, number spelling and FastAPI's
  422 error bodies. The fixtures in `server/testdata/parity/` were recorded from the Python
  (FastAPI) backend with `record_python.py` on a frozen clock (2026-10-08T09:30:00 UTC) before it
  was removed; check out commit `aba5abb` to re-run the recorder against it. Only two values are
  normalised, both non-deterministic in Python itself (see `testdata/parity/README.md`).
* **Postgres.** With `TESSERA_TEST_PG_URL` set (see "Postgres") the whole suite runs on Postgres 16 as
  the non-owner `tessera_app` role, and `store/pg_isolation_test.go` checks row-level security,
  composite foreign keys and the audit privileges. `TESSERA_REQUIRE_PG_TESTS=1` turns a missing
  server into a failure.
* **CI diagnostics.** `scripts/ci-diagnostics.sh` runs the CI and security-scan gates locally,
  one log per step, into `logs/ci-<timestamp>/SUMMARY.md` (git-ignored). `--quick` skips the
  race suite, `--only go,frontend,…` picks steps, and `--pr <n>` (with `gh` signed in) also saves
  GitHub's runs, jobs, runners, annotations and job logs for that PR. It also checks that every
  action version the workflows pin exists. Use it when CI is red: if every local step passes and
  the jobs show `runner_id=0` with no steps, they never ran (see the annotations, usually billing).
* **Security scanners:** gosec reports 0 issues; each of the few `#nosec` annotations carries a
  justification. govulncheck reports no vulnerabilities.
* **AWS evaluator indexes and queries** (`internal/aws/index`, `internal/aws/query`, pure, no
  behaviour change to the API yet). `TestAtomsEqualBruteForce` and `TestDiffEqualsBruteForce`
  check atom-based answers against the engine cell by cell on small random tenants
  (`awstest.NewWorld(seed)`); `TESSERA_EQUIV_SEEDS=200` runs more seeds and
  `go test -fuzz FuzzAtomsEqualBruteForce ./internal/aws/query` explores others.
  `go test -bench . -run XXX ./internal/aws/query` runs the benchmarks (track with `benchstat`).
  The nightly SLO check against a synthetic tenant at twice the design's target scale is
  `go test -tags slow -run TestPerf -timeout 90m ./internal/aws/query`. It needs about 8 GB of
  memory and a quiet machine (the SLOs are for 16 vCPU). Options: `TESSERA_PERF_SCALE=1` for the
  target itself, `TESSERA_PERF_SAMPLE=n` for the number of sampled principals,
  `TESSERA_PERF_PROFILE=<dir>` for CPU and heap profiles (keep `<dir>` out of the repository), and
  `TESSERA_PERF_ROOT=1` for the root-SCP diff.

* **Accessibility.** `cd frontend && npm run test:a11y` runs the Playwright suite in `frontend/e2e`
  against the real stack. It starts `run.sh` on ports 8610/5610/8611 with a temporary DB.
  - axe-core checks the WCAG 2.2 AA rules on the sign-in page, on every route (light and dark)
    and on the detail pages, and fails on any serious or critical violation.
  - Reflow at 320 px, text spacing and focus-not-obscured are scripted checks.
  - A keyboard-only walkthrough signs in, requests access, approves and reviews.
  - Viewport tests (`e2e/mobile.spec.ts`, project `mobile`) run at 360, 400 and 768 px:
    sign-in, the rate-limited screen, inbox, request access, my requests, home, the step-up
    sheet, the rail menu and side panels. Each fails on sideways scrolling or on a control
    under 44 px, and attaches a screenshot to the report. Run only them with
    `npx playwright test --project=setup --project=mobile`.

  CI runs it in `.github/workflows/a11y.yml`. The audit, with the criteria-by-criteria evidence
  and the screen-reader pass still to do by hand, is in `docs/accessibility/wcag-2.2-aa-audit.md`.
  `TESSERA_AUTH_RATE_BURST` and `TESSERA_ANON_RATE_BURST` (defaults 30 and 120) set the per-IP
  burst of the `/api/auth/*` and anonymous limiters; the suite raises them for its own instance.

## Server hardening

* Request bodies are capped at 1 MiB (413); JSON bodies are decoded strictly (unknown fields and
  trailing data are rejected with a 422).
* Read-header, read, write and idle timeouts on the HTTP server, and a 30 s per-handler timeout.
* Graceful shutdown on SIGINT/SIGTERM: in-flight requests drain and the JIT sweeper stops.
* CORS allows only the dev UI origins (`http://localhost:$UI_PORT`, `http://127.0.0.1:$UI_PORT`;
  override with `TESSERA_CORS_ORIGINS`; must be empty in production, where the UI is same-origin),
  with credentials. The UI normally reaches the API through Vite's proxy.
* Every response carries `Content-Security-Policy` (`default-src 'none'; frame-ancestors 'none'` on the
  API), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`;
  API responses are `Cache-Control: no-store`; production adds HSTS.
* Sessions are server-side (design §11): the `__Host-tessera_sid` cookie (`Secure`, `HttpOnly`,
  `SameSite=Lax`, `Path=/`) carries 32 random bytes and the database keeps only their SHA-256. A session
  ends after 60 minutes idle or 24 hours (15 minutes / 12 hours while an admin role is active), on sign
  out, or when it is revoked. State-changing requests need the session's CSRF token in
  `X-Tessera-CSRF`, an allowed `Origin` and a JSON body (403 `csrf_failed`, 415 otherwise).
* Logs carry method, path, status and duration only: no query strings, headers or bodies.
  Internal errors are logged server-side and never echoed to the client.
* Configuration (`internal/config`): with `TESSERA_ENV=prod` the server refuses to start on a
  non-https `TESSERA_PUBLIC_URL`, `TESSERA_COOKIE_SECURE=false`, no KEK, any
  `TESSERA_CORS_ORIGINS` (the production UI is same-origin, so CORS is off),
  `TESSERA_OUTBOUND_ALLOW_LOOPBACK=true`, a `TESSERA_DEV_IDP_URL`, a `TESSERA_AUDIT_ANCHOR` that
  is not `s3://bucket/prefix` (missing and `file://` included), a frozen clock (`TESSERA_NOW`), a
  `TESSERA_TRUSTED_PROXIES` prefix broader than /8 (IPv4) or /32 (IPv6), or a `postgres://`
  `TESSERA_DB` without `sslmode=require` (or stricter) and `app_role`, and lists every problem
  at once (never echoing the DSN). A /0 proxy prefix is refused in every environment. `TESSERA_COOKIE_SECURE=false` is
  accepted only with `TESSERA_ENV=dev`, a `localhost`/`127.0.0.1` public URL and a loopback
  `-addr`. `serve` and `seed` both need an explicit `TESSERA_ENV` (`run.sh` exports `dev`).
* Keys: `seed` and `serve` run the ensure-keys step (one active and one next ES256 key per tenant
  and purpose, the platform Ed25519 key, daily rotation). Private keys are stored only sealed
  under the KEK (`TESSERA_KEK` or `TESSERA_KEK_FILE`, base64 of 32 bytes, file mode 0600). Sealed
  values are AES-256-GCM under `HKDF(KEK, "tessera/seal/v1")` (format version 2); version 1
  values (the raw KEK, before #127) still open and are re-sealed lazily on write. In dev a KEK is
  generated at `server/var/dev-kek` (temp file, then linked into place, never overwritten); if it
  is lost, the server refuses to start until the database is reseeded. A stored public key that
  fails validation is left out of a JWKS and logged as `keys.bad_public_jwk` with `alert=true`.
  Emergency revocation and the JWKS cache trade-off: `docs/runbooks/signing-key-emergency-revocation.md`.
  The tenant slugs `platform` and `platform-*` are reserved.
* Outbound HTTP (`internal/safehttp`, built only by `safehttp.ForConfig`; tests use
  `safehttp.NewForTest`, which `internal/archtest` bans elsewhere): https only, destination ports
  443 and 8443 unless the connection's configured URL names its port (that host only), addresses
  checked after DNS on every dial and redirect hop, numeric host spellings (`2130706433`,
  `0177.0.0.1`) and zoned IPv6 literals refused. In dev the loopback exception (127.0.0.1, [::1])
  allows plain http on any port, so the dev IdP on :8001 works; a `TESSERA_ENV=test` server gets
  the production client.
* Rate limits: per-IP buckets keyed by `ratelimit.IPKey` (IPv6 by /64); each key class (IP,
  session, user code) has its own, smaller LRU, so one class cannot evict another's buckets.

## Go vs Python

Measured with `./run.sh bench` (`tools/benchcmp`, 100 sequential requests per route after warm-up)
on an Apple M3, both servers on the same seeded demo company:

| | Go | Python (FastAPI + SQLAlchemy + networkx) |
|---|---:|---:|
| startup to first healthy response | 27 ms | 1.2 s (3.8 s cold) |
| RSS after the run | 34 MiB | 92 MiB |
| seed the demo company | 0.9 s | 1.5–2.6 s |
| p50 `GET /api/summary` | 29 ms | 51 ms |
| p50 `GET /api/identities` | 14 ms | 50 ms |
| p50 `GET /api/identities/{id}` | 13 ms | 48 ms |
| p50 `GET /api/graph?identity_id=` | 11 ms | 25 ms |
| p50 `GET /api/violations` | 12 ms | 30 ms |
| p50 `GET /api/least-privilege/recommendations` | 12 ms | 35 ms |
| p95 `GET /api/identities/{id}` | 14 ms | 347 ms |

## Differences from the Python backend

The HTTP API is the same (routes, status codes, JSON bodies and key order, validation errors,
OpenAPI document). Deliberate differences:

* Unknown fields in request bodies are rejected (`422 extra_forbidden`) instead of ignored.
* Bodies over 1 MiB get `413`; handlers that run over 30 s get `503`.
* CORS no longer allows every origin (`*`); see above.
* `violations.resolved` / `violations.introduced` in simulate and revoke responses are sorted by
  `key` (Python's order depended on the hash seed).
* `POST /api/hris/events` returns `422` for an `identity_id` that does not exist; `GET .../plan` returns `409` (not `500`) for a stored event whose identity is gone.
* A joiner whose email (case-insensitive, trimmed) or `payload.employee_id` (the HR id, stored as the identity's external id) matches an
  *active* identity is refused with `409 {"error":"identity_exists","existing_identity_id":N,"matched_on":"email|hr_id"}`, at
  `POST /api/hris/events` and, authoritatively, at `POST .../execute` (the event stays pending; the refusal is audited as
  `jml.joiner.refused`). A terminated identity does not match, so a rehire joins as a new identity.
* A connector sync never undoes Tessera-side decisions: terminated identities, disabled accounts, executed HRIS events and
  grants revoked by a leaver plan, access review or least-privilege revoke (tombstones in `revoked_grants`) stay as they are.
* `add_edges[].duration_hours` simulates a time-boxed JIT grant, which never counts as standing access.
* Policies are embedded in the binary; set `TESSERA_POLICY_DIR` (run.sh does) to edit them live.

## Known gaps (MVP)

* No authentication or RBAC on the API or UI. Actor names on approvals and revokes are placeholders:
  the audit ledger records every request as `anonymous` and keeps the supplied name only as an
  unverified `claimed_actor`.
* Revokes and JML plans change Tessera's graph only unless the connection has a provisioning target
  with write-back on (see Closed-loop provisioning); JIT approval and rotating secrets are not yet
  sent to targets, and only SCIM 2.0 and Okta have connectors (no Entra native connector yet).
* The durable queue (see Durable job queue) runs the sweepers and the containment retry sweep. The
  notification outbox and provisioning operations still run their own loops, so they are not safe on more
  than one instance yet; moving them is the follow-up. There is no queue depth or oldest-job-age metric
  yet (only `tessera_queue_job_runs_total` and the per-sweep loop lag in `obs.DefaultLoops`), and schedules cannot be edited or disabled through the API.
* There is no scheduled connector sync. Seeding runs discovery once, and `POST /api/connectors/sync`
  re-runs discovery on demand (`?mode=full` ignores connector checkpoints).
* Effective-permission paths are capped at 8 per permission, and "lost if removed" uses those paths.
* AWS permissions are modelled as discrete actions on resources. IAM policy conditions, deny
  statements, SCPs and wildcard expansion are not evaluated.
* Delegated agent scopes are shown and compared with what the principal holds, but they do not
  narrow the agent's own effective permissions.
* SQLite and a per-request graph rebuild are fine for this demo but would not scale to large tenants.

## Offline migration assessment

The report-only `tessera migration assess` command assesses bounded IIQ XML or
Tessera normalized JSON packs for SailPoint/Saviynt. It requires explicit tenant,
product and source-instance labels, a local file and an explicit `--out` path.
It writes a private JSON report, refusing overwrites without `--force`,
without opening the database or changing access. Native vendor compatibility is
unverified; unsupported logic is reported as blocking diagnostics.
See [the contract, examples and phase limits](../docs/migration-assessment.md).
