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
  internal/
    connectors/         Connector interface + normalized record types, deterministic demo company
                        (pyrand.go reproduces CPython's Mersenne Twister so seed 7 gives the same
                        company the Python backend generated), registry (TESSERA_CONNECTORS)
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
    ratelimit/          keyed token-bucket limiter with a bounded key set
    ojson/, timeutil/   ordered JSON + Python float repr; CPython-compatible time arithmetic
    testkit/            shared test fixtures (tiny world through a real Connector, seeded demo DB; each is seeded once per test binary and handed out as a private copy per test)
    devidp/             dev IdP: mock OIDC issuer, vendor emulation profiles, fault injection;
                        devidptest/ runs it in-process for tests. Never imported by the API.
  policies/*.yaml       policy-as-code (embedded in the binary; run.sh reads them from disk)
  testdata/parity/      golden request/response fixtures recorded from the original Python API
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
`POST /api/reviews/items/{id}/decision` (a decision is final: repeating it is a 200 no-op, a different one is
`409 review_item_decided` and an audited `review.decide.refused`) ·
`GET|POST /api/hris/events` (422 for an unknown `identity_id`) · `GET /api/hris/events/{id}/plan` · `POST /api/hris/events/{id}/execute` ·
`GET /api/jml/leaver-plan/{identity_id}` · `POST /api/identities/{id}/contain` (kill switch, see "Identity containment") · `POST /api/identities/{id}/disable|enable` ·
`PUT /api/connections/{id}/containment-credential` · `GET /api/accounts[?system=]` ·
`GET /api/audit[?limit=&before_seq=&action=&actor_id=&target_type=&target_id=&from=&to=&include_http=]` ·
`GET /api/audit/events/{event_id}/proof` · `GET /api/audit/checkpoints[?from_seq=]` · `GET /api/audit/keys` ·
`POST /api/audit/verify {from_seq?, to_seq?}` · `GET /api/audit/export[?from_seq=&to_seq=]` (NDJSON) ·
`GET /api/auth/session` · `POST /api/auth/logout` · `GET /api/auth/sessions` · `DELETE /api/auth/sessions/{session_id}` ·
`GET /api/auth/step-up?acr=&max_age=&return_to=` ·
`GET /api/auth/discover?tenant=&email=` · `GET /api/auth/login?tenant=&connection=&return_to=` (302 to the IdP) ·
`GET /api/auth/oidc/{connection_id}/callback` · `GET /api/auth/saml/{connection_id}/metadata` ·
`POST /api/auth/saml/{connection_id}/acs` · `GET /api/auth/oauth2/{connection_id}/callback` ·
`GET /t/{slug}/bootstrap?code=` (public)
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
`GET /api/approvals/inbox` · `GET /api/approvals/delegates` · `GET|POST /api/approvals/delegations` ·
`POST /api/approvals/delegations/{id}/revoke` ·
`GET /api/correlation/queue` · `GET /api/correlation/decisions` ·
`POST /api/accounts/{id}/link {identity_id, reason}` · `POST /api/accounts/{id}/not-person {reason}` ·
`DELETE /api/accounts/{id}/link` · `POST /api/identities/{id}/merge {into, reason}` ·
`GET /api/identity-merges` · `POST /api/identity-merges/{id}/unmerge {reason}` ·
`GET|POST /api/reviews/schedules` · `PUT /api/reviews/schedules/{id}` · `POST /api/reviews/schedules/{id}/run` ·
`GET /api/identities/{id}/affiliations` · `GET /api/identities/{id}/identifiers` ·
`POST /api/identities/{id}/affiliations {type, org_unit?, population?, starts_at?, ends_at?, reason}` ·
`POST /api/affiliations/{id}/end {reason}`
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
  `provision.cancelled`; target changes write `provision.target_set` and `provision.target_removed`
  (never the token). Completions write the event the direct path wrote (`jit.expire`, `review.revoke`,
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

The test login: while signed in, the requester opens `GET /api/auth/login?connection=<id>&test=1`
(login transactions have a `test` purpose, schema `0315`; OIDC and SAML). The callback records the
test login on the requester's own session and returns to `/?test_login=ok`. It never creates a session,
a user, an external login or a role, and only the requester of that connection can run it, once.

Every submit and approve needs `STEP_UP_ADMIN` (phishing-resistant sign-in within 5 minutes). The payload
is decoded into a typed struct with unknown fields refused; the approver echoes its SHA-256 (`payload_hash`)
and a mismatch is 409. States: `pending_approval` → `cooling_off` → `applied`, or `rejected`, `cancelled`,
`expired` (72 h without approval) or `failed` (the applier raised; recorded with the reason). Applying before
`effective_at` is 409; the sweeper (`RunSweeper`) applies due changes and expires old ones, using the
injected clock. A tenant with fewer than two admins can grant `tenant_admin` with one person and the 24 h;
a change that needs two people is refused (`bootstrap_restricted`) until it has two. A client secret
travels beside the payload, is sealed, and is cleared when the request ends; it never appears in the
payload, audit, a response or a list. `api_client.*` and `breakglass.*` types arrive with the PRs that add
their tables. Every transition writes an `admin.change.*` audit event and queues an `admin_notifications`
row for every active tenant admin and security contact, in the same transaction (delivery is the
notification outbox's job, issue #189; until then the rows and the banner are the notice).

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
tenure_days), `resource.*` (name, risk, and for catalog items system and privileged) and `context.*`
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
Not yet: location, worker type and custom HRIS fields (the identity record does not store them, so
a test on one is always unknown and denies; they arrive with the HRIS attribute mapping).

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

Not yet: the claim link and the guest's invitation email (GU-6; the intake's `invitation_status`
stays `ready`), granting the bundle (GU-12), sponsor-leaver transfer from JML events and the
transfer task in the Inbox (GU-11), self-registration (GU-3), resend and revoke invitation, and
per-tenant sponsor policy editing. After pulling this change run `./run.sh --reseed`: it adds three
tables and widens the lifecycle `source` check.
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

- `revoke_sessions`: Okta `DELETE /api/v1/users/{id}/sessions?oauthTokens=true`; Entra
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
  `succeeded` or `gave_up`. The sweeper (the 30 s `RunSweeper` loop, clock-aware like the rest)
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
  tenant, table, column and connection) in `containment_credentials`; it is never returned or
  logged. Okta needs `base_url` (the org URL), GitHub `org`; Entra and Google default to
  `graph.microsoft.com` and `admin.googleapis.com`. Tokens: Okta API token (SSWS), Entra and Google
  bearer access tokens with the permission to revoke sessions (`User.RevokeSessions.All`,
  `DelegatedPermissionGrant.ReadWrite.All`; `admin.directory.user.security`), GitHub an owner's
  token with `admin:org` (SAML SSO organizations only).
- **Still manual or not covered.** Okta has no API that lists IdP sessions and Google none for
  sessions: those re-reads cover refresh tokens and say so in the step's notes. `rotate_secret`
  still only stamps a timestamp.

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
- Routes (all need `groups.admin`, held by `tenant_admin` until GR-4; every route is audited):

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
| **Identity** | Users, Machine identities & agents, Groups (with an *All entitlements* tab), Applications, Accounts (with *Account matches*), Roles, Organizations (live, read-only, derived from departments) |
| **Access** | Request access, My access (with *My requests*), Guests I sponsor (invite, bulk invite, renew, transfer, approvals), Just-in-time, Access reviews (with *Lifecycle* and *Workflows* tabs) |
| **Protection** | Policies & SoD (violations, policies, what-if simulation), Attribute policies, Access graph, Insights (Risk overview, Least privilege, SoD conflicts, Deployment health) |
| **Settings** | Connections (governed connections and the setup wizard), Admin |

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
| Identity Disable / Enable (identity page, panel, bulk, palette) | `POST /api/identities/{id}/disable`, `.../enable`, `GET .../disables` | `identities.contain` and a fresh phishing-resistant sign-in. Disable runs the kill switch's containment (revoke sessions, tokens, OAuth grants at connected providers), then sets the active accounts and the identity to disabled in one audited transaction (`identity.disable`). A failed provider step is retried and reported. Tessera does not suspend the account inside the provider. Enable (`identity.enable`) sets back only the accounts Disable disabled and that are still disabled. It cannot restore revoked sessions and grants, and says so. No Undo. |
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

**Bundle.** Every route is lazy-loaded. The main chunk is about 87 kB gzipped and the stylesheet
about 8 kB; cytoscape (about 146 kB gzipped) only loads with the access graph.

## Signing in

Every API call needs a signed-in session (design `docs/design/phase-0-platform-security.md` §11, §12),
and Tessera never sees a password: users sign in through their company's identity provider (OIDC, SAML 2.0,
or an OAuth 2.0-only provider such as GitHub).

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

### Dev IdP

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

**A new tenant** is created by an operator (design §15.3); every step is audited as the OS user:

```bash
cd server
TESSERA_ENV=dev go run ./cmd/tessera admin create-tenant -slug acme -name "Acme Corp"
TESSERA_ENV=dev go run ./cmd/tessera admin add-idp -tenant acme -file okta.yaml -client-secret-file okta.secret
TESSERA_ENV=dev go run ./cmd/tessera admin invite-admin -tenant acme -connection <id> -email jane@acme.example
```

`add-idp` reads a connection file (§18.2; unknown keys are refused, secrets are never in it). OIDC uses
`client_secret_basic` for now and prints the redirect URI. `protocol: saml` with `profile: generic_saml`
needs `idp_entity_id`, `idp_sso_url` and `idp_signing_certs` (pinned), takes `subject_source` and
`attribute_map` (`email`, `name`, `groups`), generates and seals an SP key, and prints the SP entity
ID/metadata and ACS URLs to register at the IdP. `protocol: oauth2` takes `profile: github` (GitHub's
endpoints and `id` by default) or `generic_oauth2` with `authorization_endpoint`, `token_endpoint`,
`userinfo_endpoint` and `subject_field` (never a name or email), needs `-client-secret-file`, and
prints the redirect URI. `invite-admin` prints a one-time
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
  Alice and Ivan (tenant admins), Pat (policy admin), Olu (operator), Vic (viewer) in `larkspur`,
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
3. Register a factory in `connectors.Factories` (`Factories["okta"] = func(time.Time) (Connector, error) {…}`)
   and run with, for example, `TESSERA_CONNECTORS=demo-workday,okta,demo-aws,...`. You can replace
   demo connectors one system at a time. Read credentials from the environment and never log them.
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

* **Accessibility.** `cd frontend && npm run test:a11y` runs the Playwright suite in `frontend/e2e`
  against the real stack. It starts `run.sh` on ports 8610/5610/8611 with a temporary DB.
  - axe-core checks the WCAG 2.2 AA rules on the sign-in page, on every route (light and dark)
    and on the detail pages, and fails on any serious or critical violation.
  - Reflow at 320 px, text spacing and focus-not-obscured are scripted checks.
  - A keyboard-only walkthrough signs in, requests access, approves and reviews.

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
* There is no scheduled connector sync. Seeding runs discovery once, and `POST /api/connectors/sync`
  re-runs discovery on demand.
* Effective-permission paths are capped at 8 per permission, and "lost if removed" uses those paths.
* AWS permissions are modelled as discrete actions on resources. IAM policy conditions, deny
  statements, SCPs and wildcard expansion are not evaluated.
* Delegated agent scopes are shown and compared with what the principal holds, but they do not
  narrow the agent's own effective permissions.
* SQLite and a per-request graph rebuild are fine for this demo but would not scale to large tenants.
