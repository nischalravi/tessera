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
./run.sh audit-deps  # govulncheck ./... on the Go module (install with server/scripts/install-tools.sh)
```

* UI: http://localhost:5173 (Vite dev server; it proxies `/api` to the backend via `TESSERA_API`).
  Sign in with **dev sign-in** (see [Dev sign-in](#dev-sign-in)): pick a seeded user, for example
  Alice (tenant admin) or Pat (policy admin), with a passkey.
* API: http://127.0.0.1:8000. OpenAPI docs are at http://127.0.0.1:8000/docs
* Dev IdP: http://127.0.0.1:8001 (see [Dev sign-in](#dev-sign-in))

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
| Joiner / mover / leaver | Inbox, Governance → Lifecycle | Simulated Workday feed. The leaver plan for Marcus disables accounts, removes grants, re-homes the AI agent and service account he owned, rotates their secrets and revokes delegations. For historical leavers it shows the access the legacy process missed (Oren still has an active Okta account) and offers one-click cleanup. |

## Architecture

The backend is a single Go binary (`mvp/server`, module `github.com/nischalravi/tessera/mvp/server`)
with SQLite through the pure-Go `modernc.org/sqlite` driver, so it needs no C toolchain.

```
server/
  cmd/tessera/          main: `serve` (default), `seed` and `audit verify|checkpoint|export`; timeouts,
                        graceful shutdown, JIT sweeper, audit checkpointer
  cmd/tessera-devidp/   the dev IdP binary (development and tests only; see Dev sign-in)
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
    api/                HTTP routes under /api, FastAPI-compatible validation errors, OpenAPI/docs
    config/             typed settings from TESSERA_* variables; production guard rails
    seal/               AES-256-GCM sealing under the KEK (AAD-bound), random secrets, SHA-256 helpers
    keys/               per-tenant ES256 signing keys and the platform Ed25519 key: rotation, JWKS
    safehttp/           SSRF-guarded outbound HTTP client (https only, address checks after DNS)
    ratelimit/          keyed token-bucket limiter with a bounded key set
    ojson/, timeutil/   ordered JSON + Python float repr; CPython-compatible time arithmetic
    testkit/            shared test fixtures (tiny world through a real Connector, seeded demo DB)
    devidp/             dev IdP: mock OIDC issuer, vendor emulation profiles, fault injection;
                        devidptest/ runs it in-process for tests. Never imported by the API.
  policies/*.yaml       policy-as-code (embedded in the binary; run.sh reads them from disk)
  testdata/parity/      golden request/response fixtures recorded from the original Python API
  tools/benchcmp/       end-to-end benchmark (seed, startup, p50/p95, RSS; optionally vs Python)
  scripts/install-tools.sh  pinned govulncheck + gosec
frontend/               React 18 + Vite + TypeScript, react-router, cytoscape.js, lucide-react
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

### Main API endpoints

`GET /api/summary` · `GET /api/identities[?type=&q=]` · `GET /api/identities/{id}` · `GET /api/accounts[?system=]` ·
`GET /api/graph?identity_id=|resource_id=` · `GET /api/nhi` ·
`GET /api/least-privilege/recommendations?unused_days=60&kind=remove|right_size|role_trim` ·
`POST /api/least-privilege/revoke {edge_id, dry_run}` · `GET /api/policies` · `GET /api/violations` ·
`POST /api/simulate {remove_edge_ids, add_edges:[{src,dst}], disable_account_ids}` ·
`GET|POST /api/jit/requests` · `POST /api/jit/requests/{id}/approve|deny|revoke` ·
`GET|POST /api/reviews/campaigns` · `POST /api/reviews/items/{id}/decision` ·
`GET|POST /api/hris/events` · `GET /api/hris/events/{id}/plan` · `POST /api/hris/events/{id}/execute` ·
`GET /api/jml/leaver-plan/{identity_id}` · `GET /api/accounts[?system=]` ·
`GET /api/audit[?limit=&before_seq=&action=&actor_id=&target_type=&target_id=&from=&to=&include_http=]` ·
`GET /api/audit/events/{event_id}/proof` · `GET /api/audit/checkpoints[?from_seq=]` · `GET /api/audit/keys` ·
`POST /api/audit/verify {from_seq?, to_seq?}` · `GET /api/audit/export[?from_seq=&to_seq=]` (NDJSON) ·
`GET /api/auth/session` · `POST /api/auth/logout` · `GET /api/auth/sessions` · `DELETE /api/auth/sessions/{session_id}` ·
`GET|POST /api/auth/dev-login` (dev and test only) ·
`GET /api/jobs[?status=running|succeeded|failed&kind=&connection_id=&limit=]` · `GET /api/jobs/{job_id}` ·
`POST /api/jobs/{job_id}/retry` ·
`GET /api/provisioning/targets` · `PUT|DELETE /api/provisioning/targets/{connection_id}` ·
`GET /api/provisioning/ops[?status=&kind=&connection_id=&limit=]` · `GET /api/provisioning/ops/{op_id}` ·
`POST /api/provisioning/ops/{op_id}/retry|cancel` · `POST /api/provisioning/run` ·
`GET /api/provisioning/findings[?status=open|resolved]`

Each route declares the permission it needs (design §12.1, §16.2; `api.Routes()` lists them and
`internal/api/rbac_routes_test.go` holds the table). The decider of a JIT request, review item, revoke
or HRIS execution is always the signed-in user.

### Job run history

Every run of a connector sync, provisioning (HRIS execute), connection validation, dry run,
deployment-health re-run and JIT sweep is recorded in `job_runs` (`internal/jobs`), plus every
audit anchoring run that did something or failed. A sweep that finds nothing is not recorded.
Each record has the kind, trigger (manual, schedule or retry), status, duration, a result summary
and a one-line error. The run row is written in its own transaction before the job and finished in
another, so a job that rolls back keeps its failed run, and `job.failed` is appended to the audit
chain for alert rules to match. A request refused before the job ran (bad input, missing
permission, a blocked gate) is not a run.

`POST /api/jobs/{id}/retry` replays the run's API call as the signed-in user, through the whole
middleware: the original route's permission and step-up apply. It is offered only for idempotent
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
  Mismatch findings remain open during retry or cancellation and resolve only after successful verification.
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
  the org's origin). Changing a credentialed target URL or connector kind requires a replacement token. Credentials are sealed under the KEK (`internal/seal`, AAD = tenant, table,
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
the database (S3 Object Lock is a later step). To check a database:

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

## Web UI

The UI follows an "admin center" layout: a dark top bar, a light left rail grouped by job, list
pages with a command bar and filter chips, and details that slide in from the right so you never
lose your place in the list.

**Top bar** (48px, dark). The hamburger collapses the rail to icons (below 768px it opens the rail
as a drawer), then the Tessera mark, the global search box (`/` focuses it; `⌘K` opens the
palette), and on the right the Inbox with its count, recent activity (from the audit log),
settings (theme: light, dark or match system), help (shortcuts) and the user menu with the
tenant name and the persona switcher.

**Left rail** (236px, light). Active items are white with a blue left indicator; counts sit on
the right. Arrow keys move between items.

| Group | Items |
|---|---|
| (top) | **Home**, **Inbox** (count) |
| **Identity** | Users, Machine identities & agents, Groups (with an *All entitlements* tab), Applications, Accounts, Roles (Preview), Organizations (Preview) |
| **Access** | Request access, My access (with *My requests*), Just-in-time, Access reviews (with *Lifecycle* and *Workflows* tabs) |
| **Protection** | Policies & SoD (violations, policies, what-if simulation), Access graph, Insights (Risk overview, Least privilege, SoD conflicts, Deployment health) |
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

**Preview features.** Some screens have no backend endpoint yet: business roles, organizations,
workflows, catalog (non-JIT) requests, delegations, disable / reset password / edit, imports and
most admin settings. They run on typed mock data in `src/mocks/`, keep their state in the
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

## Dev sign-in

Every API call needs a signed-in session (design `docs/design/phase-0-platform-security.md` §11, §12).
Tessera signs users in through their company's identity provider (Okta, Entra ID, SAML); that browser
flow arrives in Phase 0 PR6 and PR7. Until then a development server (`TESSERA_ENV=dev` or `test`,
which `./run.sh` sets) offers **dev sign-in**:

1. `./run.sh` and open http://localhost:5173. The sign-in page lists the users the seed created for the
   dev IdP (below) and asks how they authenticate.
2. Pick a user and a method. The page calls `POST /api/auth/dev-login {tenant, subject, method}`; the
   API resolves the user through the tenant's `dev_mock` IdP connection and the (connection, subject)
   link (never by email), builds the authentication context the dev IdP's Okta emulation would return
   when Tessera asks for phishing resistance, and sets the session cookie.
3. Roles follow from the method, as with a real IdP (design §12.2): admin roles (`tenant_admin`,
   `policy_admin`) are active only after a phishing-resistant method (**Passkey** or **Hardware security
   key**); other roles need MFA (**Password + OTP** or better); **Password only** activates no role.
   The user menu shows inactive roles and offers to sign in again.

| User | Tenant | Role | What they can do |
|---|---|---|---|
| Alice (`00u-alice-admin`), Ivan | larkspur | tenant_admin | read everything, the audit log, connections and readiness; no data-plane writes (separation of duties) |
| Pat (`00u-pat-policy`) | larkspur | policy_admin | read, JIT and review decisions, revoke grants, run HRIS plans, sync connectors |
| Olu (`00u-olu-operator`) | larkspur | operator | read, request and decide JIT, review decisions |
| Vic (`00u-vic-viewer`) | larkspur | viewer | read (with MFA; his only authenticator in the dev IdP is a password) |
| Gina (`00u-gina-globex`) | globex | tenant_admin | the second tenant |

Approvals, review decisions, HRIS execution, applying a revoke and editing a connection's config or
credential also need a phishing-resistant sign-in in the last 15 minutes (step-up, §10.2). Nobody can
approve a JIT request they made, or one that grants access to their own identity (403 `self_approval`). Until the step-up flow lands (PR8) the API answers
`401 step_up_required` and the UI asks you to sign in again.

Dev sign-in is a development shim with guard rails (§18.4): the routes exist only with
`TESSERA_ENV=dev`, or with `TESSERA_ENV=test` plus the opt-in `TESSERA_DEV_LOGIN=1`, and then answer
loopback clients only; the picker (`GET /api/auth/dev-login?tenant=<slug>`) lists one tenant's users;
the request needs a JSON body and an allowed `Origin`; every attempt is audited (`auth.login.success` /
`auth.login.failure`); signing in again revokes the browser's previous session; and a production server
refuses to start with `TESSERA_DEV_LOGIN` or while a `dev_mock` connection exists. PR7 removes it.

Unauthenticated traffic is rate-limited per client IP before it reaches the audit ledger: every
`/api/auth/*` request (burst 30, then one per 2 s) and every request without a valid session (burst
120, then one per 500 ms) answer `429 rate_limited` with `Retry-After` beyond that. Behind a load
balancer, list it in `TESSERA_TRUSTED_PROXIES` so the limit applies to the `X-Forwarded-For` client.

A tenant's `require_phr_for_all` setting (`tenants.settings`, §18.3) makes every role need a
phishing-resistant sign-in in that tenant. Other session routes: `GET /api/auth/session`,
`POST /api/auth/logout`, `GET /api/auth/sessions`, `DELETE /api/auth/sessions/{session_id}`.

### Dev IdP

Tessera's sign-in through an identity provider is tested against a **dev IdP**: a small mock OpenID
Connect issuer in pure Go (`server/internal/devidp`, binary `server/cmd/tessera-devidp`). It replaces a
real Okta or Entra tenant; nothing it issues is a real identity. Design:
`docs/design/phase-0-platform-security.md` §8.2 and §18.5.

`./run.sh` starts it on http://127.0.0.1:8001 (`DEVIDP_PORT` to change, `DEVIDP=0` to skip) and
exports `TESSERA_DEV_IDP_URL` (seeding points the `dev_mock` connections at it). Tessera's IdP sign-in
(`/api/auth/login`, the OIDC callback) lands in Phase 0 PR6; until then you can drive the IdP directly
with any OIDC client:

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

**SAML** (`/saml/metadata`, `/saml/sso`) answers 501 until the SAML SP lands (Phase 0 PR9).

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
* **Security scanners:** gosec reports 0 issues; each of the few `#nosec` annotations carries a
  justification. govulncheck reports no vulnerabilities.

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
  `TESSERA_OUTBOUND_ALLOW_LOOPBACK=true`, a `TESSERA_DEV_IDP_URL`, a missing or `file://`
  `TESSERA_AUDIT_ANCHOR`, a frozen clock (`TESSERA_NOW`), or a `TESSERA_TRUSTED_PROXIES` prefix
  broader than /8 (IPv4) or /32 (IPv6), and lists every problem at once. A /0 proxy prefix is
  refused in every environment.
* Keys: `seed` and `serve` run the ensure-keys step (one active and one next ES256 key per tenant
  and purpose, the platform Ed25519 key, daily rotation). Private keys are stored only sealed
  under the KEK (`TESSERA_KEK` or `TESSERA_KEK_FILE`, base64 of 32 bytes, file mode 0600). In dev
  a KEK is generated at `server/var/dev-kek`; if it is lost, the server refuses to start until
  the database is reseeded.

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
