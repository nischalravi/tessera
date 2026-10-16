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
`POST /api/simulate {remove_edge_ids, add_edges:[{src,dst,duration_hours?}], disable_account_ids}` ·
`GET|POST /api/jit/requests` · `POST /api/jit/requests/{id}/approve|deny|revoke` ·
`GET|POST /api/reviews/campaigns` · `POST /api/reviews/items/{id}/decision` ·
`GET|POST /api/hris/events` (422 for an unknown `identity_id`) · `GET /api/hris/events/{id}/plan` · `POST /api/hris/events/{id}/execute` ·
`GET /api/jml/leaver-plan/{identity_id}` · `POST /api/identities/{id}/contain` (kill switch, see "Identity containment") ·
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
`GET /api/correlation/queue` · `GET /api/correlation/decisions` ·
`POST /api/accounts/{id}/link {identity_id, reason}` · `POST /api/accounts/{id}/not-person {reason}` ·
`DELETE /api/accounts/{id}/link` · `POST /api/identities/{id}/merge {into, reason}` ·
`GET /api/identity-merges` · `POST /api/identity-merges/{id}/unmerge {reason}` ·
`GET /api/admin/users` · `POST /api/admin/users/{id}/disable {reason}` · `GET /api/admin/idp-connections` ·
`POST /api/admin/idp-connections/{id}/activate` · `GET|POST /api/admin/change-requests` ·
`GET /api/admin/change-requests/{id}` · `POST /api/admin/change-requests/{id}/approve|reject|cancel|apply` ·
`GET /api/admin/notifications` · `GET /api/admin/recovery` · `POST /api/admin/recovery/{id}/cancel` ·
`GET /api/admin/api-clients` (see "Admin changes")

Each route declares the permission it needs (design §12.1, §16.2; `api.Routes()` lists them and
`internal/api/rbac_routes_test.go` holds the table). The decider of a JIT request, review item, revoke
or HRIS execution is always the signed-in user.

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
`0281_groups_engine.sql` adds `grp_engine_state`). Changes recompute the affected identities in
ascending level order from the stored rows, stopping where membership does not change. A disabled or
deleted group, or one outside its own `enabled_from`/`disabled_at`, is an empty set.

| Route (`groups.read`/`groups.write`, then the privilege; the two engine routes `groups.admin`) | |
|---|---|
| `GET /api/groups/{id}/members?filter=direct\|effective&limit=&offset=` | members (`read`); `stale` is true while a recompute is queued (more filters in "Groups REST API", GR-5) |
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
Schema `0282_group_events.sql` (the design calls it `0103`): `grp_event_heads`, `grp_events`,
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

Design `docs/design/groups-grouper-parity.md` §7. Schema `0285_group_privs.sql` (the design calls it
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
| `PUT /api/groups/users/{id}/identity` `{identity_id \| null}` | link a platform user to an identity (`groups.admin`, fresh phishing-resistant sign-in; audited) |

- Tests: `go test ./internal/groups/privs` (`TestImplication` for all 21 privileges,
  `TestPrivs_InheritanceOneVsSub`, `TestPrivs_ExplainListsAllPaths`,
  `TestPrivs_EveryoneNeedsTenantAdmin`), `internal/api` (`TestGroupsRoutesRequirePrivilege` for every
  route, `TestPrivs_ViewFiltersBrowseAndSearch`, `TestPrivs_GrantsGiveAccess`, ...),
  `TestIsolation_GroupPrivilegeTables` in `internal/store`.

#### Groups REST API and SCIM server (GR-5, issue #48)

Design `docs/design/groups-grouper-parity.md` §10.11. Schema `0286_groups_api.sql` (`0285` is the
last numbered file before it; `0287` is another PR's): `grp_idempotency`. Code:
`server/internal/groups/api` (idempotency keys, the SCIM resources and filter, the OpenAPI document),
`server/internal/groups/model/{batch,trace,simulate}.go` (the operations), and the handlers in
`server/internal/api/{groups_members,groups_api,scim}.go`. (The design puts the whole API in
`internal/groups/api`; the handlers need the server's routing, authentication and audit, so they sit
beside the other group routes, as GR-1 to GR-4 did, and `internal/groups/api` holds what does not
depend on `net/http`.) Every route needs its route permission and then the privilege of the group it
names, like the routes of GR-1 to GR-4; `TestGroupsRoutesRequirePrivilege` and the rbac table list them.

| Route | |
|---|---|
| `GET /api/groups/{id}/members?filter=direct\|indirect\|effective\|composite&list=members&enabled=true\|false&q=&sort=name\|-name\|since\|-since&page=&limit=&offset=` | `direct` (default): the rows, `enabled` keeps those that count now or not; `effective`: every identity; `indirect`: effective members with no active direct row of their own (they come through nesting or factors); `composite`: the members a composite definition gives (none for a basic group). `q` is a substring of the member's name (or email), `page` is 1-based with `limit` (instead of `offset`). Needs `read` |
| `GET /api/groups/{id}/members?as_of=T` and `?between=T1,T2` | as GR-3; `q`, `sort`, `enabled` and `page` are refused with them |
| `GET /api/groups/{id}/members/{identity}?trace=true` | adds `paths`: every way the identity is a member, each a list of steps from the group down to the group whose direct row names the identity (`via`: `start`, `nested`, `factor`; `op`: the composite's operator; at most 100 paths, then `truncated`). A complement is explained by its left factor, an intersection by all of its factors |
| `POST /api/groups/{id}/members:batch` `{add:[{identity \| group, enabled_from, disabled_at, reason}], remove:["<identity id or group id>"], enabled_from, disabled_at, reason, atomic}` | 1 to 1,000 operations on one group (adds first, then removes; a member in both lists is `422 conflicting_operations`). **Atomic by default**: the first refused operation undoes the whole batch and the answer is its error with `index`. With `"atomic": false` every operation stands or falls by itself (a savepoint each) and `results[i]` says `created`, `updated`, `removed` or `failed` with the error; if every operation was refused for want of a privilege the answer is `403` instead. Each operation asks the privileges of the single routes (`update`, or `optin`/`optout` for oneself, `read` on a nested group), each writes its own event, and the batch writes `groups.member.batch`. `200`, or `202` with `ops` when a recompute was queued |
| `GET /api/identities/{identity_id}/groups?filter=effective\|direct\|indirect&as_of=T&limit=&offset=` | the groups an identity is in, by name, only those the caller holds `read` on (read, because it tells who is a member); `as_of` answers from the point-in-time history. `groups.read` |
| `POST /api/groups:simulate` `{changes:[{kind: add_member\|remove_member\|set_composite\|convert_to_composite, group, identity, member_group, member, op, factors, discard_members, ...}]}` | what the changes (at most 100) would do: `groups[]` with `before`, `after`, `added`, `removed` and a sample of the identities, for the groups the changes name (`targeted`) and for every group above them (downstream); `changes[]` says created, updated or removed. Needs `groups.write` and the privileges of the changes themselves. **Writes nothing**: see below |
| `GET /api/openapi/groups.json` | the OpenAPI 3.1 document of the groups, SCIM and identity-groups routes, built from the server's route table (`x-tessera-permission` per operation); `TestGroupsOpenAPI_CoversRoutes` fails if a route has no entry |
| `GET /scim/v2/Groups[/{id}]`, `/scim/v2/Users[/{id}]`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/ResourceTypes` | the read-only SCIM 2.0 server, below |

- **Idempotency.** `POST /members`, `DELETE /members/{member}` and the batch accept
  `Idempotency-Key` (1 to 255 of `A-Za-z0-9._~:+=-`). The first answer (2xx) is stored with the
  change, in its transaction, in `grp_idempotency`; for 24 hours the same key with the same method,
  path and body replays that answer (`Idempotent-Replayed: true`) and writes nothing. The key is
  scoped to the tenant and the caller (`user:<id>`, or `client:<id>` for a machine client), so two
  callers never share one; the same key with another request is `422 idempotency_key_reused`. A
  refused request stores nothing. Expired keys are purged by the tenant's next keyed write; the table
  is immutable (a trigger) and has no cross-table references, so it needs no cross-tenant guard.
- **Simulation writes nothing.** It runs the real operations, the real engine included (with a budget
  of 100,000 row operations, so it never queues), inside a savepoint, reads the effective changes back
  from the events the engine wrote, and rolls the savepoint back: rows, events, audit events, the
  queue and the counters all return to what they were. The request's own `http.request` event is the
  only trace, and the route fails closed like a read if that cannot be written.
  `TestSimulate_NoSideEffects` compares every groups table, the event head, the engine state and the
  audit ledger before and after. A change too big for the budget is `422 simulation_too_large`.
- **SCIM authentication.** There is no separate credential. The SCIM server is authenticated like
  every other route: the request needs a signed-in principal (a session cookie today; `Principal`
  already has the `api_client` kind for the token principals of the machine-client work) whose roles
  hold `groups.read`, the tenant is the principal's and never a header or path, and nothing is served
  anonymously (`TestSCIM_PrivilegeAndAuth` tries a bearer token, a tenant header and a stray cookie).
  A provisioning tool therefore needs a machine client when those land; until then the SCIM server is
  usable by signed-in people and by tests. `ServiceProviderConfig.authenticationSchemes` is empty
  because no SCIM scheme names this sign-in.
- **SCIM resources.** `Users` are the tenant's identities (`id` the identity id, `userName` the email
  or else the external id, `active` is status `active`, `userType` the identity type, `groups` on a
  single user: the groups the caller may read). `Groups` are the native groups the caller holds `read`
  on (`id` the group id, `displayName` the full `:` name, `members` the effective identities: the first
  100 on a list, 1,000 on a single group, with `memberCount` and `membersTruncated` in the extension
  `urn:tessera:params:scim:schemas:extension:group:2.0:Group`); a deleted group does not exist, a
  disabled one has no members. `filter` supports `eq ne co sw ew gt ge lt le pr`, `and or not` and
  parentheses (strings compare without case) on `id displayName` (Groups) and `id userName
  displayName externalId emails.value active userType title` (Users), `startIndex` and `count` page
  (`count` at most 200), `attributes` and `excludedAttributes` select. Errors are SCIM's
  (`urn:ietf:params:scim:api:messages:2.0:Error`, `scimType` `invalidFilter` or `invalidValue`);
  answers are `application/scim+json`. Sorting, PATCH, bulk and ETags are not supported, and there
  are no write routes (`405`).
- Audit events `groups.member.batch` (and one `groups.member.*` per operation); reads, simulations and
  replays write only the `http.request` event.
- Parity fixtures `161`-`179` (`testdata/parity/README.md`).
- Tests: `internal/api` (`TestMembers_FiltersSearchSortAndPaging`, `TestMembers_Trace`,
  `TestBatch_AtomicAndIdempotent`, `TestBatch_NonAtomicReportsEachOperation`, `TestBatch_Validation`,
  `TestBatch_PrivilegesPerOperation`, `TestIdempotency_SingleMembershipRoutes`, `TestIdentityGroups`,
  `TestSimulate_*`, `TestGroupsOpenAPI_CoversRoutes`, `TestSCIM_*`, `TestGroupsAPI_Isolation`),
  `internal/groups/api` (filter, selection, key store and expiry, OpenAPI), `internal/store`
  (`TestIsolation_GroupsAPIStatements`, `TestSavepoint`, `TestIsolation_IdempotencyTable`).

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
| **Identity** | Users, Machine identities & agents, Groups (with an *All entitlements* tab), Applications, Accounts (with *Account matches*), Roles (Preview), Organizations (Preview) |
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
* **API parity.** `internal/api/parity_test.go` replays 179 golden request/response pairs (160 recorded from the Python backend, 19 for the groups API), in order
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
* `POST /api/hris/events` returns `422` for an `identity_id` that does not exist; `GET .../plan` returns `409` (not `500`) for a stored event whose identity is gone.
* A connector sync never undoes Tessera-side decisions: terminated identities, disabled accounts, executed HRIS events and
  grants revoked by a leaver plan, access review or least-privilege revoke (tombstones in `revoked_grants`) stay as they are.
* `add_edges[].duration_hours` simulates a time-boxed JIT grant, which never counts as standing access.
* Policies are embedded in the binary; set `TESSERA_POLICY_DIR` (run.sh does) to edit them live.

## Known gaps (MVP)

* No authentication or RBAC on the API or UI. Actor names on approvals and revokes are placeholders:
  the audit ledger records every request as `anonymous` and keeps the supplied name only as an
  unverified `claimed_actor`.
* The test sign-in of a requested IdP connection (`GET /api/auth/login?connection=…&test=1`, design §15.2)
  is not wired into the login flow yet: `admin.RecordTestLogin` records it and `POST
  /api/admin/idp-connections/{id}/activate` requires it, but a connection created by a change request stays
  `pending` until the login flow calls it (it needs a `test` purpose on `login_transactions`).
* Revokes and JML plans change Tessera's graph only. Nothing is written back to source systems.
  Connectors do not have a `provision()`/`deprovision()` interface yet.
* There is no scheduled connector sync. Seeding runs discovery once, and `POST /api/connectors/sync`
  re-runs discovery on demand.
* Effective-permission paths are capped at 8 per permission, and "lost if removed" uses those paths.
* AWS permissions are modelled as discrete actions on resources. IAM policy conditions, deny
  statements, SCPs and wildcard expansion are not evaluated.
* Delegated agent scopes are shown and compared with what the principal holds, but they do not
  narrow the agent's own effective permissions.
* SQLite and a per-request graph rebuild are fine for this demo but would not scale to large tenants.
