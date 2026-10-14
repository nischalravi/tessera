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
  cmd/tessera/          main: `serve` (default), `seed`, `audit verify|checkpoint|export` and
                        `notify seal-password`; timeouts, graceful shutdown, JIT sweeper, audit
                        checkpointer, notification dispatcher
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
    notify/             notification outbox, in-app inbox, email senders (dev sink, SMTP), dispatcher
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
`GET /api/jml/leaver-plan/{identity_id}` · `GET /api/accounts[?system=]` ·
`GET /api/audit[?limit=&before_seq=&action=&actor_id=&target_type=&target_id=&from=&to=&include_http=]` ·
`GET /api/audit/events/{event_id}/proof` · `GET /api/audit/checkpoints[?from_seq=]` · `GET /api/audit/keys` ·
`POST /api/audit/verify {from_seq?, to_seq?}` · `GET /api/audit/export[?from_seq=&to_seq=]` (NDJSON) ·
`GET /api/auth/session` · `POST /api/auth/logout` · `GET /api/auth/sessions` · `DELETE /api/auth/sessions/{session_id}` ·
`GET /api/correlation/queue` · `GET /api/correlation/decisions` ·
`POST /api/accounts/{id}/link {identity_id, reason}` · `POST /api/accounts/{id}/not-person {reason}` ·
`DELETE /api/accounts/{id}/link` · `POST /api/identities/{id}/merge {into, reason}` (202 and a request
when a second reviewer is needed) · `GET /api/identity-merges` · `POST /api/identity-merges/{id}/unmerge {reason}` ·
`GET /api/identity-matches[?status=review|reverification|decided|all&limit=]` ·
`POST /api/identity-matches/{match_id}/decide {decision: link|new_person|reject, reason}` ·
`GET /api/identity-merge-requests[?status=]` · `POST /api/identity-merge-requests/{id}/approve {}|reject {reason}` ·
`GET|PUT /api/admin/matching {auto_link_tier_b, require_review_tier_a, unmerge_window_days}` ·
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
`GET /api/identities/{identity_id}/access-bundle` · `GET /api/refgroups` · `POST /api/refgroups/reconcile` ·
`POST /public/t/{slug}/claim/start|verify/send|verify/check|existing-account|credential|resend|terms/accept|consent` ·
`GET /public/t/{slug}/claim/status|terms` (public: the guest's claim, see Guest claim) ·
`GET|POST /api/admin/terms {key, title, body, grace_days}` · `PUT /api/admin/terms/{key}/assignments {populations, bundles}` ·
`GET /api/me/terms` · `POST /api/me/terms/accept {documents: [{id, sha256}]}` · `POST /api/me/recovery-codes` ·
`POST /api/guests/{identity_id}/recovery {reason}` · `GET /api/guest-recoveries[?status=]` ·
`POST /api/guest-recoveries/{case_id}/cancel {reason}` (see Guest terms, consent and recovery) ·
`GET /api/guest-lifecycle` · `GET /api/guest-lifecycle/items[?bucket=]` · `GET /api/guest-lifecycle/tasks` ·
`POST /api/guest-lifecycle/tasks/{id}/resolve {action: accept|decline|keep|confirm|dismiss}` ·
`GET|PUT /api/admin/guest-lifecycle {sponsor_reminder_days, guest_reminder_days, transfer_deadline_days, on_sponsor_departure, conversion_dual_status, grace_days, retention_days, retention_days_visitor, keep_rematch_hashes}` ·
`POST /public/t/{slug}/guest/renewal-request {token}` (public, always 202; see Guest lifecycle) ·
`GET /api/approvals/inbox` · `GET /api/approvals/delegates` · `GET|POST /api/approvals/delegations` ·
`POST /api/approvals/delegations/{id}/revoke` ·
`GET /api/notifications[?unread=1&limit=]` · `POST /api/notifications/read {ids}|{all:true}` ·
`GET|PUT /api/notifications/preferences {prefs:{kind:channel}}` ·
`GET /api/email/messages[?status=&kind=&recipient=&limit=]` · `GET /api/email/messages/{id}` ·
`POST /api/email/messages/{id}/retry` ·
`GET /api/auth/discover?tenant=&email=` · `GET /api/auth/login?tenant=&connection=&return_to=` (302 to the IdP) ·
`GET /api/auth/oidc/{connection_id}/callback` · `GET /t/{slug}/bootstrap?code=` (public) ·
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
  account decisions, owned identities, reports and agent delegations to the identity kept, and
  since GU-5 also its source records, identifiers, affiliations, sponsorships, access bundle
  items, lifecycle record and pending access requests (see Identity matching and merging below).
  The merged identity gets status `merged`; syncs keep it merged and resolve references to it to
  the survivor. History (usage, reviews, decided requests, HRIS events) is not moved. Credentials
  never move: the merged person's sign-in users are disabled and their sessions ended (a user that
  holds a role blocks the merge until the role is removed). A merge where either person holds
  privileged access, has IAL 2 or more or is an employee needs a second reviewer.
- **Undo** (Merges tab) works for 180 days by default (the tenant can set another window, under
  Identity matches → Settings). It moves back every recorded row that still points
  at the survivor; rows changed since stay and are listed, and so are the rows created after the
  merge, which stay with the survivor (`created_after`). Merges into an identity that was
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
nothing: reconcile a role to see the rest. Not yet: provisioning into the target system (#103),
role mining (Phase 3), and ABAC conditions in rules (#162).

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
- **The end.** On the end date the sweeper runs the person's **leaver plan**: accounts are
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
   claimant. "No" continues. "Yes" is recorded on the intake (`existing_account`) and answers
   `{status:"redirect", redirect}`: a sign-in as that account at the tenant's identity provider (login
   purpose `claim`, recorded as a `claim_links` row, `prompt=login`, the sponsorship's AAL). The answer
   itself never links (K3). When the sign-in comes back and the person who signed in is one of the
   candidates the matcher found for this invitation, the intake is **linked by sign-in** (Tier A): the
   sponsorship, affiliations and bundle become theirs, no credential is created, the claim completes
   (`/claim?result=complete`). Otherwise nothing is linked and the claim goes on at step 4 as a new
   identity with the suspicion still in the review queue (`/claim?result=continue`, the same for every
   reason). Whether the matcher found anything never shows: every claimant gets the same question and
   the same answer.
4. **credential**: the guest is sent to the bound credential authority to sign in. The claim
   completes only on a sign-in at the sponsorship's required AAL, as the account that was set up for
   this claim, through that authority (§7.1): then identity `invited` → `active`, the sponsorship's
   affiliation `pending` → `active`, the intake `claimed`, the sponsor told (`guest.claimed`), and a
   **new platform user with no roles**, linked to the identity, whose external login is the
   `(issuer, subject)` of that sign-in (never the email), exists. Tessera creates no session for it.
5. With no authority configured (production today) the claim stops at step 4 with "your organization
   will finish setting up your sign-in" and stays pending. An IAL above 0 (IDV, GU-7) stops at
   `verify_identity`. The step list is `claim.Steps`. Step 5, terms and consent (GU-10), is a gate on
   step 4, not a step of its own: see "Guest terms, consent and recovery".

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
the tenant's database (`claim_proof_uses`, schema `0228_claim_proofs.sql`), so it holds across
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
`/claim?result=complete|failed|continue`. The Vite dev server proxies `/public/t`.

**Rate limits** (`internal/ratelimit`, in process, token buckets of N per window; throttles are
audited as `claim.throttled` without a token or code): start 10 per IP per 10 minutes (client IP as
the API's rate limiter, trusting `TESSERA_TRUSTED_PROXIES`) and 100 per tenant per minute (429; no
bot challenge yet); verify/send 3 per session per 10 minutes, 5 per address per hour, 10 per day
(the answer is the same when throttled); verify/check 5 tries per code; resend 3 per address per day.

**Audit actions:** `claim.invitation.issue|revoke|expire`, `claim.start`, `claim.start.refused`,
`claim.code.send|failed|locked`, `claim.verify_contact`, `claim.existing_account`,
`claim.credential.start|pending|failed`, `claim.complete`, `claim.link`, `claim.link.failed`, `claim.throttled`,
`claim.proof.rejected`.

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

**Deferred:** identity verification and IAL above 0 (GU-7), real
credential authorities, passwords, MFA enrolment, the Tessera-hosted service (GU-8), SMS codes, claim codes for letters, a bot challenge, and shared (multi-node)
rate-limit state. Parity fixtures are unchanged. After pulling this change run `./run.sh --reseed`:
it adds the claim tables and three columns to `intake_records`, widens its `invitation_status` check
and allows the login purpose `claim`.
themselves. Not yet: provisioning into the target system (#103), business roles (#161).

### Identity matching and merging

Issue #68 (GU-5; design `docs/design/guest-accounts-and-claim.md` §5, §6.5, §9). Code:
`internal/identity/match` (the matcher), `internal/correlation` (the merge engine of #160, extended: there
is no second engine), `internal/identity/merge` (policy around it), `internal/api/matching.go`, schema
`0230_matching.sql`, the page `frontend/src/features/directory/IdentityMatches.tsx`.

**Matcher.** Names are normalized (Unicode NFKC, case folding, diacritics removed, "given family" and "family
given" order, preferred names) and compared with Jaro-Winkler (tested against the published reference values).
Tiers (§5.3) and the rules that fire: **A** exact (the same source record already linked, the same authoritative
identifier in two sources, the same federated `(issuer, subject)` already bound, or the claimant signed in as the
person), **B** strong (verified email, date of birth and name similarity 0.92 or more), **C** possible (name 0.85 and
date of birth, the same verified email, the same verified phone), **D** none. A date of birth is kept only as a keyed
hash (`dob_key` in a source record), and a day-and-month transposition still compares equal. Modes: *authoritative*
(HRIS, SIS: Tier A auto-links, Tier B only if the tenant allows it and both sides are authoritative, otherwise review),
*self-asserted* (sponsor invitations: **never auto-links**; a match is a "suspected existing person" flag),
*federated* (an existing binding auto-binds). Every result is a `match_results` row with the tier, score, the rules
fired and the attributes compared **masked**, so "why did this match" is answerable for every link. Sponsor
invitations (single and bulk) run the matcher; nothing the sponsor sees depends on it. The matcher is exposed in
authoritative mode and tested, but no authoritative intake path exists yet (SIS/HRIS intake is GU-4). A national-identifier
rule is deliberately absent (design §13.4 is open); `match.NationalIDRule` marks where it would go.

**Review queue.** Directory → Users → **Identity matches** (`/directory/identity-matches`; the Inbox shows a banner with
the count): one item per intake with the candidates side by side with the invited person, masked attributes, the
rules that fired, the candidate's affiliations, privileged access and IAL, and the decision with a reason:
**link**, **new person**, **reject intake** (the invitation and sponsorship end). Tabs: To review, Second reviewer,
Waiting for sign-in, Decided, Settings. The seeded demo tenant has one item: `./run.sh --reseed`.

**Four eyes.** A merge, or a reviewer's link, where either person holds privileged access, has IAL 2 or more (recorded, or
an HR or student record, vetted at hire) or is an employee does not apply when asked. It becomes a pending
`identity_merge_requests` row (HTTP 202) that a **different** reviewer approves or rejects (the requester can withdraw
it); a self-approval is refused by the API and by the table. A link by sign-in is proof of possession and needs none.

**Reverification (§5.5.3).** A reviewer's link needs the claimant at the existing person's IAL. While the claimant's IAL
is lower nothing is linked and no access is granted: the decision is recorded as `reverification_required` and completes
when the claimant signs in as the existing person (the claim's "yes" step). An IAL 2 employee is never linked to someone
who proved only email control.

**What a merge does.** One transaction, one ledger entry listing the moves (`identity.merge`): the engine moves the
rows (each recorded so an unmerge restores it); the merged person's sign-in users are disabled and sessions ended
(credentials never transfer; the survivor's are untouched; a user with a role blocks the merge); both people's contact
channels are told through the notification outbox (a security alert that names no one); the intakes' claim links stop
working; bundle memberships follow the moved accounts and waiting bundles are granted, and the reference groups are
recomputed, through `internal/guests/access` (`access.Merged`). Unmerge replays the moves in reverse within the window,
recomputes both people and lists what was created since. A merge is refused when it would make a person their own sponsor.

**Deviations and follow-ups.** The groups engine (GR-1/GR-2) is not built, so group memberships move through the
GU-12 access code instead; one ledger entry lists all moves instead of one event per moved item; routes use `/decide`,
`/approve`, `/unmerge` path segments like the rest of the API, not the design's colon actions. Follow-ups: the TAP ID
Match-compatible endpoint (`PUT /match/api/1/v1/people/{sor}/{sorid}`, tenant flag, needs a reference-id table and a
choice of intake channel), a "this wasn't me" link in the merge notification (a public freeze endpoint and incident),
wiring the matcher to SIS/HRIS intake (GU-4), the national-identifier rule, and a blocking index for large tenants (the
matcher scans every person per intake, once per bulk file).

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

### Job run history

Every run of a connector sync, provisioning (HRIS execute), connection validation, dry run,
deployment-health re-run, JIT sweep and guest lifecycle sweep is recorded in `job_runs` (`internal/jobs`), plus every
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

### Guest access: bundles and reference groups

Issue #75 (GU-12, design §8.2 and §9.3). The groups engine (GR-*) is not built, so these run on Tessera
itself and move into the groups engine when GR-1/GR-2 land.

- **Bundles.** The catalog items chosen at invite are recorded per sponsorship (`guest_bundle_items`, state
  pending / granted / failed / removing / removed) when the sponsorship becomes active, and granted when the
  claim completes (at once for a guest who is active already). For each system the bundle touches: with
  write-back on, a `create_account` operation (key `guest:<sponsorship>:<system>:account`) if the guest has no
  account there, then `add_entitlement` (`guest:<sponsorship>:<group>:add`), source `guest`. The membership edge
  is written by the operation's completion only after the re-read shows it; a failed or mismatched operation
  leaves no edge. With write-back off the account and edge are written directly. The edge has source
  `guest_sponsorship`, its source_ref is the bundle item (the sponsorship), and it expires at the sponsorship's
  end date (the graph drops it on time). Renewing extends it. Ending, revoking, a lapsed transfer or the end date
  removes that sponsorship's memberships (`remove_entitlement` when write-back is on) unless another live
  sponsorship of the guest still needs the group, so each sponsorship ends independently. Accounts are disabled
  only when the last sponsorship ends, by the lifecycle leaver plan, which leaves the bundle's edges to the removal.
  The sweeper reconciles what events missed. The state of each item is in the sponsorship view (Guests I
  sponsor), on the person's page (Affiliations tab, `guests.read`) and the operations link back by
  `sponsorship_id` in Admin, Provisioning.
- **Reference groups.** System `tessera`, kind `reference`: `ref:guest:active|visitor|contractor|volunteer`,
  `ref:partner:active`, `ref:ial:2`, `ref:sponsor:eligible`. Membership is derived from affiliations, identity
  status (only claimed, active people count), assurance and the sponsor policy, and recomputed on affiliation,
  claim and sponsorship changes and by the sweeper; edits by hand (or an access review revoke) are undone. They
  appear in Groups and access reviews, policies can name them, and they are never provisioned. Not built:
  `ref:applicant|admit|prehire` (need SIS/HRIS intake, GU-4) and `ref:partner:<org>` (partner orgs, GU-14).
  People from the HR or student system count as IAL 2; guests use the assurance recorded at claim
  (`identity_assurance`, IAL 0 today; the step-up that raises it is GU-7/GU-8).
- **Guest requests.** A catalog item is open to guests only if it names their population (`populations` on
  `PUT /api/catalog/items/{group_id}`). Approval goes to the guest's sponsor first (`sponsor` stage), then the
  item's owner (or deciders). Privileged or high-risk items need IAL 2: a guest below it is refused with
  `step_up_claim_required` (the step-up claim itself is not built).
- **Not here.** Sponsor attestation campaign (needs frozen-population reviews, #110), Grouper external-subject
  import (GR-15), policy groups as code (GR-9). Schema changes: new tables in `0229_guest_access.sql` and the
  `sponsor` stage kind in `0206_approvals.sql`; reseed existing databases (`./run.sh --reseed`).
- **Try it** with the dev fake target: `TESSERA_DEV_FAKE_TARGET=1`, Admin, Provisioning, set the Okta target to
  kind `fake` with write-back on; put an Okta group in the catalog; invite a guest with it in the bundle; claim;
  watch the operations verify and the item turn Granted.

### Guest lifecycle

Issue #74 (GU-11, design §8). Code: `internal/guests/lifecycle` (the jobs), `internal/guests/sponsorship`
(renew with step-up, take over, end or suspend, return). Tables in `schema/0231_guest_lifecycle.sql`
(`guest_lifecycle_settings`, `guest_reminders`, `guest_renewal_tokens`, `guest_lifecycle_tasks`,
`sponsorship_stepups`, `guest_deprovisioning`); `suspended` joined the sponsorship statuses and events in
`0227_sponsorships.sql`, so reseed existing databases (`./run.sh --reseed`). The jobs run in the sweeper
(every tick, each step in its own transaction) and are recorded as `guest_lifecycle` runs in Admin → Jobs when
they did something or failed. Every change is audited in its own transaction; the audit ledger itself is never
modified.

- **Settings** (tenant, `GET|PUT /api/admin/guest-lifecycle`, `guest_lifecycle.configure`, policy admins;
  Governance → Guest lifecycle → Settings). Defaults: sponsor reminders at 30, 14 and 3 days; guest reminder at
  14 days (0 turns it off); transfer deadline 14 days; `on_sponsor_departure` `end` (or `suspend`);
  `conversion_dual_status` `end` (or `sponsor_confirms`); grace 0 days for visitors and 30 for contractors,
  volunteers and partners; retention 2555 days (7 years) for anyone who held access, 365 days for a visitor who
  held none; `keep_rematch_hashes` off. Per connection, Admin → Provisioning has *on deprovision*:
  `disable` (default, the account stays disabled) or `delete` (a verified `delete_account` after the grace period).
- **Reminders.** `guest_reminders` holds one row per (sponsorship, end date, audience, threshold), written before
  the message in the same transaction, so each goes out once across sweeps and restarts; a renewal moves the end
  date and re-arms them. A sponsor gets the bucket they are in (30, 14 or 3 days). The guest (active, with an
  address; needs `TESSERA_PUBLIC_URL` and the identifier key) gets a mail with a one-time "request renewal" link
  `/renew#t=<token>`: only its SHA-256 is stored and the link is handed to the mailer through memory only (like
  the claim link). `POST /public/t/{slug}/guest/renewal-request {token}` spends the token once and opens a
  renewal-request task for the sponsor; every call (good, bad, spent, unknown tenant) answers the same `202
  {"status":"received"}` after the same minimum time, with an Origin check and a per-tenant rate limit.
- **Renewal and step-up.** Renewal re-runs the sponsor policy (eligible, within limits, at most the maximum).
  If the guest's `identity_assurance` is below what the sponsorship now needs (its own requirement, the
  population default, the bundle minimum) the renewal is **recorded and held** (`sponsorship_stepups`, event
  `stepup_required`, the sponsorship view's `stepup`): nothing extends. When the assurance is recorded at that
  level (after a claim completes, or by the sweeper) the renewal is applied under a fresh policy check, or
  cancelled if it can no longer stand. *Not built:* the guest's step-up claim itself (a claim session for an
  active guest, `claim_tokens.purpose = renewal_stepup`, and identity verification at IAL 2, GU-7): today the
  assurance rises only through the claim; this is the missing piece.
- **Sponsor leaver or mover.** Executing an HRIS leaver or mover event for a sponsor, or the sweeper finding a
  sponsor who is no longer eligible, opens a `sponsor_transfer` task per active sponsorship, with a deadline
  (the transfer deadline, never past the sponsorship's end). The sponsor's manager and the holders of
  `sponsorships.approve` are notified (kind *Guest lifecycle task*; Inbox banner; Governance → Guest lifecycle →
  My tasks). **Take over** moves the sponsorship to the person acting under a fresh policy check; **keep** (movers)
  leaves an eligible sponsor in place; **decline** and the deadline end the sponsorship or, by setting, **suspend**
  it (`suspended`: no access, affiliation ended, not final; a sponsor admin ends it, or it ends at its end date).
  Until the deadline the sponsorship stands under the departed sponsor; at the deadline nothing is left without
  a living sponsor or without a decision. Only the departed sponsor's manager and sponsor admins see and decide
  these tasks (others get 404).
- **Several sponsorships.** The person stays active until the last one ends; each bundle ends independently
  (`TestExpiry_LastSponsorshipEndsIdentity`, `TestBundle_TwoSponsorshipsEndIndependently`).
- **Conversion.** An HR or student employee affiliation that appears on an identity with a running guest
  sponsorship (after a merge, GU-5) ends the sponsorship at the hire date, or with `sponsor_confirms` asks the
  sponsor (task `dual_status`; ends at the deadline unless confirmed). The person stays one identity and keeps
  every history; the lifecycle becomes employee instead of ending; a `conversion` sponsorship event and a
  `jml.conversion` audit event record it. Employee to guest: a person who left (terminated, deprovisioned, not
  purged) can be sponsored again; they are revived on the same identity, with a new guest affiliation next to the
  ended employee one. Applicant, admit and pre-hire conversions need SIS/HRIS intake (GU-4) and are not built.
- **Deprovisioning.** When the last sponsorship ends the lifecycle leaver plan runs as before (memberships and
  grants end, accounts disabled through provisioning, verified by re-read). The sweeper then starts the grace
  period (`guest_deprovisioning`), revokes the person's sign-in sessions, and after the grace period, once every
  operation that ended their access is verified, deletes accounts where the target says so, reassigns the
  ownership they still hold (NHI owners, secrets, delegations, reports: the leaver plan's steps) and sets the
  identity `deprovisioned`. A failed or unverified operation holds the person in grace (shown as blocked).
- **Purge.** After the retention period the identity becomes a tombstone (`purged`): the id, affiliation history,
  lifecycle and dates stay; name, email, department, title, identifiers (`value_norm` always; the keyed hash
  only when `keep_rematch_hashes`), source-record attributes, the linked sign-in user's name and email, and the
  notifications and email log rows addressed to the person are nulled or redacted. The `guest.purge` audit event
  lists counts, never values. A purge is idempotent. **The audit ledger is append-only and is not minimised
  here; ledger PII minimisation is a follow-up**, as are notifications about the guest sent to others and the
  claim tokens' keyed email hashes (those rows are immutable). A person who returns within retention is matched
  (Tier A on a federated binding or authoritative identifier, or by sign-in) and gets the same identity back; after
  a purge only when hashes were kept.
- **Governance → Guest lifecycle** (`/governance/guest-lifecycle`, `guests.read`): counts and lists for ending in
  30, 14 and 3 days, renewal requests, step-up required, pending transfer, ended by sponsor departure, suspended,
  dual status, in grace, deprovisioned and purged, a side panel per row, My tasks and (policy admins) Settings.
  `./run.sh --reseed` adds a contractor ending in 10 days and one whose sponsor left (a pending transfer).
  RBAC: `guests.read` for the page, `guests.sponsor` for tasks (the service decides who may act),
  `guest_lifecycle.configure` for settings.

### Guest terms, consent and recovery

Issue #73 (GU-10; design `docs/design/guest-accounts-and-claim.md` §7.4, §7.5). Code:
`internal/guests/terms` (documents, acceptance, consent), `internal/guests/claim/{terms,recovery}.go`,
`internal/notify/recovery.go`, `internal/api/terms.go`, schema `0232_terms_recovery.sql` (`terms_documents`,
`terms_assignments`, `terms_acceptances`, `attribute_consents`, `recovery_cases`, `recovery_codes`; reseed
existing databases with `./run.sh --reseed`, which also lets `claim_sessions.step` hold `verify_identity`).
Every change is audited in its own transaction (`terms.publish|assign|accept`, `consent.attributes`,
`recovery.issue|cooling_off|complete|cancel`, `recovery.codes.generate`, `recovery.code.use`; never a token or a code).

**Terms.** A document has a key and numbered versions; each version stores its text and the SHA-256 of that text.
A document is assigned to guest populations and to access bundles (a bundle is the group of a catalog item); it
applies to a guest whose live sponsorship has that population or carries that item. `GET|POST /api/admin/terms` list
and publish (`terms.manage`, step-up; the same text twice is `409 unchanged`), `PUT /api/admin/terms/{key}/assignments`
replaces where it applies. **Claim step 5:** while a document that applies is not accepted the claim status says
`pending: "terms"`, `POST claim/credential` answers `409 terms_required`, and the OIDC callback refuses to bind
(`terms_not_accepted`), so acceptance always comes before a credential. `GET claim/terms` returns each text with its hash;
`POST claim/terms/accept` takes `{id, sha256}` of what the guest saw (a changed text is `409 terms_changed`) and writes
`terms_acceptances` (document, version, hash, time, claim session, keyed hashes of the client address and user agent) and the
audit event in one transaction. **New version:** a person who accepted version N must accept N+1 within the document's
`grace_days` (from its publication; for a document first assigned later, from the assignment); `GET /api/me/terms` shows
`accepted | grace | blocked` and `POST /api/me/terms/accept` accepts. After the grace period every route except
`/api/auth/*` and `/api/me/terms*` answers `403 terms_required` until they accept (the check runs in `authorize`, and
reads nothing for a tenant with no terms). A guest who links to an existing person by signing in (step 3) skips step 5
and meets the same check at their next request.

**Attribute-release consent.** For a federated authority (`home_idp`, `incommon`, `edugain`; none is built yet, GU-8/9) step 5
also shows what the home IdP releases and why (`GET claim/terms` → `consent`); `POST claim/consent {attributes}` records the
choice (the required attributes are always included) in `attribute_consents` and the ledger, once per claim session. Other
authorities show no consent screen.

**Recovery.** `POST /api/guests/{identity_id}/recovery` issues a `purpose=recovery` claim token for an active guest. The
caller is the guest's live sponsor (`via: sponsor`) or holds `guests.recover` (operator, policy admin: the help desk,
`via: help_desk`); a new recovery cancels the open one. The link goes to the guest's address only; **every channel on file**
gets a `guest.recovery` notice (the guest's address, each active sign-in user by email and inbox, the sponsor). The person
opens the link (same `/claim` page, `purpose: "recovery"` in the status), confirms the address, and must **re-verify at the
identity's recorded IAL** (the higher of `identity_assurance.ial` and the sponsorship's: IAL above 0 waits at
`verify_identity` until GU-7, there is no downgrade). The new sign-in is then added to the existing platform user (a sign-in
that belongs to another user is refused). An identity holding a privileged or high-risk bundle waits a **24 hour
cooling-off**: the callback answers `/claim?result=cooling_off`, the credential is held in the case (`recovery_cases`), every
channel is told, and the sweeper binds it when the time is up (`recovery.complete`; the user's sessions end).
`POST /api/guest-recoveries/{case_id}/cancel` stops a recovery at any time before that (same caller rule);
`GET /api/guest-recoveries` lists cases (`guests.read`).

**Recovery codes.** For identities of the Tessera-hosted credential service (`Authority.Kind() == "hosted"`, GU-8 builds it)
`POST /api/me/recovery-codes` returns 10 single-use codes once (`Cache-Control: no-store`); only a tenant-keyed hash of each
is stored, a new batch voids the old one, and `claim.Service.UseRecoveryCode` spends one atomically.

**UI:** the claim page shows the terms and consent screen (`TermsStep`); Governance → Guest terms lists documents, publishes
a version and sets the populations (GU-13 does the full UI). Tests: `go test ./internal/api -run 'TestTerms|TestRecovery|TestClaim_Consent'`,
`./internal/guests/terms`, `./internal/store -run Terms`; `npm test` covers the claim model.

**Deferred:** wiring a recovery code into the hosted service's sign-in (GU-8), identity verification itself (GU-7),
the full admin and help-desk UI (GU-13), GDPR lawful-basis text per attribute for EU partners, and an acceptance screen
outside the claim for a guest already blocked (they accept through `/api/me/terms`).

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
palette), and on the right the Inbox with its count, the notification bell (unread count, the
latest notifications, mark all as read, and **All notifications and settings**), settings (theme: light, dark or match system), help (shortcuts) and the user menu with the
tenant name and the persona switcher.

**Left rail** (236px, light). Active items are white with a blue left indicator; counts sit on
the right. Arrow keys move between items.

| Group | Items |
|---|---|
| (top) | **Home**, **Inbox** (count) |
| **Identity** | Users (with *Identity matches*), Machine identities & agents, Groups (with an *All entitlements* tab), Applications, Accounts (with *Account matches*), Roles (Preview), Organizations (Preview) |
| **Identity** | Users, Machine identities & agents, Groups (with an *All entitlements* tab), Applications, Accounts, Roles, Organizations (Preview) |
| **Access** | Request access, My access (with *My requests*), Guests I sponsor (invite, bulk invite, renew, transfer, approvals), Just-in-time, Access reviews (with *Lifecycle*, *Guest lifecycle* and *Workflows* tabs) |
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

**Preview features.** Some screens have no backend endpoint yet: organizations,
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
Tessera signs users in through their company's identity provider (OIDC: see
[Sign-in through the IdP](#sign-in-through-the-idp-oidc); SAML arrives in PR9); the UI switches to that
flow in PR7. Until then a development server (`TESSERA_ENV=dev` or `test`,
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

With `./run.sh`, http://localhost:5173/api/auth/login?tenant=larkspur signs in through the dev IdP (the
seed seals its client secret, `DEVIDP_CLIENT_SECRET`, default `tessera-dev-secret`, into the `dev_mock`
connections). The UI's sign-in page switches to this flow in PR7.

**A new tenant** is created by an operator (design §15.3); every step is audited as the OS user:

```bash
cd server
TESSERA_ENV=dev go run ./cmd/tessera admin create-tenant -slug acme -name "Acme Corp"
TESSERA_ENV=dev go run ./cmd/tessera admin add-idp -tenant acme -file okta.yaml -client-secret-file okta.secret
TESSERA_ENV=dev go run ./cmd/tessera admin invite-admin -tenant acme -connection <id> -email jane@acme.example
```

`add-idp` reads a connection file (§18.2; unknown keys are refused, secrets are never in it; OIDC with
`client_secret_basic` for now) and prints the redirect URI. `invite-admin` prints a one-time
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
  `TESSERA_OUTBOUND_ALLOW_LOOPBACK=true`, the dev mail sink (`TESSERA_NOTIFY_EMAIL=dev`), SMTP
  without TLS, a `TESSERA_DEV_IDP_URL`, a missing or `file://`
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
