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

Requirements: Python 3.11+ (tested on 3.13), Node 18+ (tested on 24), npm.

```bash
./run.sh             # first run: creates venv, installs deps, seeds DB, starts API + UI
./run.sh --reseed    # reset the demo data
./run.sh test        # pytest suite
./run.sh build       # tsc + vite production build
```

* UI: http://localhost:5173 (Vite dev server; it proxies `/api` to the backend)
* API: http://127.0.0.1:8000. OpenAPI docs are at http://127.0.0.1:8000/docs

Ctrl+C stops both processes. You can change the ports with `API_PORT=… UI_PORT=… ./run.sh`.

## What the demo shows

| Area | Where | Highlights in the seed data |
|---|---|---|
| Effective permissions with paths | Directory → a person, Insights → Access graph | Alice reaches `customer-pii` through Okta `engineering` → AWS `DevAdmin`. The graph explorer highlights upstream and downstream paths when you click a node, and "Who can access…" works in reverse from a resource. |
| Usage-based least privilege | Insights → Least privilege | Grants that are **safe to remove** (nothing they uniquely provide was used in N days). **Role trims**: no one of 17 engineers has used `DevAdmin → s3:GetObject customer-pii`. **Right-size** suggestions. Every revoke runs a dry run first that shows the blast radius: identities affected, permissions lost, which of those were used in the last 30 days, and which violations are resolved or introduced. |
| NHIs & AI agents | Directory → Machine identities & agents | Orphaned keys (`svc-legacy-etl`, `old-migration-token`), owners who have left (`jenkins-pat`, `LOOKER_SVC`), stale secrets (a 780-day-old access key). For agents: the delegation chain owner → agent → on-behalf-of, tool scopes, and "agent holds permissions its principal doesn't". |
| Just-in-time access | Access → Just-in-time, Inbox | Time-bound role grants with approve, deny and revoke. A background sweeper expires them automatically (every 30 s, and also on each request). JIT paths never count as standing access. |
| Policy-as-code + simulation | Governance → Policies & violations, Insights → SoD conflicts | YAML policies in `backend/policies/`: SoD on payments, no standing prod admin, AI agents may not reach PII, NHI ownership, secret age, and leavers keep no access. The what-if simulator adds or removes grants on a copy of the graph and diffs effective permissions and violations. |
| Exception-only access reviews | Inbox, Governance → Access reviews | Out of 219 grants, about 62% are auto-certified from usage evidence. Reviewers see only unused, violating, orphaned, leaver or idle-privileged access, with usage and peer-coverage context. A revoke decision applies to the graph. |
| Joiner / mover / leaver | Inbox, Governance → Lifecycle | Simulated Workday feed. The leaver plan for Marcus disables accounts, removes grants, re-homes the AI agent and service account he owned, rotates their secrets and revokes delegations. For historical leavers it shows the access the legacy process missed (Oren still has an active Okta account) and offers one-click cleanup. |

## Architecture

```
backend/
  tessera/
    connectors/
      base.py           Connector ABC (discover(), stream_events()) + normalized record types
      demo_company.py   deterministic fictional company model
      demo.py           Demo{Workday,Okta,AWS,GitHub,Snowflake}Connector
      registry.py       TESSERA_CONNECTORS selection / factories
    ingest.py           phased, idempotent upsert of connector output (cross-system refs resolve)
    models.py           SQLAlchemy models (identities, accounts, groups, permissions, resources,
                        grant_edges, secrets, delegations, usage_events, JIT, reviews, HRIS, audit)
    graph.py            GraphSnapshot (networkx DiGraph): effective permissions + all grant paths,
                        copy-on-write for simulation, expired-JIT / disabled-account handling
    usage.py            last-used / 90-day usage index
    policies.py         YAML policy loader + evaluators (sod, no_standing_access, forbidden_access,
                        secret_max_age, nhi_ownership, terminated_with_access)
    simulate.py         what-if engine: apply edits to a snapshot copy, diff perms + violations
    leastpriv.py        grant-level and role-level recommendations
    nhi.py, jit.py, reviews.py, jml.py, audit.py
    api/app.py          FastAPI routes under /api
    seed.py             python -m tessera.seed
  policies/*.yaml       policy-as-code
  tests/                pytest (graph, policies, simulation, least privilege, JIT, JML, API smoke)
frontend/               React 18 + Vite + TypeScript, react-router, cytoscape.js, lucide-react
  src/
    api.ts              the single API client (typed responses, cached useApi hook)
    app/                shell, routes, sidebar nav, command palette, global search, theme, persona
    components/         shared primitives: Button, Badge, DataTable, Dialog, Drawer, Menu, Toast, Page...
    features/<section>/ one folder per sidebar section (home, inbox, access, directory,
                        insights, governance, admin)
    mocks/              typed Preview data for features with no backend endpoint yet
```

Design notes:

* **One edge table.** Every grant (membership, role mapping, role→permission, direct grant, JIT)
  is a row in `grant_edges` with `src`/`dst` node keys such as `account:12` and `group:7`.
  Revoking, JIT, reviews and simulation all work on this table, so they work the same way in
  every system.
* **The graph is recomputed for each request** from SQLite. That takes about 30 ms for about 90
  identities, 400 edges and 730 effective permissions. Expired JIT edges and disabled accounts
  are excluded at build time. This is fine for an MVP. At larger scale you would cache the
  snapshot and invalidate it on writes, or update it incrementally.
* **Policies run against a `GraphSnapshot`**, not the database, so the same evaluators handle
  live state and simulated state.
* **Usage events** are stored as daily aggregates per (identity, permission). A real connector
  would map CloudTrail, Okta System Log, GitHub audit log and Snowflake `ACCESS_HISTORY` events
  onto these.

### Main API endpoints

`GET /api/summary` · `GET /api/identities[?type=&q=]` · `GET /api/identities/{id}` ·
`GET /api/graph?identity_id=|resource_id=` · `GET /api/nhi` ·
`GET /api/least-privilege/recommendations?unused_days=60&kind=remove|right_size|role_trim` ·
`POST /api/least-privilege/revoke {edge_id, dry_run}` · `GET /api/policies` · `GET /api/violations` ·
`POST /api/simulate {remove_edge_ids, add_edges:[{src,dst}], disable_account_ids}` ·
`GET|POST /api/jit/requests` · `POST /api/jit/requests/{id}/approve|deny|revoke` ·
`GET|POST /api/reviews/campaigns` · `POST /api/reviews/items/{id}/decision` ·
`GET|POST /api/hris/events` · `GET /api/hris/events/{id}/plan` · `POST /api/hris/events/{id}/execute` ·
`GET /api/jml/leaver-plan/{identity_id}` · `GET /api/accounts[?system=]` · `GET /api/audit`

## Web UI

The UI is organised around jobs rather than object types. The left sidebar (collapsible to icons,
a drawer below 860px) has seven sections:

| Section | What it is for |
|---|---|
| **Home** | Changes with the persona chosen in the user menu (a demo stand-in until sign-in exists). Employee: what is waiting on you, your access, request access. Manager: adds team approvals and review progress. Admin & security: risk KPIs and the riskiest identities. |
| **Inbox** | One queue for JIT and catalog approvals, access-review items, joiner/mover/leaver tasks and delegations. Filter chips, a detail panel with usage context, bulk actions, and keys: `j`/`k` move, `a` approve or keep, `d` deny, `r` revoke, `x` select, `?` help. |
| **Access** | Request access (catalog of roles, entitlements and JIT-eligible access with a cart, for yourself, someone else or several people, with duration, justification and a risk/SoD preview), My access, Requests (history and drafts), Just-in-time. |
| **Directory** | People, Machine identities & agents, Accounts, Roles, Entitlements, Applications & systems, Organizations, Groups. Every list has search, filters, saved views, bulk select, CSV import and export, and a **New** button. Rows open an object page with an action bar (for a person: Disable, Reset password, Edit, Request access for, Start review). |
| **Insights** | Risk overview, Access graph, Least privilege, SoD conflicts. |
| **Governance** | Policies & violations, Access reviews, Lifecycle, Workflows. |
| **Admin** | Searchable settings cards. Connections, Jobs and Audit log are live; the rest describe what they will do. |

Routes from the previous UI (`/identities`, `/graph`, `/nhi`, `/jit`, `/policies`, `/reviews`,
`/lifecycle`, `/least-privilege`) redirect to their new homes.

**Command palette.** Press `⌘K` (macOS) or `Ctrl+K` anywhere. It fuzzy-searches pages, people,
machine identities, roles, entitlements and apps, and runs actions such as *Request access*,
*Disable user…*, *Reset password…*, *Start access review*, *Approve pending requests*,
*Open graph for…*, *Create role* and *Import users*. Actions ending in `…` ask for an identity
next. Choosing a person shows actions for them. Use the arrow keys, `Enter`, `Backspace` to go
back a step and `Esc` to close. `/` focuses the top-bar search.

**Preview features.** Some screens have no backend endpoint yet: business roles, organizations,
workflows, catalog (non-JIT) requests, delegations, disable / reset password / edit, imports and
most admin settings. They run on typed mock data in `src/mocks/`, keep their state in the
browser's localStorage, and carry a **Preview** badge. To wire one up, add a function to
`src/api.ts` that returns the same type and remove the badge.

**Theme and accessibility.** Light and dark themes follow the OS setting by default, with a
toggle in the top bar. Focus rings are always visible, controls are labelled, motion is reduced
when the OS asks for it, and the layout works down to about 400px wide.

**Bundle.** Every route is lazy-loaded. The main chunk is about 85 kB gzipped; cytoscape
(about 146 kB gzipped) only loads with the access graph.

## Adding a real connector

1. Subclass `tessera.connectors.base.Connector`:

   ```python
   class OktaConnector(Connector):
       system = "okta"
       display_name = "Okta"

       def __init__(self, org_url: str, token: str): ...

       def discover(self) -> DiscoveryResult:
           r = DiscoveryResult()
           for u in self._paged("/api/v1/users"):
               r.accounts.append(AccountRecord("okta", u["id"], u["profile"]["login"],
                                               IdentityRef(email=u["profile"]["email"]),
                                               status="active" if u["status"] == "ACTIVE" else "disabled"))
           for g in self._paged("/api/v1/groups"):
               r.groups.append(GroupRecord("okta", g["id"], g["profile"]["name"]))
               for m in self._paged(f"/api/v1/groups/{g['id']}/users"):
                   r.edges.append(EdgeRecord(Ref("account", "okta", m["id"]),
                                             Ref("group", "okta", g["id"]), "member_of"))
           return r

       def stream_events(self, since=None):
           for e in self._paged("/api/v1/logs", since=since):   # System Log
               yield UsageRecord(IdentityRef(email=e["actor"]["alternateId"]), Ref("perm", "okta", ...), day, 1)
   ```

2. Identities are correlated by `IdentityRef(external_id=…)` first and then by email. Cross-system
   edges, for example an Okta group mapped to an AWS role through SAML, are emitted by whichever
   connector can see them, using `Ref(kind, system, external_id)`. Ingestion runs in phases, so
   the order of connectors does not matter.
3. Register a factory in `connectors/registry.py` (`FACTORIES["okta"] = lambda: OktaConnector(...)`)
   and run with, for example, `TESSERA_CONNECTORS=demo-workday,okta,demo-aws,...`. You can replace
   demo connectors one system at a time.
4. `tests/conftest.py::TinyConnector` is a minimal working connector you can use as a template.

## Known gaps (MVP)

* No authentication or RBAC on the API or UI. Actor names on approvals and revokes are placeholders.
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
