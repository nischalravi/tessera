# IGA feature coverage checklist (for customers moving from Saviynt)

| | |
|---|---|
| Status | Draft for review |
| Author | iam-architect, with iam-governance-expert |
| Date | 2026-10-09 |
| Purpose | Make sure Tessera covers every capability a Saviynt Enterprise Identity Cloud customer uses day to day, so a migration has no missing feature. |

**How to read this.** One row per capability, as observed in a 2026 Saviynt EIC tenant. Capability names are generic descriptions, not the vendor's screen names or branding. **Section** is where the capability lives in Tessera's redesigned UI (Home, Inbox, Access, Directory, Insights, Governance, Admin; branch `ui-redesign`). **Phase** is the capability-map phase in [`docs/knowledge/README.md`](../knowledge/README.md); rows marked *new* were added to the map by this work.

**Status.**

- **have**: works today against demo data in the MVP (Python on `dev`, ported to Go on `go-backend`).
- **partial**: modelled but simplified, or the screen exists as a *Preview* in `ui-redesign` without a backend.
- **planned**: in the capability map or in a design doc, not built.
- **gap**: not in the capability map before this review; a new map row now covers it.

---

## 1. Checklist

### 1.1 Home and My Access

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 1 | Request access for yourself from a catalog (roles, entitlements, apps) with a cart | Access → Request access | partial (JIT requests have a backend; catalog is Preview) | 2 |
| 2 | Request access on behalf of another person | Access → Request access | partial (Preview) | 2 |
| 3 | Request for several people at once (multi-user request) | Access → Request access | partial (Preview) | 2 |
| 4 | Request enterprise (business) roles | Access → Request access | partial (business roles are Preview) | 2 |
| 5 | Saved requests and request templates, drafts | Access → Requests | partial (drafts in browser storage only) | 2 |
| 6 | Request history and status tracking | Access → Requests | partial | 2 |
| 7 | Pending requests and approvals queue | Inbox | have (JIT approve/deny/revoke) | 2 |
| 8 | View existing access, with how each grant was obtained | Access → My access | have (effective permissions with paths) | 1 |
| 9 | Request removal of your own access | Access → My access | partial | 2 |
| 10 | Home dashboard by persona (employee, manager, admin) | Home | have (persona switcher, demo) | 2 |

### 1.2 User management

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 11 | One-click disable of a user across connected systems | Directory → People | partial (leaver plan has a backend; the Disable action is Preview) | 2 |
| 12 | Create a user manually | Directory → People | partial (Preview) | 2 |
| 13 | Upload users in bulk (CSV) | Directory → People | partial (Preview import) | 2 |
| 14 | Update user attributes | Directory → People | partial (Preview) | 2 |
| 15 | Sponsored guests, contractors and external users | Access → Guests I sponsor | planned (`guest-accounts-and-claim.md`) | 2 *new* |
| 16 | Duplicate detection when a user is created or imported | Inbox → Identity matches | planned (`guest-accounts-and-claim.md` §5) | 2 |

### 1.3 Passwords

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 17 | Change your own password in target systems | Access → My access | gap | 3 *new* |
| 18 | Reset another user's password (help desk), with verification before reset | Directory → People | gap (action is Preview only) | 3 *new* |
| 19 | Reset or rotate service-account passwords and secrets | Directory → Machine identities | planned (secret rotation orchestration, integrate vaults) | 4 |
| 20 | Password policies per target system | Admin → Password policies | gap | 3 *new* |
| 21 | Password synchronization across systems | Admin → Password policies | gap | 3 *new* |

### 1.4 Objects: entitlements, systems, roles, organizations, service accounts, delegates, tasks

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 22 | Entitlement catalog with owner, risk, sensitivity, requestable and certifiable flags | Directory → Entitlements | partial (list and privileged flag; metadata editing missing) | 1–2 |
| 23 | Entitlement types per system (group, role, permission set, license, …) | Directory → Entitlements | partial | 2 |
| 24 | Applications, endpoints and security systems | Directory → Applications & systems | have (connected systems) | 1 |
| 25 | Enterprise (business) roles with owners and versions | Directory → Roles | partial (Preview) | 2 |
| 26 | Technical roles and groups from connected systems | Directory → Entitlements, Groups | have | 1 |
| 27 | Native groups (folders, composites, privileges, policy groups) | Directory → Groups | planned (`groups-grouper-parity.md`) | 2 *new* |
| 28 | Organizations: hierarchy, owners, organization-scoped admins | Directory → Organizations | partial (Preview, no backend) | 2 *new* |
| 29 | Service accounts with human owners and lifecycle | Directory → Machine identities & agents | have (owner, orphan and stale detection) | 1–2 |
| 30 | Delegates: out-of-office delegation of approvals, audited | Inbox | partial (delegations listed; no delegation rules) | 2 |
| 31 | Tasks: provisioning, manual fulfilment and ticket tasks | Inbox | partial (JML tasks; no ticketing) | 2 |

### 1.5 Intelligence and analytics

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 32 | Risk and identity dashboard | Insights → Risk overview | have | 1 |
| 33 | Configurable analytics (custom controls and queries) | Insights → Analytics | gap | 3 *new* |
| 34 | Analytics run history and results over time | Insights → Analytics | gap | 3 *new* |
| 35 | Duplicate identity management | Inbox → Identity matches | planned (guest design §5) | 2 |
| 36 | Role workbench: design and edit roles with impact preview | Governance → Roles | gap | 3 *new* |
| 37 | Role mining from existing access | Governance → Roles | planned (capability map F, moved to 3) | 3 |
| 38 | Entitlement discovery: unowned, undescribed, rarely used entitlements | Insights → Least privilege | partial | 2 |
| 39 | Role-access mismatches: members who lack, or have more than, the role's access | Insights → Least privilege | partial (role trims) | 2 |
| 40 | Recommendation rulesets (peer- and usage-based approve/revoke recommendations) | Inbox, Governance → Access reviews | partial (usage-based recommendations; rulesets not configurable) | 2 |
| 41 | License management: SaaS license counts, unused licenses, reclaim | Insights → Licenses | gap | 3 *new* |
| 42 | Usage analytics (last use per grant, unused access) | Insights → Least privilege | have | 1 |
| 43 | Application audit logs: ingest and search per application | Insights → Activity | partial (usage aggregates only) | 3 *new* |
| 44 | Privileged activity logs | Insights → Activity | gap | 3 *new* |

### 1.6 Integrations

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 45 | Manage applications and connectors (credentials, schedules, status) | Admin → Connections | have (demo connectors, live screen) | 1 |
| 46 | Application onboarding workflow (owner, entitlements, review and request settings) | Admin → Applications | gap | 2 *new* |
| 47 | Onboarding questionnaires for application owners | Admin → Applications | gap | 2 *new* |

### 1.7 Separation of duties

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 48 | SoD overview (control centre) | Insights → SoD conflicts | partial | 3 |
| 49 | SoD dashboard with trends | Insights → SoD conflicts | partial | 3 |
| 50 | SoD violations list with owners | Insights → SoD conflicts, Governance → Policies | have (simple SoD policy) | 3 |
| 51 | Mitigating controls with owner, frequency, expiry and evidence | Governance → Policies | planned | 3 |
| 52 | Rulesets | Governance → Policies | partial (YAML policy) | 3 |
| 53 | Risks (toxic combinations) | Governance → Policies | planned | 3 |
| 54 | Functions (entitlement-to-function mapping) | Governance → Policies | planned | 3 |
| 55 | Business processes grouping functions | Governance → Policies | planned | 3 |
| 56 | SoD simulation before granting or changing roles | Governance → Policies (what-if) | partial (graph what-if simulator) | 2 |
| 57 | SoD results shown on requests | Access → Request access, Inbox | partial (Preview risk/SoD preview) | 2 |

### 1.8 Attestations

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 58 | Manager (user) certifications | Governance → Access reviews | partial (exception-only campaign) | 2 |
| 59 | Entitlement-owner certifications | Governance → Access reviews | planned | 2 |
| 60 | Role and group membership certifications | Governance → Access reviews | planned (groups design §10.4) | 2 |
| 61 | Service-account owner certifications | Governance → Access reviews | partial | 2 |
| 62 | Event-based micro-certifications (mover, new privileged grant) | Inbox | planned | 2 |
| 63 | Campaign evidence export (frozen population, decisions, remediation) | Governance → Access reviews | planned | 2 |

### 1.9 Admin: identity repository

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 64 | Users | Directory → People | have | 1 |
| 65 | Accounts, including orphans | Directory → Accounts | have | 1 |
| 66 | Entitlements | Directory → Entitlements | have | 1 |
| 67 | Roles | Directory → Roles | partial | 2 |
| 68 | User groups | Directory → Groups | planned (native groups) | 2 *new* |
| 69 | Security systems | Directory → Applications & systems | have | 1 |
| 70 | Connections (connector endpoints and secrets) | Admin → Connections | partial (sealed secrets in Phase 0 PR2) | 0–1 |
| 71 | Password policies | Admin → Password policies | gap | 3 *new* |
| 72 | Organizations | Directory → Organizations | partial | 2 *new* |
| 73 | Datasets (lookup tables used by rules and forms) | Admin → Datasets | gap | 2 *new* |

### 1.10 Admin: identity and access rules

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 74 | Technical (birthright) rules: attributes → accounts and entitlements | Governance → Lifecycle | partial (JML birthright in demo) | 2 |
| 75 | User update rules (attribute transformations on HR changes) | Governance → Lifecycle | planned (JML mover) | 2 |
| 76 | Organization update rules | Governance → Lifecycle | gap | 2 *new* |
| 77 | Entitlement update rules (set owner, risk, flags by pattern) | Governance → Policies | gap | 2 *new* |
| 78 | Request rules (approval routing by risk, owner, attribute) | Governance → Workflows | planned | 2 |
| 79 | Rule execution trail | Admin → Audit log | partial (audit log; ledger in Phase 0) | 0–2 |
| 80 | Scan rules (scheduled policy and risk scans) | Governance → Policies & violations | have (policy evaluation) | 1 |

### 1.11 Admin: global configuration and operations

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 81 | Global configuration settings | Admin | partial (searchable settings cards, mostly descriptive) | 0–2 |
| 82 | Product admin roles (fine-grained administration of the IGA product itself) | Admin → Roles & access | planned (Phase 0 RBAC, Cedar later) | 0 |
| 83 | Job control panel: schedules, run now, history, failures | Admin → Jobs | partial (live screen; few jobs) | 2 |
| 84 | Archival library: archive closed requests and campaigns, retention | Admin → Retention | gap | 3 *new* |
| 85 | Application onboarding | Admin → Applications | gap (see 46) | 2 *new* |
| 86 | Questionnaires | Admin → Applications | gap (see 47) | 2 *new* |

### 1.12 Admin: settings

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 87 | SMTP / outbound email | Admin → Notifications | planned (Phase 0 PR12 notification outbox with SMTP sender) | 0 |
| 88 | Email templates | Admin → Notifications | gap | 2 *new* |
| 89 | Analytics settings | Admin → Analytics | gap | 3 *new* |
| 90 | Configurable dashboards | Home, Insights | gap | 3 *new* |
| 91 | Configuration files (connector and rule configuration) | Admin; policy repository in Git | planned (access-as-code repo) | 1 |
| 92 | IdP and SSO for the product | Admin → Sign-in | planned (Phase 0 OIDC/SAML) | 0 |
| 93 | OAuth clients for the product's API | Admin → API clients | planned (Phase 0 OAuth AS) | 0 |
| 94 | Web service authentication for outbound connectors (OAuth, mTLS, keys) | Admin → Connections | planned (Phase 0 sealing and safe outbound HTTP) | 0–1 |
| 95 | File directory for inbound files (SFTP drops for imports) | Admin → Connections | gap | 2 *new* |
| 96 | UI branding (logo, colors, sign-in and claim pages) | Admin → Branding | gap | 3 *new* |
| 97 | Labels and localization | Admin → Branding | gap | 3 *new* |
| 98 | Product REST API with OpenAPI | Admin → API | have | 1 |
| 99 | Tab and navigation configuration per role | Admin → Branding | gap | 3 *new* |
| 100 | Trust model for on-premises connectors (agent with mutual TLS to the cloud service) | Admin → Connections | planned (LDAP/AD agent in directory ingestion) | 2 |

### 1.13 Workflows

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 101 | Approval workflow designer (stages, escalations, conditions) | Governance → Workflows | partial (live, issue #298: step-list designer, versions, conditions, assignment; no canvas or parallel branches) | 2 |
| 102 | Workflow approvals in a single inbox, Slack and Teams | Inbox | partial (Inbox; ChatOps planned) | 2 |

### 1.14 Admin functions

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 103 | Log viewer (tenant-facing diagnostic logs for connectors and jobs) | Admin → Jobs | gap | 3 *new* |
| 104 | Audit trail | Admin → Audit log | have (audit log); planned (tamper-evident ledger, Phase 0) | 0 |
| 105 | Certificate management (SAML, connector and agent certificates, expiry alerts) | Admin → Certificates | gap | 2 *new* |
| 106 | Data analyzer (ad-hoc, permission-checked queries over the identity data) | Insights → Analytics | gap | 3 *new* |
| 107 | Application restart | n/a in SaaS (operator runbook); self-hosted: operator CLI | gap | later |
| 108 | Email history (what was sent to whom, delivery status) | Admin → Notifications | gap | 2 *new* |

### 1.15 Transport

| # | Capability | Section | Status | Phase |
|---|---|---|---|---|
| 109 | Export configuration packages (rules, workflows, connectors, templates) | Admin → Transport | gap (policy in Git covers part) | 3 *new* |
| 110 | Import configuration packages into another environment, with diff and approval | Admin → Transport | gap | 3 *new* |

---

## 2. Summary

**Totals (110 rows):** have 17, partial 37, planned 24, gap 32 (counted by the first word of the Status column).

| Status | Count |
|---|---|
| have | 17 |
| partial | 37 |
| planned | 24 |
| gap | 32 |

**Biggest gaps** (not in the capability map before this review):

1. **Password management** (rows 17, 18, 20, 21, 71): self-service change, help-desk reset with verification, password policies per system, sync. Saviynt customers use these daily. Tessera should orchestrate resets through each target's connector and the customer's IdP (do not store passwords), with the D1·S14 help-desk verification flow. Phase 3.
2. **Role engineering** (36, 37): a role workbench with impact preview and mining. Tessera's version should output policy-as-code proposals (D4·C20). Phase 3, moved earlier from "later".
3. **Analytics and data analyzer** (33, 34, 89, 90, 106): configurable controls, run history, dashboards and ad-hoc queries. Phase 3, with permission-checked queries over the graph.
4. **Application and privileged activity logs** (43, 44): beyond the usage aggregates Tessera has today. Phase 3.
5. **License management** (41): SaaS license usage and reclaim, which pairs naturally with usage-based least privilege. Phase 3.
6. **Application onboarding with questionnaires** (46, 47, 85, 86) and **notification management** (88, 108): Phase 2, because guests, attestation and groups depend on templated email.
7. **Configuration transport and archival** (84, 109, 110): Phase 3.
8. **Tenant customization** (96, 97, 99): branding, labels, navigation. Phase 3; branding of claim pages is needed in Phase 2 and is covered by the guest design.
9. **Smaller Phase 2 gaps**: datasets (73), organization and entitlement update rules (76, 77), SFTP file drops (95), certificate management (105).

The new capability-map rows are in `docs/knowledge/README.md`, section G.
