# Tessera product checklist

The goal is to check every box: 64 capabilities in 13 areas (issue #157). The roadmap ([`ROADMAP.md`](ROADMAP.md)) orders the work. This page is how we measure it.

**Last validated:** 2026-10-11, by a code audit of `dev` plus the open sign-in PRs #146–#156.

## When a box is checked

A box is checked (☑) only when all of these hold:

1. The capability is **merged to `dev`**. Open PRs do not count.
2. It is **real backend logic with tests**, reachable from the API or UI. A UI screen backed by `frontend/src/mocks` with a **Preview** badge does not count.
3. It works on **real connector data**, not only on the demo connectors in `server/internal/connectors/demo*.go`, wherever data is involved.
4. Where it changes access, it **changes the target system and verifies the change by re-reading it**. Changing only Tessera's graph does not count.

Status shows how far an unchecked item has come:

| Status | Meaning |
|---|---|
| **Done** | All four rules hold (box checked) |
| **Built** | Real logic and tests; fails rule 1, 3 or 4 (named in the row) |
| **Partial** | Some real logic; gaps named in the row |
| **Preview** | Only a mock-backed UI screen |
| **Demo** | Only simulated connector data |
| **Missing** | No code |

## Summary

| | Done | Built | Partial | Preview | Demo | Missing | Total |
|---|---|---|---|---|---|---|---|
| Count | 1 | 12 | 32 | 3 | 2 | 14 | 64 |

Three gaps account for most unchecked boxes:

- **No live connectors.** Every source is a demo connector; this is M2.
- **No write-back to target systems.** Lifecycle, revoke, review and JIT actions change Tessera's graph only; this is M3.
- **Sign-in and admin permissions are not on `dev` yet.** They are in open PRs #146–#156, M1.

## Identity lifecycle

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Create accounts automatically | Partial | `jml.JoinerPlan` / `ExecuteEvent` create the identity and birthright accounts in Tessera's graph only; HRIS events are simulated (`POST /api/hris/events`); UI `governance/Lifecycle.tsx` | M2 real HR source, M3 write-back |
| ☐ | Update access when someone changes roles | Partial | `jml.MoverPlan` adds and removes grants in the graph only (`TestDemoJoinerAndMoverPlans`) | M3 write-back |
| ☐ | Disable accounts when someone leaves | Partial | `jml.LeaverPlan`, `GET /api/jml/leaver-plan/{id}`; the account is disabled in the graph only | M3 write-back, kill switch #106 |
| ☐ | Support employees, contractors, partners and guests | Missing | `identities.type` covers human, service and agent only | #159 (contractors, partners); guests M4 #74, #76, #77 |
| ☐ | Support temporary accounts with expiration dates | Missing | Only grants, JIT requests and sessions expire; identities and accounts do not | #159; guest expiry M4 #74 |

## Identity sources

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Connect to HR systems and directories | Demo | Readiness, validation and dry-run machinery is real (`readiness/`); the Workday and AD data is simulated (`connectors/demo_company.go`, `demo_ad.go`) | M2 #20–#31, #82–#99 |
| ☑ | Maintain unique identity identifiers | **Done** | `UNIQUE (tenant_id, external_id)` on identities and `(tenant_id, system, external_id)` on accounts (`store/schema/0001_tenancy.sql`) | — |
| ☐ | Correlate accounts across applications | Partial | `reconcile/correlate.go` (confidence tiers, tested), UI `ReconReport.tsx`; demo data only, results are staged, no link, merge or unmerge | #160 (link, merge, unmerge); guests #68; M2 real sources #104 |
| ☐ | Detect duplicate and orphaned accounts | Partial | `reconcile/findings.go` orphans, duplicates and stale; NHI orphaned flag; demo data only | M2 |

## Authentication

Tessera is a relying party to the customer's IdP. It never stores passwords or second factors.

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Single sign-on (SSO) | Built (open PRs) | OIDC login, sessions and sign-in UI (`api/login.go`, `auth/sessions.go`, `oidc_login_test.go`) | Merge #146, #147, #148 |
| ☐ | Multi-factor authentication (MFA) | Partial (open PRs) | IdP `acr`/`amr` normalized to AAL; step-up requires phishing resistance (`auth/normalize`, `api/stepup.go`). MFA posture of governed accounts is missing | Merge #149; M3 MFA posture |
| ☐ | Passwordless authentication | Partial (open PRs) | Passkey and security-key sign-ins at the IdP are recognized and required for admin roles | Merge #146–#149 |
| ☐ | Account recovery and password reset | Missing | Only first-admin bootstrap invitations (`/t/{slug}/bootstrap`, open PR #147) | M3 verified help-desk resets; Phase 3 password orchestration |
| ☐ | Support SAML, OAuth 2.0 and OpenID Connect | Built (open PRs) | OIDC (#147), SAML 2.0 (#150), OAuth 2.0-only providers (#154), plus CAS (#155) and WS-Federation (#156), each tested against the dev IdP | Merge #147, #150, #154 (#155, #156 extra) |

## Access policies

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Role-based access control (RBAC) | Built (open PR) | Six platform roles and per-route permissions (`auth/rbac.go`, `rbac_routes_test.go`); business roles in the UI are Preview | Merge #146; business roles #161 |
| ☐ | Attribute-based access control (ABAC) | Missing | Policies filter by identity type only; no attribute conditions | #162 (M2 AWS engine covers AWS conditions only) |
| ☐ | Least-privilege access | Built | `leastpriv` recommendations from usage, `GET /api/least-privilege/recommendations`, `POST /api/least-privilege/revoke`; demo usage data, revoke changes the graph only | M2 real usage data, M3 write-back |
| ☐ | Conditional access based on device, location or risk | Missing | Only step-up (fresh, phishing-resistant sign-in) exists | #163 (device, location); risk signals M3 SSF/CAEP #114 |
| ☐ | Time-limited access | Built | `jit` with a 72 h maximum, `Sweep` removes expired grants (`jit_test.go`); in Tessera's graph only | M3 write-back |

## Access requests and approvals

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Self-service access catalog | Partial | Requestable groups and JIT are real (`RequestAccess.tsx` → `/api/jit/requests`); roles and other items are Preview | #164 |
| ☐ | Manager and application-owner approvals | Partial | One approver with `PermJITDecide` and a self-approval block; no manager or owner routing | #165 |
| ☐ | Multiple approval stages | Preview | `governance/Workflows.tsx` with mock `WORKFLOWS` | Knowledge row 86 (Phase 2) |
| ☐ | Request tracking and notifications | Partial | Tracking is real for JIT (`GET /api/jit/requests`); there are no notifications | #16 (notifications) |
| ☐ | Automatic access expiration and removal | Built | `jit.Sweep` / `SweepAll`; in Tessera's graph only | M3 write-back |

## Provisioning and integrations

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Create, update and remove application accounts | Missing | The connector interface is read-only; execute and revoke change the graph only | M3 write-back verified by re-read |
| ☐ | Manage groups, roles and entitlements | Partial | Read and analyse only (`/api/groups`, `/api/accounts`, `/api/resources`); role editing is Preview | Knowledge rows 94, 95 |
| ☐ | Support SCIM, APIs and directory connectors | Missing | No SCIM client or server; no real directory connector | M2 #20–#31, #82–#99; SCIM: knowledge row 85 |
| ☐ | Integrate with cloud and on-premises applications | Demo | Simulated read-only Workday, Okta, AWS, GitHub, Snowflake and AD (`connectors/demo*.go`) | M2 |
| ☐ | Retry failed operations and reconcile actual access | Partial | Reconciliation runs on staged demo data (`reconcile/`, `/api/connections/{id}/dry-run`); there is no retry queue | M2, M3 |

## Identity governance (IGA)

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Periodic access reviews and certifications | Partial | Campaigns and decisions are real (`reviews.go`, `/api/reviews/*`); created by hand, no schedule | #166 (scheduling); M3 frozen populations #110 |
| ☐ | Segregation-of-duties checks | Built | `separation_of_duties` policies (`policy_test.go`), `/api/violations`, `/api/simulate`; demo data | M2 real data |
| ☐ | Detect excessive or inappropriate access | Built | `leastpriv` recommendations and the standing-admin policy; demo data | M2 real data |
| ☐ | Assign application and entitlement owners | Partial | Owners on connections only; none on resources or groups | #167 |
| ☐ | Track remediation through completion | Partial | A review revoke deletes the graph edge and is audited; the target system is not verified | M3 #106–#111 |

## Privileged access (PAM)

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Discover privileged accounts | Built | `privileged` flag on permissions and resources, counted per identity; demo data | M2 real data |
| ☐ | Vault and rotate credentials | Missing | No vault or rotation | M3 secret rotation |
| ☐ | Provide just-in-time administrative access | Partial | `jit` request, approve (step-up), revoke and sweep; in Tessera's graph only | M3 write-back; Phase 3 broker |
| ☐ | Record or monitor privileged sessions | Missing | No code | Knowledge "session recording proxy" (later) |
| ☐ | Manage emergency access | Partial | The break-glass role and session type exist for Tessera's own admins (open PRs); no recovery flow | Phase 0 break-glass PR (#17) |

## Service and machine identities

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Inventory service accounts and workload identities | Built | `nhi.Inventory` (service, ai_agent, secrets, agent delegations), `GET /api/nhi`; demo data | M2 real data |
| ☐ | Assign owners and purposes | Partial | `owner_id`, `description`, orphaned and owner-left flags; the leaver plan reassigns owners; no API or UI to set an owner (the form is Preview) | #167 |
| ☐ | Manage secrets and certificates | Partial | Secrets are read-only metadata; certificates are a Preview page | Phases 2 and 4 certificate inventory |
| ☐ | Rotate credentials and track expiration | Partial | Age and last-rotated tracking plus the 90-day stale-secret policy; no rotation, no expiry dates | M3 secret rotation |
| ☐ | Identify unused identities | Built | `dormant` flag, `leastpriv.UnusedPermissions`; demo data | M2 real data |

## Security and monitoring

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Log sign-ins and access changes | Partial | The hash-chained audit ledger is on `dev` (`audit/ledger.go`); sign-in events are in the open PRs | Merge #146, #147 |
| ☐ | Detect suspicious identity activity | Missing | No detection code | M3 #109, #114 |
| ☐ | Generate alerts | Missing | Only a server log line when anchoring fails | #168; break-glass alerts #17 |
| ☐ | Integrate with SIEM and incident-response tools | Missing | The NDJSON audit export (`/api/audit/export`) is the only feed | #169; inbound signals M3 #114 |
| ☐ | Revoke sessions and access during incidents | Partial | Session revoke is in the open PRs; access revoke changes the graph only | Merge #146; M3 kill switch #106 |

## Audit and reporting

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Report who has access to what | Built | `/api/identities/{id}`, `/api/graph`, `/api/simulate`, `GraphExplorer.tsx`; demo data | M2 real data, exact AWS engine |
| ☐ | Show who requested and approved access | Partial | JIT and review decisions are real and audited; general requests are Preview | #164 (general requests) |
| ☐ | Retain access and policy-change history | Partial | Append-only ledger with proofs and checkpoints; no point-in-time policy history | M3 #111 |
| ☐ | Export audit evidence | Partial | `GET /api/audit/export`, `/api/audit/verify`; no evidence packs | M3 #89, #110, #111 |
| ☐ | Configure log retention | Missing | No retention code | Knowledge row 166 (Phase 3) |

## Administration and reliability

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Delegate administration with restricted permissions | Partial (open PRs) | Six roles and per-route permissions; the admin-change workflow has no routes yet | Merge #146; #16, #91 |
| ☐ | Separate development, testing and production | Partial | Code promotion dev → test → prod (`promote.yml`) and connection dry-runs; config transport is Preview | #170 (config transport) |
| ☐ | Support high availability and disaster recovery | Missing | Single-file SQLite; no backup or DR | #171; Postgres #18 |
| ☐ | Monitor connector health and failed jobs | Partial | Connector health is real (`/api/insights/deployment-health`, `/api/connections/{id}/health`); no failed-job history | #172 (job history) |
| ☐ | Provide APIs, documentation and support | Partial | OpenAPI, `/docs`, `/redoc`, `mvp/README.md`; API keys are Preview; no support channel | #15 (machine clients) |

## User experience

| ☐ | Item | Status | Evidence | Closes with |
|---|---|---|---|---|
| ☐ | Easy access-request portal | Preview | `RequestAccess.tsx` uses mock roles and requests; only JIT is real; open bug #144 | #164; bug #144 |
| ☐ | Clear approval and review screens | Partial | Reviews, JIT and HRIS approvals call the API; inbox requests and delegations are mock | #165 |
| ☐ | Accessible interface | Partial | ARIA throughout and reduced-motion support; no automated accessibility tests or WCAG audit | #173 |
| ☐ | Useful notifications | Preview | The admin notifications section is mock | #16 |
| ☐ | Mobile-friendly authentication | Partial (open PRs) | Redirect sign-in and step-up work on mobile; the UI has only basic breakpoints | Merge #146–#149; layout #174 |

## Re-validating

Re-run the audit after each milestone, and whenever a PR claims to close an item:

1. Check out `dev`. Open PRs are noted but do not check boxes.
2. For each item, find the code and its tests. Note whether it reads real connector data and whether it writes to the target system.
3. Update the row's status, evidence and "Closes with". Check the box only if all four rules above hold.
4. Update the summary counts and the "Last validated" date.

A PR that completes an item should update its row in the same PR.
