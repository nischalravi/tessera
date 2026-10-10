Full doc: [saviynt-feature-coverage.md](../saviynt-feature-coverage.md). Checked 2026-10-10 against origin/dev d9a42f3.

# Saviynt feature coverage: gaps only

**How to use.** Read this table to see which Saviynt-parity capabilities Tessera lacks and where each is planned. For a row's detail, open the full doc and search by the row numbers (`#` column of its section 1 checklist). Capability rows are planned in `docs/knowledge/README.md` section G (capability map) unless an issue is named. Status below was re-checked in code on this date; the full doc's status labels and section names predate the current nav (Identity, Access, Protection, Settings) and the Go backend.

"Preview" means the screen runs on browser mock data with no backend endpoint (Admin pages show a Preview badge and "the settings API is part of a later phase").

| Gap (full-doc rows) | Tessera status (verified) | Tracked in |
|---|---|---|
| Password management: self-service change, help-desk reset, per-system policies, sync (17, 18, 20, 21, 71) | No code. Only demo connector data holds a `password` secret metadata field | Map G (Phase 3); help-desk verified reset: issue #108 (open) |
| Role workbench and role mining (36, 37) | Role trims exist in Least privilege; no workbench, no mining; Roles page is Preview | Map G (Phase 3, D4·C20) |
| Configurable analytics, run history, dashboards, data analyzer (33, 34, 89, 90, 106) | None found in code or nav | Map G (Phase 3) |
| Application audit logs and privileged activity logs (43, 44) | Usage aggregates only; tamper-evident audit ledger of Tessera itself is merged (#7), not app logs | Map G (Phase 3) |
| License management (41) | None found in code | Map G (Phase 3) |
| Application onboarding workflow and questionnaires (46, 47, 85, 86) | None found in code or mocks | Map G (Phase 2) |
| Notification management: email templates, email history (88, 108) | Preview only; no outbox in code | Map G (Phase 2); SMTP outbox: #16 (open) |
| Organizations with hierarchy, owners, update rules (28, 72, 76) | Directory Orgs page is Preview | Map G (Phase 2) |
| Datasets / lookup tables (73) | None found in code | Map G (Phase 2) |
| Entitlement update rules (77) | None found in code | Map G (Phase 2) |
| SFTP file drops for imports (95) | No SFTP code | Map G (Phase 2); flat-file CSV/SFTP import: #105 (open) |
| Certificate inventory and expiry alerts (105) | Admin Certificates page is Preview | Map G (Phase 2) |
| Request templates, approval delegation rules (5, 30) | Partial: drafts in browser storage; no delegation rules | Map G (Phase 2) |
| Tenant branding, labels, localization, per-role navigation (96, 97, 99) | Admin Branding page is Preview; no localization code | Map G (Phase 3); claim-page branding: guest design (#76) |
| Config transport between environments (109, 110) | Admin export/import page is Preview; policies live in `server/policies/` YAML | Map G (Phase 3) |
| Archival and retention of closed requests/campaigns (84) | None found in code | Map G (Phase 3) |
| Tenant-facing log viewer for connectors and jobs (103) | Admin Jobs page is Preview | Map G (Phase 3) |
| Sponsored guests, duplicate detection (15, 16, 35) | Not built (design only) | `guest-accounts-and-claim.md`; #64-#77 |
| Native groups (27, 68) | Directory Groups lists connector groups; no native groups engine (unverified whether any page is mock-only) | `groups-grouper-parity.md`; #44-#63 |
| Product SSO, OAuth clients, product admin roles (82, 92, 93) | Auth core not merged; API serves one dev tenant | Phase 0: #9-#15 |
| Application restart (107) | Not applicable in SaaS | Full doc only ("later") |

Unverified: exact counts in the full doc's summary (have 17, partial 37, planned 24, gap 32); issue numbers other than those listed were not found for map G rows.
