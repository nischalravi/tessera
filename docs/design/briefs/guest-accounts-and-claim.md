Full doc: [guest-accounts-and-claim.md](../guest-accounts-and-claim.md). Checked 2026-10-10 against origin/dev d9a42f3.

# Guest accounts and claim: agent brief

**Status:** nothing of GU-1..GU-14 is merged (no guest/claim/sponsor/affiliation code or schema in `mvp/`; `git log origin/dev` shows only the design, PR #78). Issues #64-#77 are all open.

## Non-negotiable rules (K1-K10)
- One person, one identity, many affiliations. Conversion adds/ends affiliations, never a second identity.
- Source records sit under persons; link/merge/unmerge move source records; every merge is reversible (default 180 days).
- Self-asserted intake (sponsor invite, self-registration, partner invite) NEVER auto-links. Auto-link only HRIS/SIS (authoritative) on authoritative identifiers. Claimant is never told a match exists; the "already have an account?" question is asked of everyone.
- Credentials never move in a merge. Four-eyes for merge/link into privileged, IAL2+ or employee identities. Reviewer link requires re-verification at the existing identity's IAL.
- Claim link = 256-bit single-use continuation secret in the URL fragment, stored only as SHA-256 hash (`"tessera-claim-v1|"+tenant+"|"+token`). Verification uses separate 6-digit confirmation codes (10 min, 5 attempts).
- Assurance levels A0, IAL1, IAL2 (IAL3 out of scope). No knowledge-based verification ever counts toward IAL (weak signal only).
- Tessera orchestrates; credentials live with home IdP, customer IdP, or (Phase 3, guests only) a hosted service. Passwords are never stored or logged.
- Every sponsorship has an end date and a living sponsor; sponsor leaver means transfer task with deadline, else end.
- Guest access = group access: `ref:guest:*`, `ref:applicant:*`, `ref:prehire:*`, `ref:partner:*`; bundles are direct memberships with `disabled_at = sponsorship end`.
- Public endpoints: identical body, status, headers and timing for unknown/expired/used/locked (300 ms floor, dummy hash lookup).
- Claim complete only after a sign-in at the required AAL through the bound authority; until then `pending_claim`.

## Security properties to preserve
Constant-time compares (`seal.Equal`); token single use via atomic `UPDATE ... WHERE status='issued' AND expires_at>now RETURNING`; `__Host-tessera_claim` cookie (60 min idle, 24 h max) bound to a WebCrypto key; `Referrer-Policy: no-referrer`; rate limits per doc §6.4 audited without code/token; DOB/phone sealed (`seal.Seal` with `seal.AAD(tenant, table, column, row)`), national IDs only as tenant-keyed HMAC; federation binds `(issuer, subject)`, never email; unscoped eppn rejected; IDV evidence references only, no images; every decision records policy version.

## Existing platform (verified in code)
- Merged and usable: tenancy (`internal/tenancy`, UUID `tenancy.ID`), `internal/store` (`TenantTx` via `DB.InTenant/ReadTenant`; `GlobalTables` allowlist; every table has `tenant_id`, every UNIQUE starts with it), `internal/seal`, `internal/keys`, `internal/ratelimit` (in-process `Limiter.Allow(key)`, no callers yet), `internal/safehttp`, `internal/config`, `internal/audit` (`audit.Record(ctx, tx, action, detail, opts...)`, hash-chained; middleware fails closed for POSTs without a committed domain event), `internal/devidp` (OIDC+SAML mock), `internal/jml` (demo JML), `internal/readiness`.
- Not merged: auth core/sessions/RBAC (#9), OIDC login (#10), SAML SP (#13), notifications outbox (#16), step-up (#12), groups engine (GR-*, #44-#63), Cedar (policies are YAML in `server/policies/`), `go-webauthn` (not in `go.mod`). API serves one dev tenant (`larkspur`) and needs `TESSERA_ENV=dev`; no public-route/`/public/t/{slug}` mechanism exists.

## Layout (designed; none exists yet)
Server: `internal/guests/{sponsorship,claim,idv,credential,lifecycle}/`, `internal/identity/{affiliations,match,merge}/`, store `model_identity.go`, `repo_identity_ext.go`, schema `0201_guests.sql`. Frontend: `src/features/access/Guests.tsx`, `src/public/claim/`.
Today: `internal/store` has `repo_identities.go` (flat `identities`: id INTEGER, tenant_id, external_id, type, status, no lifecycle/IAL columns); schema files `0001_tenancy, 0003_keys, 0004_audit, 0201_connections, 0202_readiness, 0203_staging`; frontend `features/{access,admin,directory,governance,home,inbox,insights}`, shared `components/`, `mocks/`.

## Key names
Tables: `identity_source_records`, `identity_identifiers`, `affiliations`, `sponsorships`, `intake_records`, `match_results`, `identity_merges`, `claim_tokens`, `claim_sessions`, `confirmation_codes`, `proofing_results`, `credential_bindings`, `terms_documents`, `terms_acceptances`, `partner_organizations`, `guest_populations`. Tiers A exact/B strong/C possible/D none; modes authoritative/self_asserted/federated. Routes: `/api/guests/*`, `/api/sponsorships/*`, `/api/identity-matches/*`, public `/claim/*`, `/register`.

## Tests
`./run.sh test` (go vet + `go test ./...`), `./run.sh build` (Go build + `tsc --noEmit` + vite), `./run.sh audit-deps` (govulncheck). Each PR adds `TestIsolation_*` for its tables and keeps `TestIsolation_NoRawSQLOutsideStore` (archtest) and the sqllint statement check green. Named security tests: doc §10.2 (`TestClaim_*`, `TestMatch_SelfAssertedNeverAutoLinks`, `TestMerge_CredentialsNotTransferred`, `TestExpiry_RemovesAccessWithin60s`, ...). Staticcheck is required by the doc but is not in `run.sh` (CI unverified). Frontend has no test runner (no vitest/Playwright in `package.json`); doc's component/Playwright tests need one added.

## PR plan (all open)
| PR | Issue | Scope | Needs |
|---|---|---|---|
| GU-1 | #64 | identity data model, affiliations, identifiers | #5,#6,#7 (merged), #9 |
| GU-2 | #65 | sponsorships, sponsor policy, invites | GU-1, #9, #16 |
| GU-3 | #66 | self-registration + approval | GU-2 |
| GU-4 | #67 | SIS/HRIS intake, conversions | GU-1 |
| GU-5 | #68 | matching, review queue, merge/unmerge | GU-1, GU-4, GR-1/2 |
| GU-6 | #69 | claim core | GU-2, GU-5 |
| GU-7 | #70 | IDV providers, proofing agent (needs-human) | GU-6 |
| GU-8 | #71 | credential binding (needs-human) | GU-6, #10, #13 |
| GU-9 | #72 | InCommon/eduGAIN (needs-human) | GU-8, #13 |
| GU-10 | #73 | terms, consent, recovery | GU-6 |
| GU-11 | #74 | lifecycle, deprovisioning | GU-2, GU-4, GR-11 |
| GU-12 | #75 | groups/access-request integration | GU-11, GR-5, GR-9 |
| GU-13 | #76 | UI | GU-2, GU-5, GU-6 |
| GU-14 | #77 | B2B partner orgs, Phase 3 (needs-human) | GU-8, GU-12 |

## Which sections to read
- Data model, migration: §9.1, §3. Sponsor policy/limits: §4.3, §9.3. Matching/merge: §5. Claim tokens, sessions, rate limits: §6.2-6.5. IAL pathways, IDV: §6.3. Federation: §6.6, §7.1. Passwords/MFA/recovery/terms: §7. Lifecycle/conversion: §8. APIs/UI: §9.2, §9.4. Tests and threats: §10. Per-PR files/tests: §11. Open questions (IDV vendor, hosted core, SMS): §13.

## Known deviations (doc says X, code does Y)
- Doc: `internal/store/schema/0201_guests.sql`; code: 0201 is `0201_connections.sql`. Use the next free number.
- Doc uses `ALTER TABLE identities ADD COLUMN ...`; code schema is create-if-not-exists, applied by embed `schema/*.sql`, with reseed instead of migrations (goose arrives with #18). How to add columns is undecided; unverified.
- Doc: groups engine, Cedar, outbox, sessions as dependencies; none merged. Sponsor policy fallback is a Go evaluator (doc §11 GU-2).
- Doc nav "Access -> Guests I sponsor", "Directory -> People"; current rail is Identity/Access/Protection/Settings with Users at `/directory/people`, no Guests route.
