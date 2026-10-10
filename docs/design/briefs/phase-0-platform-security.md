[Full doc: phase-0-platform-security.md](../phase-0-platform-security.md) | Checked 2026-10-10 against origin/dev d9a42f3

# Brief: Phase 0, make Tessera safe to connect (§ = section of the full doc)

Exit criteria: admin signs in via Okta with a passkey; every API call authenticated and audited; tenant isolation tests pass.

## Non-negotiable rules
- Tessera is an OIDC RP / SAML SP to each tenant's IdP. Never stores passwords or second factors. Phishing resistance (`phr`) is proved via `acr`/`amr`, never assumed. Okta ignores unrequested `acr_values`: "phr not requested" means not phr.
- Users keyed by `(connection, subject)`, never email. Admin roles never granted from IdP group claims. One user belongs to one tenant.
- Browser = server-side cookie session (BFF). CLI/machines = DPoP-bound JWT (RFC 9068). Tokens never reach browser JS; no tokens in localStorage/sessionStorage.
- Only `internal/store` may import `database/sql`/drivers or call Query/Exec. Tenant tables only via `*store.TenantTx` (needs a `tenancy.ID`, binds `tenant_id = @tenant` itself, zero ID fails closed `ErrNoTenant`). Cross-tenant ids return `ErrNotFound` / 404, never 403.
- Domain audit events commit in the same tx as the change. Audit is append-only. Reads whose `http.request` audit write fails return 503 `audit_unavailable` (buffered response).
- Admin changes (IdP trust, admin role grant, break-glass enrolment): two-person, step-up (`max_age` 300 s, phr), 24 h cooling-off. No email/phone reset path.
- JOSE: algorithm allow-list always explicit; reject `jku/x5u/jwk/x5c/crit`; a tenant's key never verifies another tenant's `iss` (§10.4).
- Secrets stored as sha256 hex only; constant-time compares; `crypto/rand`. No tokens/cookies/auth bodies in logs or audit.
- Time via injected clock, not `time.Now()`, in admin/oauth packages. Tests use `go test -race`.

## Security properties (where specified)
- Roles/permissions static map, §12.1; role floors: admin roles active only if phr (§12.2); `effective = perms(active_roles) ∩ perms(scope)` (§12.3).
- Lifetimes table §10.2 (admin session 15 min idle/12 h; other 60 min/24 h; step-up 900 s policy/300 s admin; access token 600 s; DPoP iat window ±60 s; checkpoints 5 min/1000 events).
- Cookie `__Host-tessera_sid`, Secure, HttpOnly, SameSite=Lax; CSRF header `X-Tessera-CSRF` plus Origin check (§11).
- Audit: per-tenant SHA-256 chain over RFC 8785 JCS, Ed25519 signed checkpoints, anchor sink; verify exit codes 2 edit, 3 deleted row, 4 forged checkpoint, 5 missing anchor (§13).
- Prod guard rails §18.4; dev IdP never linked into API/prod binary.

## Key types and names
`tenancy.ID`, `tenancy.Platform`; `store.DB.{InTenant,ReadTenant,InSystem,ForEachActiveTenant}`, `TenantTx`, `SystemTx`, `store.TxFrom(ctx)`; `ErrNoTenant/ErrCrossTenant/ErrNotFound`; `seal.Sealer` (`Seal/Open/AAD`), `keys.{EnsureKeys,JWKSFor,ActiveSigningKey,RevokeKey}`; `audit.{Append,Record,Middleware,WithSystemActor}`; `safehttp.Client`; `ratelimit`; `config` (`TESSERA_ENV` dev|test|prod). Designed, not yet built: `auth.Principal/AuthnContext/Require/Authenticate`, `StepUpPolicy` (900 s) / `StepUpAdmin` (300 s), `oauth/dpop`, `admin/changes`.

## Layout: designed (§5.3) vs. now
| Designed | Actual (d9a42f3) |
|---|---|
| `internal/{config,tenancy,store,seal,keys,safehttp,ratelimit,audit,devidp}` | exist (audit has `canon/`, `checkpoint.go`, `verify.go`, `export.go`, `middleware.go`, `record.go`, `ledger.go`; devidp has `devidptest/`) |
| `cmd/tessera` (serve, seed, audit verify/checkpoint/export), `cmd/tessera-devidp` | exist. `tessera admin ...` absent |
| `internal/{auth,oauth,admin,cliauth}`, `cmd/tessera-cli` | absent (PR5+) |
| `internal/api/router.go`, `Router.Handle(pattern, Route{Perm,Authn,Public}, h)` | absent; see deviations |
| `store/schema/0001_tenancy 0002_auth 0003_keys 0004_audit` | 0001, 0003, 0004 exist; readiness uses 0201-0203 |
| `store/tenant_tx.go system_tx.go model_*.go repo_*.go` | exist; `internal/archtest`, `store/storetest` (`TwoTenants`) exist |
| Frontend `src/pages/*`, `components/*`, `auth.tsx`, `api.ts` | actual: `src/{api.ts,app/,components/,features/<area>/,mocks/}`; no `auth.tsx`, Login, UserMenu, StepUpDialog |

Seeded tenants `larkspur`, `globex`. Parity fixtures `testdata/parity/`, golden `testdata/golden/audit_v1.json`.

## Tests
- `cd mvp/server && go vet ./... && go test -race ./...`; `./run.sh test` (see deviations). Isolation group: `go test -race -run '^TestIsolation' ./...`. Frontend: `npm run build` (tsc).
- Existing: `TestIsolation_{EveryTableScopedOrAllowlisted,EveryStatementBindsTenant,NoRawSQLOutsideStore,DevIdPNotImportedByAPI,RouteCrossTenant,ListRoutesNeverLeak}`, `TestAudit_EveryRouteFailsClosed`. Every new table/statement/route must satisfy them. `./run.sh audit-deps` = govulncheck; gosec/staticcheck gates §20.4.
- Per-PR test lists: §19. Exit mapping: §20.
- New routes: register with a declared permission; route-coverage test (PR5) needs 401 unauthenticated plus exactly one `http.request` event.
- Where a PR changes an API contract, update `testdata/parity/` fixtures in the same PR.

## PR plan (doc PRn = GitHub issue #n+4; PR #s below are GitHub PRs)
| Doc PR | Issue | State |
|---|---|---|
| PR1 tenancy | #5 | merged (#119) |
| PR2 config/crypto/keys/safehttp | #6 | merged (#124) |
| PR3 audit ledger | #7 | merged (#129) |
| PR4 dev IdP | #8 | merged (#125) |
| PR5 auth core, all routes protected | #9 | open |
| PR6 OIDC login | #10 | open |
| PR7 frontend sign-in | #11 | open (merge with PR5) |
| PR8 step-up | #12 | open |
| PR9 SAML SP | #13 | open |
| PR10 OAuth AS, device flow, DPoP, CLI | #14 | open |
| PR11 machine clients | #15 | open |
| PR12 admin changes, recovery | #16 | open |
| PR13 break-glass | #17 | open |
| PR14 Postgres RLS (may slip to Phase 1) | #18 | open |
| PR15 exit gate | #19 | open |

## Which sections to read
- Tenancy/store/SQL: §7, §14. Schema/structs: §7.4-7.5. Audit: §13, §19 PR3.
- Login/OIDC/SAML/normalize: §8, §9, §10.4. Step-up: §9.4, §12.4. CLI/DPoP/tokens: §9.3, §10, §10.5.
- Roles/routes/permissions: §12, §16.2 (per-route Perm/Authn table). Sessions/CSRF: §11.
- Admin changes, recovery, break-glass: §15. Frontend: §17. Config/dev IdP faults: §18.
- PR scope and test lists: §19. Test plan: §20. Libraries/versions: §6. Open questions: §22. Threats: §4.

## Known deviations already merged (doc says X, code does Y)
- Route registration: code uses `s.handle(method, pattern, tenantMode, h)` in `internal/api/server.go` (modes `noTenant|read|swept|write|phased`) and `Server.Routes()`; no `Route{Perm,Authn,Public}`, no `router.go`, no separate tenant middleware (the `Server.serve` method opens the tenant tx). `Perm/Authn/Public` arrive in PR5.
- Pipeline order in `Handler()`: securityHeaders, logRequests, audit.Middleware, recoverPanics, cors, limitBody, timeouts, dispatch. No `RequestID` middleware seen (unverified).
- Schema numbers: doc §7.5 says `0002_auth.sql`, PR5 says `0005_auth.sql`; 0002 is unused. Pick numbers deliberately; readiness holds 0201-0203.
- Audit UI: lives in `frontend/src/features/admin/Admin.tsx` (`AuditLog`), not `pages/AuditLog.tsx`.
- `/api/audit/export` and `/verify` are `phased`; `/audit/keys` is `noTenant`. `GET /api/audit` limit clamped to 1000 (`MaxAuditLimit`), negative refused. `POST /api/simulate` is `answersRead`, fails closed.
- `./run.sh test` runs `go vet` + `go test ./...` without `-race`; the doc's `-race` is run by hand (README) and CI.
- Audit actor is `anonymous` and `/api/audit*` unauthenticated until PR5; `actor`/`approver` request body fields still exist until PR5 (handlers.go).
- Not verified: CI job details, `TestAudit_*` beyond names above, ratelimit/safehttp behaviour vs §19 test lists.
