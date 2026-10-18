[Full design: aws-effective-permission-evaluator.md](../aws-effective-permission-evaluator.md) | Checked 2026-10-10 against origin/dev d9a42f3

# Brief: AWS effective-permission evaluator

Goal: pure-Go engine answering "does principal P get action A on resource R, and why", exact vs AWS (nightly sandbox agreement >= 99.5%, Wilson 95% lower bound, n >= 10,000). Second exit criterion: a policy PR shows exactly who gains or loses which permission. The doc wins over `docs/knowledge/03` §4.5 (K1-K6, §4.2).

## Non-negotiable rules
- Decision = `ALLOW | DENY | CONDITIONAL(residual)` plus fidelity `EXACT | APPROXIMATE | UNSUPPORTED` with reason codes. A wrong confident answer is worse than CONDITIONAL.
- Ambiguous AWS docs: choose the more permissive reading, flag `AMBIGUITY:<id>`, register a probe (§4.3, A1-A22). Never silently pick.
- Order (§7.2): explicit Deny across ALL policy types first; then RCP and SCP gates (an Allow needed at every org level); then grant paths; boundary and session limits. The engine still evaluates later stages for the trace.
- Same-account principal-type matrix (§4.1 fact 3, §7.4): account-principal grants delegate, role-ARN grants stay capped by boundary and session, user and session ARNs do not. Cross-account needs both accounts to allow.
- Missing keys: negated operators true; `ForAllValues` true; `ForAnyValue` false; IfExists true (§9). `NotPrincipal` + Deny always denies principals with a boundary.
- Case (§8.1): actions and condition keys insensitive (ASCII A-Z only); element names, `Effect`, ARNs sensitive.
- Never skip an unparseable or Dropped-anomaly policy: affected decisions become `UNSUPPORTED` + `POLICY_UNPARSEABLE` (fail-closed, §3.3).
- Only outcome-sensitive fidelity reasons downgrade a decision (§7.9). Least privilege and auto-revoke never act on APPROXIMATE or UNSUPPORTED.
- Catalog from AWS Service Reference JSON; iam-dataset (MIT) only with notices. No AGPL code or data (PMapper, iam-simulate).

## Security properties
- Policy JSON is untrusted: strict parse (duplicate keys, trailing data, bad UTF-8, BOM rejected), size/depth/string/value caps (`policy.Limits`), linear-time glob (no regexp, no recursion, ReDoS-safe), per-evaluation `context.Context` deadline, fuzzing.
- Purity: `eval,glob,model,policy,index,query` do no I/O, read no clock, no map-order dependence; the snapshot is immutable after `Build()`; traces byte-identical across runs and shuffled inputs.
- Every decision records `engine_version`, `catalog_version`, `snapshot_id`; raw policy bytes stored verbatim; `explanation_id` = hash of canonical JSON.
- Connector is read-only, federated (no stored keys), all outbound HTTP via `safehttp`; its own IAM policy checked read-only against the catalog. `aws_*` tables carry `tenant_id`, access only via `store.TenantTx`, isolation-tested. Harness is never imported by the server binary.
- All `/api/aws/*` routes read-only, tenant-scoped, RBAC-declared, audited.

## Key types and names
- `internal/authz`: `Outcome` (Allow/Deny/Conditional), `DenyKind` (Explicit/Implicit/Guardrail), `Fidelity`, `ReasonCode` (consts; `AmbiguityReason("A3")`), `FidelityReason`, `StmtRef`, `ExplanationStep`, `CondTrace`, `Decision`, `Tri` (`Bool`, `U`, `AnyOf`, `AllOf`), `Residual` sum type (`Const`, `And`, `Or`, `Not`, `Atom`).
- `internal/aws/model`: `Snapshot`, `Principal`, `PolicyDoc`, `Statement`, `PatternSet`, `PrincipalSet`, `Organization`, `OrgNode`, `Boundary`, `ResourcePolicy`, `KMSGrant`, `S3BucketState`, `TrustEdge`, enums.
- `internal/aws/policy`: `Parse(raw, Options) (*Result, error)`, `Serialize`, `Lint`, `Limits`, `Anomaly` codes, `ParseError` codes, `ClassifyAWSPrincipal`, `CompleteARN`.
- Designed, not yet built: `eval.EvaluationRequest`, `eval.Options{Fast}`, `eval.Concrete|Symbolic`, `snapshot.Builder`, `snapshot.PolicyChange`, `catalog.Catalog`, `query.{Can,EffectivePermissions,WhoCan,Diff}`.
- JSON keeps v1 snake_case names; enums marshal as lower-case strings.

## Layout (as designed, §5), under mvp/server
`internal/authz` (core, tri, residual; later simplify, render) · `internal/aws/{model,policy,glob,catalog,eval,snapshot,index,query,render,awstest,harness}` · `internal/connectors/awsorg` · `internal/store` (`model_aws.go`, `repo_aws.go`, `schema/00NN_aws.sql`) · `cmd/tessera-harness` · `catalog/aws/` · `testdata/aws/{golden,cassettes}` · `infra/sandbox/`.

Exists now: `internal/authz/{core,tri,residual}.go`; `internal/aws/model/{model,enums}.go`; `internal/aws/policy/*` (see deviations). Nothing else under `internal/aws`; no `testdata/aws`, `catalog/aws`, `cmd/tessera-harness`, `awsorg`. Frontend: no AWS evaluator UI (only demo AWS rows in `mvp/frontend/src/mocks/data.ts`); designed UI is the profile chip and amber/grey fidelity badges (§3.3, Q4), not planned in any PR.

## Tests
- `cd mvp/server && go test -race -timeout 25m ./...` (what CI runs). `mvp/run.sh test` runs `go vet` + `go test ./...` (no -race). Frontend CI: `npm ci && npm run build` in `mvp/frontend`.
- Golden corpus (PR-5 on): `go test -run TestGolden ./internal/aws/eval`, single case `-run 'TestGolden/GC-57'`; GC-01..59 and 69..74 at 100% in PR-5, GC-60..68 in PR-6. YAML in `testdata/aws/golden/` (§14.1).
- Required properties: trace determinism, `TestEvalDoesNotMutateSnapshot`, `TestSymbolicSoundness` (rapid), parse/serialize round-trip, atoms == brute force.
- Fuzz seed corpora run in every `go test`; crashers committed under the package's `testdata/fuzz/`. Perf: `go test -tags slow -run TestPerf ./internal/aws/query` (nightly).
- Every PR: no behaviour change until PR-11; existing parity fixtures stay green; add `internal/archtest` import ban in PR-5.

## PR plan (issue number: state; verified against origin/dev)
- #20 PR-1 core types + parser: MERGED (#102)
- #21 PR-2 catalog: open
- #22 PR-3 matching (linear glob, principal match): open
- #23 PR-4 conditions, context, residuals: open
- #24 PR-5 engine + golden corpus + archtest purity: open (needs 3, 4)
- #25 PR-6 KMS and S3: open (needs 5)
- #26 PR-7 read-only connector + persistence: open (needs 1, 2)
- #27 PR-8 harness offline: open (needs 5)
- #28 PR-9 sandbox Terraform + nightly: open (needs 8; blocked on Phase 0 sign-off, Q3)
- #29 PR-10 indexes and queries: open (needs 5, 6)
- #30 PR-11 MVP integration, `/api/aws/*`, PR comment: open (needs 7, 10)
- #31 PR-12 knowledge-base corrections, ambiguity register doc: open, can merge anytime
- Critical path: 1 -> 3/4 -> 5 -> 8 -> 9.

## Which sections to read
- Parser/lint/types: §6.1, §8.4, §4.3 (A18-A22). Semantics: §4.1, §7. Matching: §8. Conditions: §9. Catalog: §10. Index/perf: §12 (SLOs §12.1).
- Connector/API/simulate/frontend contract: §11. Persistence: §6.2. Harness/gates: §13 (gate §13.7). Golden cases: §14. PR scope: §15. Risks: §16. Open questions Q1-Q11: §17. Scope/fidelity codes: §3.

## Known deviations (doc says X, code does Y)
- §15 PR-1: parser uses `json.Decoder` `DisallowUnknownFields`; code uses a custom token-stream tree (`strictjson.go`), since that flag loses key order, duplicates and spans; closed grammar enforced in `parse.go`.
- Doc PR-1 lists `parse,lint,limits`; code adds `serialize.go`, `strictjson.go`, `variables.go`; `Parse` also takes `Options{MultivaluedKey}` (catalog supplies it in PR-2).
- Doc §15 says `./run.sh test` runs `go test -race`; it does not (CI does).
- §15 lists `staticcheck` and a licence scan per PR; `.github/workflows/ci.yml` has `go vet`, race tests; `govulncheck` and `gosec` are in `security-scan.yml`. No staticcheck or licence scan found (unverified elsewhere).
- Doc header says "17 ambiguity entries"; §4.3 and the code lint go to A22 (A18-A22 are parser rules). PR-1 emits warnings `NONCANONICAL_OPERATOR_CASE`, `INCOMPLETE_ARN`, `NON_ASCII_CONDITION_KEY`.
- The parser's golden documents are inline in `internal/aws/policy/golden_test.go` (copied from §14.2); the YAML corpus and `TestGolden` do not exist yet.
- "PR-1 blocked until Go port merged": resolved; the module is on `go 1.27.2`.
- Schema dir `internal/store/schema` has `0001,0003,0004,0201-0203`; the `00NN_aws.sql` number is unassigned.
- Doc §11 says API and registry names are "confirmed later"; `internal/api`, `internal/simulate`, `internal/leastpriv`, `internal/nhi`, `internal/graph`, `internal/usage` all exist now (not re-checked for the field names in §11.2).
