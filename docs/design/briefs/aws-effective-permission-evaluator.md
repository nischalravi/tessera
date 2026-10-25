[Full design: aws-effective-permission-evaluator.md](../aws-effective-permission-evaluator.md) | Checked 2026-10-25 against origin/dev 20323f8

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
- Built (see Layout): `eval` (`Eval`, requests, options, concrete and symbolic modes), `snapshot` (`Builder`, `Apply`, `PolicyChange`), `catalog` (`Catalog`, `Load`, `Compile`), `index`, `query` (`Can`, `EffectivePermissions`, `WhoCan`, `Diff`), `render` (PR comment). Read the package docs for signatures; they changed during build.
- JSON keeps v1 snake_case names; enums marshal as lower-case strings.

## Layout, under mvp/server (as built)
- `internal/authz`: core, tri, residual.
- `internal/aws/{model,policy,glob,catalog,eval,snapshot,index,query,render}`: the engine. `eval/explain.go` builds the trace, `eval/fidelity.go` the fidelity reasons.
- `internal/aws/{harness,awsreplay,awstest,sigv4}`: harness library (oracles `sim_custom`, `sim_principal`, `access_analyzer`, `probe`; Wilson gate in `metrics.go`; `minimize.go`, `triage.go`, `aaprobe.go`), the cassette replayer, test-only fixtures, and the stdlib SigV4 signer.
- `internal/connectors/awsorg`: read-only collector (Organizations, IAM, resource policies, Identity Center), `Persist`/`Load`, `Materialize`, `ReaderPolicy`. No AWS SDK; SigV4 plus `safehttp`.
- `internal/api`: `aws.go` (connectors, snapshots), `aws_eval.go` (can, effective, who-can, explanations, pr-comment settings), `aws_simulate.go` (simulate-policy-change, PR comment to GitHub).
- `internal/store`: `model_aws.go`, `repo_aws.go`, `repo_aws_prcomment.go`; schema `0319_aws_snapshots.sql`, `0321_aws_integration.sql` (+ Postgres variants).
- `cmd/tessera-harness`: `replay` and `gate`. `catalog/aws/` holds overlays, the iam-dataset pin and notices; no compiled artifact or snapshot is committed (`tessera catalog refresh|compile` builds one; the routes need `TESSERA_AWS_CATALOG_DIR`, else `503 aws_catalog_unavailable`).
- `testdata/aws/golden/*.yaml` (74 cases, GC-01..GC-74, run by `TestGolden`), `testdata/aws/cassettes/` (12 files).
- Not built: `infra/sandbox/` (#28), nightly run, any route or job that calls `awsorg.Service.Collect` (#637 is adding it).

## Honest status
- **Agreement with real AWS has never been measured.** All 12 cassettes in `testdata/aws/cassettes/` are synthetic (hand-authored; `Case.Synthetic` is set and the corpus test checks each is bound to its fixture version). They prove the harness plumbing, not the engine's fidelity. The 99.5% (Wilson, n >= 10,000) target is a goal, not a result.
- `Collect` is not wired to any route or job, so nothing collects on its own. Snapshots come only from tests or a direct call to `Service.Collect`. #637 does the route and scheduler.
- Federated reader credentials are built (#638): `AssumeRoleWithWebIdentity` with a Tessera JWT, no stored key; the sealed-key mode exists only behind `TESSERA_AWS_ALLOW_STATIC_KEYS`, which prod refuses (`mvp/README.md` "AWS connector").
- The UI is the Insights "AWS access" page (`mvp/frontend/src/features/insights/AwsAccess.tsx`). Fidelity badges, the profile chip and a trace viewer are not built yet (#642).

## API (`/api/aws/*`, all read-only except connector and pr-comment settings)
`GET /api/aws/can`, `/principals/{arn}/effective`, `/resources/{arn}/who-can`, `/explanations/{id}`, `POST /simulate-policy-change`, `GET|PUT /pr-comment` (`aws_eval.go`, `aws_simulate.go`); `GET|POST /connectors`, `DELETE /connectors/{id}`, `GET /snapshots`, `GET /snapshots/{id}` (`aws.go`). Results carry fidelity `exact|approximate|unsupported` and reason codes. Route table and ops: `mvp/README.md` "AWS evaluator in the MVP".

## Tests
- `cd mvp/server && go test -race -timeout 25m ./...` (what CI runs). `mvp/run.sh test` runs `go vet` + `go test ./...` (no -race). Frontend CI: `npm ci && npm run build` in `mvp/frontend`.
- Golden corpus: `go test -run TestGolden ./internal/aws/eval`, single case `-run 'TestGolden/GC-57'`. 74 cases (GC-01..GC-74) in `testdata/aws/golden/*.yaml` (§14.1).
- Harness: `go run ./cmd/tessera-harness replay` (default dir `testdata/aws/cassettes`), then `gate -report FILE`. Offline only; there is no `nightly` command yet.
- Required properties: trace determinism, `TestEvalDoesNotMutateSnapshot`, `TestSymbolicSoundness` (rapid), parse/serialize round-trip, atoms == brute force.
- Fuzz seed corpora run in every `go test`; crashers committed under the package's `testdata/fuzz/`. Perf: `go test -tags slow -run TestPerf ./internal/aws/query` (nightly).
- `internal/archtest` has the purity ban (`purity_test.go`) and the harness import rules (`harness_test.go`): only `cmd/tessera-harness` imports the harness, and the server never does.

## PR plan (issue: state, checked 2026-10-25)
- #20 PR-1 types + parser, #21 PR-2 catalog, #22 PR-3 matching, #23 PR-4 conditions and residuals, #24 PR-5 engine + golden corpus, #25 PR-6 KMS and S3, #26 PR-7 connector + persistence, #27 PR-8 harness offline, #29 PR-10 indexes and queries, #30 PR-11 MVP integration and `/api/aws/*`, #31 PR-12 knowledge-base corrections and ambiguity register: all closed.
- #28 PR-9 sandbox Terraform + nightly: open (blocked on Phase 0 sign-off, Q3).
- Follow-ups are planned in `docs/design/differentiators-plan.md` §1 (EP-0..EP-8, issues #636-#647): collection job (#637), federated credentials, sandbox, stratified generator, probes, shadow agreement, why UI (#642).

## Which sections to read
- Parser/lint/types: §6.1, §8.4, §4.3 (A18-A22). Semantics: §4.1, §7. Matching: §8. Conditions: §9. Catalog: §10. Index/perf: §12 (SLOs §12.1).
- Connector/API/simulate/frontend contract: §11. Persistence: §6.2. Harness/gates: §13 (gate §13.7). Golden cases: §14. PR scope: §15. Risks: §16. Open questions Q1-Q11: §17. Scope/fidelity codes: §3.

## Known deviations (doc says X, code does Y)
- §15 PR-1: parser uses `json.Decoder` `DisallowUnknownFields`; code uses a custom token-stream tree (`strictjson.go`), since that flag loses key order, duplicates and spans; closed grammar enforced in `parse.go`.
- Doc PR-1 lists `parse,lint,limits`; code adds `serialize.go`, `strictjson.go`, `variables.go`; `Parse` also takes `Options{MultivaluedKey}` (catalog supplies it in PR-2).
- Doc §15 says `./run.sh test` runs `go test -race`; it does not (CI does).
- §15 lists `staticcheck` and a licence scan per PR; `.github/workflows/ci.yml` has `go vet`, race tests; `govulncheck` and `gosec` are in `security-scan.yml`. No staticcheck or licence scan found (unverified elsewhere).
- Doc header says "17 ambiguity entries"; §4.3 and the code lint go to A22 (A18-A22 are parser rules). PR-1 emits warnings `NONCANONICAL_OPERATOR_CASE`, `INCOMPLETE_ARN`, `NON_ASCII_CONDITION_KEY`.
- The parser's golden documents stay inline in `internal/aws/policy/golden_test.go`; the engine's YAML corpus and `TestGolden` exist in `internal/aws/eval` and `testdata/aws/golden/`.
- Doc §11.1 has a federated reader; code stores a sealed access key (see Honest status).
- Doc §11.2 route names match the code; the code adds `GET|PUT /api/aws/pr-comment` and connector and snapshot routes.
- The harness library imports the AWS SDK for the SimulatePrincipalPolicy and Access Analyzer oracles (`internal/aws/harness/oracle.go`); the connector and the server do not.
- Schema `00NN_aws.sql` resolved to `0319_aws_snapshots.sql` and `0321_aws_integration.sql`.
- `catalog/aws` has no committed compiled artifact; running the evaluator needs `tessera catalog refresh` and `compile` first.
