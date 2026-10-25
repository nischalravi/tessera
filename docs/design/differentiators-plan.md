# The three differentiators: plan to production quality

*October 2026. Planned by `iam-architect` against the code on `dev`. This plan feeds milestones M5–M8 in [`../ROADMAP.md`](../ROADMAP.md). Why these three: [`../competitive-analysis.md`](../competitive-analysis.md) §0 and §3–§6.*

Each section gives the current state in code, the gaps, a PR list (one PR is one agent's work), the parts that need a human or real systems, and the metric that proves the differentiator. PR ids (EP-, AC-, LP-) match the GitHub issue titles: M5 is #636–#647 (plus #28 and #577), M6 is #648–#657, M7 is #658–#666 (plus #569), and M8 is #667–#668.

---

## 1. Exact, explainable effective permissions

Do this first. The other two depend on it.

### Current state

**Real.** The engine is well past what its brief describes. All paths below are under `mvp/server/`:

- **Engine:** `internal/aws/{policy,glob,catalog,eval,snapshot,index,query,render,harness,awsreplay,awstest}` and `internal/authz`. It evaluates SCP and RCP gates, permission boundaries, session policies, resource policies, trust, and the KMS and S3 rules.
- **Decisions:** each one carries a fidelity and reason codes, and is traced (`eval/explain.go`).
- **Tests:** a golden corpus (`testdata/aws/golden/*.yaml`) and a soundness property test.
- **Collector:** `internal/connectors/awsorg` collects Organizations, IAM, resource policies and Identity Center through its own SigV4 signer and safehttp. It fails closed on unreadable policies. `Materialize` writes the evaluator's edges into the graph.
- **API:** `/api/aws/can`, `/effective`, `/who-can`, `/explanations/{id}`, `/simulate-policy-change` and `/pr-comment` (`internal/api/aws_simulate.go`).
- **Harness:** `cmd/tessera-harness` has `replay` and `gate` (Wilson bound).

**Partial.**

- The harness corpus is 12 cassettes in `testdata/aws/cassettes/`, and all of them are synthetic. **Agreement with real AWS has never been measured.**
- `awsorg.Service.Collect` is not called from any route or job, so nothing collects on a schedule.
- The connector stores a sealed long-lived access key. The design calls for federation with no stored keys.
- There is no fidelity or "why" UI beyond the Insights "AWS access" page.

**Missing.**

- The sandbox Terraform and the nightly run (#28).
- Any check against production estates.
- Azure and GCP evaluators.

### Build plan

| PR | Scope | Deps | Acceptance and tests |
|---|---|---|---|
| EP-0 Docs refresh | Bring the AWS brief, the capability map (`knowledge/README.md` §A) and the checklist rows up to the code | none | Docs only; the reviewer spot-checks the paths |
| EP-1 Collection job | `POST /api/aws/connectors/{id}/collect` (async job plus a runs table), a scheduler, and `Materialize` after each collection; incremental where `GetAccountAuthorizationDetails` allows | none | An unchanged estate writes nothing; audited; both SQL dialects; awstest replay; job isolation test |
| EP-2 Federated reader credentials | `AssumeRoleWithWebIdentity` with a Tessera-issued JWT (`internal/keys`) that an IAM OIDC provider trusts. Key mode stays only behind a flag that prod refuses | EP-1 | Config guardrail test; no secret in the database in federated mode; replayed STS calls. Reviewed by `iam-pam-nhi-expert` and `iam-protocols-expert` |
| EP-3 = #28 Sandbox and nightly harness | `infra/sandbox`: an org with 3 OUs and 4 accounts, SCPs and RCPs, boundaries and resource policies; nightly `tessera-harness nightly` | none in code | A nightly report artifact; cassettes recorded and committed; the gate fails the workflow. Touches `.github/`, so `needs-human` |
| EP-4 Stratified generator | Sample requests across strata (deny, SCP, RCP, boundary, session, cross-account, KMS and S3, condition keys) until n ≥ 10,000; shrink each failure to a minimal new golden case | EP-3 | Wilson 95% lower bound ≥ 99.5% overall and ≥ 99% per stratum; minimizer tests |
| EP-5 Real-call probes | Cover what the simulator cannot model (RCPs, cross-account resource policies, session policies) with assume-role probe principals in the sandbox (`harness/aaprobe.go`) | EP-3 | Every `AMBIGUITY:<id>` in [`../knowledge/aws-evaluation-ambiguities.md`](../knowledge/aws-evaluation-ambiguities.md) has a probe and a recorded verdict |
| EP-6 Production shadow agreement | Opt in per tenant: sample K decisions a day and compare them with `iam:SimulatePrincipalPolicy` in the customer account (already a read action in `ReaderPolicy`); a disagreement becomes a finding | EP-1 | Rate-limited; triage records; a per-tenant agreement metric on Deployment health |
| EP-7 "Why" UI | Fidelity badges, a profile chip, and a trace viewer from `/api/aws/explanations/{id}` in the side panel | none | Keyboard and AA checks; uses `src/api.ts` only; no Preview badge |
| EP-8 Explanation links | `explanation_id` on violations, least-privilege recommendations and review items | EP-7 | Parity fixtures unchanged, or any change explained in their README |
| AZ-0, GC-0 Designs | Azure: RBAC, deny assignments, ABAC conditions, PIM eligibility and management-group inheritance. GCP: allow and deny policies, principal access boundaries, conditions and the org-policy hierarchy. Oracles: GCP Policy Troubleshooter and `testIamPermissions`; real calls in an Azure sandbox subscription | EP-4 | Design docs and briefs approved by a human. Reviewed by `iam-authz-expert` |
| AZ-1…6, GC-1…6 | Parser, collector, evaluator, golden corpus, harness and integration, mirroring the AWS PRs | AZ-0, GC-0 | The same ≥ 99.5% gate |

### Needs a human or real systems

An AWS sandbox organization with a budget and a nightly OIDC role (#28, after the Phase 0 sign-off #19); a design-partner AWS organization that approves the read role; an Azure subscription and a GCP organization sandbox.

### Success metric

- **Nightly gate:** real-AWS agreement with a Wilson 95% lower bound ≥ 99.5% at n ≥ 10,000, for 14 nights in a row.
- **Per stratum:** every stratum ≥ 99%.
- **No confident-wrong verdicts:** no EXACT verdict that a probe shows to be wrong.
- **Production:** shadow agreement ≥ 99.5% on the first design partner.

---

## 2. Access as code, with pre-merge blast radius

### Current state

**Real.**

- **Graph what-if:** `internal/simulate/simulate.go` runs a change over a copy of the graph. It diffs effective permissions per identity, including recent use of removed permissions, and diffs policy violations.
- **AWS change diff:** `internal/aws/snapshot/apply.go`, `query.Diff` and `render/prcomment.go` turn an AWS policy change into a who-gains-or-loses diff and a PR comment.
- **Groups as Cedar in Git:** `internal/groups/policygroups`, `/api/groups/policy/{validate,diff,apply}`, `policy_ref` recorded on changes, and a CI example ([`groups-policy-repo-example.md`](groups-policy-repo-example.md)).
- **Drift detection:** `internal/reconcile/drift.go`.

**Partial.**

- **Detection policies are built in:** they are 7 YAML types in `policies/*.yaml`, embedded in the binary, not set per tenant, and not evaluated as Cedar (`internal/policy/policy.go`).
- **Roles, birthright and SoD live in the UI and database:** they are not code (`internal/roles`, `internal/sod`).
- **AWS simulation input is hand-built:** a JSON list of operations, not Terraform.
- **The two simulators don't meet:** the graph and AWS simulators are separate. Nothing joins AWS principals to Tessera identity types, so "3 of them are agents" is not possible yet.

**Missing.**

- **JIT eligibility as data:** `internal/jit` lets anyone request any group for up to 72 hours.
- **Agent scopes as code.**
- **Policy tests:** unit and invariant tests, and a `tessera policy test` CLI.
- **A GitHub App or check run.**
- **Prediction check:** nothing checks after apply that what was predicted actually happened.
- **The Cedar engine:** `cedar-go` is not a dependency yet.

### Build plan

| PR | Scope | Deps | Acceptance and tests |
|---|---|---|---|
| AC-0 Design: the access-as-code repo | Cedar schema for `Role`, `BirthrightRule`, `JitEligibility`, `SodRule`, `AgentScope` and `Invariant`; repo layout; mapping to existing tables; apply semantics (atomic, full or partial, retire); two-person apply | none | A design doc and brief approved by a human. Reviewed by `iam-authz-expert`, `iam-governance-expert` and `iam-agent-identity-expert` |
| AC-1 `internal/cedarx` on cedar-go (Apache-2.0) | Schema generated from the graph, validation, size and depth limits; the groups fragment parser cross-checked against cedar-go | AC-0 | Differential test on the groups corpus; fuzzing; archtest purity |
| AC-2 Bundle and offline CLI | `tessera policy validate` and `tessera policy test -dir .`. Test files give entities and expected decisions; invariants run against a fixture snapshot | AC-1 | Golden CLI tests; exit codes; no network |
| AC-3 Invariants in Cedar | Port the 7 YAML types to Cedar `forbid` invariants over effective-permission facts (for example "no engineer reaches prod PII without JIT"); per-tenant bundles in the database; YAML kept as a fallback | AC-1 | `/api/policies` and `/api/violations` parity fixtures unchanged; both dialects; isolation test |
| AC-4 Roles and birthright as code | Import and export; apply goes through `roles.Plan`, so a dry run is a diff; `policy_ref` on role versions | AC-2 | Round-trip test; a plan matches a UI-made change |
| AC-5 JIT eligibility as code | A `jit_eligibility` table (who, what, maximum duration, approvers, step-up); `jit.CreateRequest` enforces it | AC-2 | Both dialects; deny by default once a tenant enables it; JIT tests |
| AC-6 SoD rules as code | Import and export the SoD rulesets, risks and functions | AC-2 | Round trip; violations unchanged |
| AC-7 Agent scopes as code | An agent's allowed action and resource classes, compiled to a graph invariant | AC-3 | Reviewed by `iam-agent-identity-expert` |
| AC-8 Unified blast radius: `POST /api/policy/diff` | Compile a bundle change into graph edits (`simulate.Run`) and AWS operations (`snapshot.Apply`, then `query.Diff`); join AWS principals to identities through materialized edges; summarize by identity type and resource, with violations before and after | AC-3, EP-1 | Fixture: "N identities gain a new path to bucket X; k are agents"; p95 < 60 s at 10,000 identities and 50 accounts |
| AC-9 Terraform plan input | Map `terraform show -json` to AWS operations for IAM policies, attachments, roles, bucket policies, SCPs and RCPs. Unsupported resources are reported, never dropped | EP-1 | Plan fixtures; unknown values become CONDITIONAL |
| AC-10 GitHub App check run | Replace the stored personal token with a short-lived GitHub App installation token; post a check run and a comment; fail on new violations | AC-8 | safehttp; sealed secrets; replayed GitHub API. Reviewed by `iam-protocols-expert` |
| AC-11 Merge sync, prediction check, rollback | Apply on push and record the commit. After apply, re-collect and compare what was predicted with what is observed, and raise a finding on any mismatch. Reverting the commit restores the earlier state. A second approver is required (builds on #569) | AC-8, LP-4 | E2E with a fake target; the mismatch finding is raised |

### Needs a human

A GitHub App registration; a design partner's policy repo; approval of the Cedar schema (AC-0).

### Success metric

- **Adoption:** a design partner makes 100% of governed entitlement changes by PR for 30 days.
- **Diff speed:** every PR gets a blast-radius diff, with p95 under 60 s.
- **Accuracy:** after apply, the observed changes match the prediction on every EXACT result.
- **Safety:** no invariant violation reaches the main branch.

---

## 3. Provable, reversible least privilege

### Current state

**Real.**

- **Usage index:** `internal/usage/usage.go` holds a 90-day usage index. Its only real sources are Okta and Entra sign-in events.
- **Recommendations:** `internal/leastpriv/leastpriv.go` recommends removing a grant, right-sizing it or trimming a role.
- **Revoke route:** `POST /api/least-privilege/revoke` dry-runs through `simulate.Run`. It refuses conditional, approximate and unsupported grants, and needs step-up to apply.
- **Verified write-back:** revokes go through `internal/provision`, a closed loop of queued, sent, pending verification, then verified or mismatch, with a deletion guard. The only targets are SCIM and Okta.

**Partial.** `leastpriv.VerifyAWS` checks that a right-sized policy keeps every used call and adds nothing new, but no production code calls it.

**Missing.**

- **AWS usage data:** CloudTrail and IAM Access Advisor are not ingested.
- **A confidence model.**
- **An AWS write target:** IAM or Identity Center.
- **Staged revocation.**
- **Automatic restore:** neither on denial nor on a JIT re-request.
- **An auto mode.**
- **Evidence records.**

### Build plan

| PR | Scope | Deps | Acceptance and tests |
|---|---|---|---|
| LP-0 Design: the least-privilege loop | State machine, confidence model, restore targets, blast limits, kill switch | none | Approved by a human. Reviewed by `iam-pam-nhi-expert` and `iam-governance-expert` |
| LP-1 AWS usage ingest | Org CloudTrail from S3 or CloudTrail Lake, EventBridge for near-real-time denials, and IAM Access Advisor (`GenerateServiceLastAccessedDetails`, action-level where AWS supports it), into an `aws_usage_daily` table mapped to evaluator actions | EP-1 | Read-only actions added to `ReaderPolicy` (`CheckReadOnly`); cassette tests; isolation test; both dialects |
| LP-2 Confidence model | Per identity and permission: window coverage, source completeness, log gaps, identity age and periodic jobs, giving `high`, `medium`, `low` or `unknown` with reasons on the recommendations API. Without S3 data events, object actions are `unknown` | LP-1 | Property tests; with data events off, S3 object actions are never `high` |
| LP-3 Wire `VerifyAWS` | Generate the right-sized policy from used calls and verify it with `query.Diff`; EXACT results only | LP-1, EP-4 | The recommendation includes the diff; APPROXIMATE is refused (test) |
| LP-4 AWS write target | A `provision` target for IAM (detach a policy, delete an inline policy, add a new policy version, remove from a group) and for Identity Center (delete an assignment). Each change is verified by re-reading it with IAM `Get*`. The writer role is separate from the reader, and the original document is stored verbatim for restore | EP-2 | Replayed signed calls; mismatch finding; writer role in Terraform; two-person enablement (#569) |
| LP-5 Staged revocation | An `lp_revocations` state machine: candidate → announced (owner notified, N days) → revoked (restore payload kept) → finalized (M days with no denial). Per-run and per-day caps through the deletion guard; a tenant kill switch | LP-2, LP-4 | State-machine tests; caps enforced; audited in the same transaction |
| LP-6 Restore on denial | A CloudTrail `AccessDenied`, or an IdP denial, on revoked access triggers a verified automatic restore and tells the owner | LP-1, LP-5 | E2E with fake events; restore within 15 min of the event arriving |
| LP-7 Restore on JIT re-request | A JIT request for access revoked in the window takes a fast path: restore it, label it a false positive, and feed the calibration | LP-5, AC-5 | JIT tests; calibration counter |
| LP-8 Auto mode as code | A tenant policy in the access-as-code repo (high confidence, unused ≥ 90 days, not break-glass, a cap per day). Off by default; enabling it needs two people | LP-5, AC-2 | Policy tests; disabled-by-default test |
| LP-9 Recommendations as PRs | Emit right-sizing as a PR to the policy repo or as a Terraform suggestion | AC-10, LP-3 | Fixture PR body |
| LP-10 Evidence and metrics | Per revocation: the usage window, confidence, simulation diff, verified re-read and any restore. Included in the audit export, with a false-positive rate on a dashboard | LP-5 | Golden export; hash chain intact |

### Needs a human

CloudTrail organization-trail access (and S3 data events) at a design partner; approval of the writer role; the first tenant to enable auto mode.

### Success metric

Measured at a design partner over 60 days:

- **Unused access:** at least 50% fewer unused AWS permissions.
- **Restores:** restore rate ≤ 1%, with a median restore under 15 minutes.
- **Safety:** no serious outage caused by a revocation.
- **Proof:** every revocation verified by re-read, with complete evidence.

---

## Order and dependencies

Close M1 first (#19, the Phase 0 exit gate). It gates connecting real AWS accounts and #28.

| Milestone | Contents | Hard dependencies |
|---|---|---|
| M5 · Exact AWS, proven | EP-0…EP-8 and #28. Also LP-1 and LP-2, which are read-only and can start early, and AC-0 and AC-1 in parallel | M1 |
| M6 · Access as code and blast radius | AC-2…AC-11 | AC-8 needs EP-1; AC-11 needs LP-4 |
| M7 · Provable least privilege | LP-0, LP-3…LP-10 | LP-3 needs EP-4 to pass the gate; LP-6 needs LP-1; LP-7 and LP-8 need AC-5 and AC-2 |
| M8 · Azure and GCP | AZ-*, GC-* | The EP-4 pattern; then AC-8 and LP-* per cloud |

The critical path is M1 → #28 (EP-3) → EP-4 (the gate) → LP-3 → LP-5 → LP-6.

Open issues that already cover parts of this plan:

- **#28:** EP-3, the sandbox and nightly harness.
- **#577:** permission-edge pruning that respects partial reads, so an unread edge is never treated as unused. It belongs in M5.
- **#569:** a second admin for write-back, the base for LP-4, LP-8 and AC-11.
- **#95 and #96:** the Entra and Okta live checks.

## Security notes for Tessera itself

- **AWS credentials:** the AWS connector stores a long-lived key today. EP-2 replaces it with federation.
- **GitHub token:** the PR comment uses a stored personal token. AC-10 replaces it with a GitHub App.
- **Writer role:** it is separate from the reader and needs two people to enable.
- **Automatic revocation:** it is capped and has a tenant kill switch.
- **Cedar bundles:** they are untrusted input, held to the same size, depth and fuzzing limits as the AWS policy parser.
