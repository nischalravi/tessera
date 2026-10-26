# The least-privilege loop: revoke, verify, restore (LP-0)

| | |
|---|---|
| Status | **Draft — needs human approval** |
| Issue | #658 (LP-0), milestone M7; plan: [`differentiators-plan.md`](differentiators-plan.md) §3 |
| Author | iam-architect (agent draft) |
| Date | 2026-10-26, checked against `origin/dev` 4e7f774 |
| Reviewers to sign off | `iam-pam-nhi-expert` (§§3, 4, 6, 9: auto-revocable set, writer role, JIT), `iam-governance-expert` (§§5, 7, 8: state machine, evidence, reviews) |
| Brief | [`briefs/least-privilege-loop.md`](briefs/least-privilege-loop.md) |

Paths are relative to `mvp/server/` unless they start with `frontend/` or `docs/`.

## 1. Goal

Take unused AWS access away **safely**: only where the evidence is complete and the evaluator is exact, in small capped batches, announced first, verified by re-read, and restored automatically within minutes when the removal turns out to be wrong. Every revocation leaves an evidence record that proves why it was safe. Success at a design partner over 60 days: ≥ 50% fewer unused AWS permissions, restore rate ≤ 1%, median restore < 15 min, no outage, every revocation verified.

## 2. What LP-1, LP-2 and their neighbours already built (verified in code)

| Piece | Where | What it gives the loop |
|---|---|---|
| Usage ingest (LP-1, #644, hardening #677, #680) | `internal/connectors/awsorg/usage*.go`, `0915_aws_usage.sql` | `aws_usage_daily` (principal, action in evaluator spelling or `svc:*`, resource scope, day, source `cloudtrail`/`access_advisor`), `aws_usage_state` (cursor, `covered_from/to`, `s3_data_events` enabled/disabled/unknown), `aws_usage_gaps` (refused files, unreadable principals, `digest_*` validation failures). Usage kept 400 days, gaps 180 days. Access Advisor is opt-in, ≤ 100 principals per run. |
| Confidence (LP-2, #645) | `internal/leastpriv/confidence.go` `Assess` | `high / medium / low / unknown` with reasons. Ceilings only (a rule can only lower): no ingest → unknown; S3 object action without data events → unknown; coverage < ½ window → low, < window → medium; newest log > 2 days old → medium; CloudTrail gap → low, Access Advisor gap → medium; unknown creation date → medium; identity < 14 days → low, < window → medium; periodic (quiet-stretch) pattern → medium. Exposed at `GET /api/aws/principals/{arn}/least-privilege` (default window 60 days, max 365). |
| Usage is the snapshot's connector's (#690) | `internal/api/aws_leastpriv.go` | Evidence and principal always come from the same connector. |
| Verification | `internal/leastpriv/aws.go` `VerifyAWS`, `aws_usage.go` `UsedCallsFromUsage` | A candidate keeps every used (action, resource) call and adds nothing; only EXACT, unconditional results may be acted on. Not yet called by production code (LP-3). |
| Explanation links (EP, #643) | `Recommendation.ExplanationID`, `aws_explanations` (content-addressed traces) | Each finding points at the evaluator trace that made the grant effective. |
| Shadow agreement (EP-6, #641) | `0916_aws_shadow.sql`, `internal/api/aws_shadow.go` | Daily sample of decisions compared with `iam:SimulatePrincipalPolicy`; `disagree` rows are triaged (`engine_bug`, `expected`, …). |
| Revoke route | `POST /api/least-privilege/revoke` (`internal/api/handlers.go`) | Dry run through `simulate.Run`; refuses conditional, approximate and unsupported grants (409); step-up on apply (`grants.revoke`); writes a `revoked_grants` tombstone; `routeGrantRevoke` queues a `provisioning_ops` `remove_entitlement`. |
| Closed-loop write-back | `internal/provision`, `0283_provisioning_ops.sql` | queued → sent → pending_verification → verified / mismatch; idempotency key per intent; deletion guard on disable/delete. Targets: SCIM, Okta (no AWS). |
| Deletion guard | `internal/deleteguard`, `0670` | Sliding-window thresholds per category, held remainder released by a second admin. |
| Two-person | `admin_change_requests` (`0008`), #569 open | Typed change requests with payload-hash echo and step-up. |

Not built: an AWS write target (LP-4), the state machine (LP-5), restore (LP-6/7), auto mode (LP-8), evidence records (LP-10).

## 3. Modes (tenant setting, `lp_settings`)

| Mode | What Tessera does | Who turns it on |
|---|---|---|
| `off` (default) | Nothing. | — |
| `suggest` | Recommendations and confidence only (today's behaviour). | one admin |
| `staged` | Builds candidate batches; a person approves each batch; Tessera announces, revokes within caps, verifies, restores. | two people (change request `lp.settings.update`) |
| `auto` | As `staged`, but batches that match the tenant's auto policy (LP-8, in the access-as-code repo) need no per-batch approval. | two people, plus the auto policy merged through a two-person apply (AC-0 §7) |

Loosening (to a stronger mode, larger caps, shorter announce period) takes two people; tightening and **pausing take one** (§6.3).

## 4. What may be revoked automatically, and what is only suggested

A finding is **auto-eligible** (may be revoked in `staged` after batch approval, or in `auto` without it) only when all of these hold:

1. confidence is `high` (so: full window covered, fresh logs, no relevant gap, known creation date ≥ window old, no periodic pattern);
2. unused for ≥ `auto_min_days` (proposed **90**, above the API default of 60);
3. the grant and every permission it removes are `EXACT` and unconditional (the revoke route's existing refusal);
4. for a right-size, `VerifyAWS` passes: `Broken` is empty and `Added == 0` (LP-3);
5. no open `aws_shadow_checks` disagreement in `investigating` or `engine_bug` for that service in the last 30 days;
6. the change kind is in the auto column below;
7. the principal and grant are not protected (§4.2), not in an open review item (§8), not exempted (§5.4), and not revoked-then-restored in the last 180 days.

`medium` findings are **suggested** (owner or admin decides, the loop still verifies and restores). `low` and `unknown` are **shown, never acted on**, with the reasons.

### 4.1 Change kinds

| Change (LP-4 write) | Restore | Auto-eligible | Note |
|---|---|---|---|
| Detach a customer-managed or AWS-managed policy from a role or user | re-attach | yes | most common unused grant |
| Delete an inline role/user policy | `Put*Policy` with the stored document | yes | document kept verbatim |
| Right-size: new default version of a customer-managed policy | `SetDefaultPolicyVersion` to the old version | yes, if the policy is attached to this principal only | the old version is **kept** until finalized |
| Remove a user from an IAM group | `AddUserToGroup` | yes, if every permission the group gives is unused by that user | |
| Delete an Identity Center account assignment | `CreateAccountAssignment` | yes | asynchronous; status polled |
| Right-size a policy shared by several principals, or `role_trim` | — | **suggest only** | touches more than the finding's principal |
| Okta / SCIM / Entra group removal | existing provisioning | **suggest only** | IdP usage (sign-ins) has no confidence model yet |
| Trust policies, permission boundaries, SCP/RCP, resource policies, access keys, disabling or deleting a principal | — | **never** | out of scope for the loop |

### 4.2 Protected

Never auto-revoked, suggested with a warning: principals tagged `tessera:protected=true` or listed in `lp_protected` (break-glass roles, the Tessera reader and writer roles, service-linked roles, roles assumed by AWS services only, the organization management account's admin roles); permissions marked privileged in prod unless the tenant opts in (Q3).

## 5. The state machine (`lp_revocations`, LP-5)

```
candidate ──approve batch / auto policy──▶ announced ──N days, no objection──▶ revoking ──verified──▶ revoked ──M days, no denial──▶ finalized
    │                                          │                                 │                     │
    └──── superseded / expired                 └── objected ▶ exempted            └── mismatch ▶ failed  └── denial / JIT re-request / owner ▶ restoring ──verified──▶ restored
```

| State | Meaning | Recorded |
|---|---|---|
| `candidate` | built from a recommendation that passed §4 for its mode | finding, confidence + reasons, assessor version, snapshot id, explanation ids, `VerifyAWS` result, simulate diff |
| `announced` | owner(s) notified (identity owner from `ownership`/`identities.owner_id`, manager, resource owner); objection link | notification ids, `announce_until` (default **7 days**) |
| `revoking` | provisioning op queued through the AWS target | `provisioning_ops.id`, idempotency key `lp:<id>:revoke` |
| `revoked` | target re-read confirms the change; restore payload held | re-read digest, `restore_until` (= finalize time) |
| `finalized` | **M days** (default **30**) with no denial or re-request | payload kept for evidence; restore now needs an ordinary access request |
| `restoring` / `restored` | restore op queued / verified | trigger (denial event id, JIT request id, user), latency |
| `exempted` | owner objected or reviewer kept it; not proposed again for 180 days | who, why |
| `failed` | mismatch on re-read or write error; a `provisioning_findings` row | finding id |
| `superseded` | the grant changed or vanished before revoking (re-collected snapshot no longer shows it) | snapshot id |

Every transition is audited in the same transaction as the row change. Before `revoking`, the candidate is **re-checked** against the newest snapshot and usage (any usage since announce → `superseded`).

### 5.1 Caps and kill switch

- Caps per tenant (settings, two people to raise): **25 revocations per run, 100 per day, 10 per AWS account per day, 1 per principal per day**. Enforced through the deletion guard with a new category `lp_revocations`, so an excess is held for a second admin rather than dropped.
- **Kill switch**: `lp_settings.paused`. One person (`lp.manage`) pauses; resuming takes two. Pausing stops new announcements and revokes (queued ops of state `queued` are cancelled); it never blocks restores.
- **Automatic pause**: ≥ 3 restores in one run, a rolling-7-day restore rate > 2%, an open `engine_bug` shadow finding, a `failed` revocation, or the usage ingest stale > 2 days. The alert names the trigger.
- An operator-level environment switch `TESSERA_LP_DISABLE=1` stops every tenant's writes (restores still run).

### 5.2 Restore targets and reversibility

- **Restore payload**: the exact prior state, stored verbatim with its SHA-256: policy ARN and attachment target, inline policy name and document, policy version id (still present), group name, Identity Center (instance, permission set, account, principal) tuple. Not a secret, but integrity-protected: the payload's digest is in the audit event of the `revoked` transition and the restore refuses a payload whose digest differs.
- **Triggers**: (a) a CloudTrail or EventBridge `AccessDenied` for the principal on an action the revocation removed (LP-6); (b) a JIT request for the revoked access (LP-7); (c) the owner or an admin presses *Restore*; (d) an admin undoes a whole run. Restores need no second person (speed beats ceremony; the payload is bounded to what existed) but are audited and alerted.
- **SLO**: verified restore within 15 minutes of the denial event arriving. EventBridge delivery is the fast path; CloudTrail S3 delivery (~5–15 min) is the fallback, so the SLO is measured from arrival.
- **IAM limits**: managed policies keep at most 5 versions. Right-size deletes the oldest non-default version not held by any open restore; if none can be freed the right-size is refused, not forced.
- **Restore failure** (the policy was deleted meanwhile, or a quota): `failed`, high-severity alert, a provisioning finding; no retry loop beyond the provisioning engine's.
- A restored item is labelled a **false positive**, feeds the calibration counters per confidence rule (LP-7), and is exempted for 180 days.

## 6. AWS permissions

### 6.1 Reader role additions (must pass `awsorg.CheckReadOnly`)

Already in `ReaderActions`: Access Advisor generate/get, `cloudtrail:GetEventSelectors`, `GetTrail`, `ListPublicKeys`, `iam:GetAccountAuthorizationDetails`, `iam:SimulatePrincipalPolicy`, `sso:List*`. Add, for **targeted re-read verification** (cheaper than a full authorization-details call per change):

`iam:GetRolePolicy`, `iam:GetUserPolicy`, `iam:GetGroupPolicy`, `iam:ListAttachedRolePolicies`, `iam:ListAttachedUserPolicies`, `iam:ListAttachedGroupPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListPolicyVersions`, `iam:ListGroupsForUser`, `sso:DescribeAccountAssignmentCreationStatus`, `sso:DescribeAccountAssignmentDeletionStatus`.

Optional CloudTrail Lake source: `cloudtrail:StartQuery`, `GetQueryResults`, `DescribeQuery` — **only if the action catalog classes them list/read**; otherwise Lake needs its own opt-in role (Q6). Trail log objects stay on `TrailReaderPolicy` (one bucket prefix).

**Verification uses the reader, not the writer.** The role that made a change never certifies it.

### 6.2 Near-real-time denials

The customer deploys (Terraform module, LP-6) an EventBridge rule per account/region matching CloudTrail events with `errorCode` `AccessDenied`/`UnauthorizedOperation` for principals with an open `revoked` row, delivered by an **API destination** to a per-tenant Tessera endpoint authenticated with a sealed per-tenant secret. Tessera adds no AWS permission for this. The event is only a trigger: Tessera confirms the denied action is one the revocation removed before restoring.

### 6.3 Writer role (LP-4, separate from the reader)

A different role, different trust policy (only Tessera's federated identity, `sts:ExternalId`), two-person enablement (#569), shipped as Terraform:

- **Allow**: `iam:DetachRolePolicy`, `DetachUserPolicy`, `DetachGroupPolicy`, `DeleteRolePolicy`, `DeleteUserPolicy`, `DeleteGroupPolicy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `DeletePolicyVersion`, `RemoveUserFromGroup`, `sso:DeleteAccountAssignment`; for restore `AttachRolePolicy`, `AttachUserPolicy`, `AttachGroupPolicy`, `PutRolePolicy`, `PutUserPolicy`, `PutGroupPolicy`, `AddUserToGroup`, `sso:CreateAccountAssignment` (plus whatever Identity Center requires of the caller, to be confirmed in the #28 sandbox).
- **Explicit Deny**: `iam:CreatePolicy`, `CreateRole`, `CreateUser`, `CreateAccessKey`, `UpdateAssumeRolePolicy`, `PassRole`, `Put*PermissionsBoundary`, `Delete*PermissionsBoundary`, `Tag*`/`Untag*`, `organizations:*`, `sts:*`; every write on resources tagged `tessera:protected=true` and on the reader and writer roles themselves.
- **Escalation risk**: restore attaches policies. Tessera only restores a payload whose digest it recorded at revoke time, and Attach/Put is limited to principals with an open `revoked` row (checked in Go; AWS cannot express it). Q4 asks whether restore should use a third, restore-only role.

## 7. Evidence and retention (LP-10)

One immutable `lp_evidence` row per revocation, written at `revoked` and appended to at `finalized`/`restored`:

- the usage window, per-source coverage and gaps **copied** (counts, `covered_from/to`, gap codes, the used-call list from `UsedCallsFromUsage`) — usage rows are pruned at 400 days, evidence must not depend on them;
- confidence level, reasons and the assessor version;
- snapshot id, the `aws_explanations` traces **copied** into the record (content-addressed traces may be garbage-collected with snapshots);
- the simulate diff and the `VerifyAWS` result;
- announcement, approvals (batch or auto-policy commit and `policy_ref`), objections;
- provisioning op id, the verified re-read digest, and any restore with its trigger and latency.

The record's SHA-256 is in the audit event of its transition (hash chain). New retention class `lp_evidence`: default **730 days**, minimum **365** (same as audit), archived by `internal/archive`, included in the audit export and evidence packs (`0261`). Dashboard metrics: unused permissions removed, restore rate per confidence rule, median restore latency, auto vs staged counts.

## 8. Interaction with access reviews

- A grant in an **open** review item is not revoked by the loop; the reviewer's decision wins. *Revoke* goes through the existing review revoke path and marks the candidate `superseded`; *keep* exempts it (`exempted`, reason `review_keep`) until the next campaign or 180 days.
- Review items show the loop's state ("scheduled for removal on 3 Dec, high confidence, 0 calls in 94 days") from a new context endpoint, so review parity fixtures do not change.
- Campaign generation skips grants that are `revoked`; finalized revocations appear in the campaign's evidence as completed remediation.
- SoD: a revocation that clears an SoD violation is noted; SoD mitigations are untouched.

## 9. Interaction with JIT

- Grants made by JIT (`access_requests` with `expires_at`) are never candidates; they expire on their own.
- **Convert to JIT**: for an unused standing grant of a privileged permission, the loop proposes, as a suggestion, an AC-5 JIT eligibility for the same principal and entitlement instead of plain removal, so the person can still get it.
- **JIT re-request in the revoke window (LP-7)**: a request for access with a `revoked` row takes the fast path — restore the standing grant, label false positive, feed calibration. Q5 asks whether the restore should instead be a time-bound JIT grant.
- Usage during a JIT grant does not block revoking the standing grant of the same permission (it shows JIT works), but it is shown in the evidence.

## 10. Confidence calibration and thresholds

Thresholds of `confidence.go` stay as shipped (14-day young identity, 2-day stale logs, half-window low cutoff). The loop adds: `auto_min_days` 90, announce 7 days, finalize 30 days. Calibration: per rule and level, restores ÷ revocations over 60 days; if `high` exceeds 1%, the tenant is paused for auto and the rule is reviewed by a person (no self-tuning in v1).

## 11. Open questions for the human

1. **Thresholds**: auto requires `high` and ≥ 90 days unused, announce 7 days, finalize 30 days, caps 25/run, 100/day, 10/account/day. Accept?
2. **Medium findings in `staged`**: may a person approve a batch containing `medium` items (recommended: yes, item by item), or `high` only?
3. **Privileged prod permissions**: auto-eligible (with a longer 14-day announcement) or suggest only (recommended for v1)?
4. **Restore role**: let the writer role restore (Attach/Put), or a third restore-only role?
5. **JIT re-request**: restore the standing grant (plan) or grant time-bound JIT access and keep the standing one revoked?
6. **CloudTrail Lake**: support it in the reader role if catalogued read-only, or only S3 trails in v1?
7. **Evidence retention**: 730 days default, 365 minimum — or tie to the tenant's audit retention?
8. **Silence as consent**: in `auto`, does no objection during announcement count as consent (recommended), or must the owner acknowledge?

## 12. PR plan (unchanged from the plan)

LP-3 #659 verified right-sizing · LP-4 #660 AWS write target · LP-5 #661 staged revocation, caps, kill switch · LP-6 #662 restore on denial · LP-7 #663 restore on JIT re-request · LP-8 #664 auto mode as code · LP-9 #665 recommendations as PRs · LP-10 #666 evidence and metrics · #569 second admin for write-back. New schema (LP-5/LP-10): `lp_settings`, `lp_revocations`, `lp_revocation_events`, `lp_protected`, `lp_exemptions`, `lp_evidence`; both dialects, isolation tests.
