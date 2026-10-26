[Full design: least-privilege-loop.md](../least-privilege-loop.md) | Issue #658 (LP-0) | Checked 2026-10-26 against origin/dev 4e7f774 · Paths relative to `mvp/server/`.

# Brief: the least-privilege loop (revoke, verify, restore)

**Status: Approved 2026-10-26** (decisions in the full doc §11). Built: LP-1 usage ingest, LP-2 confidence, EP-6 shadow agreement, explanation links. Not built: LP-3..LP-10, #569.

## Non-negotiable rules
- Modes `off` (default) → `suggest` → `staged` (person approves each batch) → `auto` (LP-8 policy in the access-as-code repo). Loosening takes two people; tightening and pausing take one.
- Auto-eligible only if ALL: confidence `high`; unused ≥ 90 days; grant EXACT and unconditional; right-size passes `VerifyAWS` (no broken used call, nothing added); no open `investigating`/`engine_bug` shadow disagreement for the service in 30 days; change kind auto-eligible; not protected, not in an open review item, not exempted, not restored in 180 days. `medium` = suggest; `low`/`unknown` = never act.
- Auto-eligible kinds: detach policy, delete inline policy, right-size a single-principal managed policy (new default version, old one kept), remove user from IAM group, delete Identity Center assignment. Suggest only: shared-policy right-size, `role_trim`, IdP group removal. Never: trust policies, boundaries, SCP/RCP, resource policies, keys, disabling principals.
- States: candidate → announced (7 days) → revoking → revoked → finalized (30 days); restoring → restored; exempted, failed, superseded. Re-check before revoking. Every transition audited in its transaction.
- Caps 25/run, 100/day, 10/account/day, 1/principal/day via deletion guard category `lp_revocations`. Kill switch `lp_settings.paused` (one to pause, two to resume); auto-pause on ≥ 3 restores/run, > 2% 7-day restore rate, `engine_bug`, a `failed`, stale ingest; `TESSERA_LP_DISABLE=1` for operators. Restores are never blocked.
- Restore payload = exact prior state, verbatim with SHA-256 recorded at revoke; restore refuses a mismatched digest. Triggers: denial event, JIT re-request, owner/admin, undo run. SLO 15 min from event arrival. Restored = false positive, exempt 180 days, feeds calibration.

## Security properties
Reader verifies, writer never certifies its own change. Writer role separate, `sts:ExternalId`, two-person enablement, explicit Deny on create/pass-role/boundaries/tags/organizations/sts and on `tessera:protected` resources; restore only to principals with an open `revoked` row. Denials arrive by EventBridge API destination with a sealed per-tenant secret; Tessera confirms the action before restoring.

## Existing code to reuse
`leastpriv.Assess` (confidence.go), `GrantRecommendations`/`RoleTrimRecommendations`, `VerifyAWS` + `UsedCallsFromUsage`, `GET /api/aws/principals/{arn}/least-privilege` (default 60 days, max 365), `POST /api/least-privilege/revoke` (dry run via `simulate.Run`, EXACT-only, step-up, `revoked_grants`, `routeGrantRevoke`), `internal/provision` (verified ops), `internal/deleteguard`, `aws_usage_*` (usage 400 d, gaps 180 d), `aws_shadow_checks`, `aws_explanations`, `ownership`, `internal/archive`, evidence packs (`0261`).

## AWS permissions
Reader additions (must pass `CheckReadOnly`): `iam:Get{Role,User,Group}Policy`, `iam:ListAttached{Role,User,Group}Policies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListPolicyVersions`, `iam:ListGroupsForUser`, `sso:DescribeAccountAssignment{Creation,Deletion}Status`; CloudTrail Lake reads only if catalogued read-only. Writer: Detach*/Delete*Policy, Create/SetDefault/DeletePolicyVersion, RemoveUserFromGroup, `sso:DeleteAccountAssignment`; restore Attach*/Put*Policy, AddUserToGroup, `sso:CreateAccountAssignment`.

## Key names
Tables: `lp_settings`, `lp_revocations`, `lp_revocation_events`, `lp_protected`, `lp_exemptions`, `lp_evidence` (retention class `lp_evidence`, 730 d default, 365 min). Change type `lp.settings.update`. Permission `lp.manage`. Idempotency `lp:<id>:revoke`.

## Tests
State-machine tests; caps enforced; audited in same transaction; S3 object actions never `high` without data events (exists); APPROXIMATE refused (LP-3); E2E restore with fake events within 15 min (LP-6); calibration counter (LP-7); disabled by default (LP-8); golden evidence export, hash chain intact (LP-10); both dialects, isolation tests.

## PR plan
LP-3 #659 · LP-4 #660 · LP-5 #661 · LP-6 #662 · LP-7 #663 · LP-8 #664 · LP-9 #665 · LP-10 #666 · #569.

## Which sections to read
Already built §2; modes §3; auto vs suggest §4; states, caps, restore §5; AWS roles §6; evidence §7; reviews §8; JIT §9; open questions §11.

## Decisions
Approved 2026-10-26; see the full doc's decisions section.
