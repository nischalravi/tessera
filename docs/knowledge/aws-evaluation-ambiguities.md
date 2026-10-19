# AWS evaluation ambiguity register

*Living document. Source of the entries: [AWS evaluator design §4.3](../design/aws-effective-permission-evaluator.md#43-ambiguity-register), AWS documentation read 2026-10-08 and 2026-10-09. Companion to [03 Authorization and policy §4.5](03-authorization-and-policy.md). Status below checked 2026-10-15.*

## Why this exists

AWS documents IAM evaluation well, but in places the pages conflict, are silent, or contradict a launch announcement. Tessera's evaluator must be exact against live AWS, and a wrong confident answer is worse than an honest "not sure". So each gap is written down here with:

- **the conflict or gap**, with the AWS page it comes from;
- **our default**, chosen under design rule D3: when the docs are ambiguous, take the **more permissive** reading, mark the decision `APPROXIMATE`, and never pick silently;
- **the probe** that would settle it against a live sandbox account.

A decision whose outcome depends on an entry that no probe has settled carries the fidelity reason `AMBIGUITY:<id>` (for example `AMBIGUITY:A5`). Only outcome-sensitive entries downgrade a decision (design §7.9): if the answer would be the same under either reading, the decision stays `EXACT`.

## Status vocabulary

| Status | Meaning |
|---|---|
| **Open** | The default is in force. No probe has been run. |
| **Open, implemented** | Open, and the default is already enforced in merged code. |
| **Open, proposed resolution** | Open, and an unmerged PR made a call the design left unspecified. The call is **pending review**, not settled. |
| **Settled** | A live probe confirmed or corrected the default. The probe date and result go in the entry. (None yet.) |

No probe has run yet. The harness and sandbox land in AWS evaluator PR-8 and PR-9 (issues #27, #28); PR-9 is blocked on the Phase 0 sign-off (design Q3). Until then every entry is Open.

## How to maintain this register

1. A new doubt found while building or reviewing: add an entry with the next free ID (A23, A24, and so on), a default, a probe and a source. Never reuse or renumber an ID, because decisions, traces and tests quote them.
2. A probe result changes the default, or confirms it: set the status to **Settled**, record the date and probe, and update the code and golden cases in the same PR. A changed default is a behaviour change and needs the usual review.
3. Weekly re-probes (design R4) catch AWS changing behaviour. If a settled entry flips, move it back to Open and say why.
4. Keep this file and design §4.3 in step. Where they disagree, fix this file first and open a design change.

## Proposals pending review (open PRs)

Three open PRs implement the first evaluator layers. Where they made a call that the design left open, it is recorded in the entries below as **Proposed resolution (PR #235/#236/#237), pending review**.

| PR | Issue | Scope |
|---|---|---|
| #235 | #22 PR-3 | linear glob, action, ARN and principal matching |
| #236 | #23 PR-4 | conditions, request context, residuals |
| #237 | #21 PR-2 | catalog and overlays |

**A1 differs between #235 and #236.** Both implement "a trailing `*` in segments 3 to 5 takes the remainder of the ARN", but not identically. See A1.

## Entries A1 to A22

Source labels `[S…]` are listed at the end.

### Resource matching

| ID | Conflict or gap | Default | Probe | Status |
|---|---|---|---|---|
| **A1** | A `Resource` page says that if `*` is the last character of a resource ARN segment it "can expand to match beyond the colon boundaries". Which segments, and does a non-trailing `*` ever cross a colon? [S11] | Segments 1 to 5 (`arn`, partition, service, region, account) match one by one. The 6th segment is the rest of the string, colons included, matched as one glob. A `*` that is the **last character of segments 3 to 5** matches the remainder of the ARN (`arn:aws:s3:*` matches every S3 ARN). A non-trailing `*` never crosses a colon. | `arn:aws:sqs:us-east-1:*`, `arn:aws:sqs:*:queue` and `arn:aws:logs:*:*:log-group:a*` against resources whose names contain colons. | **Open, proposed resolution** (#235, #236 differ; see below) |
| **A21** | Identity-based policies complete an ARN with fewer than six segments (`arn:aws:sqs` is `arn:aws:sqs:*:*:*`) and session policies reject it. SCPs are not mentioned. [S33, S4b] | Complete it the same way (an over-approximation), keep the raw pattern, warn `INCOMPLETE_ARN`, flag dependent decisions `AMBIGUITY:A21`. | SCP denying `sqs:*` on `arn:aws:sqs`, then `sqs:GetQueueAttributes` on a queue. Also `CreatePolicy` (type SCP) with it, to see whether Organizations rejects it. | **Open, implemented** (parser, merged #102) |

**A1, proposed resolution (PR #235 and #236), pending review.** The design text says "last character of segments 3 to 5" and does not say whether later pattern segments constrain the match. The two PRs read it differently:

- **#235** (`eval/arn.go`): a trailing `*` in segment 3, 4 or 5 takes the remainder only when **every later pattern segment is empty or `*`**. This applies to patterns of any length. So `arn:aws:s3:*::*` matches `arn:aws:s3:us-east-1:111111111111:x` (the `*` in segment 4 absorbs the rest). A pattern with fewer than six segments that the rule does not close matches nothing (the parser completes incomplete ARNs where AWS does). The bare pattern `*` matches everything.
- **#236** (`eval/values.go`, `arnLikeMatch`, for `ArnLike` and `ArnEquals`): a trailing `*` takes the remainder only when it ends the **last pattern segment** and the pattern has **fewer than six segments**. A six-segment pattern is always matched segment by segment, so `arn:aws:s3:*::*` does **not** match that same ARN (account must be empty). A value that is not a six-segment ARN never matches.
- **Reviewer checks.** (1) The two readings give different answers for six-segment patterns whose later segments are empty or `*`. The resource matcher and the condition matcher should agree, so one reading has to be chosen; the more permissive one is #235's, which fits D3. (2) As read from the code (not run), #236 returns false for `ArnLike` with the bare pattern `*` against any value, because a one-segment pattern is rejected before the trailing-star rule applies, and no test covers it. #235 matches `*` to everything. AWS documents `*` as matching anything, so this looks like an under-match to confirm.

### Principals and `NotPrincipal`

| ID | Conflict or gap | Default | Probe | Status |
|---|---|---|---|---|
| **A3** | Same-account trust policy naming a **specific user or role ARN**: does the caller also need `sts:AssumeRole` in its identity policy? The docs state the explicit-allow requirement and the same-account union rule but never this case. [S1, S31] | No identity allow needed, using the same matrix as other resource policies. A role-ARN caller is still capped by its boundary and session policy. | User with no identity policies assumes a role whose trust names the user's ARN. | Open |
| **A4** | `NotPrincipal` layering for sessions: must you list the account, the role **and** the session ARN, or are account and role enough? [S7] | Exempt only if the account ARN **and** (role ARN **or** session ARN) are listed. Users: account ARN and user ARN. Otherwise the Deny applies. | Three bucket policies (account+role; account+session; role+session) against an assumed-role caller. | **Open, proposed resolution** (#235) |
| **A9** | Wildcard `Principal: "*"` **without** an `aws:PrincipalArn` condition in a same-account policy: is it limited by the boundary or session policy? The docs say "no other permissions are required" and describe the `PrincipalArn` exception, but not this plain case. [S1, S5] | A direct grant to the requester (not limited by an implicit deny). | Role with a boundary that excludes S3; bucket policy `Principal:"*"` allows `GetObject`. | Open |
| **A10** | Services other than IAM and KMS that "may also require" an explicit Allow in their resource policy for the same account. [S1] | Per-service table (design §7.4.3), initially IAM and KMS only. Unknown services use the union rule and are flagged. | For each resource-policy service in the sandbox: identity allow only, no resource-policy statement. | **Open, proposed resolution** (#237) |
| **A11** | The session-policy branch of the deny/allow page is garbled ("checks whether the principal is a role session… Otherwise… Deny"). [S1, S6] | A role session with no session policy: no limit. A federated-user session always has a session policy (`GetFederationToken` requires one). | `GetFederationToken` with a narrow policy, then an action outside it. | Open |

**A4, proposed resolution (PR #235), pending review.** `NotPrincipalDenyApplies` implements the default and adds that a root requester needs only the account listed, and a service principal must be listed itself. It sets the ambiguity flag only when the account is listed and **exactly one** of the role and session ARNs is. The code comment also says "or neither", but the code does not flag that case. The Deny applies there under either reading of A4, so the outcome is the same; the comment should be corrected.

**A10, proposed resolution (PR #237), pending review.** `overlays/rbp_rules.yaml` ships `default: union` with two verified rows, `iam` (role trust policy) and `kms` (key policy). Any other service takes the union rule and carries the reason `SERVICE_RBP_RULE_UNVERIFIED`. This is the design default, recorded as data.

**Root requester and an account principal.** Not a register entry. #235 matches a root requester named by an account principal as `SELF`, which follows design §8.4.2 (root holds every permission of its account). It is consistent with fact 3 ("the account principal delegates to identity policies"), because no identity policies apply to root.

### Conditions

| ID | Conflict or gap | Default | Probe | Status |
|---|---|---|---|---|
| **A5** | `ForAnyValue:` with a **negated** operator and a missing key. The general rule makes negated-plus-missing true; the set-operator page makes `ForAnyValue`-plus-missing false. [S8, S9] | **false** (the set-operator rule is more specific). | Allow with `ForAnyValue:StringNotEquals aws:TagKeys` and no tags in the request. | **Open, proposed resolution** (#236) |
| **A6** | Unresolved policy variable: "might cause the entire statement to be invalid", versus "inverted operators… do match against a null value". [S10] | Per-occurrence semantics, not statement drop. Positive operator false, negated true, `Resource` entry no match. | Deny with `StringNotEquals s3:ExistingObjectTag/Team: ${aws:PrincipalTag/Team}` and an untagged caller (the docs' own example, which says denied). | **Open, proposed resolution** (#236) |
| **A7** | A single-valued operator with no set qualifier used on a **multivalued** key. Not documented ("require a set operator"). [S9] | Positive operators: true if **any** request value matches. Negated: true if **no** request value matches. Flag `APPROXIMATE`. | `StringEquals aws:TagKeys` with two tags. | **Open, proposed resolution** (#236) |
| **A8** | A set qualifier on a single-valued key ("can lead to overly permissive policies"). [S9] | Treat the value as a one-element set. A missing key follows the set-operator rule. | `ForAllValues:StringEquals aws:PrincipalTag/team` with an untagged principal. | **Open, proposed resolution** (#236) |
| **A17** | `aws:SourceIp` is absent behind a VPC endpoint, so an allow conditioned on `IpAddress` fails, while a deny with `NotIpAddress` **applies** (negated plus missing). Documented, but probed because it is a frequent incident cause. [S8, S19] | As stated. | Request through a VPC endpoint against both policies. | **Open, proposed resolution** (#236) |

**A5 to A8 and A17, proposed resolution (PR #236, `eval/cond.go`), pending review.** The condition evaluator implements each default and returns the ids that decided part of a result (`AtomResult.Ambiguities`); the engine, in PR-5, decides which are outcome-sensitive. Detail a reviewer should know:

- **A5** is flagged only on the `ForAnyValue` + negated operator + absent key path.
- **A6**: an unresolved variable in a value makes that value match nothing; it does not drop the statement. It is flagged only when the key being tested is present, because an absent key already decides the result.
- **A7** is flagged only when the key is multivalued **and** the request carries more than one value. With a single value the answer does not depend on A7, so it is not flagged.
- **A8** is flagged whenever a set qualifier is used on a single-valued key, whether or not the key is present.
- **A17** is flagged for any IP operator on `aws:SourceIp` with the key absent, for both the positive (false) and negated (true) operators.
- An unknown key, a variable naming an unknown key, or an operator the evaluator does not know gives "unknown" (a residual), never a confident answer.

**New calls in #236 that the design leaves open (candidates for new entries, IDs provisional).** They are proposals, pending review.

| Candidate | Call made in #236 | Why it needs a decision |
|---|---|---|
| **N1** | `IfExists` beats a set qualifier when the key is absent: `ForAnyValue:StringEqualsIfExists` with a missing key is **true**. | Design §9 lists "`ForAnyValue` false when missing" and "`IfExists` true when missing" without saying which wins when both apply. True is the more permissive reading (D3). #236 does **not** flag this combination with an `AMBIGUITY` reason; D3 asks for a flag and a probe. |
| **N2** | `NullIfExists` is kept as written by the parser (a lint error) and evaluated as `Null`. | `IfExists` on `Null` is not documented. Probe: `CreatePolicy` with `NullIfExists`. |
| **N3** | A value that is not a six-segment ARN never matches an `Arn*` operator (see the A1 note on bare `*`). | AWS does not say how `ArnLike` treats a non-ARN context value. |

### Principals, grants and special resources

| ID | Conflict or gap | Default | Probe | Status |
|---|---|---|---|---|
| **A12** | KMS **grant** to a cross-account grantee: is an IAM allow needed in the grantee's account? The docs say "IAM policies… **or** use grants". [S14, S15] | No: the grant suffices on both sides. SCPs, RCPs and explicit denies still apply. | Grant to a role in account B that has no KMS identity permission. | Open |
| **A12b** | Is a same-account KMS grant to a **role ARN** capped by the role's boundary? [S14, S1] | Yes, with the same matrix as a role-ARN resource-policy grant. Over-approximation would say no, but the matrix rule is more specific. Flag until probed. | Role with a boundary excluding `kms:*`, plus a grant on `Decrypt`. | Open |
| **A13** | Access-point delegation versus double evaluation. | Both the access-point policy and the bucket policy (or its delegation to access points) must allow. | Sandbox access point with and without delegation. | Open |
| **A16** | Org-level S3 Block Public Access in "all or none" mode versus account-level partial settings. [S17] | The most restrictive of org, account, bucket and access point. | Toggle in the sandbox (management account only). | Open |

### Organizations policies and oracles

| ID | Conflict or gap | Default | Probe | Status |
|---|---|---|---|---|
| **A2** | The SCP syntax page's table allows `Resource`, `NotResource` and `Condition` with Allow, but its prose says Allow may only use `"*"` in `Resource`. [S4b, S30] | Follow the September 2025 announcement: full language. The linter warns. | SCP Allow scoped to one bucket ARN, then access to another bucket. | **Open, implemented** (lint, merged #102) |
| **A14** | Do RCP statements naming services outside the supported list get rejected at attach time, or silently ignored? [S5a, S5b] | Silently ignored for evaluation. | Attach `Deny lambda:InvokeFunction` as an RCP. | **Open, proposed resolution** (#237, see below) |
| **A15** | Does the simulator apply SCPs to management-account principals and to service-linked roles the way live enforcement does? [S4, S20, S21] | Trust live probes over the simulator for these strata. | Simulator versus probe on the management account and a service-linked role. | Open |

**A14, proposed resolution (PR #237), pending review.** The catalog holds the RCP service list as a reviewed overlay (`overlays/rcp_services.yaml`, 62 prefixes, `fetched_on: 2026-10-15`; the design's own count is 62 on 2026-10-08). `lambda` and `sns` are absent, as the design expects. This makes "which services does an RCP cover" data, which is what A14's default needs; it does not settle whether AWS rejects the other statements. The overlay is never edited automatically: `catalog compile` reports drift against the live page, and a change needs `iam-authz-expert` review.

**Overlays in #237 relevant to this register.** `rbp_rules.yaml` (A10), `rcp_services.yaml` (A14), `kms_xacct_ops.yaml` (the cross-account KMS operation list, design fact 14), `s3_public_fixed_keys.yaml` (the S3 "public" keys, fact 15), `global_keys.yaml` (key types and multivalued flags that A7 and A8 read), `s3_acl_map.yaml` and `opt_in_regions.yaml`. The design (§10.1) also lists "SCP/RCP exemption rules" as an overlay; #237 has no file for them, so reviewers should confirm where the exemptions (service-linked roles, management account, AWS-managed KMS keys, `kms:RetireGrant`) are encoded.

### Parser rules (A18 to A22)

These are choices about spelling and case in policy documents. The parser (merged in #102) implements each default and fails closed where it rejects a document.

| ID | Conflict or gap | Default | Probe | Status |
|---|---|---|---|---|
| **A18** | Condition **operator-name** case. The docs spell operators one way (`StringEquals`) and never say whether `stringequals` is accepted or how it evaluates. [S8] | Accept any ASCII case, store the canonical spelling, warn `NONCANONICAL_OPERATOR_CASE`. Two blocks that differ only by case are a duplicate-key error. Non-ASCII look-alikes (`ſ`, the Kelvin sign) never match an operator. | `CreatePolicy` and `SimulateCustomPolicy` with `stringequals` and `STRINGEQUALS`. | **Open, implemented** |
| **A19** | Policy **element-name** case (`Statement`, `Effect`, `Resource`, principal-map keys such as `AWS`). The grammar gives them as literal strings and does not say whether matching is case-sensitive. [S33] | Case-sensitive. A differently spelled element is unknown and the document is rejected (`unknown_element`), so it fails closed. | `CreatePolicy` with `"statement"`, `"effect"` and `{"aws": ...}`. | **Open, implemented** |
| **A20** | `Effect` **value** case (`"allow"`, `"DENY"`). [S33] | Case-sensitive. Only `Allow` and `Deny` parse; anything else is rejected (`invalid_value`) and fails closed. | `CreatePolicy` and `PutBucketPolicy` with `"Effect": "allow"`. | **Open, implemented** |
| **A22** | **Non-ASCII condition-key names.** Keys are case-insensitive, but AWS does not say whether that is ASCII-only or Unicode case folding (under which the Kelvin sign U+212A folds to `k` and `İ` U+0130 to `i`). [S10, S19] | ASCII-only folding (A to Z). Keys that differ only by non-ASCII case are distinct keys and never equal an ASCII key; any non-ASCII key gets the warning `NON_ASCII_CONDITION_KEY`. This stops a look-alike from silently matching `aws:SourceIp`. | `PutBucketPolicy` with `aws:PrincipalTag/É` and `aws:PrincipalTag/é` in one block, and a request tagged `é`. | **Open, implemented** |

(A21 is in the resource-matching table above because it concerns ARN patterns.)

## Counts

23 entries from the design (A1 to A22, with A12b), plus 3 candidates proposed here (N1 to N3). None is Settled.

- Open, implemented in merged code (6): A2, A18, A19, A20, A21, A22.
- Open, proposed resolution in an open PR (9): A1, A4, A5, A6, A7, A8, A10, A14, A17.
- Open, no code yet (8): A3, A9, A11, A12, A12b, A13, A15, A16.

The status cell of each entry is authoritative.

## Sources

AWS documentation, read 2026-10-08 unless noted. The labels match design §18.

- **[S1]** How AWS enforcement code logic evaluates requests: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html
- **[S4]** SCP evaluation: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html
- **[S4b]** SCP syntax: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html
- **[S5]** Principal element: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
- **[S5a]** Resource control policies: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
- **[S5b]** RCP syntax: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_syntax.html
- **[S6]** Policies and permissions (session policies, root user): https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html
- **[S7]** NotPrincipal: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html
- **[S8]** Condition operators: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
- **[S9]** Single-valued vs. multivalued context keys: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
- **[S10]** Policy variables and tags: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
- **[S11]** Resource element: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html
- **[S14]** KMS grants: https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
- **[S15]** KMS cross-account use: https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying-external-accounts.html
- **[S17]** S3 Block Public Access: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- **[S19]** Global condition context keys: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
- **[S20]** `SimulatePrincipalPolicy`: https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html
- **[S21]** `SimulateCustomPolicy`: https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html
- **[S30]** AWS What's New, 2025-09-19, full IAM policy language for SCPs: https://aws.amazon.com/about-aws/whats-new/2025/09/aws-organizations-iam-language-service-control-policies
- **[S31]** Grant a user permissions to switch roles: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_permissions-to-switch.html
- **[S33]** Grammar of the IAM JSON policy language (read 2026-10-09): https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html

A13 has no AWS page cited by the design; it is a pure sandbox question.
