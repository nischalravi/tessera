// Fidelity badges and the why-trace viewer's model (EP-7, #642). The fixture has the shape the Go
// API sends (internal/authz.Decision inside GET /api/aws/explanations/{id}), including the nulls a
// Go nil slice or map becomes. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();
const urls: string[] = [];
let status = 200;
(globalThis as any).fetch = async (url: string) => {
  urls.push(url);
  return status === 200
    ? { ok: true, status, statusText: "", json: async () => EXPLANATION }
    : { ok: false, status, statusText: "Not Found", json: async () => ({ error: "not_found", message: "no such explanation; run the query again" }) };
};

const ID = "a".repeat(64);
const STMT = {
  policy_id: "p-1234", policy_kind: "scp", source_arn: "arn:aws:organizations::111111111111:policy/o-x/service_control_policy/p-1234",
  version_id: "", statement_index: 1, sid: "DenyS3", span: { start_line: 3, start_col: 5, end_line: 9, end_col: 6 },
  attachment_path: null, org_level: "ou-ab12",
};
const EXPLANATION = {
  id: ID,
  decision: {
    outcome: "deny", deny_kind: "explicit", residual: false, fidelity: "approximate",
    fidelity_reasons: [{ code: "VPCE_POLICY_UNKNOWN", detail: "the endpoint policy was not collected", outcome_sensitive: true }],
    steps: [
      { stage: "explicit_deny", result: "deny", statement: STMT, matched_on: { resource: "arn:aws:s3:::b/*", action: "s3:*" }, condition_trace: null, residual: null, note: "", decisive: true },
      { stage: "identity", result: "no_match", statement: null, matched_on: null, condition_trace: [{ atom: { op: "IpAddress", key: "aws:sourceip", raw_key: "aws:SourceIp", values: ["10.0.0.0/8"], qualifier: "", if_exists: false, negated: false }, request_state: "absent", request_values: null, result: "unknown" }], residual: null, note: "", decisive: false },
    ],
    decisive: [STMT], request: { principal_arn: "arn:aws:iam::111111111111:user/alice", action: "s3:GetObject", resource_arn: "arn:aws:s3:::b/k", mode: "concrete" },
    engine_version: "e1", catalog_version: "c1", snapshot_id: "f".repeat(64),
  },
};

const api = await import("../src/api.ts");
const t = await import("../src/features/insights/awsTrace.ts");

test("awsExplanation calls /api/aws/explanations/{id} and keeps the Go shape", async () => {
  const x = await api.awsExplanation(ID);
  assert.deepEqual(urls, [`/api/aws/explanations/${ID}`]);
  assert.equal(x.decision.steps?.length, 2);
  status = 404;
  await assert.rejects(api.awsExplanation(ID), /run the query again/);
  status = 200;
});

test("fidelity values map to a tone and a plain-words meaning", () => {
  const cases: [string, t.Tone][] = [["exact", "ok"], ["approximate", "warning"], ["unsupported", "bad"], ["weird", "bad"]];
  for (const [f, tone] of cases) {
    assert.equal(t.fidelityTone(f), tone, f);
    assert.ok(t.fidelityMeaning(f).length > 20, f);
  }
  assert.match(t.fidelityMeaning("approximate"), /never acts on it/);
});

test("outcomes and deny kinds read correctly", () => {
  assert.equal(t.outcomeTone("allow"), "ok");
  assert.equal(t.outcomeTone("deny"), "bad");
  assert.equal(t.outcomeTone("conditional"), "warning");
  assert.match(t.outcomeMeaning("deny", "explicit"), /Deny statement/);
  assert.match(t.outcomeMeaning("deny", "guardrail"), /guardrail/);
  assert.match(t.outcomeMeaning("deny", ""), /nothing allowed/);
  assert.match(t.outcomeMeaning("conditional", ""), /condition/);
});

test("a step is summarised by stage, result, statement and decisiveness", () => {
  const steps = EXPLANATION.decision.steps;
  assert.equal(t.stepSummary(steps[0]), "Explicit deny: Denied: scp p-1234, statement 2 (DenyS3), at ou-ab12, lines 3 to 9: decisive");
  assert.equal(t.stepSummary(steps[1]), "Identity policy: No match");
  assert.equal(t.stageLabel("not_a_stage"), "not_a_stage");
  assert.equal(t.resultTone("deny"), "bad");
  assert.equal(t.resultTone("pass"), "ok");
  assert.equal(t.resultTone("conditional"), "warning");
});

test("null maps and lists from Go are safe", () => {
  assert.deepEqual(t.matchedOn(EXPLANATION.decision.steps[1] as any), []);
  assert.deepEqual(t.matchedOn(EXPLANATION.decision.steps[0] as any), [["action", "s3:*"], ["resource", "arn:aws:s3:::b/*"]]);
  assert.equal(t.residualText(null), "");
  assert.equal(t.stmtText({ ...STMT, policy_id: "", span: null, org_level: "", sid: "" }), "scp p-1234, statement 2");
});

test("residuals render as one readable line", () => {
  const atom = (key: string, extra = {}) => ({ op: "StringEquals", key: key.toLowerCase(), raw_key: key, values: ["a", "b"], qualifier: "", if_exists: false, negated: false, ...extra });
  assert.equal(t.residualText(true), "always true");
  assert.equal(t.residualText(false), "never true");
  assert.equal(t.residualText(atom("aws:PrincipalTag/team")), "aws:PrincipalTag/team StringEquals [a, b]");
  assert.equal(t.residualText({ and: [atom("a:X", { qualifier: "ForAnyValue", if_exists: true }), { not: atom("a:Y", { negated: true }) }] }),
    "(a:X ForAnyValue:StringEqualsIfExists [a, b] AND NOT not a:Y StringEquals [a, b])");
  assert.equal(t.residualText({ or: null }), "(never true)");
  let deep: any = true;
  for (let i = 0; i < 50; i++) deep = { not: deep };
  assert.ok(t.residualText(deep).includes("…"), "depth is capped");
});

test("only a 64-hex explanation id opens the panel", () => {
  assert.equal(t.isExplanationId(ID), true);
  for (const bad of [null, "", "abc", "A".repeat(64), `${ID}0`, "../x"]) assert.equal(t.isExplanationId(bad), false, String(bad));
  assert.equal(t.shortId(ID), "aaaaaaaa…");
});
