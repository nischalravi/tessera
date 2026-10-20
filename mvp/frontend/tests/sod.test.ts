// SoD client calls (issue #298): method, path, body and the CSRF token of each, plus the view logic.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-pat", tenant: { slug: "larkspur" }, user: {} } : {};
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");
const m = await import("../src/features/governance/sodModel.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("SoD changes send method, path, body and CSRF", async () => {
  const fn = { name: "Approve", description: "", owner_id: null, selectors: [{ name_pattern: "payments:approve" }] };
  const risk = { name: "R", description: "", priority: "high", business_process: "", owner_id: null, ruleset_id: "rs1", function_ids: ["a", "b"], subjects: {} } as const;
  const rs = { name: "Finance", description: "", enabled: true };
  await api.sod.createFunction(fn);
  await api.sod.updateFunction("f/1", 2, fn);
  await api.sod.retireFunction("f1", "unused");
  await api.sod.createRisk(risk as any);
  await api.sod.updateRisk("r1", 3, risk as any);
  await api.sod.retireRisk("r1", "done");
  await api.sod.createRuleset(rs);
  await api.sod.updateRuleset("rs1", 1, { ...rs, enabled: false });
  await api.sod.retireRuleset("rs1", "gone");
  await api.sod.importRuleset("ruleset: {}", { dry_run: true });
  await api.sod.importLegacy();
  await api.sod.simulate([4], ["i1", "i2"]);
  await api.sod.simulate([4], ["i1"], 8);
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/sod/functions", fn],
      ["PUT", "/api/sod/functions/f%2F1", { version: 2, ...fn }],
      ["POST", "/api/sod/functions/f1/retire", { reason: "unused" }],
      ["POST", "/api/sod/risks", risk],
      ["PUT", "/api/sod/risks/r1", { version: 3, ...risk }],
      ["POST", "/api/sod/risks/r1/retire", { reason: "done" }],
      ["POST", "/api/sod/rulesets", rs],
      ["PUT", "/api/sod/rulesets/rs1", { version: 1, ...rs, enabled: false }],
      ["POST", "/api/sod/rulesets/rs1/retire", { reason: "gone" }],
      ["POST", "/api/sod/rulesets/import", { yaml: "ruleset: {}", dry_run: true }],
      ["POST", "/api/sod/import-legacy", { dry_run: false }],
      ["POST", "/api/sod/simulate", { beneficiary_ids: [4], catalog_item_ids: ["i1", "i2"] }],
      ["POST", "/api/sod/simulate", { beneficiary_ids: [4], catalog_item_ids: ["i1"], duration_hours: 8 }],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat", `${c.method} ${c.url}`);
});

test("violation filters become a query string and leave empty ones out", () => {
  assert.equal(api.sodViolationQuery({}), "");
  assert.equal(api.sodPaths.violations({ priority: "high", risk: "", identity: "a b" }), "/sod/violations?priority=high&identity=a+b");
  assert.equal(api.sodPaths.risk("a/b"), "/sod/risks/a%2Fb");
});

test("selectors are described and validated like the server does", () => {
  assert.equal(m.describeSelector({ system: "workday", name_pattern: "payments:approve", attribute: "environment", value: "prod" }), "workday: payments:approve where environment = prod");
  assert.equal(m.describeSelector({ name_pattern: "*:admin" }), "any system: *:admin");
  assert.equal(m.describeSelector({ system: "aws", entitlement_id: 7 }), "aws: entitlement #7");
  assert.equal(m.selectorError({ name_pattern: "x" }), null);
  assert.ok(m.selectorError({}));
  assert.ok(m.selectorError({ name_pattern: "x", entitlement_id: 1, system: "aws" }));
  assert.ok(m.selectorError({ entitlement_id: 1 }));
  assert.ok(m.selectorError({ name_pattern: "x", attribute: "tag" }));
  assert.ok(m.selectorError({ name_pattern: "x", attribute: "privileged", value: "yes" }));
  assert.deepEqual(m.cleanSelector({ system: " ", name_pattern: " p ", attribute: "tag", value: "" }), { name_pattern: "p" });
});

test("a risk needs two distinct functions, a name and a ruleset", () => {
  assert.equal(m.riskError({ name: "R", ruleset_id: "rs", function_ids: ["a", "b"] }), null);
  assert.ok(m.riskError({ name: " ", ruleset_id: "rs", function_ids: ["a", "b"] }));
  assert.ok(m.riskError({ name: "R", ruleset_id: "", function_ids: ["a", "b"] }));
  assert.ok(m.riskError({ name: "R", ruleset_id: "rs", function_ids: ["a"] }));
  assert.ok(m.riskError({ name: "R", ruleset_id: "rs", function_ids: ["a", "a"] }));
});

test("conflicts sort most severe first and the request warning follows the highest priority", () => {
  const v = (priority: string, risk: string, who: string) => ({ priority, risk_name: risk, identity_name: who }) as any;
  assert.deepEqual(m.sortViolations([v("low", "A", "z"), v("critical", "B", "y"), v("critical", "B", "x")]).map((x: any) => x.identity_name), ["x", "y", "z"]);
  assert.equal(m.sodWarning(null), null);
  assert.equal(m.sodWarning({ checked: 1, skipped: [], would_trigger: [], highest_priority: "" }), null);
  const t = { risk_key: "r", risk_name: "Pay own invoice", priority: "high", identity_name: "Ada", function1: { name: "Create" }, function2: { name: "Approve" } } as any;
  const w = m.sodWarning({ checked: 1, skipped: [], would_trigger: [t, { ...t, risk_key: "r2" }], highest_priority: "high" })!;
  assert.equal(w.tone, "bad");
  assert.match(w.title, /2 separation-of-duties conflicts \(2 risks, highest high\)/);
  assert.equal(m.sodWarning({ checked: 1, skipped: [], would_trigger: [t], highest_priority: "low" })!.tone, "warn");
  assert.deepEqual(m.distinct([{ s: ["b", "a"] }, { s: ["a", ""] }], (r) => r.s), ["a", "b"]);
});

test("mitigation calls send method, path, body and CSRF", async () => {
  const spec = { name: "Monthly review", description: "", owner_id: 3, type: "detective", frequency: "monthly", evidence_requirement: "report" } as const;
  await api.sodControls.create(spec as any);
  await api.sodControls.update("c/1", 2, spec as any);
  await api.sodControls.retire("c1", "obsolete");
  await api.sodMitigations.request({ risk_id: "r1", identity_id: 4, kind: "control", control_id: "c1", justification: "j", ends_at: "2026-12-31", evidence: ["T-1"] });
  await api.sodMitigations.approve("m1");
  await api.sodMitigations.approve("m1", "fine");
  await api.sodMitigations.reject("m/2", "no");
  await api.sodMitigations.cancel("m3");
  await api.sodMitigations.revoke("m4", "control failed");
  await api.sodRemediate.escalate("r1", 4, "decide");
  await api.sodRemediate.revoke("r1", 4, 9, true);
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/sod/controls", spec],
      ["PUT", "/api/sod/controls/c%2F1", { version: 2, ...spec }],
      ["POST", "/api/sod/controls/c1/retire", { reason: "obsolete" }],
      ["POST", "/api/sod/mitigations", { risk_id: "r1", identity_id: 4, kind: "control", control_id: "c1", justification: "j", ends_at: "2026-12-31", evidence: ["T-1"] }],
      ["POST", "/api/sod/mitigations/m1/approve", { note: "" }],
      ["POST", "/api/sod/mitigations/m1/approve", { note: "fine" }],
      ["POST", "/api/sod/mitigations/m%2F2/reject", { note: "no" }],
      ["POST", "/api/sod/mitigations/m3/cancel", {}],
      ["POST", "/api/sod/mitigations/m4/revoke", { reason: "control failed" }],
      ["POST", "/api/sod/violations/escalate", { risk_id: "r1", identity_id: 4, note: "decide" }],
      ["POST", "/api/sod/violations/revoke", { risk_id: "r1", identity_id: 4, edge_id: 9, dry_run: true }],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat", `${c.method} ${c.url}`);
  assert.equal(api.sodControlPaths.mitigations(), "/sod/mitigations");
  assert.equal(api.sodControlPaths.mitigations({ status: "active", expiring_within_days: 14 }), "/sod/mitigations?status=active&expiring_within_days=14");
  assert.equal(api.sodControlPaths.reviewContext(7), "/sod/review-context?campaign_id=7");
});

test("the end date is mandatory, in the future and within the limit", () => {
  const now = new Date("2026-10-08T09:30:00Z");
  assert.equal(m.endDayError("2026-12-31", now, 365), null);
  assert.ok(m.endDayError("", now, 365));
  assert.ok(m.endDayError("2026-10-08", now, 365), "today is not the future");
  assert.ok(m.endDayError("2026-10-01", now, 365));
  assert.ok(m.endDayError("tomorrow", now, 365));
  assert.equal(m.latestEndDay(now, 30), "2026-11-07");
  assert.equal(m.endDayError("2026-11-07", now, 30), null);
  assert.match(m.endDayError("2026-11-08", now, 30)!, /at most 30 days/);
  assert.equal(m.defaultEndDay(now, 365), "2027-01-06");
  assert.equal(m.defaultEndDay(now, 30), "2026-11-07");
});

test("only the options a risk offers are available, and covered violations are not open", () => {
  assert.equal(m.offers({ remediation: ["revoke", "escalate"] }, "revoke"), true);
  assert.equal(m.offers({ remediation: ["revoke", "escalate"] }, "mitigate"), false);
  assert.equal(m.offers({}, "accept"), true);
  assert.equal(m.openCount([{ status: "open" }, { status: "mitigation_pending" }, { status: "mitigated" }, { status: "accepted" }]), 2);
  assert.equal(m.statusLabel("mitigation_pending"), "Mitigation requested");
});

test("four-eyes in the UI: the requester is never offered the decision", () => {
  assert.equal(m.canDecide({ status: "pending", requested_by_me: false }, true), true);
  assert.equal(m.canDecide({ status: "pending", requested_by_me: true }, true), false);
  assert.equal(m.canDecide({ status: "pending", requested_by_me: false }, false), false);
  assert.equal(m.canDecide({ status: "active", requested_by_me: false }, true), false);
});

test("expiry wording and the expiring-soon filter", () => {
  assert.equal(m.daysLeftLabel(null), "");
  assert.equal(m.daysLeftLabel(-1), "ended");
  assert.equal(m.daysLeftLabel(0), "ends today");
  assert.equal(m.daysLeftLabel(1), "1 day left");
  assert.equal(m.daysLeftLabel(9), "9 days left");
  assert.equal(m.expiringSoon({ status: "active", days_left: 9 }, 14), true);
  assert.equal(m.expiringSoon({ status: "active", days_left: 30 }, 14), false);
  assert.equal(m.expiringSoon({ status: "pending", days_left: 3 }, 14), false);
  assert.equal(m.mitigationStatusLabel({ status: "active", kind: "accept" }), "Accepted");
  assert.equal(m.mitigationStatusLabel({ status: "active", kind: "control" }), "Mitigated");
  assert.equal(m.mitigationStatusLabel({ status: "pending", kind: "control" }), "Awaiting approval");
  assert.deepEqual(m.parseEvidence(" a \n\n b\n"), ["a", "b"]);
});

test("ruleset remediation sends method, path, body and CSRF", async () => {
  await api.sod.setRulesetRemediation("rs/1", ["revoke", "escalate"], 7);
  await api.sod.setRulesetRemediation("rs1", [], null);
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.headers["x-tessera-csrf"], c.body]),
    [
      ["PUT", "/api/sod/rulesets/rs%2F1/remediation", "csrf-pat", { options: ["revoke", "escalate"], escalate_to_id: 7 }],
      ["PUT", "/api/sod/rulesets/rs1/remediation", "csrf-pat", { options: [], escalate_to_id: null }],
    ],
  );
});

test("own options are sent only when chosen, and all four mean none", () => {
  assert.deepEqual(m.optionsToSend(false, ["revoke"]), []); // inherit: the chosen list is ignored
  assert.deepEqual(m.optionsToSend(true, ["escalate", "revoke"]), ["revoke", "escalate"]); // display order
  assert.deepEqual(m.optionsToSend(true, ["accept", "escalate", "revoke", "mitigate"]), []); // all four = the default
  assert.equal(m.optionsError(true, []), "Choose at least one option, or inherit them");
  assert.equal(m.optionsError(false, []), null);
  assert.equal(m.optionsError(true, ["accept"]), null);
});

test("remediation wording names where options come from and who gets an escalation", () => {
  assert.equal(m.sourceLabel("risk"), "Set on this risk");
  assert.equal(m.sourceLabel("ruleset"), "Inherited from the ruleset");
  assert.match(m.sourceLabel("default"), /Every option/);
  assert.equal(m.describeOptions([]), "None");
  assert.equal(m.describeOptions(["escalate", "revoke"]), "Revoke access, Escalate to an approver");
  assert.equal(m.escalationLabel({ name: "Carol" }), "Carol");
  assert.match(m.escalationLabel(null), /Nobody/);
  // a violation offers only what its risk (or ruleset) offers
  assert.equal(m.offers({ remediation: ["revoke", "escalate"] }, "accept"), false);
  assert.equal(m.offers({ remediation: ["revoke", "escalate"] }, "escalate"), true);
});
