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
