// Attribute policy client calls (issue #162): method, path, body and the CSRF token of each, and
// the plain-language rendering of conditions. Run with `npm test`.
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
const text = await import("../src/features/governance/abacText.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

const finance = { all: [{ attr: "identity.department", op: "eq", value: "Finance" }, { attr: "identity.type", op: "eq", value: "human" }] } as const;

test("policy changes send method, path, body and CSRF", async () => {
  const spec = { name: "Finance", description: "", condition: finance, note: "v1" };
  await api.abac.create(spec as any);
  await api.abac.update("p/1", 2, spec as any);
  await api.abac.retire("p1", "unused");
  await api.abac.simulate(finance as any);
  await api.abac.simulate(finance as any, "p1", { resource: { "resource.risk": "high" }, context: { "context.aal": 2 } });
  await api.abac.bindCatalog(7, "p1");
  await api.abac.bindCatalog(7, null);
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/abac/policies", spec],
      ["PUT", "/api/abac/policies/p%2F1", { version: 2, ...spec }],
      ["POST", "/api/abac/policies/p1/retire", { reason: "unused" }],
      ["POST", "/api/abac/simulate", { condition: finance }],
      ["POST", "/api/abac/simulate", { condition: finance, policy_id: "p1", resource: { "resource.risk": "high" }, context: { "context.aal": 2 } }],
      ["PUT", "/api/catalog/items/7/policy", { policy_id: "p1" }],
      ["PUT", "/api/catalog/items/7/policy", { policy_id: null }],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat", `${c.method} ${c.url}`);
});

test("read paths", () => {
  assert.equal(api.abacPaths.list, "/abac/policies");
  assert.equal(api.abacPaths.one("a b"), "/abac/policies/a%20b");
  assert.equal(api.abacPaths.bindings, "/abac/bindings");
});

test("describeCondition reads in words", () => {
  assert.equal(text.describeCondition(finance as any), "department = Finance and type = human");
  assert.equal(
    text.describeCondition({ all: [{ attr: "identity.type", op: "eq", value: "human" }, { any: [{ attr: "identity.title", op: "prefix", value: "Lead" }, { not: { attr: "context.aal", op: "lt", value: 2 } }] }] } as any),
    "type = human and (title starts with Lead or not context aal < 2)",
  );
  assert.equal(text.describeCondition({ attr: "identity.department", op: "in", value: ["HR", "Legal"] }), "department is one of HR, Legal");
  assert.equal(text.describeCondition({ attr: "identity.manager_id", op: "exists" }), "manager id is set");
});

test("parseConditionText reports what is wrong", () => {
  assert.equal(text.parseConditionText("").error, "Write a condition.");
  assert.match(text.parseConditionText("{").error ?? "", /Not valid JSON/);
  assert.equal(text.parseConditionText("[]").error, "A condition is a JSON object.");
  assert.equal(text.parseConditionText("null").error, "A condition is a JSON object.");
  const ok = text.parseConditionText(JSON.stringify(finance));
  assert.equal(ok.error, null);
  assert.deepEqual(ok.condition, finance);
});
