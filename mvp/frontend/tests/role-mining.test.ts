// Role mining client calls (issue #298): method, path, body and the CSRF token of each.
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
const { confidenceTone, ruleLabel } = await import("../src/features/roles/miningModel.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("mining changes send method, path, body and CSRF", async () => {
  await api.roleMining.start({ department: ["Engineering"], min_members: 4, async: true });
  await api.roleMining.accept("c/1", { name: "Backend", entitlement_group_ids: [3, 4] });
  await api.roleMining.accept("c2", {});
  await api.roleMining.dismiss("c3", "too broad");
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/role-mining/runs", { department: ["Engineering"], min_members: 4, async: true }],
      ["POST", "/api/role-mining/candidates/c%2F1/accept", { name: "Backend", entitlement_group_ids: [3, 4] }],
      ["POST", "/api/role-mining/candidates/c2/accept", {}],
      ["POST", "/api/role-mining/candidates/c3/dismiss", { reason: "too broad" }],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat", `${c.method} ${c.url}`);
});

test("read paths", () => {
  assert.equal(api.miningPaths.runs, "/role-mining/runs");
  assert.equal(api.miningPaths.run("a b"), "/role-mining/runs/a%20b");
  assert.equal(api.miningPaths.candidate("c/1"), "/role-mining/candidates/c%2F1");
});

test("confidence bands and rule labels", () => {
  assert.equal(confidenceTone(95), "ok");
  assert.equal(confidenceTone(80), "ok");
  assert.equal(confidenceTone(79), "info");
  assert.equal(confidenceTone(59), "warning");
  assert.equal(ruleLabel(null), null);
  assert.equal(ruleLabel({ attribute: "department", values: ["A", "B"], precision: 100, recall: 90 }), "department: A or B");
});
