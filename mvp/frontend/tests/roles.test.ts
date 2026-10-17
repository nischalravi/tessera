// Business role client calls (issue #161): method, path, body and the CSRF token of each.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-pat", tenant: { slug: "larkspur" }, user: {} } : { role: {}, plan: {} };
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

const spec = {
  name: "Engineer", description: "", owner_identity_id: null, risk: "medium" as const, requestable: true,
  birthright: { department: ["Engineering"], type: [], title: [] }, entitlement_group_ids: [3, 4], note: "v1",
};

test("role changes send method, path, body (dry run as ?dry_run=1) and CSRF", async () => {
  await api.roles.create(spec, true);
  await api.roles.create(spec);
  await api.roles.update("r/1", 2, spec, true);
  await api.roles.retire("r1", "replaced");
  await api.roles.reconcile("r1", true);
  await api.roles.assign("r1", 7, "", false);
  await api.roles.unassign("r1", 7, "moved", true);
  await api.roles.request("r1", 7, "month-end");
  await api.roles.approve("q1");
  await api.roles.approve("q1", "ok");
  await api.roles.deny("q/2", "no");
  await api.roles.cancel("q3");
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/roles?dry_run=1", spec],
      ["POST", "/api/roles", spec],
      ["PUT", "/api/roles/r%2F1?dry_run=1", { version: 2, ...spec }],
      ["POST", "/api/roles/r1/retire", { reason: "replaced" }],
      ["POST", "/api/roles/r1/reconcile?dry_run=1", {}],
      ["POST", "/api/roles/r1/members", { identity_id: 7, reason: "" }],
      ["POST", "/api/roles/r1/members/7/remove?dry_run=1", { reason: "moved" }],
      ["POST", "/api/role-requests", { role_id: "r1", beneficiary_id: 7, justification: "month-end" }],
      ["POST", "/api/role-requests/q1/approve", {}],
      ["POST", "/api/role-requests/q1/approve", { reason: "ok" }],
      ["POST", "/api/role-requests/q%2F2/deny", { reason: "no" }],
      ["POST", "/api/role-requests/q3/cancel", {}],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat", `${c.method} ${c.url}`);
});

test("read paths", () => {
  assert.equal(api.rolePaths.list, "/roles");
  assert.equal(api.rolePaths.one("a b"), "/roles/a%20b");
  assert.equal(api.rolePaths.versions("r1"), "/roles/r1/versions");
  assert.equal(api.rolePaths.drift("r1"), "/roles/r1/drift");
});
