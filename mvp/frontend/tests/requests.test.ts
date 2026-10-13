// Access request client calls (issue #164): method, path, body and the CSRF token of each.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-vic", tenant: { slug: "larkspur" }, user: {} } : { lines: [] };
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("request calls send method, path, body and CSRF", async () => {
  await api.submitRequest({ beneficiary_ids: [4], catalog_item_ids: ["i1", "i2"], justification: "project", duration_hours: null });
  await api.approveRequest("l1");
  await api.approveRequest("l1", "ok");
  await api.denyRequest("l/2", "no");
  await api.cancelRequest("l3");
  await api.removeRequest("l4");
  await api.putCatalogItem(9, { requestable: true, description: "", owner_identity_id: null, risk: "low", eligible_types: [], eligible_departments: [], default_hours: null, max_hours: 72 });
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/requests", { beneficiary_ids: [4], catalog_item_ids: ["i1", "i2"], justification: "project", duration_hours: null }],
      ["POST", "/api/requests/l1/approve", {}],
      ["POST", "/api/requests/l1/approve", { reason: "ok" }],
      ["POST", "/api/requests/l%2F2/deny", { reason: "no" }],
      ["POST", "/api/requests/l3/cancel", {}],
      ["POST", "/api/requests/l4/remove", {}],
      ["PUT", "/api/catalog/items/9", { requestable: true, description: "", owner_identity_id: null, risk: "low", eligible_types: [], eligible_departments: [], default_hours: null, max_hours: 72 }],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-vic");
});
