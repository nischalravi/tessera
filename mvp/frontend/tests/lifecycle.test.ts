// Identity lifecycle client calls (issue #159): method, path, body and the CSRF token of each.
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

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("lifecycle changes send method, path, body and CSRF", async () => {
  const spec = { worker_type: "contractor" as const, sponsor_identity_id: 3, organization: "Acme", starts_at: null, ends_at: "2026-12-31T23:59:59.000Z", reason: "SOW 42" };
  await api.lifecycle.set(7, spec);
  await api.lifecycle.extend(7, "2027-03-31T23:59:59.000Z", "renewed");
  await api.lifecycle.sweep();
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.body]), [
    ["PUT", "/api/identities/7/lifecycle", spec],
    ["POST", "/api/identities/7/lifecycle/extend", { ends_at: "2027-03-31T23:59:59.000Z", reason: "renewed" }],
    ["POST", "/api/lifecycle/sweep", {}],
  ]);
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat");
});

test("read paths", () => {
  assert.equal(api.lifecycle.paths.list(), "/lifecycle");
  assert.equal(api.lifecycle.paths.list("ending"), "/lifecycle?state=ending");
  assert.equal(api.lifecycle.paths.sponsored, "/lifecycle/sponsored");
  assert.equal(api.lifecycle.paths.one(4), "/identities/4/lifecycle");
});
