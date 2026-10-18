// Removal request client calls: method, path, body and the CSRF token of each.
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

test("removal requests use the removal-requests routes", async () => {
  await api.removals.submit(12, "no longer on the team");
  await api.removals.approve("q1");
  await api.removals.approve("q1", "confirmed");
  await api.removals.deny("q/2", "still needed");
  await api.removals.cancel("q3");
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/removal-requests", { edge_id: 12, justification: "no longer on the team" }],
      ["POST", "/api/removal-requests/q1/approve", {}],
      ["POST", "/api/removal-requests/q1/approve", { reason: "confirmed" }],
      ["POST", "/api/removal-requests/q%2F2/deny", { reason: "still needed" }],
      ["POST", "/api/removal-requests/q3/cancel", {}],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat", `${c.method} ${c.url}`);
});

test("removalsPath names the scope", () => {
  assert.equal(api.removalsPath(), "/removal-requests?scope=mine");
  assert.equal(api.removalsPath("approvals"), "/removal-requests?scope=approvals");
});
