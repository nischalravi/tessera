// Request draft client calls: method, path, body and the CSRF token of each.
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

const input = {
  beneficiary_ids: [7],
  items: [{ kind: "group" as const, group_id: 3 }, { kind: "role" as const, role_id: "r-1" }],
  duration_hours: 24,
  justification: "joining the platform team",
};

test("a draft is created with POST and replaced with PUT; delete is DELETE", async () => {
  await api.requestDrafts.save(input);
  await api.requestDrafts.save(input, "d/1");
  await api.requestDrafts.remove("d/1");
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/request-drafts", input],
      ["PUT", "/api/request-drafts/d%2F1", input],
      ["DELETE", "/api/request-drafts/d%2F1", undefined],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat", `${c.method} ${c.url}`);
});

test("draft paths are encoded", () => {
  assert.equal(api.draftsPath, "/request-drafts");
  assert.equal(api.draftPath("a b"), "/request-drafts/a%20b");
});
