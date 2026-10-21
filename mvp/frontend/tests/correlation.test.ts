// Account correlation client calls (issue #160): each decision is a state-changing request with
// the session's CSRF token, the path and method the API registers, and the reason in the body.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-pat", tenant: { slug: "larkspur" }, user: {} } : { merge: {}, restored: [], kept: [] };
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("decisions send method, path, body and CSRF", async () => {
  await api.linkAccount(7, 3, "checked");
  await api.markNotPerson(8, "shared login");
  await api.releaseAccount(7);
  await api.cancelAccountLinkRequest(7);
  await api.mergeIdentity(5, 2, "duplicate");
  await api.unmergeIdentity("a b/c", "wrong person");
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/accounts/7/link", { identity_id: 3, reason: "checked" }],
      ["POST", "/api/accounts/8/not-person", { reason: "shared login" }],
      ["DELETE", "/api/accounts/7/link", undefined],
      ["DELETE", "/api/correlation/link-requests/7", undefined],
      ["POST", "/api/identities/5/merge", { into: 2, reason: "duplicate" }],
      ["POST", "/api/identity-merges/a%20b%2Fc/unmerge", { reason: "wrong person" }],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat", `${c.method} ${c.url} carries the CSRF token`);
});
