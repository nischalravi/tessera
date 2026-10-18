// Identity disable / enable client calls: method, path, body and the CSRF token of each.
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

test("disable, enable and the disable history use the identity routes", async () => {
  await api.disableIdentity(7, "suspected token theft");
  await api.enableIdentity(7, "false alarm confirmed");
  await api.identityDisables(7);
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/identities/7/disable", { reason: "suspected token theft" }],
      ["POST", "/api/identities/7/enable", { reason: "false alarm confirmed" }],
      ["GET", "/api/identities/7/disables", undefined],
    ],
  );
  assert.equal(calls[0].headers["x-tessera-csrf"], "csrf-pat");
  assert.equal(calls[1].headers["x-tessera-csrf"], "csrf-pat");
});
