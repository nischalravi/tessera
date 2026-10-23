// Vendor breach response client calls (issue #475): the path and method the API registers, the CSRF
// token on every change, and an evidence download failure surfacing as an ApiError.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];
let downloadStatus = 200;

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  if (url.endsWith("/evidence")) {
    return downloadStatus === 200
      ? { ok: true, status: 200, statusText: "", blob: async () => new Blob(["{}"]) }
      : { ok: false, status: downloadStatus, statusText: "Not Found", json: async () => ({ error: "not_found", detail: "no such breach plan" }) };
  }
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-br", tenant: { slug: "larkspur" }, user: {} } : { id: "p1" };
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
  downloadStatus = 200;
});

test("each call goes to the route the API registers, with the CSRF token", async () => {
  await api.breach.inventory("railway");
  await api.breach.create("railway", "Vendor breach notice of 21 Oct");
  await api.breach.run("p 1");
  await api.breach.verify("p1");
  await api.breach.attest("p1", "i/1", "disabled in the console");
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/breach/inventory", { vendor: "railway" }],
      ["POST", "/api/breach/plans", { vendor: "railway", reason: "Vendor breach notice of 21 Oct" }],
      ["POST", "/api/breach/plans/p%201/run", {}],
      ["POST", "/api/breach/plans/p1/verify", {}],
      ["POST", "/api/breach/plans/p1/items/i%2F1/attest", { note: "disabled in the console" }],
    ],
  );
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-br");
});

test("the read paths encode the plan id", () => {
  assert.equal(api.breach.plansPath, "/breach/plans");
  assert.equal(api.breach.planPath("a b/c"), "/breach/plans/a%20b%2Fc");
});

test("the evidence download goes to the plan's evidence path and a failure is an ApiError", async () => {
  const blob = await api.breach.evidence("a b");
  assert.equal(blob.size, 2);
  assert.equal(calls[0].url, "/api/breach/plans/a%20b/evidence");
  downloadStatus = 404;
  await assert.rejects(api.breach.evidence("p1"), (e: any) => e instanceof api.ApiError && e.status === 404);
});
