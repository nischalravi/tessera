// Evidence pack and as-of client calls (issue #111): the path and method the API registers, the
// CSRF token on the generate call, and a download failure surfacing as an ApiError.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];
let downloadStatus = 200;

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  if (url.endsWith("/download")) {
    return downloadStatus === 200
      ? { ok: true, status: 200, statusText: "", blob: async () => new Blob(["zip"]) }
      : { ok: false, status: downloadStatus, statusText: "Not Found", json: async () => ({ detail: "evidence pack not found" }) };
  }
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-ev", tenant: { slug: "larkspur" }, user: {} } : { id: "p1" };
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
  downloadStatus = 200;
});

test("generating a pack posts the framework and dates with the CSRF token", async () => {
  await api.createEvidencePack({ framework: "soc2", from: "2026-01-01", to: "2026-03-31" });
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [["POST", "/api/evidence/packs", { framework: "soc2", from: "2026-01-01", to: "2026-03-31" }]],
  );
  assert.equal(calls[0].headers["x-tessera-csrf"], "csrf-ev");
});

test("the as-of path encodes the resource and the date", () => {
  assert.equal(api.asOfPath(12, "2026-03-31"), "/access/as-of?resource=12&date=2026-03-31");
  assert.equal(api.asOfPath("1&x=2", "2026-03-31T09:30:00"), "/access/as-of?resource=1%26x%3D2&date=2026-03-31T09%3A30%3A00");
});

test("a download goes to the pack's download path and a failure is an ApiError", async () => {
  const blob = await api.downloadEvidencePack("a b/c");
  assert.equal(blob.size, 3);
  assert.equal(calls[0].url, "/api/evidence/packs/a%20b%2Fc/download");
  downloadStatus = 404;
  await assert.rejects(api.downloadEvidencePack("p1"), (e: any) => e instanceof api.ApiError && e.status === 404 && /not found/.test(e.message));
});
