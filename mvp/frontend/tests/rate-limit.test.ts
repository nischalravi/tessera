// The sign-in rate limit (per IP on /api/auth/*): a 429 is a RateLimitedError with the wait
// the API asked for, so the sign-in page can say so and retry instead of "unreachable".
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = Object.assign(new EventTarget(), { location: { assign: () => undefined } });
let status = 429;
let retryAfter: string | null = "17";
(globalThis as any).fetch = async () => ({
  ok: status < 400, status, statusText: "Too Many Requests",
  headers: { get: (h: string) => (h.toLowerCase() === "retry-after" ? retryAfter : null) },
  json: async () => ({ connections: [] }),
});

const api = await import("../src/api.ts");

test("Retry-After is read as seconds or an HTTP date, clamped to 1..300, 30 when missing", () => {
  const now = Date.parse("2026-10-11T09:00:00Z");
  assert.equal(api.retryAfterSeconds("17", now), 17);
  assert.equal(api.retryAfterSeconds(" 0 ", now), 1);
  assert.equal(api.retryAfterSeconds("99999", now), 300);
  assert.equal(api.retryAfterSeconds("Sun, 11 Oct 2026 09:00:42 GMT", now), 42);
  assert.equal(api.retryAfterSeconds("Sun, 11 Oct 2026 08:00:00 GMT", now), 1);
  assert.equal(api.retryAfterSeconds(null, now), 30);
  assert.equal(api.retryAfterSeconds("soon", now), 30);
});

test("a rate-limited session check is a RateLimitedError, not 'unreachable'", async () => {
  status = 429;
  retryAfter = "17";
  await assert.rejects(api.getSession(), (e: any) => e instanceof api.RateLimitedError && e.retryAfter === 17 && e.status === 429);
  await assert.rejects(api.discover("larkspur"), (e: any) => e instanceof api.RateLimitedError && e.retryAfter === 17);
  retryAfter = null;
  await assert.rejects(api.getSession(), (e: any) => e instanceof api.RateLimitedError && e.retryAfter === 30);
});

test("other failures stay ordinary errors", async () => {
  status = 503;
  await assert.rejects(api.getSession(), (e: any) => !(e instanceof api.RateLimitedError) && e.status === 503);
});
