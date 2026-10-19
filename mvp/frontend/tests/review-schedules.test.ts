// Scheduled review client calls (issue #166): method, path, body and CSRF. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();
type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];
(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-olu", tenant: { slug: "larkspur" }, user: {} } : {};
  return { ok: true, status: 200, statusText: "", json: async () => body };
};
const api = await import("../src/api.ts");
beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("schedule calls", async () => {
  const b = { name: "Q", system: null, privileged_only: true, unused_days: 60, duration_days: 14, reminder_days: 3, close_out: "revoke" as const,
    escalation_identity_id: null, escalation_days: 7, recurrence: "quarterly" as const, first_run_at: "2026-11-01T09:00:00.000Z", enabled: true };
  await api.createReviewSchedule(b);
  await api.updateReviewSchedule("s/1", b);
  await api.runReviewSchedule("s1");
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.body]), [
    ["POST", "/api/reviews/schedules", b],
    ["PUT", "/api/reviews/schedules/s%2F1", b],
    ["POST", "/api/reviews/schedules/s1/run", {}],
  ]);
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-olu");
});
