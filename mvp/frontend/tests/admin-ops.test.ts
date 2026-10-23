// Admin > Audit log server filters, schedule pause and resume calls, and the config-transfer plan sections
// (issue #497). Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; body: any };
let calls: Call[] = [];

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-ops", tenant: { slug: "larkspur" }, user: {} } : {};
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");
const q = await import("../src/features/admin/auditQuery.ts");

beforeEach(() => {
  calls = [];
});

test("an empty audit query asks for the newest 500 and nothing else", () => {
  assert.equal(q.auditPath(q.EMPTY_AUDIT_QUERY), "/audit?limit=500");
  assert.ok(q.isUnfiltered(q.EMPTY_AUDIT_QUERY));
});

test("actor, target and date range go to the server as query parameters", () => {
  const path = q.auditPath({ actorId: " u-1 ", targetType: "access_request", targetId: "4", from: "2026-10-01", to: "2026-10-02", includeHttp: true });
  const p = new URL(path, "http://x").searchParams;
  assert.equal(p.get("actor_id"), "u-1");
  assert.equal(p.get("target_type"), "access_request");
  assert.equal(p.get("target_id"), "4");
  assert.equal(p.get("from"), "2026-10-01T00:00:00Z");
  assert.equal(p.get("to"), "2026-10-02T23:59:59.999999Z");
  assert.equal(p.get("include_http"), "true");
  assert.ok(!q.isUnfiltered({ ...q.EMPTY_AUDIT_QUERY, actorId: "u-1" }));
});

test("a malformed date is dropped instead of sent", () => {
  const p = new URL(q.auditPath({ ...q.EMPTY_AUDIT_QUERY, from: "yesterday", to: "2026-13" }), "http://x").searchParams;
  assert.equal(p.get("from"), null);
  assert.equal(p.get("to"), null);
});

test("pausing and resuming a schedule post to the schedule's own routes", async () => {
  await api.queue.pauseSchedule("sweep_drift", "maintenance");
  await api.queue.resumeSchedule("sweep drift/x");
  const posts = calls.filter((c) => c.method === "POST");
  assert.equal(posts[0].url, "/api/queue/schedules/sweep_drift/pause");
  assert.deepEqual(posts[0].body, { reason: "maintenance" });
  assert.equal(posts[1].url, "/api/queue/schedules/sweep%20drift%2Fx/resume");
});
