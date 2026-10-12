// Notification client calls (issue #189): method, path, body and the CSRF token of each.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-vic", tenant: { slug: "larkspur" }, user: {} } : { unread: 0, items: [], kinds: [] };
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("the inbox is read with a GET and the bell path asks for a bounded page", async () => {
  await api.api(api.NOTIFICATIONS_PATH);
  assert.deepEqual(calls.map((c) => [c.method, c.url]), [["GET", "/api/notifications?limit=30"]]);
  assert.equal(calls[0].headers["x-tessera-csrf"], undefined);
});

test("mark-as-read and preference calls send method, path, body and CSRF", async () => {
  await api.markNotificationsRead({ ids: ["n1", "n2"] });
  await api.markNotificationsRead({ all: true });
  await api.putNotificationPrefs({ "request.approved": "digest" });
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.body]), [
    ["POST", "/api/notifications/read", { ids: ["n1", "n2"] }],
    ["POST", "/api/notifications/read", { all: true }],
    ["PUT", "/api/notifications/preferences", { prefs: { "request.approved": "digest" } }],
  ]);
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-vic");
});
