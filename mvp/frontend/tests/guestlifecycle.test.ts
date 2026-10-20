// Guest lifecycle client calls and the renewal page's token rule (issue #74). Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];
let status = 200;

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-pat", tenant: { slug: "larkspur" }, user: {} } : {};
  return { ok: status < 400, status, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");
const model = await import("../src/features/governance/guestLifecycleModel.ts");

beforeEach(async () => {
  status = 200;
  await api.getSession();
  calls = [];
});

test("resolving a task and saving settings send method, path, body and CSRF", async () => {
  await api.guestLifecycle.resolveTask("t 1/x", "accept");
  const s = {
    sponsor_reminder_days: [30, 14, 3], guest_reminder_days: 14, transfer_deadline_days: 14, on_sponsor_departure: "end" as const,
    conversion_dual_status: "end" as const, grace_days: { visitor: 0, contractor: 30, volunteer: 30, partner: 30 }, retention_days: 2555,
    retention_days_visitor: 365, keep_rematch_hashes: false,
  };
  await api.guestLifecycle.putSettings(s);
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.body]), [
    ["POST", "/api/guest-lifecycle/tasks/t%201%2Fx/resolve", { action: "accept" }],
    ["PUT", "/api/admin/guest-lifecycle", s],
  ]);
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat");
});

test("the renewal request is a public POST of the token, without a session header", async () => {
  await api.requestRenewal("lark spur", "T".repeat(43));
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.body]), [["POST", "/public/t/lark%20spur/guest/renewal-request", { token: "T".repeat(43) }]]);
  assert.equal(calls[0].headers["x-tessera-csrf"], undefined);
  status = 202; // the API's answer, whatever the token was
  await api.requestRenewal("larkspur", "x");
  status = 429;
  await assert.rejects(api.requestRenewal("larkspur", "x"), /Too many tries/);
});

test("task actions depend on the kind, the trigger and the tenant's setting", () => {
  const base = { guest: { id: 1, name: "Gwen" }, can_act: true };
  const labels = (it: any, d: "end" | "suspend") => model.taskActions({ ...base, ...it }, d).map((a) => a.action);
  assert.deepEqual(labels({ task_kind: "sponsor_transfer", trigger: "leaver" }, "end"), ["accept", "decline"]);
  assert.deepEqual(labels({ task_kind: "sponsor_transfer", trigger: "mover" }, "end"), ["accept", "keep", "decline"]);
  assert.deepEqual(labels({ task_kind: "dual_status" }, "end"), ["confirm", "decline"]);
  assert.deepEqual(labels({ task_kind: "renewal_request" }, "end"), ["dismiss"]);
  assert.deepEqual(labels({}, "end"), []);
  const decline = (d: "end" | "suspend") => model.taskActions({ ...base, task_kind: "sponsor_transfer", trigger: "leaver" }, d).at(-1)!.label;
  assert.equal(decline("end"), "End");
  assert.equal(decline("suspend"), "Suspend");
});

test("settings are checked the way the API checks them", () => {
  const ok = {
    sponsor_reminder_days: [30, 14, 3], guest_reminder_days: 14, transfer_deadline_days: 14, on_sponsor_departure: "end" as const,
    conversion_dual_status: "end" as const, grace_days: { visitor: 0, contractor: 30, volunteer: 30, partner: 30 }, retention_days: 2555,
    retention_days_visitor: 365, keep_rematch_hashes: false,
  };
  assert.equal(model.settingsProblem(ok), null);
  assert.deepEqual(model.parseDays("30, 14  3"), [30, 14, 3]);
  assert.ok(model.settingsProblem({ ...ok, sponsor_reminder_days: model.parseDays("30, x") }));
  assert.ok(model.settingsProblem({ ...ok, sponsor_reminder_days: [0] }));
  assert.ok(model.settingsProblem({ ...ok, sponsor_reminder_days: [1, 2, 3, 4, 5, 6] }));
  assert.ok(model.settingsProblem({ ...ok, guest_reminder_days: -1 }));
  assert.ok(model.settingsProblem({ ...ok, transfer_deadline_days: 0 }));
  assert.ok(model.settingsProblem({ ...ok, grace_days: { ...ok.grace_days, partner: 400 } }));
  assert.ok(model.settingsProblem({ ...ok, retention_days: 0 }));
});
