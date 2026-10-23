// Two-admin change UI (issue #526): payload mapping from forms, the 409 detection, and the pause checks. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();
const calls: { url: string; method: string; body: any }[] = [];
(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: true, status: 200, statusText: "", json: async () => ({}) };
};

const t = await import("../src/features/admin/twoAdmin.ts");
const api = await import("../src/api.ts");

const sink = { id: "s1", event_filter: ["auth.*", "grant.revoke"], include_http: true };

test("twoAdminType reads the 409 and nothing else", () => {
  const e = new api.ApiError("x", 409, { error: "two_admin_change_required", message: "m", change_type: "siem.sink.target" });
  assert.equal(t.twoAdminType(e), "siem.sink.target");
  assert.equal(t.twoAdminType(new api.ApiError("x", 409, { error: "two_admin_change_required" })), null);
  assert.equal(t.twoAdminType(new api.ApiError("x", 409, { error: "other", change_type: "siem.sink.target" })), null);
  assert.equal(t.twoAdminType(new api.ApiError("x", 422, { error: "two_admin_change_required", change_type: "siem.sink.target" })), null);
  assert.equal(t.twoAdminType(new api.ApiError("x", 409, { error: "two_admin_change_required", change_type: "role.grant" })), null);
  assert.equal(t.twoAdminType(new Error("x")), null);
  assert.equal(t.twoAdminType(null), null);
});

test("siem filter payload carries only what changed", () => {
  const cases: [string, { event_filter: string[]; include_http: boolean }, unknown][] = [
    ["narrower filter", { event_filter: ["auth.*"], include_http: true }, { sink_id: "s1", event_filter: ["auth.*"] }],
    ["include_http off", { event_filter: ["grant.revoke", "auth.*"], include_http: false }, { sink_id: "s1", include_http: false }],
    ["both", { event_filter: ["x"], include_http: false }, { sink_id: "s1", event_filter: ["x"], include_http: false }],
    ["filter cleared", { event_filter: [], include_http: true }, { sink_id: "s1", event_filter: [] }],
    ["nothing changed (order only)", { event_filter: ["grant.revoke", "auth.*"], include_http: true }, null],
  ];
  for (const [name, form, want] of cases) assert.deepEqual(t.siemFilterPayload(sink, form), want, name);
});

test("target and loosen payloads", () => {
  assert.deepEqual(t.siemTargetPayload("s1", "  https://new.example/collector "), { sink_id: "s1", target: "https://new.example/collector" });
  assert.deepEqual(t.alertLoosenPayload("r1", { enabled: false, severity: "low", threshold: 5, window_minutes: 10 }),
    { rule_id: "r1", enabled: false, severity: "low", threshold: 5, window_minutes: 10 });
});

test("filing the request posts the payload to change-requests", async () => {
  await api.adminChanges.submit("siem.sink.target", t.siemTargetPayload("s1", "https://n.example"));
  assert.deepEqual(calls.at(-1), { url: "/api/admin/change-requests", method: "POST", body: { type: "siem.sink.target", payload: { sink_id: "s1", target: "https://n.example" } } });
  await api.adminChanges.submit("alerts.rule.loosen", t.alertLoosenPayload("r1", { enabled: true, severity: "high", threshold: 1, window_minutes: 5 }));
  assert.equal(calls.at(-1)!.body.type, "alerts.rule.loosen");
});

test("pausing a schedule sends the reason and the hours", async () => {
  await api.queue.pauseSchedule("a b", "maintenance", 6);
  assert.deepEqual(calls.at(-1), { url: "/api/queue/schedules/a%20b/pause", method: "POST", body: { reason: "maintenance", resume_after_hours: 6 } });
  await api.queue.pauseSchedule("x");
  assert.deepEqual(calls.at(-1)!.body, {});
});

test("pause checks", () => {
  assert.equal(t.pauseHours("1"), 1);
  assert.equal(t.pauseHours(" 24 "), 24);
  for (const bad of ["0", "25", "", "1.5", "-1", "abc", "012x"]) assert.ok(Number.isNaN(t.pauseHours(bad)), bad);
  assert.equal(t.pauseProblem("", "6") !== null, true);
  assert.equal(t.pauseProblem("   ", "6") !== null, true);
  assert.equal(t.pauseProblem("why", "0") !== null, true);
  assert.equal(t.pauseProblem("x".repeat(501), "6") !== null, true);
  assert.equal(t.pauseProblem("maintenance window", "6"), null);
});
