// Alerts client (issue #168): routes, verbs and bodies, and the severity tones.
// Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();

const calls: { url: string; method: string; body: any }[] = [];
(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: true, status: 200, statusText: "", json: async () => ({}) };
};

const api = await import("../src/api.ts");

test("triage posts to the alert's action routes", async () => {
  await api.alertsApi.acknowledge("a/1");
  assert.deepEqual(calls.at(-1), { url: "/api/alerts/a%2F1/acknowledge", method: "POST", body: {} });
  await api.alertsApi.resolve("a1", "drill");
  assert.deepEqual(calls.at(-1), { url: "/api/alerts/a1/resolve", method: "POST", body: { note: "drill" } });
  await api.alertsApi.assign("a1", null);
  assert.deepEqual(calls.at(-1), { url: "/api/alerts/a1/assign", method: "POST", body: { assignee_user_id: null } });
});

test("rules and channels use PUT for updates", async () => {
  await api.alertsApi.setRule("signin_failures", { enabled: true, severity: "high", threshold: 3, window_minutes: 10 });
  assert.equal(calls.at(-1)!.method, "PUT");
  assert.equal(calls.at(-1)!.url, "/api/alerts/rules/signin_failures");
  await api.alertsApi.createChannel({ name: "Slack", kind: "webhook", target: "https://hooks.slack.com/x", min_severity: "high", enabled: true });
  assert.equal(calls.at(-1)!.method, "POST");
  await api.alertsApi.updateChannel("c1", { name: "Slack", min_severity: "critical", enabled: true });
  assert.deepEqual(calls.at(-1), { url: "/api/alerts/channels/c1", method: "PUT", body: { name: "Slack", min_severity: "critical", enabled: true } });
  await api.alertsApi.testChannel("c1");
  assert.equal(calls.at(-1)!.url, "/api/alerts/channels/c1/test");
});

test("severity tones", () => {
  assert.equal(api.severityTone("critical"), "critical");
  assert.equal(api.severityTone("high"), "warning");
  assert.equal(api.severityTone("medium"), "info");
  assert.equal(api.severityTone("low"), "neutral");
  assert.deepEqual(api.ALERT_SEVERITIES, ["low", "medium", "high", "critical"]);
});
