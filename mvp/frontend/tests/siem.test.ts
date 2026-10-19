// SIEM sinks client (issue #169): routes, verbs and bodies, and the health labels.
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

test("sink calls", async () => {
  await api.siemApi.create({ name: "Splunk", kind: "webhook", format: "ocsf", target: "https://s.example/collector", flavor: "hec", token: "t", include_http: false, enabled: true, start: "now" });
  assert.deepEqual(calls.at(-1)!.method, "POST");
  assert.equal(calls.at(-1)!.url, "/api/siem/sinks");
  await api.siemApi.update("s/1", { name: "Splunk", format: "json", include_http: true, enabled: false });
  assert.deepEqual(calls.at(-1), { url: "/api/siem/sinks/s%2F1", method: "PUT", body: { name: "Splunk", format: "json", include_http: true, enabled: false } });
  await api.siemApi.rewind("s1", 0);
  assert.deepEqual(calls.at(-1), { url: "/api/siem/sinks/s1/rewind", method: "POST", body: { seq: 0 } });
  await api.siemApi.test("s1");
  assert.equal(calls.at(-1)!.url, "/api/siem/sinks/s1/test");
});

test("every health status has a label", () => {
  for (const s of ["healthy", "catching_up", "degraded", "failing", "paused"] as const) {
    assert.ok(api.SIEM_HEALTH[s].label);
  }
  assert.equal(api.SIEM_HEALTH.failing.tone, "critical");
});
