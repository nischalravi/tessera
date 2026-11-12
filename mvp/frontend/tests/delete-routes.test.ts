// DELETE routes of group loaders, connections, alert channels and SIEM sinks (issue #963):
// verbs, paths without a body, and the step-up resume labels. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();

const calls: { url: string; method: string; body: any }[] = [];
(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: true, status: 200, statusText: "", json: async () => ({ deleted: true, id: "x" }) };
};

const api = await import("../src/api.ts");

test("each delete is a DELETE with no body", async () => {
  const id = "00000000-0000-4000-8000-000000000001";
  await api.siemApi.remove("s/1");
  assert.deepEqual(calls.at(-1), { url: "/api/siem/sinks/s%2F1", method: "DELETE", body: undefined });
  await api.alertsApi.deleteChannel("c/1");
  assert.deepEqual(calls.at(-1), { url: "/api/alerts/channels/c%2F1", method: "DELETE", body: undefined });
  await api.readiness.remove(id);
  assert.deepEqual(calls.at(-1), { url: `/api/connections/${id}`, method: "DELETE", body: undefined });
  await api.groupLoaders.remove(id);
  assert.deepEqual(calls.at(-1), { url: `/api/groups/loaders/${id}`, method: "DELETE", body: undefined });
});

test("a delete that needs step-up resumes with a plain label", () => {
  assert.equal(api.actionLabel("DELETE", "/siem/sinks/s1"), "Delete SIEM sink s1");
  assert.equal(api.actionLabel("DELETE", "/alerts/channels/c1"), "Delete alert channel c1");
  assert.equal(api.actionLabel("DELETE", "/connections/k1"), "Delete connection k1");
  assert.equal(api.actionLabel("DELETE", "/groups/loaders/l1"), "Delete group loader l1");
  // the other verbs on the same paths keep their own wording
  assert.equal(api.actionLabel("PATCH", "/groups/loaders/l1"), "PATCH /groups/loaders/l1");
  assert.equal(api.actionLabel("DELETE", "/access/policies/p1"), "Change conditional access (policies)");
});
