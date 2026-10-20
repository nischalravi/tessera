// Directory Agent enrolment in the API client (DR-11): issuing an enrolment code answers with a
// secret shown once, so a write refused for step-up must never be kept for a background resume
// (replaying it would create the agent and lose the code). Revoking an agent can resume.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

const mem = new Map<string, string>();
(globalThis as any).sessionStorage = {
  getItem: (k: string) => mem.get(k) ?? null,
  setItem: (k: string, v: string) => void mem.set(k, v),
  removeItem: (k: string) => void mem.delete(k),
};
const events: string[] = [];
const win = Object.assign(new EventTarget(), { location: { pathname: "/admin/connections/agents", search: "", assign() {} } });
win.addEventListener("tessera:step-up", () => events.push("step-up"));
(globalThis as any).window = win;
(globalThis as any).fetch = async () => ({
  ok: false, status: 401, statusText: "",
  json: async () => ({ error: "step_up_required", acr: "urn:tessera:acr:phr", max_age: 900 }),
});

const api = await import("../src/api.ts");

beforeEach(() => { mem.clear(); events.length = 0; });

test("an enrolment request refused for step-up is not kept for resume", async () => {
  await assert.rejects(api.agents.enrol("Oslo datacentre"));
  assert.deepEqual(events, ["step-up"]); // the step-up dialog still opens
  assert.equal(mem.size, 0);
  assert.equal(api.takePendingAction(), null);
});

test("a revoke refused for step-up is kept and labelled", async () => {
  await assert.rejects(api.agents.revoke("3f2b9c1e-0000-4000-8000-000000000001"));
  assert.deepEqual(events, ["step-up"]);
  const a = api.takePendingAction();
  assert.equal(a?.method, "POST");
  assert.equal(a?.path, "/agents/3f2b9c1e-0000-4000-8000-000000000001/revoke");
  assert.match(a?.label ?? "", /^Revoke Directory Agent /);
});
