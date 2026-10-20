// The conditional access client (issue #163): the paths, methods and bodies it sends, the plain-language
// message of a conditional_access_denied refusal, and how policies are described. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

const mem = new Map<string, string>();
(globalThis as any).sessionStorage = {
  getItem: (k: string) => mem.get(k) ?? null,
  setItem: (k: string, v: string) => void mem.set(k, v),
  removeItem: (k: string) => void mem.delete(k),
};
(globalThis as any).window = Object.assign(new EventTarget(), { location: { pathname: "/admin/conditional-access", search: "", assign() {} } });

type Sent = { url: string; method: string; body: unknown; csrf?: string };
let sent: Sent[] = [];
let reply: { status: number; body: unknown } = { status: 200, body: {} };
(globalThis as any).fetch = async (url: string, init: any) => {
  sent.push({ url, method: init.method, body: init.body ? JSON.parse(init.body) : undefined, csrf: init.headers?.["x-tessera-csrf"] });
  return { ok: reply.status < 400, status: reply.status, statusText: "", headers: new Headers(), json: async () => reply.body };
};

const api = await import("../src/api.ts");

beforeEach(() => {
  sent = [];
  reply = { status: 200, body: {} };
  mem.clear();
  api.resetSessionState();
  api.setCsrfToken("csrf-1");
});

const policy: any = {
  name: "off-net", description: "", scope: "privileged", mode: "report_only", outcome: "step_up", step_up_acr: "urn:tessera:acr:phr",
  step_up_max_age: 300, network_op: "not_in", network_range_ids: ["n1"], device: "any", priority: 100,
};

test("policies and ranges use the access routes with the right verbs, and writes carry the CSRF token", async () => {
  await api.conditionalAccess.policies();
  await api.conditionalAccess.createPolicy(policy);
  await api.conditionalAccess.updatePolicy("p 1/2", policy);
  await api.conditionalAccess.deletePolicy("p1");
  await api.conditionalAccess.networks();
  await api.conditionalAccess.createNetwork({ name: "HQ", description: "", cidrs: ["198.51.100.0/24"] });
  await api.conditionalAccess.updateNetwork("n1", { name: "HQ", description: "", cidrs: ["198.51.100.0/24"] });
  await api.conditionalAccess.deleteNetwork("n1");
  assert.deepEqual(sent.map((s) => `${s.method} ${s.url}`), [
    "GET /api/access/policies",
    "POST /api/access/policies",
    "PUT /api/access/policies/p%201%2F2", // ids are encoded into one path segment
    "DELETE /api/access/policies/p1",
    "GET /api/access/networks",
    "POST /api/access/networks",
    "PUT /api/access/networks/n1",
    "DELETE /api/access/networks/n1",
  ]);
  assert.equal(sent[0].csrf, undefined);
  assert.ok(sent.slice(1, 4).every((s) => s.csrf === "csrf-1"));
  assert.deepEqual(sent[1].body, policy);
});

test("device signals and the what-if check", async () => {
  await api.conditionalAccess.signals();
  await api.conditionalAccess.setSignal("u1", { status: "not_compliant", reason: "lost laptop", expires_in_hours: 24 });
  await api.conditionalAccess.clearSignal("u1");
  await api.conditionalAccess.evaluate({ scope: "signin", client_ip: "203.0.113.9", device_managed: null });
  assert.deepEqual(sent.map((s) => `${s.method} ${s.url}`), [
    "GET /api/access/device-signals",
    "PUT /api/access/device-signals/u1",
    "DELETE /api/access/device-signals/u1",
    "POST /api/access/evaluate",
  ]);
  assert.deepEqual(sent[1].body, { status: "not_compliant", reason: "lost laptop", expires_in_hours: 24 });
  assert.deepEqual(sent[3].body, { scope: "signin", client_ip: "203.0.113.9", device_managed: null });
});

test("a conditional_access_denied refusal says what to do, without a step-up", async () => {
  reply = { status: 403, body: { error: "conditional_access_denied", permission: "jit.decide" } };
  let events = 0;
  (globalThis as any).window.addEventListener("tessera:step-up", () => events++);
  await assert.rejects(api.api("/jit/requests/3/approve", {}), (e: any) => {
    assert.ok(e instanceof api.ApiError);
    assert.equal(e.status, 403);
    assert.match(e.message, /conditional access policy/);
    assert.match(e.message, /network or device/);
    return true;
  });
  assert.equal(events, 0);
  assert.equal(mem.size, 0, "a refusal is not an action to resume");
});

test("a step-up asked by a policy keeps the write to resume, with a readable label", async () => {
  reply = { status: 401, body: { error: "step_up_required", acr: "urn:tessera:acr:phr", max_age: 300, step_up_url: "/api/auth/step-up?acr=urn%3Atessera%3Aacr%3Aphr&max_age=300" } };
  await assert.rejects(api.conditionalAccess.createPolicy(policy));
  assert.equal(api.takePendingAction()?.label, "Change conditional access (policies)");
  assert.equal(api.actionLabel("PUT", "/access/device-signals/u1"), "Change conditional access (device signals)");
});

test("conditions read as a sentence", () => {
  const ranges = [{ id: "n1", name: "Corporate" }, { id: "n2", name: "VPN" }];
  const d = api.describeConditions;
  assert.equal(d({ network_op: "any", network_range_ids: [], device: "any" }, ranges), "always");
  assert.equal(d({ network_op: "not_in", network_range_ids: ["n1", "n2"], device: "any" }, ranges), "network is not in Corporate, VPN");
  assert.equal(d({ network_op: "in", network_range_ids: ["n1"], device: "unmanaged" }, ranges), "network is in Corporate and device is not managed");
  assert.equal(d({ network_op: "in", network_range_ids: ["gone"], device: "not_compliant" }, ranges), "network is in a deleted range and device is not known to be compliant");
});
