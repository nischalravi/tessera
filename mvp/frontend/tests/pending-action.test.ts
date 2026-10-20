// The pending step-up action keeps a rebuilt, primitive-only copy of the body (never a secret). Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

const store = new Map<string, string>();
(globalThis as any).sessionStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
};
(globalThis as any).window = Object.assign(new EventTarget(), { location: { pathname: "/", search: "" } });
let status = 401;
(globalThis as any).fetch = async () => ({
  ok: status === 200,
  status,
  statusText: "x",
  json: async () => (status === 401 ? { error: "step_up_required" } : {}),
});

const api = await import("../src/api.ts");

test("storableBody keeps primitives, arrays and plain objects only", () => {
  assert.deepEqual(api.storableBody({ reason: "r", n: 3, ok: true, none: null, ids: [1, 2], nested: { a: "b" } }), {
    reason: "r", n: 3, ok: true, none: null, ids: [1, 2], nested: { a: "b" },
  });
  assert.equal(api.storableBody({ when: new Date() }), null);
  assert.equal(api.storableBody({ f: () => 1 }), null);
  assert.equal(api.storableBody({ "bad key": 1 }), null);
  assert.equal(api.storableBody({ client_secret: "x" }), null);
});

test("a write refused for step-up is stored as a rebuilt copy and resumes", async () => {
  store.clear();
  const body = { reason: "approved by phone", extra: undefined };
  await assert.rejects(api.api("/jit/requests/5/approve", body));
  const raw = store.get("tessera.pendingAction");
  assert.ok(raw);
  const a = JSON.parse(raw!);
  assert.deepEqual(Object.keys(a).sort(), ["at", "body", "label", "method", "path"]);
  assert.deepEqual(a.body, { reason: "approved by phone" });
  assert.equal(a.label, "Approve JIT request #5");
  const taken = api.takePendingAction();
  assert.equal(taken?.path, "/jit/requests/5/approve");
});

test("bodies with secrets or unstorable values are not stored", async () => {
  store.clear();
  await assert.rejects(api.api("/connections/okta/credential", { client_secret: "s" }));
  assert.equal(store.size, 0);
  await assert.rejects(api.api("/x", { when: new Date() }));
  assert.equal(store.size, 0);
});
