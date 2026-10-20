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

test("an empty-body write is stored from constants and resumes", async () => {
  store.clear();
  await assert.rejects(api.api("/jit/requests/5/approve", {}));
  const a = JSON.parse(store.get("tessera.pendingAction")!);
  assert.deepEqual(Object.keys(a).sort(), ["at", "label", "method", "path"]);
  assert.equal(a.label, "Approve JIT request #5");
  const taken = api.takePendingAction();
  assert.equal(taken?.path, "/jit/requests/5/approve");
  status = 200;
  await api.runPendingAction(taken!);
  status = 401;
});

test("a body is kept in memory only: never in storage", async () => {
  store.clear();
  await assert.rejects(api.api("/flatfile/tasks/t1/close", { reason: "private note" }));
  const raw = store.get("tessera.pendingAction")!;
  assert.ok(!raw.includes("private note"));
  assert.equal(JSON.parse(raw).needsBody, true);
  const taken = api.takePendingAction();
  assert.deepEqual(taken?.body, { reason: "private note" });
  // after a reload the body is gone: the resume refuses rather than sending an empty form
  store.set("tessera.pendingAction", raw);
  const reloaded = api.takePendingAction();
  assert.equal(reloaded?.body, undefined);
  await assert.rejects(api.runPendingAction(reloaded!), /submit again/);
});

test("secrets, odd methods and odd paths are not stored", async () => {
  store.clear();
  await assert.rejects(api.api("/connections/okta/credential", { client_secret: "s" }));
  assert.equal(store.size, 0);
  await assert.rejects(api.api("/x<script>", {}));
  assert.equal(store.size, 0);
});
