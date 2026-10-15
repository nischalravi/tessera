// Step-up in the API client (design §9.4, §17): a 401 step_up_required on a write keeps the request
// (never a token) for ten minutes so it can be resumed after re-authentication, and the step-up URL
// comes back to the current page. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

const mem = new Map<string, string>();
(globalThis as any).sessionStorage = {
  getItem: (k: string) => mem.get(k) ?? null,
  setItem: (k: string, v: string) => void mem.set(k, v),
  removeItem: (k: string) => void mem.delete(k),
};
const events: string[] = [];
const win = Object.assign(new EventTarget(), { location: { pathname: "/access/jit", search: "?tab=open&stepup=ok", assign() {} } });
win.addEventListener("tessera:step-up", () => events.push("step-up"));
(globalThis as any).window = win;
(globalThis as any).fetch = async () => ({
  ok: false, status: 401, statusText: "",
  json: async () => ({ error: "step_up_required", acr: "urn:tessera:acr:phr", max_age: 900, step_up_url: "/api/auth/step-up?acr=urn%3Atessera%3Aacr%3Aphr&max_age=900" }),
});

const api = await import("../src/api.ts");

beforeEach(() => { mem.clear(); events.length = 0; });

test("a write refused for step-up is kept, labelled, and taken once", async () => {
  await assert.rejects(api.api("/jit/requests/12/approve", {}));
  assert.deepEqual(events, ["step-up"]);
  const raw = [...mem.values()][0];
  assert.ok(raw && !/csrf|cookie|token/i.test(raw), raw);
  const a = api.takePendingAction();
  assert.equal(a?.label, "Approve JIT request #12");
  assert.equal(a?.method, "POST");
  assert.equal(api.takePendingAction(), null);
});

test("a read refused for step-up keeps nothing", async () => {
  await assert.rejects(api.api("/audit"));
  assert.equal(mem.size, 0);
});

test("a pending action expires after ten minutes", async () => {
  await assert.rejects(api.api("/least-privilege/revoke", { edge_id: 1, dry_run: false }));
  const later = Date.now() + api.PENDING_TTL_MS + 1000;
  assert.equal(api.takePendingAction(later), null);
});

test("the step-up URL returns to the current page without the previous result", () => {
  assert.equal(api.stepUpHref({ step_up_url: "/api/auth/step-up?acr=urn%3Atessera%3Aacr%3Aphr&max_age=900" }),
    "/api/auth/step-up?acr=urn%3Atessera%3Aacr%3Aphr&max_age=900&return_to=%2Faccess%2Fjit%3Ftab%3Dopen");
});

test("labels", () => {
  assert.equal(api.actionLabel("PATCH", "/connections/c1/config"), "Save the configuration of connection c1");
  assert.equal(api.actionLabel("POST", "/somewhere"), "POST /somewhere");
});
