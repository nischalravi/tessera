// Error classification and panel wording (issue #143): the API client raises a typed error,
// and the shared panel words each kind in plain language, with no port and no raw JSON.
// Run with `npm test`.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

(globalThis as any).window = Object.assign(new EventTarget(), { location: { assign: () => undefined } });
let respond: () => any = () => ({ ok: true, status: 200, json: async () => ({}) });
(globalThis as any).fetch = async () => respond();

const api = await import("../src/api.ts");
const { errorCopy } = await import("../src/components/errorCopy.ts");

test("status maps to a kind", () => {
  const cases: [number, string][] = [
    [0, "network"], [400, "validation"], [404, "not_found"], [401, "forbidden"], [403, "forbidden"],
    [409, "conflict"], [413, "validation"], [422, "validation"], [429, "server"], [500, "server"], [503, "server"],
  ];
  for (const [status, kind] of cases) assert.equal(api.errorKind(status), kind, `status ${status}`);
});

test("error bodies yield a code and a string message, never a list", () => {
  const cases: [any, { code: string | null; message: string | null }][] = [
    [{ detail: "identity not found" }, { code: null, message: "identity not found" }],
    [{ error: "forbidden", detail: "no", permission: "graph.read" }, { code: "forbidden", message: "no" }],
    [{ code: "X", message: "m" }, { code: "X", message: "m" }],
    [{ detail: [{ type: "int_parsing", loc: ["path", "identity_id"] }] }, { code: null, message: null }],
    [[{ type: "int_parsing" }], { code: null, message: null }],
    [null, { code: null, message: null }],
  ];
  for (const [body, want] of cases) assert.deepEqual(api.parseErrorBody(body), want);
});

test("ApiError carries status, code, message and kind", () => {
  const e = new api.ApiError("identity not found", 404, { detail: "identity not found" });
  assert.equal(e.status, 404);
  assert.equal(e.kind, "not_found");
  assert.equal(e.serverMessage, "identity not found");
  assert.equal(e.code, null);
  const f = new api.ApiError("x", 403, { error: "forbidden", detail: "needs graph.read" });
  assert.equal(f.kind, "forbidden");
  assert.equal(f.code, "forbidden");
});

test("api() raises a typed error for HTTP failures and for an unreachable API", async () => {
  respond = () => ({ ok: false, status: 404, statusText: "Not Found", json: async () => ({ detail: "identity not found" }) });
  await assert.rejects(api.api("/identities/99999"), (e: any) => e instanceof api.ApiError && e.kind === "not_found" && e.status === 404);

  respond = () => ({ ok: false, status: 422, statusText: "", json: async () => ({ detail: [{ type: "int_parsing", loc: ["path", "identity_id"], input: "abc" }] }) });
  await assert.rejects(api.api("/identities/abc"), (e: any) => e.kind === "validation" && !e.message.includes("int_parsing") && !e.message.includes("["));

  respond = () => ({ ok: false, status: 502, statusText: "Bad Gateway", json: async () => { throw new Error("not json"); } });
  await assert.rejects(api.api("/identities/1"), (e: any) => e.kind === "server");

  (globalThis as any).fetch = async () => { throw new TypeError("fetch failed"); };
  await assert.rejects(api.api("/identities/1"), (e: any) => e instanceof api.ApiError && e.kind === "network" && e.status === 0);
});

test("numeric ids are validated before fetching", () => {
  for (const ok of ["1", "42", "99999"]) assert.equal(api.isNumericId(ok), true, ok);
  for (const bad of ["abc", "", "0", "-1", "1.5", "1e3", "12a", "01", "99999999999999999999", undefined]) assert.equal(api.isNumericId(bad as any), false, String(bad));
  assert.equal(api.invalidLink().kind, "validation");
});

test("panel copy per kind", () => {
  assert.deepEqual(errorCopy("not_found", "identity"), { text: "This identity no longer exists or the link is wrong.", retry: false });
  assert.equal(errorCopy("not_found").text, "This item no longer exists or the link is wrong.");
  assert.deepEqual(errorCopy("validation", "identity"), { text: "That link isn't valid.", retry: false });
  assert.equal(errorCopy("forbidden", "identity").text, "You don't have access.");
  assert.equal(errorCopy("forbidden", "identity", "needs graph.read").detail, "needs graph.read");
  assert.equal(errorCopy("conflict", "identity").retry, false);
  for (const kind of ["network", "server"] as const) {
    const c = errorCopy(kind, "identity");
    assert.equal(c.text, "Tessera can't reach its API right now. Try again in a moment.");
    assert.equal(c.retry, true);
  }
});

test("only network and server errors offer Retry; no copy has a port, host or JSON", () => {
  for (const kind of ["network", "not_found", "validation", "forbidden", "conflict", "server"] as const) {
    const c = errorCopy(kind, "application", "detail text");
    assert.equal(c.retry, kind === "network" || kind === "server", kind);
    assert.doesNotMatch(`${c.text} ${c.detail ?? ""}`, /:\d{2,5}|localhost|https?:|[{}[\]]/i, kind);
  }
});

test("no source file hard-codes the API port in a user-facing string", () => {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(ts|tsx)$/.test(name)) files.push(p);
    }
  };
  walk(new URL("../src", import.meta.url).pathname);
  assert.ok(files.length > 50);
  for (const f of files) {
    const src = readFileSync(f, "utf8");
    assert.ok(!src.includes(":8000"), `${f} mentions :8000`);
    assert.ok(!/API is running/i.test(src), `${f} says "API is running"`);
  }
});
