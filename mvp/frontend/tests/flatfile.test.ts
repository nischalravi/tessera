// Flat-file import client (issue #105): the upload goes as text/csv with the session's CSRF token,
// a rejected file (422) resolves with its report instead of throwing, mapping and close calls match
// the routes the API registers, and the form helpers build what the API accepts.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];
let reply: { status: number; body: any } = { status: 200, body: {} };

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-pat", tenant: { slug: "larkspur" }, user: {} } : reply.body;
  const status = url === "/api/auth/session" ? 200 : reply.status;
  return { ok: status >= 200 && status < 300, status, statusText: "", headers: new Headers(), json: async () => body };
};

const api = await import("../src/api.ts");
const form = await import("../src/features/admin/flatfileForm.ts");

const file = (text: string, name = "accounts.csv") => ({ name, size: text.length, text: async () => text }) as unknown as File;

beforeEach(async () => {
  reply = { status: 200, body: {} };
  await api.getSession();
  calls = [];
});

test("an upload is the file as text/csv, with the kind and name in the query and the CSRF token", async () => {
  reply = { status: 201, body: { upload: { status: "applied", errors: [], changes: [] }, confirmed_tasks: [] } };
  const f = file("id,login\n1,a\n", "hr export.csv");
  await api.uploadFlatFile("hr-app", "entitlements", f);
  const c = calls[0];
  assert.equal(c.method, "POST");
  assert.equal(c.url, "/api/flatfile/apps/hr-app/uploads?kind=entitlements&filename=hr+export.csv");
  assert.equal(c.headers["content-type"], "text/csv");
  assert.equal(c.headers["x-tessera-csrf"], "csrf-pat");
  assert.equal(c.body, f); // sent as it is, not wrapped in JSON
});

test("a rejected file resolves with its report; other errors still throw", async () => {
  reply = { status: 422, body: { upload: { status: "rejected", errors: [{ row: 2, column: "Mail", code: "invalid_email", message: "x" }] }, confirmed_tasks: [] } };
  const r = await api.uploadFlatFile("hr-app", "accounts", file("a"));
  assert.equal(r.upload.status, "rejected");
  assert.equal(r.upload.errors[0].row, 2);
  reply = { status: 404, body: { detail: "app not found: save its column mapping first" } };
  await assert.rejects(api.uploadFlatFile("nope", "accounts", file("a")), /save its column mapping first/);
  reply = { status: 403, body: { error: "forbidden", permission: "flatfile.upload" } };
  await assert.rejects(api.uploadFlatFile("hr-app", "accounts", file("a")), /flatfile\.upload/);
});

test("saving a mapping and closing a task use the registered routes", async () => {
  await api.saveFlatMapping("hr-app", form.toBody({ ...form.emptyForm(), system: "hr-app", name: "HR", account_id: "id", username: "login" }));
  assert.equal(calls[0].method, "PUT");
  assert.equal(calls[0].url, "/api/flatfile/apps/hr-app/mapping");
  assert.equal(calls[0].headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(calls[0].body), { name: "HR", owner: "", accounts: { account_id: "id", username: "login" }, entitlements: null });
  await api.closeFlatTask("a/b", "removed in the console");
  assert.equal(calls[1].url, "/api/flatfile/tasks/a%2Fb/close");
  assert.deepEqual(JSON.parse(calls[1].body), { reason: "removed in the console" });
});

test("a step-up on a mapping save remembers the action for after the sign-in", async () => {
  reply = { status: 401, body: { error: "step_up_required", acr: "urn:tessera:acr:phr", max_age: 900 } };
  let fired = false;
  (globalThis as any).window.addEventListener(api.STEP_UP, () => (fired = true));
  await assert.rejects(api.saveFlatMapping("hr-app", form.toBody({ ...form.emptyForm(), name: "HR", account_id: "id", username: "u" })));
  assert.ok(fired);
  assert.equal(api.actionLabel("PUT", "/flatfile/apps/hr-app/mapping"), "Save the column mapping of hr-app");
  assert.equal(api.actionLabel("POST", "/flatfile/tasks/x/close"), "Close the manual task");
});

test("the mapping form: required columns, one column per field, optional fields left out", () => {
  const ok = { ...form.emptyForm(), system: "payroll", name: "Payroll", account_id: "UserID", username: "Login" };
  assert.deepEqual(form.formProblems(ok, true), {});
  assert.deepEqual(Object.keys(form.formProblems(form.emptyForm(), true)).sort(), ["account_id", "name", "system", "username"]);
  assert.ok(form.formProblems({ ...ok, system: "Payroll App" }, true).system);
  assert.deepEqual(form.formProblems({ ...ok, system: "" }, false), {}); // a saved app's system cannot change
  assert.ok(form.formProblems({ ...ok, email: " login " }, true).accounts, "one column serving two fields");
  const withEnts = { ...ok, hasEntitlements: true };
  assert.deepEqual(Object.keys(form.formProblems(withEnts, true)).sort(), ["e_account_id", "entitlement"]);
  assert.ok(form.formProblems({ ...withEnts, e_account_id: "UserID", entitlement: "UserID" }, true).entitlements);
  assert.deepEqual(
    form.toBody({ ...withEnts, email: " Mail ", e_account_id: "UserID", entitlement: "Role", privileged: "Admin" }).entitlements,
    { account_id: "UserID", entitlement: "Role", privileged: "Admin" },
  );
});

test("the header of a file is read for column suggestions, quotes and byte order mark included", () => {
  assert.deepEqual(form.headerOf("﻿UserID,\"Last, First\",Mail\r\n1,2,3\n"), ["UserID", "Last, First", "Mail"]);
  assert.deepEqual(form.headerOf(""), []);
  assert.deepEqual(form.headerOf("a,,b\n"), ["a", "b"]);
});

test("a file that can never be accepted is not sent", () => {
  assert.equal(form.checkFile({ name: "a.csv", size: 10 }), null);
  assert.equal(form.checkFile({ name: "A.CSV", size: 10 }), null);
  assert.match(form.checkFile({ name: "a.csv", size: 0 })!, /empty/);
  assert.match(form.checkFile({ name: "a.csv", size: form.MAX_UPLOAD_BYTES + 1 })!, /larger than 512 KiB/);
  assert.match(form.checkFile({ name: "a.xlsx", size: 10 })!, /\.csv/);
});

test("every error code the API sends has plain-language help", () => {
  for (const code of ["not_utf8", "column_count", "required", "formula_prefix", "invalid_email", "duplicate_key", "unknown_account", "file_too_large", "too_many_rows"]) {
    assert.notEqual(form.errorHelp(code), code);
  }
  assert.equal(form.errorHelp("something_new"), "something_new");
  assert.equal(form.rowLabel(0), "File");
  assert.equal(form.rowLabel(3), "Row 3");
});
