// Directory CSV import and the create / edit forms (issue #915): the client calls match the routes the API
// registers, a refused file (422) resolves with its report, and the form rules decide create, edit or read-only.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];
let reply: { status: number; body: any } = { status: 200, body: {} };

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-ivan", tenant: { slug: "larkspur" }, user: {} } : reply.body;
  const status = url === "/api/auth/session" ? 200 : reply.status;
  return { ok: status < 400, status, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");
const m = await import("../src/features/directory/importModel.ts");
const csv = await import("../src/components/csv.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
  reply = { status: 200, body: {} };
});

const plan = (over: Partial<import("../src/api.ts").ImportPlan> = {}): import("../src/api.ts").ImportPlan => ({
  system: "hr-sheet", target: "people", rows: 3, added: 1, changed: 1, removed: 1, unchanged: 0, errors: [], error_count: 0, errors_truncated: false,
  changes: [], changes_truncated: false, guard: null, ...over,
});
const file = new File(["email,name\na@t.example,A\n"], "people.csv", { type: "text/csv" });

test("a plan is a POST of the file as text/csv with the target, source and filename in the query", async () => {
  reply = { status: 200, body: { plan: plan(), valid: true } };
  const r = await api.planDirectoryImport("people", "hr-sheet", "HR spreadsheet", file);
  assert.equal(r.valid, true);
  const c = calls[0];
  assert.equal(c.method, "POST");
  assert.equal(c.url, "/api/directory/imports/plan?target=people&system=hr-sheet&name=HR+spreadsheet&filename=people.csv");
  assert.equal(c.headers["content-type"], "text/csv");
  assert.equal(c.headers["x-tessera-csrf"], "csrf-ivan");
  assert.equal(c.body, file);
});

test("a source without a display name sends no name", async () => {
  reply = { status: 200, body: { plan: plan(), valid: true } };
  await api.planDirectoryImport("accounts", "hr-sheet", "", file);
  assert.equal(calls[0].url, "/api/directory/imports/plan?target=accounts&system=hr-sheet&filename=people.csv");
});

test("an apply resolves with the report of a refused file instead of throwing", async () => {
  const errors = [{ row: 2, column: "email", code: "invalid_email", message: "x is not an email address" }];
  reply = { status: 422, body: { error: "invalid_file", detail: "nothing was changed", plan: plan({ errors, error_count: 1 }) } };
  const r = await api.applyDirectoryImport("people", "hr-sheet", "", file);
  assert.equal(r.error, "invalid_file");
  assert.equal(r.plan.errors[0].row, 2);
  assert.equal(calls[0].url, "/api/directory/imports/apply?target=people&system=hr-sheet&filename=people.csv");
});

test("an apply that needs a fresh sign-in throws, and its file is not kept for a resume", async () => {
  reply = { status: 401, body: { error: "step_up_required", detail: "Sign in again" } };
  await assert.rejects(api.applyDirectoryImport("people", "hr-sheet", "", file), (e: any) => e.status === 401);
  assert.equal(api.takePendingAction(), null);
});

test("a form save is a PUT of JSON; the lookup is a GET", async () => {
  reply = { status: 200, body: { plan: plan(), status: "applied" } };
  await api.putManualRecord({ target: "people", system: "hr-sheet", fields: { email: "a@t.example", name: "A" } });
  assert.equal(calls[0].method, "PUT");
  assert.equal(calls[0].url, "/api/directory/manual/records");
  assert.deepEqual(JSON.parse(calls[0].body), { target: "people", system: "hr-sheet", fields: { email: "a@t.example", name: "A" } });
  assert.equal(api.manualLookupPath("entitlements", 7), "/directory/manual/lookup?target=entitlements&id=7");
});

test("a source name becomes the slug the API takes", () => {
  assert.equal(m.slugifySource("HR spreadsheet"), "hr-spreadsheet");
  assert.equal(m.slugifySource("  Payroll (2026)!  "), "payroll-2026");
  assert.equal(m.slugifySource("Café"), "cafe");
  assert.equal(m.slugifySource("---"), "");
  assert.equal(m.slugifySource("x".repeat(100)).length, 63);
});

test("a file is checked for type, emptiness and size before it is sent", () => {
  assert.equal(m.checkImportFile({ name: "a.csv", size: 10 }), null);
  assert.equal(m.checkImportFile({ name: "a.CSV", size: m.IMPORT_MAX_BYTES }), null);
  assert.match(m.checkImportFile({ name: "a.csv", size: m.IMPORT_MAX_BYTES + 1 })!, /larger than 5 MiB/);
  assert.match(m.checkImportFile({ name: "a.xlsx", size: 10, type: "application/vnd.ms-excel" })!, /not a CSV/);
  assert.match(m.checkImportFile({ name: "a.csv", size: 0 })!, /empty/);
  assert.equal(m.IMPORT_MAX_BYTES, csv.IMPORT_MAX_BYTES, "the list's own limit matches");
});

test("the expected columns are the canonical ones, or an existing source's own for accounts", () => {
  const canon = { all: ["account_id", "username"], required: ["account_id", "username"] };
  assert.deepEqual(m.expectedColumns(canon, "accounts", null), canon);
  const src = { system: "hr-app", name: "HR", people: 0, accounts: 3, entitlements: 0, account_columns: ["UserID", "Login", "Mail"] };
  assert.deepEqual(m.expectedColumns(canon, "accounts", src), { all: ["UserID", "Login", "Mail"], required: ["UserID", "Login"] });
  assert.deepEqual(m.expectedColumns(canon, "people", src), canon);
});

test("a plan is put in words, with the deletion guard's view", () => {
  assert.equal(m.planHeadline(plan()), "1 to add, 1 to change, 1 to remove.");
  assert.match(m.planHeadline(plan({ error_count: 2 })), /2 problems in the file\. Nothing can be imported/);
  assert.match(m.planHeadline(plan({ added: 0, changed: 0, removed: 0, unchanged: 4 })), /Nothing to do: all 4 rows/);
  assert.equal(m.guardNote(plan()), null);
  const held = plan({ guard: { category: "identities", mode: "hold_excess", limit: 2, active: 9, removals: 3, would_hold: true, reasons: ["the feed shrank by 60%"] } });
  assert.match(m.guardNote(held)!, /hold 3 removals for a second admin.*feed shrank/);
  const ok = plan({ guard: { category: "accounts", mode: "hold_excess", limit: 5, active: 9, removals: 1, would_hold: false } });
  assert.match(m.guardNote(ok)!, /1 removal within the deletion guard's limit of 5/);
});

test("the message after an apply says what was held", () => {
  assert.equal(m.resultMessage({ plan: plan(), status: "applied" }, "People"), "People: 1 added, 1 changed, 1 removed");
  assert.match(m.resultMessage({ plan: plan({ added: 0, changed: 0, removed: 0 }), status: "applied" }, "People"), /no changes/);
  assert.match(m.resultMessage({ plan: plan(), status: "held", held: 1 }, "People"), /All 1 removals are held for approval/);
  assert.match(m.resultMessage({ plan: plan(), status: "partially_applied", message: "Removed 1 of 3: 2 held for approval" }, "People"), /Removed 1 of 3/);
});

test("a form creates, edits a manual object, or shows a connector's object read-only", () => {
  const manual = { target: "people", managed: true, system: "hr-sheet", fields: { email: "a@t.example" } } as const;
  const connector = { target: "people", managed: false, system: "workday" } as const;
  assert.equal(m.formMode(false, null), "create");
  assert.equal(m.formMode(true, undefined), "loading");
  assert.equal(m.formMode(true, manual), "edit");
  assert.equal(m.formMode(true, connector), "readonly");
  assert.equal(m.managedBy(connector, "fallback"), "workday");
  assert.equal(m.managedBy({ ...connector, system: "" }, "Workday"), "Workday");
  assert.equal(m.managedBy(null), "its source system");
});

test("Tessera keeps an owner for entitlements and machine identities, none for people", () => {
  assert.equal(m.ownerKindFor("entitlements"), "group");
  assert.equal(m.ownerKindFor("people", false), "identity");
  assert.equal(m.ownerKindFor("people", true), null);
  assert.equal(m.ownerKindFor("accounts"), null);
});

test("form values become what the API takes: trimmed, no empties, the promised defaults", () => {
  assert.deepEqual(m.toRecordFields("people", { name: " Ann ", email: " Ann@T.example ", department: "", title: "  ", status: "" }), { name: "Ann", email: "ann@t.example" });
  assert.deepEqual(m.toRecordFields("accounts", { username: "ann", account_id: "", status: "disabled" }), { username: "ann", account_id: "ann", status: "disabled" });
  assert.deepEqual(m.toRecordFields("accounts", { username: "ann", account_id: "u-9" }), { username: "ann", account_id: "u-9" });
  assert.deepEqual(m.toRecordFields("entitlements", { name: "Approvers", privileged: "yes" }), { name: "Approvers", external_id: "Approvers", privileged: "yes" });
  assert.deepEqual(m.toRecordFields("people", { name: "A", email: "a@t.example", bogus: "x" }), { name: "A", email: "a@t.example" });
});

test("an object's form starts from its manual source's fields, else what the caller knows", () => {
  const lookup = { target: "entitlements", managed: true, system: "hr-sheet", fields: { name: "Approvers", external_id: "ap", privileged: "true", kind: "group" } } as const;
  const v = m.initialValues("entitlements", lookup, { name: "ignored" });
  assert.equal(v.name, "Approvers");
  assert.equal(v.privileged, "yes");
  assert.equal(v.external_id, "ap");
  const c = m.initialValues("people", { target: "people", managed: false, system: "workday" }, { name: "Ann", email: "ann@t.example" });
  assert.equal(c.name, "Ann");
  assert.equal(c.title, "");
  assert.equal(m.KEY_FIELD.people, "email");
});

test("an export neutralises a cell a spreadsheet would run as a formula", () => {
  const out = csv.toCsv(["name"], [["=HYPERLINK(\"http://evil\")"], ["+1"], ["-1"], ["@SUM(A1)"], ["\tx"], ["ok"]]);
  const lines = out.split("\r\n");
  assert.equal(lines[1], "\"'=HYPERLINK(\"\"http://evil\"\")\"");
  for (const [i, want] of [[2, "'+1"], [3, "'-1"], [4, "'@SUM(A1)"], [6, "ok"]] as const) assert.equal(lines[i], want);
  assert.ok(lines[5].startsWith("'"));
});
