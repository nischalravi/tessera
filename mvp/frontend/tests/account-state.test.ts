// Account disable / enable (issue #915): the client calls and the wording of the status and the answers.
// Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();

type Call = { url: string; method: string; headers: Record<string, string>; body: any };
let calls: Call[] = [];

(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf-pat", tenant: { slug: "larkspur" }, user: {} } : {};
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");
const model = await import("../src/features/directory/accountState.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("disable and enable use the account routes, one and bulk", async () => {
  await api.disableAccount(4, "leaver cleanup, HR-1");
  await api.enableAccount(4, "back from leave, HR-2");
  await api.disableAccounts([1, 2], "leaver cleanup, HR-1");
  await api.enableAccounts([1, 2], "back from leave, HR-2");
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body]),
    [
      ["POST", "/api/accounts/4/disable", { reason: "leaver cleanup, HR-1" }],
      ["POST", "/api/accounts/4/enable", { reason: "back from leave, HR-2" }],
      ["POST", "/api/accounts/disable", { ids: [1, 2], reason: "leaver cleanup, HR-1" }],
      ["POST", "/api/accounts/enable", { ids: [1, 2], reason: "back from leave, HR-2" }],
    ],
  );
  assert.ok(calls.every((c) => c.headers["X-CSRF-Token"] === "csrf-pat" || Object.values(c.headers).includes("csrf-pat")));
});

test("a change waiting for the target shows as pending, never as done", () => {
  assert.equal(model.accountStatusLabel({ status: "active", pending: "disable" }), "disable pending");
  assert.equal(model.accountStatusLabel({ status: "disabled", pending: "enable" }), "enable pending");
  assert.equal(model.accountStatusLabel({ status: "active" }), "active");
});

test("the summary names what was sent and why the rest was not", () => {
  const s = model.accountStateSummary("disable", [
    { id: 1, status: "queued", op_id: "o1" },
    { id: 2, status: "error", error: "target_read_only" },
    { id: 3, status: "error", error: "not_found" },
  ], (id) => `acct-${id}`);
  assert.equal(s.ok, true);
  assert.match(s.text, /1 account sent to disable \(disable pending until the target confirms\)/);
  assert.match(s.text, /2 not sent: acct-2 this system is read-only for Tessera \(and 1 more\)/);
  const none = model.accountStateSummary("enable", [{ id: 9, status: "error", error: "x", detail: "the okta connector cannot set an account active again" }]);
  assert.equal(none.ok, false);
  assert.match(none.text, /Nothing was sent to enable/);
  assert.match(none.text, /cannot set an account active again/);
  assert.match(model.accountStateSummary("disable", [{ id: 1, status: "held" }]).text, /held for a second admin/);
});
