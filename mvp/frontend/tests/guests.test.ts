// Guest sponsorship client calls and form rules (issue #65): each change is a state-changing request
// with the session's CSRF token, at the path and with the body the API registers. Run with `npm test`.
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
const model = await import("../src/features/access/guestModel.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("every change sends method, path, body and CSRF", async () => {
  const invite = { given_name: "Ada", family_name: "L", email: "ada@x.org", population: "visitor" as const, purpose: "talk", ends_at: "2026-11-01T00:00:00.000Z", bundle: [4] };
  await api.guests.invite(invite);
  await api.guests.bulk("email,given_name\n", true);
  await api.guests.bulk("email,given_name\n", false);
  await api.guests.approve("a b/c");
  await api.guests.reject("s-1", "no budget");
  await api.guests.renew("s-1", "2026-12-01T00:00:00.000Z", "again");
  await api.guests.end("s-1", "done");
  await api.guests.transfer("s-1", 9, "leaving");
  await api.guests.acceptTransfer("s-1");
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.body]), [
    ["POST", "/api/guests/invitations", invite],
    ["POST", "/api/guests/invitations/bulk", { csv: "email,given_name\n", dry_run: true }],
    ["POST", "/api/guests/invitations/bulk", { csv: "email,given_name\n", dry_run: false }],
    ["POST", "/api/sponsorships/a%20b%2Fc/approve", {}],
    ["POST", "/api/sponsorships/s-1/reject", { reason: "no budget" }],
    ["POST", "/api/sponsorships/s-1/renew", { ends_at: "2026-12-01T00:00:00.000Z", justification: "again" }],
    ["POST", "/api/sponsorships/s-1/end", { reason: "done" }],
    ["POST", "/api/sponsorships/s-1/transfer", { to_identity_id: 9, reason: "leaving" }],
    ["POST", "/api/sponsorships/s-1/accept-transfer", {}],
  ]);
  for (const c of calls) assert.equal(c.headers["x-tessera-csrf"], "csrf-pat");
});

test("read paths", () => {
  assert.equal(api.guests.paths.list(), "/guests");
  assert.equal(api.guests.paths.list({ sponsor: "all", state: "active", population: "contractor" }), "/guests?sponsor=all&state=active&population=contractor");
  assert.equal(api.guests.paths.one("x/y"), "/sponsorships/x%2Fy");
  assert.equal(api.guests.paths.approvals, "/sponsorships/approvals");
});

const pops = {
  visitor: { key: "visitor", name: "Visitor", max_days: 30, max_active: 50, default_ial: 0, default_aal: 2, approval_with_sensitive_bundle: false },
  contractor: { key: "contractor", name: "Contractor", max_days: 365, max_active: 25, default_ial: 1, default_aal: 2, approval_with_sensitive_bundle: true },
} as const;

test("the required IAL and the approval rule follow the bundle", () => {
  const plain = { privileged: false, risk: "low" as const };
  const high = { privileged: false, risk: "high" as const };
  const priv = { privileged: true, risk: "medium" as const };
  assert.equal(model.requiredIal(pops.visitor, []), 0);
  assert.equal(model.requiredIal(pops.contractor, [plain]), 1);
  assert.equal(model.requiredIal(pops.visitor, [plain, high]), 2);
  assert.equal(model.requiredIal(pops.contractor, [priv]), 2);
  assert.equal(model.requiredIal(undefined, []), 0);
  assert.equal(model.needsApproval(pops.contractor, [priv]), true);
  assert.equal(model.needsApproval(pops.contractor, [plain]), false);
  assert.equal(model.needsApproval(pops.visitor, [priv]), false);
});

test("end dates are bounded by the population's maximum", () => {
  assert.equal(model.maxEndDay("", "2026-10-13", 30), "2026-11-12");
  assert.equal(model.maxEndDay("2026-12-20", "2026-10-13", 30), "2027-01-19");
  assert.equal(model.addDays("2026-02-27", 2), "2026-03-01");
  assert.equal(model.endInstant("2026-11-01"), "2026-11-01T00:00:00.000Z");
});

test("the invite form says what is missing and builds the payload", () => {
  const f = model.emptyInvite("visitor");
  assert.deepEqual(model.inviteProblems(f, pops.visitor as any, "2026-10-13"), ["a given name", "an email address", "a purpose", "an end date"]);
  Object.assign(f, { given_name: " Ada ", family_name: "Lovelace", email: " ada@x.org ", purpose: " talk ", ends: "2026-10-20", bundle: [3, 4] });
  assert.deepEqual(model.inviteProblems(f, pops.visitor as any, "2026-10-13"), []);
  assert.deepEqual(model.invitePayload(f), {
    given_name: "Ada", family_name: "Lovelace", email: "ada@x.org", population: "visitor", purpose: "talk", ends_at: "2026-10-20T00:00:00.000Z", bundle: [3, 4],
  });
  f.ends = "2026-12-01"; // 49 days
  assert.deepEqual(model.inviteProblems(f, pops.visitor as any, "2026-10-13"), ["an end date within 30 days of the start"]);
  assert.deepEqual(model.inviteProblems(f, pops.contractor as any, "2026-10-13"), []);
  f.starts = "2026-10-25";
  f.ends = "2026-10-20";
  assert.deepEqual(model.inviteProblems(f, pops.visitor as any, "2026-10-13"), ["an end date after the start"]);
  assert.equal(model.invitePayload(f).starts_at, "2026-10-25T00:00:00.000Z");
  assert.equal(model.invitePayload({ ...model.emptyInvite(), ends: "2026-10-20" }).bundle, undefined);
  assert.ok(model.inviteProblems({ ...f, email: "not an email", ends: "2026-10-30" }, pops.visitor as any, "2026-10-13").includes("an email address"));
});

test("bundle choices are the requestable items open to people", () => {
  const e = (id: number, requestable: boolean, eligible_types: string[]) => ({ requestable, eligible_types, group: { id } }) as any;
  assert.deepEqual(model.bundleChoices([e(1, true, []), e(2, false, []), e(3, true, ["service"]), e(4, true, ["human", "service"])]).map((x: any) => x.group.id), [1, 4]);
});

test("the CSV helpers count rows and warn before 500", () => {
  assert.equal(model.csvRowCount(""), 0);
  assert.equal(model.csvRowCount(model.CSV_HEADER.join(",") + "\n"), 0);
  assert.equal(model.csvRowCount(model.csvTemplate("2026-10-13")), 1);
  assert.equal(model.csvRowCount("h\r\na\r\n\r\nb\r\n"), 2);
  assert.equal(model.csvTooLong("h\n" + "a\n".repeat(500)), false);
  assert.equal(model.csvTooLong("h\n" + "a\n".repeat(501)), true);
  assert.ok(model.csvTemplate("2026-10-13").includes("2026-10-27"));
  assert.equal(model.csvTemplate("2026-10-13").split("\n")[0], "email,given_name,family_name,population,starts_at,ends_at,purpose");
});

test("labels cover every state and population", () => {
  for (const s of ["requested", "pending_approval", "active", "upcoming", "ending", "transfer_pending", "ended", "revoked", "rejected"]) {
    assert.ok((model.STATE_LABEL as any)[s] && (model.STATE_TONE as any)[s], s);
  }
  assert.deepEqual(model.POPULATIONS, ["visitor", "contractor", "volunteer", "partner"]);
  assert.equal(model.daysLeftLabel({ days_left: 0, status: "active" }), "Ends today");
  assert.equal(model.daysLeftLabel({ days_left: 1, status: "active" }), "1 day left");
  assert.equal(model.daysLeftLabel({ days_left: null, status: "ended" }), "");
  assert.equal(model.needsMe({ can_accept_transfer: false, can_approve: true }), true);
  assert.equal(model.needsMe({ can_accept_transfer: false, can_approve: false }), false);
});
