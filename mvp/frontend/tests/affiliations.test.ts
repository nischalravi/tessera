// Affiliations client calls and form rules (issue #64): add and end are state-changing requests with
// the session's CSRF token, at the path and method the API registers. Run with `npm test`.
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
const model = await import("../src/features/directory/affiliationModel.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("add and end send method, path, body and CSRF", async () => {
  await api.addAffiliation(7, { type: "guest_visitor", ends_at: "2026-11-01T23:59:59.000Z", reason: "conference" });
  await api.endAffiliation("a b/c", "left early");
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, c.body, c.headers["x-tessera-csrf"]]),
    [
      ["POST", "/api/identities/7/affiliations", { type: "guest_visitor", ends_at: "2026-11-01T23:59:59.000Z", reason: "conference" }, "csrf-pat"],
      ["POST", "/api/affiliations/a%20b%2Fc/end", { reason: "left early" }, "csrf-pat"],
    ],
  );
});

test("the form offers only types an administrator may add", () => {
  assert.deepEqual(model.MANUAL_TYPES, ["guest_visitor", "contractor", "volunteer", "partner", "alum", "retiree"]);
  for (const t of ["employee", "student", "applicant", "admit", "prehire"]) assert.ok(!model.MANUAL_TYPES.includes(t as any), t);
  for (const t of model.MANUAL_TYPES) assert.ok(model.AFFILIATION_LABEL[t], t);
});

test("end dates: required for guest types, in the future, as end of day UTC", () => {
  const now = new Date("2026-10-12T09:00:00Z");
  assert.equal(model.endOfDayUtc("2026-11-01"), "2026-11-01T23:59:59.000Z");
  assert.equal(model.endOfDayUtc(""), undefined);
  assert.equal(model.endOfDayUtc("2026-13-45"), undefined);
  assert.equal(model.endOfDayUtc("01/11/2026"), undefined);
  assert.match(model.addProblem("guest_visitor", "", "why", now) ?? "", /needs an end date/);
  assert.equal(model.addProblem("alum", "", "why", now), null);
  assert.match(model.addProblem("alum", "2026-10-01", "why", now) ?? "", /future/);
  assert.match(model.addProblem("contractor", "2026-11-01", "  ", now) ?? "", /reason/);
  assert.equal(model.addProblem("contractor", "2026-11-01", "vendor project", now), null);
});

test("only pending and running affiliations can be ended", () => {
  assert.equal(model.canEnd({ status: "pending" }), true);
  assert.equal(model.canEnd({ status: "active" }), true);
  assert.equal(model.canEnd({ status: "ended" }), false);
  assert.equal(model.canEnd({ status: "revoked" }), false);
});
