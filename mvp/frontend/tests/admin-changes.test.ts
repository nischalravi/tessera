// Admin change requests in the UI (design §15.2): which buttons a request offers an admin, and what
// the persistent banner says about pending and cooling-off changes and a recovery in flight.
// The API enforces all of it; this checks the offers and the wording. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { AdminChange, AdminRecovery } from "../src/api.ts";
import { bannerItems, canApply, canApprove, canCancel, canReject, timeLeft } from "../src/features/admin/changeState.ts";

const NOW = Date.parse("2026-10-08T09:30:00Z");
const hours = (h: number) => new Date(NOW + h * 3600_000).toISOString().replace(".000Z", "Z");

const change = (o: Partial<AdminChange> = {}): AdminChange => ({
  id: "c1", type: "role.grant", summary: "Grant tenant_admin to Carol", status: "pending_approval", target_id: null, two_person: true,
  cooling_off_seconds: 86400, requested_by: { id: "alice", display_name: "Alice" }, requested_at: hours(0), expires_at: hours(72),
  approved_by: null, approved_at: null, effective_at: null, decided_by: null, decided_at: null, applied_at: null, failure: null,
  test_login_at: null, payload_hash: "h", payload: {}, ...o,
});

test("a request is approved by someone else, never by its requester", () => {
  const c = change();
  assert.equal(canApprove(c, "alice"), false);
  assert.equal(canApprove(c, "bob"), true);
  assert.equal(canReject(c, "alice"), false);
  assert.equal(canReject(c, "bob"), true);
  assert.equal(canApprove(change({ two_person: false }), "bob"), false);
  for (const status of ["cooling_off", "applied", "rejected", "cancelled", "expired", "failed"] as const) {
    assert.equal(canApprove(change({ status }), "bob"), false, status);
  }
});

test("any admin cancels while it waits or cools off, and only then", () => {
  assert.equal(canCancel(change()), true);
  assert.equal(canCancel(change({ status: "cooling_off", effective_at: hours(24) })), true);
  for (const status of ["applied", "rejected", "cancelled", "expired", "failed"] as const) {
    assert.equal(canCancel(change({ status })), false, status);
  }
});

test("apply is offered only after the cooling-off", () => {
  const c = change({ status: "cooling_off", effective_at: hours(24) });
  assert.equal(canApply(c, NOW), false);
  assert.equal(canApply(c, NOW + 24 * 3600_000 - 1000), false);
  assert.equal(canApply(c, NOW + 24 * 3600_000), true);
  assert.equal(canApply(change(), NOW + 99 * 3600_000), false);
});

test("time left reads as hours and minutes", () => {
  assert.equal(timeLeft(hours(-1), NOW), "now");
  assert.equal(timeLeft(hours(0.5), NOW), "in 30 min");
  assert.equal(timeLeft(hours(3), NOW), "in 3 h");
  assert.equal(timeLeft(hours(3.25), NOW), "in 3 h 15 min");
  assert.equal(timeLeft(hours(72), NOW), "in 72 h");
  assert.equal(timeLeft(hours(100), NOW), "in 4 d");
});

test("the banner lists what needs review, what cools off, and a recovery first", () => {
  const rec: AdminRecovery = { id: "r1", status: "pending", ticket: "SUP-1", operator: "a", co_operator: "b", not_before: hours(70),
    created_at: hours(-2), cancelled_at: null, completed_at: null };
  const items = bannerItems(
    [change(), change({ id: "c2", requested_by: { id: "bob", display_name: "Bob" } }),
      change({ id: "c3", status: "cooling_off", effective_at: hours(20), summary: "Disable IdP connection Okta" }),
      change({ id: "c4", status: "applied" })],
    [rec, { ...rec, id: "r2", status: "cancelled" }], "bob", NOW,
  );
  assert.deepEqual(items.map((i) => i.id), ["recovery:r1", "c1", "c2", "c3"]);
  assert.equal(items[0].tone, "bad");
  assert.match(items[0].text, /ticket SUP-1.*in 70 h.*cancel it/);
  assert.match(items[1].text, /Needs your review: Grant tenant_admin to Carol \(requested by Alice\)/);
  assert.match(items[2].text, /^Your request is waiting for a second admin/);
  assert.match(items[3].text, /takes effect in 20 h\. Any admin can cancel/);
  assert.deepEqual(bannerItems([change({ status: "applied" })], [], "bob", NOW), []);
});
