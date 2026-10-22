// The deletion guard's client and screens' model (internal/deleteguard): the requests it makes, and the words and
// payloads of the settings form. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

const calls: { url: string; method: string; headers: Record<string, string>; body: unknown }[] = [];
(globalThis as any).window = Object.assign(new EventTarget(), { location: { pathname: "/", search: "" } });
(globalThis as any).sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
(globalThis as any).fetch = async (url: string, init: any) => {
  calls.push({ url, method: init.method, headers: init.headers, body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: true, status: 200, statusText: "", json: async () => ({ holds: [] }) };
};

const { deletionGuard, groups, setCsrfToken } = await import("../src/api.ts");
const m = await import("../src/features/admin/deletionGuardModel.ts");

beforeEach(() => {
  calls.length = 0;
  setCsrfToken("csrf-1");
});

const policy = (o: Record<string, unknown> = {}): any => ({
  category: "groups", max_count: 25, max_percent: null, window_minutes: 60, mode: "hold_excess", default: true, version: 0,
  used: 0, population: 100, limit: 25, remaining: 25, ...o,
});

test("holds are read with filters, decided with a POST, and thresholds change through a change request", async () => {
  await deletionGuard.holds("held", "groups");
  assert.equal(calls[0].url, "/api/admin/deletion-holds?status=held&category=groups&limit=500");
  await deletionGuard.approve("h 1", [0, 2]);
  assert.equal(calls[1].url, "/api/admin/deletion-holds/h%201/approve");
  assert.deepEqual(calls[1].body, { items: [0, 2] });
  await deletionGuard.approve("h1");
  assert.deepEqual(calls[2].body, {});
  await deletionGuard.discard("h1", "mistake");
  assert.deepEqual(calls[3].body, { note: "mistake" });
  await deletionGuard.change([{ category: "groups", max_count: 10, max_percent: null, window_minutes: 60, mode: "hold_all" }], 48);
  assert.equal(calls[4].url, "/api/admin/change-requests");
  assert.deepEqual(calls[4].body, { type: "deletion_guard.update", payload: { policies: [{ category: "groups", max_count: 10, max_percent: null, window_minutes: 60, mode: "hold_all" }], hold_expiry_hours: 48 } });
});

test("a bulk action sends one batch id so its holds join into one", async () => {
  await groups.deleteGroup("g1", "b-1");
  assert.equal(calls[0].headers["x-deletion-batch"], "b-1");
  await groups.removeMember("g1", "7");
  assert.equal(calls[1].headers["x-deletion-batch"], undefined);
});

test("thresholds read as words", () => {
  assert.equal(m.thresholdText(policy()), "25 per hour");
  assert.equal(m.thresholdText(policy({ max_count: 500, max_percent: 10, limit: 120 })), "10% or 500 per hour (120 now)");
  assert.equal(m.thresholdText(policy({ mode: "off" })), "No limit");
  assert.equal(m.windowText(1440), "per day");
  assert.equal(m.windowText(30), "per 30 minutes");
  assert.equal(m.windowText(180), "per 3 hours");
  assert.equal(m.usageRatio(policy({ used: 5, limit: 20 })), 0.25);
  assert.equal(m.usageRatio(policy({ used: 30, limit: 20 })), 1);
  assert.equal(m.usageRatio(policy({ limit: null })), 0);
});

test("the form is checked and turned into a payload entry only when it changes something", () => {
  const p = policy();
  assert.equal(m.inputOf(p, m.editOf(p)), null);
  assert.equal(m.checkEdit({ ...m.editOf(p), max_count: "", max_percent: "" }), "Set a count, a percent, or turn the category off.");
  assert.match(m.checkEdit({ ...m.editOf(p), window_minutes: "0" }) ?? "", /window/);
  assert.match(m.checkEdit({ ...m.editOf(p), max_percent: "101" }) ?? "", /percent/);
  assert.equal(m.checkEdit({ ...m.editOf(p), max_count: "", max_percent: "", mode: "off" }), null);
  assert.deepEqual(m.inputOf(p, { ...m.editOf(p), max_count: "10" }), { category: "groups", max_count: 10, max_percent: null, window_minutes: 60, mode: "hold_excess" });
  // turning a category off keeps its numbers
  assert.deepEqual(m.inputOf(p, { ...m.editOf(p), mode: "off" }), { category: "groups", max_count: 25, max_percent: null, window_minutes: 60, mode: "off" });
});

test("a looser setting is flagged: weaker mode or a higher limit per minute", () => {
  const p = policy();
  const mk = (o: Record<string, unknown>) => ({ category: "groups", max_count: 25, max_percent: null, window_minutes: 60, mode: "hold_excess", ...o }) as any;
  assert.equal(m.looksLooser(p, mk({ max_count: 10 })), false);
  assert.equal(m.looksLooser(p, mk({ max_count: 26 })), true);
  assert.equal(m.looksLooser(p, mk({ max_count: 50, window_minutes: 120 })), false);
  assert.equal(m.looksLooser(p, mk({ window_minutes: 30 })), true);
  assert.equal(m.looksLooser(p, mk({ mode: "off" })), true);
  assert.equal(m.looksLooser(p, mk({ mode: "hold_all" })), false);
  assert.equal(m.looksLooser(policy({ mode: "off" }), mk({ mode: "hold_excess" })), false);
});

test("a bulk action that was partly held says how many of how many", () => {
  const held = { status: "partially_applied", applied: 0, held: 1, hold_id: "h-1", threshold: "25 per hour", message: "x" };
  assert.equal(m.bulkHeldNotice([{ id: "a", deleted: true }], 1), null);
  const n = m.bulkHeldNotice([{ id: "a", deleted: true }, held, { ...held, hold_id: "h-1" }], 40);
  assert.deepEqual(n, { holdId: "h-1", text: "Deleted 38 of 40: 2 held for approval (threshold 25 per hour)" });
  assert.equal(m.isHeld({ hold_id: "h", held: 0 }), false);
});

test("a hold is titled by what it holds and where it came from", () => {
  assert.equal(m.holdTitle({ category: "group_members", item_count: 15, source: "loader", source_id: "ldr-1" }), "15 group memberships from a group loader ldr-1");
  assert.equal(m.holdTitle({ category: "groups", item_count: 3, source: "user", source_id: "" }), "3 groups from a person");
});
