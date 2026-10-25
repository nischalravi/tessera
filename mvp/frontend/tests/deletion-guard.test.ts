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
  await groups.deleteGroup("g1", undefined, "b-1");
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

// ------------------------------------------------------------ per-source settings

const eff = (o: Record<string, unknown> = {}): any => ({
  category: "identities", max_count: 50, max_percent: 2, window_minutes: 60, mode: "hold_all", overridden: false,
  feed: { drop_percent: 20, empty_check: true }, ...o,
});
const srcCat = (o: Record<string, unknown> = {}): any => ({
  category: "identities", tenant: { max_count: 50, max_percent: 2, window_minutes: 60, mode: "hold_excess", default: true },
  override: null, effective: eff(), last_count: 120, used: 0, limit: 5, ...o,
});

test("a source's settings are read from its own path and changed through the same change request", async () => {
  assert.equal(deletionGuard.sourcePath("connection", "c 1"), "/admin/deletion-guard/sources/connection/c%201");
  await deletionGuard.change([], undefined, [{ kind: "loader", source_id: "L", category: "group_members", remove: true }]);
  assert.equal(calls[0].url, "/api/admin/change-requests");
  assert.deepEqual((calls[0].body as any).payload, { sources: [{ kind: "loader", source_id: "L", category: "group_members", remove: true }] });
});

test("source edits: nothing set is no change, a feed-only edit leaves the thresholds inherited, a cleared override is a removal", () => {
  const c = srcCat();
  const e = m.sourceEditOf(c);
  assert.equal(e.mode, "inherit");
  assert.equal(e.window_minutes, "60");
  assert.equal(m.sourceInputOf("connection", "c1", c, e), null);
  assert.deepEqual(m.sourceInputOf("connection", "c1", c, { ...e, feed_drop: "35", empty_check: false }),
    { kind: "connection", source_id: "c1", category: "identities", feed_drop_percent: 35, feed_empty_check: false });
  assert.deepEqual(m.sourceInputOf("connection", "c1", c, { ...e, mode: "hold_all", max_count: "10", max_percent: "" }),
    { kind: "connection", source_id: "c1", category: "identities", mode: "hold_all", window_minutes: 60, max_count: 10, max_percent: null });
  const own = srcCat({ override: { kind: "connection", source_id: "c1", category: "identities", mode: "hold_all", max_count: 10, max_percent: null, window_minutes: 60, feed_drop_percent: 35, feed_empty_check: null } });
  const oe = m.sourceEditOf(own);
  assert.deepEqual([oe.mode, oe.max_count, oe.feed_drop, oe.empty_check], ["hold_all", "10", "35", true]);
  assert.equal(m.sourceInputOf("connection", "c1", own, oe), null, "unchanged");
  assert.deepEqual(m.sourceInputOf("connection", "c1", own, { ...oe, mode: "inherit", max_count: "", feed_drop: "" }),
    { kind: "connection", source_id: "c1", category: "identities", remove: true });
});

test("source edits are checked the way the form checks categories, plus the feed limit", () => {
  const e = m.sourceEditOf(srcCat());
  assert.equal(m.checkSourceEdit(e), null);
  assert.match(m.checkSourceEdit({ ...e, feed_drop: "101" }) ?? "", /0 to 100/);
  assert.match(m.checkSourceEdit({ ...e, feed_drop: "x" }) ?? "", /0 to 100/);
  assert.match(m.checkSourceEdit({ ...e, mode: "hold_all" }) ?? "", /count, a percent/);
  assert.match(m.checkSourceEdit({ ...e, mode: "hold_all", max_count: "5", window_minutes: "0" }) ?? "", /window/);
  assert.equal(m.checkSourceEdit({ ...e, mode: "hold_all", max_count: "5" }), null);
});

test("a looser source setting is flagged so the form warns that a second admin is asked", () => {
  const c = srcCat();
  const looser = (o: any) => m.sourceLooksLooser(c, { kind: "connection", source_id: "c1", category: "identities", ...o });
  assert.equal(looser({ feed_drop_percent: 30 }), true);
  assert.equal(looser({ feed_drop_percent: 10 }), false);
  assert.equal(looser({ feed_empty_check: false }), true);
  assert.equal(looser({ mode: "hold_all", max_count: 3, max_percent: 2, window_minutes: 60 }), false);
  assert.equal(looser({ mode: "hold_excess", max_count: 3, max_percent: 2, window_minutes: 60 }), true, "hold_all to hold_excess is a weaker mode");
  assert.equal(looser({ mode: "hold_all", max_count: 500, max_percent: null, window_minutes: 60 }), true);
  assert.equal(looser({ mode: "off", window_minutes: 60 }), true);
  assert.equal(looser({ remove: true }), false, "back to the category's, which is the same as what applies");
  const own = srcCat({ effective: eff({ max_count: 3, max_percent: null, feed: { drop_percent: 10, empty_check: true }, overridden: true }) });
  assert.equal(m.sourceLooksLooser(own, { kind: "connection", source_id: "c1", category: "identities", remove: true }), true, "removing a tight override");
});

test("each kind of source links to its own settings page", () => {
  assert.equal(m.sourceLink("connection", "a b"), "/admin/connections/a%20b");
  assert.equal(m.sourceLink("vms_source", "v"), "/admin/contractor-feeds");
  assert.equal(m.sourceLink("loader", "l"), "/directory/groups/loaders");
});

test("a deletion-guard save refused for step-up opens the step-up dialog and reads as a step-up refusal (#619)", async () => {
  const real = (globalThis as any).fetch;
  const events: unknown[] = [];
  const on = (e: Event) => events.push((e as CustomEvent).detail);
  (globalThis as any).window.addEventListener("tessera:step-up", on);
  (globalThis as any).fetch = async (url: string, init: any) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body ? JSON.parse(init.body) : undefined });
    return { ok: false, status: 401, statusText: "", json: async () => ({ error: "step_up_required", acr: "urn:tessera:acr:phr", max_age: 900 }) };
  };
  try {
    const input: any = { kind: "connection", source_id: "c1", category: "groups", mode: "hold_excess", window_minutes: 60, max_count: 5 };
    const err: any = await deletionGuard.change([], undefined, [input]).then(() => null, (e) => e);
    assert.equal(calls[0].url, "/api/admin/change-requests");
    assert.equal(calls[0].method, "POST");
    assert.equal(events.length, 1, "the STEP_UP event that opens the dialog fires");
    assert.equal(m.isStepUpRefusal(err), true);
    assert.equal(m.isStepUpRefusal(new Error("boom")), false);
    assert.equal(m.isStepUpRefusal(null), false);
  } finally {
    (globalThis as any).window.removeEventListener("tessera:step-up", on);
    (globalThis as any).fetch = real;
  }
});
