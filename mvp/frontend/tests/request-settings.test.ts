// Tenant request settings (issue #298): the client calls and the form logic. The server enforces
// every rule; these check what the form shows and sends. Run with `npm test`.
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
const m = await import("../src/features/access/requestSettings.ts");
const D = m.DEFAULT_REQUEST_SETTINGS;

beforeEach(async () => {
  await api.getSession();
  calls = [];
});

test("settings are read from /request-settings and saved with their version and CSRF", async () => {
  assert.equal(api.requestSettingsPath, "/request-settings");
  await api.requestSettings.save(3, { ...D, justification_min_length: 20, max_hours: 72 });
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.headers["x-tessera-csrf"], c.body]), [
    ["PUT", "/api/request-settings", "csrf-pat", { version: 3, ...D, justification_min_length: 20, max_hours: 72 }],
  ]);
});

test("a request can carry attachments", async () => {
  await api.submitRequest({ beneficiary_ids: [4], catalog_item_ids: ["i1"], justification: "project", duration_hours: 8, attachments: ["SEC-1"] });
  assert.deepEqual(calls[0].body, { beneficiary_ids: [4], catalog_item_ids: ["i1"], justification: "project", duration_hours: 8, attachments: ["SEC-1"] });
});

test("the defaults are what requests did before the settings existed", () => {
  assert.deepEqual(D, { justification_required: true, justification_min_length: 1, default_hours: null, max_hours: null, attachments_allowed: false, history_visibility: "readers", for_others: "permission" });
  assert.equal(m.settingsError(D), null);
});

test("justification: required, a minimum length, or optional", () => {
  assert.equal(m.justificationError(D, "  "), "A justification is required");
  assert.equal(m.justificationError(D, "x"), null);
  const min = { ...D, justification_min_length: 20 };
  assert.equal(m.justificationError(min, "short one"), "Write at least 20 characters (9 so far)");
  assert.equal(m.justificationError(min, "  " + "x".repeat(20) + "  "), null); // counted after trimming
  assert.match(m.justificationHint(min), /At least 20 characters/);
  const optional = { ...D, justification_required: false, justification_min_length: 50 };
  assert.equal(m.justificationError(optional, ""), null);
  assert.equal(m.justificationError(optional, "x"), null);
  assert.equal(m.justificationError(optional, "x".repeat(1001)), "A justification is at most 1000 characters");
  assert.match(m.justificationHint(optional), /Optional/);
});

test("durations: the tenant maximum and the items' limit, and no open end without a default", () => {
  const all: [string, number | null][] = [["Until removed", null], ["8 hours", 8], ["24 hours", 24], ["72 hours", 72]];
  const hours = (xs: [string, number | null][]) => xs.map(([, h]) => h);
  assert.deepEqual(hours(m.durationChoices(all, null, D)), [null, 8, 24, 72]);
  const capped = { ...D, max_hours: 24 };
  assert.deepEqual(hours(m.durationChoices(all, null, capped)), [8, 24]); // no open end
  assert.deepEqual(hours(m.durationChoices(all, 8, capped)), [8]); // the item's limit is lower
  assert.deepEqual(hours(m.durationChoices(all, 72, capped)), [8, 24]); // the tenant's is lower
  assert.deepEqual(hours(m.durationChoices(all, null, { ...capped, default_hours: 8 })), [null, 8, 24]);
  assert.deepEqual(hours(m.durationChoices(all, null, capped, true)), [null, 8, 24]); // every item has a default
  assert.equal(m.effectiveMaxHours(null, D), null);
  assert.equal(m.effectiveMaxHours(48, D), 48);
  assert.equal(m.effectiveMaxHours(48, capped), 24);
  assert.equal(m.durationRequired(capped), true);
  assert.equal(m.durationRequired(capped, true), false); // every item has a default
  assert.equal(m.durationRequired({ ...capped, default_hours: 8 }), false);
  assert.equal(m.durationRequired(D), false);
  assert.equal(m.defaultDurationLabel({ ...D, default_hours: 24 }, (h) => `${h} h`), "Each item's default, else 24 h");
  assert.equal(m.defaultDurationLabel(D, (h) => `${h} h`), "Each item's default");
});

test("attachments are references, only where the tenant allows them", () => {
  assert.deepEqual(m.parseAttachments(" SEC-1 \n\n https://wiki/x\n"), ["SEC-1", "https://wiki/x"]);
  assert.equal(m.attachmentError(D, []), null);
  assert.equal(m.attachmentError(D, ["SEC-1"]), "Attachments are turned off for requests");
  const on = { ...D, attachments_allowed: true };
  assert.equal(m.attachmentError(on, ["SEC-1"]), null);
  assert.equal(m.attachmentError(on, Array(6).fill("x")), "At most 5 attachments");
  assert.match(m.attachmentError(on, ["x".repeat(301)]) ?? "", /at most 300/);
});

test("the form says what the request-for-others policy allows", () => {
  assert.equal(m.forOthersNote(D), null);
  assert.match(m.forOthersNote({ ...D, for_others: "nobody" }) ?? "", /yourself only/);
  assert.match(m.forOthersNote({ ...D, for_others: "managers" }) ?? "", /report to you/);
  assert.deepEqual(m.FOR_OTHERS.map((o) => o.id), ["permission", "managers", "nobody"]);
  assert.deepEqual(m.HISTORY.map((o) => o.id), ["readers", "involved"]);
});

test("the admin page checks a draft the way the server does", () => {
  assert.equal(m.settingsError({ ...D, justification_min_length: 0 }), "The minimum justification length is a whole number from 1 to 1000");
  assert.equal(m.settingsError({ ...D, justification_min_length: 1001 }), "The minimum justification length is a whole number from 1 to 1000");
  assert.equal(m.settingsError({ ...D, justification_min_length: 2.5 }), "The minimum justification length is a whole number from 1 to 1000");
  assert.match(m.settingsError({ ...D, default_hours: 0 }) ?? "", /default duration is between 0 and 8760/);
  assert.match(m.settingsError({ ...D, max_hours: 9000 }) ?? "", /maximum duration is between 0 and 8760/);
  assert.equal(m.settingsError({ ...D, default_hours: 48, max_hours: 24 }), "The default duration cannot be longer than the maximum");
  assert.equal(m.settingsError({ ...D, default_hours: 24, max_hours: 24 }), null);
  assert.equal(m.parseHours(""), null);
  assert.equal(m.parseHours(" 12.5 "), 12.5);
  assert.equal(m.parseHours("abc"), "invalid");
  assert.equal(m.parseHours("-3"), "invalid");
  assert.equal(m.sameSettings(D, { ...D }), true);
  assert.equal(m.sameSettings(D, { ...D, for_others: "nobody" }), false);
});
