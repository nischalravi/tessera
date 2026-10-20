// The guest UI's rules (issue #76): the message catalog the public pages use, the masked identifiers and
// history filters on the person page, the typed inbox items for guest work, and the lifecycle tiles.
// Run with `npm test`.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, test } from "node:test";

(globalThis as any).window = new EventTarget();
type Call = { url: string; method: string; body: any };
let calls: Call[] = [];
(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
  const body = url === "/api/auth/session" ? { csrf_token: "csrf", tenant: { slug: "larkspur" }, user: {} } : {};
  return { ok: true, status: 200, statusText: "", json: async () => body };
};

const api = await import("../src/api.ts");
const i18n = await import("../src/i18n/index.ts");
const { en } = await import("../src/i18n/en.ts");
const aff = await import("../src/features/directory/affiliationModel.ts");
const items = await import("../src/features/inbox/guestItems.ts");
const lc = await import("../src/features/governance/guestLifecycleModel.ts");

beforeEach(async () => {
  await api.getSession();
  calls = [];
  i18n.setLocale(["en"]);
});

// ------------------------------------------------------------------ i18n

test("t() fills placeholders and leaves unknown ones visible", () => {
  assert.equal(i18n.t("claim.done.title", { name: "Ada" }), "You are all set, Ada");
  assert.equal(i18n.format("a {x} b {y}", { x: 1 }), "a 1 b {y}");
  assert.equal(i18n.t("claim.verify.help", { sent: "" }).includes("{sent}"), false);
});

test("an unsupported language falls back to English; a missing key shows the key, never blank", () => {
  assert.equal(i18n.pickLocale(["fr-CA", "de"]), "en");
  assert.equal(i18n.pickLocale(["en-GB"]), "en");
  assert.equal(i18n.pickLocale([]), "en");
  assert.equal(i18n.t("no.such.key" as any), "no.such.key");
});

test("message values are plain text: no markup in the catalog", () => {
  for (const [k, v] of Object.entries(en)) assert.doesNotMatch(v, /<[a-z/]/i, k);
});

test("every key the public pages use exists in the catalog, and every catalog key is used", () => {
  const dir = (d: string) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? dir(join(d, e.name)) : [join(d, e.name)]));
  const files = dir("src/public").filter((f) => /\.(tsx|ts)$/.test(f));
  const used = new Set<string>();
  const dynamic: string[] = [];
  for (const f of files) {
    const src = readFileSync(f, "utf8");
    for (const m of src.matchAll(/\bt\(\s*["'`]([^"'`]+)["'`]/g)) {
      if (m[1].includes("${")) dynamic.push(m[1]);
      else used.add(m[1]);
    }
    for (const m of src.matchAll(/titleKey="([^"]+)"/g)) used.add(m[1]);
  }
  for (const k of used) assert.ok(k in en, `missing message: ${k}`);
  // keys built at run time: claim.step.* and claim.population.*
  for (const d of dynamic) used.add(d);
  const prefixes = ["claim.step.", "claim.population."];
  const unused = Object.keys(en).filter((k) => !used.has(k) && !prefixes.some((p) => k.startsWith(p)) && !k.startsWith("common.") && !k.startsWith("brand."));
  // PublicShell and the pages use the "common." and "brand." keys through shared components
  assert.deepEqual(unused, [], "catalog keys no page uses");
  for (const p of prefixes) assert.ok(Object.keys(en).some((k) => k.startsWith(p)));
});

test("the public pages have no hard-coded sentences in JSX text", () => {
  for (const f of ["src/public/claim/ClaimPage.tsx", "src/public/register/RegisterPage.tsx", "src/public/renew/RenewPage.tsx"]) {
    const src = readFileSync(f, "utf8");
    // JSX text: >Some words here< outside braces
    const hits = [...src.matchAll(/>\s*([A-Z][a-z]+(?: [a-z']+){2,}[^<{}]*)</g)].map((m) => m[1]);
    assert.deepEqual(hits, [], `${f} has literal text`);
  }
});

// ------------------------------------------------------------------ person page

test("identifiers are masked for display", () => {
  assert.equal(aff.maskIdentifier("email", "ada.lovelace@example.edu"), "a***@example.edu");
  assert.equal(aff.maskIdentifier("phone", "+14155550123"), "***0123");
  assert.equal(aff.maskIdentifier("employee_id", "E1234567"), "E1***67");
  assert.equal(aff.maskIdentifier("netid", "abc"), "***");
  assert.equal(aff.maskIdentifier("national_id_hmac", null), null);
  assert.equal(aff.maskIdentifier("eppn", "pat@uni.example"), "p***@uni.example");
});

test("merge and match history is the person's own, newest first", () => {
  const merges = [
    { id: "a", survivor_id: 1, merged_id: 2, merged_at: "2026-01-01T00:00:00Z" },
    { id: "b", survivor_id: 3, merged_id: 4, merged_at: "2026-02-01T00:00:00Z" },
    { id: "c", survivor_id: 5, merged_id: 1, merged_at: "2026-03-01T00:00:00Z" },
  ];
  assert.deepEqual(aff.mergesFor(merges, 1).map((m) => m.id), ["c", "a"]);
  assert.deepEqual(aff.mergesFor(merges, 9), []);
  const ms = [
    { id: "x", received_at: "2026-01-01", subject: { identity_id: 7 }, candidates: [{ candidate_id: 1 }] },
    { id: "y", received_at: "2026-02-01", subject: { identity_id: 1 }, candidates: [{ candidate_id: 8 }] },
    { id: "z", received_at: "2026-03-01", subject: { identity_id: 9 }, candidates: [{ candidate_id: 8 }] },
  ];
  assert.deepEqual(aff.matchesFor(ms, 1).map((m) => m.id), ["y", "x"]);
});

test("the claim summary follows the furthest invitation", () => {
  assert.equal(aff.claimSummary([]), "none");
  assert.equal(aff.claimSummary(["expired", "claimed"]), "claimed");
  assert.equal(aff.claimSummary(["sent", "claiming"]), "in_progress");
  assert.equal(aff.claimSummary(["ready"]), "invited");
  assert.equal(aff.claimSummary(["revoked", "expired"]), "expired");
});

// ------------------------------------------------------------------ inbox

const sp = { id: "sp1", created_at: "2026-10-01T00:00:00Z" } as any;
const reg = { id: "r1", created_at: "2026-10-02T00:00:00Z" } as any;
const match = { id: "m1", received_at: "2026-10-03T00:00:00Z", candidates: [] } as any;
const transfer = { task_id: "t1", task_kind: "sponsor_transfer", guest: { id: 1, name: "G" }, deadline: "2026-10-20T00:00:00Z", can_act: true } as any;
const renewal = { task_id: "t2", task_kind: "renewal_request", guest: { id: 2, name: "H" }, can_act: true } as any;

test("each source becomes a typed guest item with its own key; a missing source adds none", () => {
  const all = items.guestInboxItems({ sponsorships: [sp], registrations: [reg], matches: [match], tasks: [transfer, renewal] });
  assert.deepEqual(all.map((i: any) => i.kind), Array(5).fill("guest"));
  assert.deepEqual(all.map((i: any) => i.guest.type), ["sponsorship", "registration", "match", "task", "task"]);
  assert.equal(new Set(all.map((i) => i.key)).size, 5);
  assert.deepEqual(items.guestInboxItems({}), []);
  assert.deepEqual(items.guestInboxItems({ sponsorships: null, tasks: undefined }), []);
});

test("row actions: approvals decide in place, a match links to its review page, a transfer can be taken or ended", () => {
  assert.deepEqual(items.guestRowActions({ type: "sponsorship", s: sp }), { primary: "Approve", secondary: "Reject" });
  assert.deepEqual(items.guestRowActions({ type: "registration", r: reg }), { primary: "Approve", secondary: "Deny" });
  assert.equal(items.guestRowActions({ type: "match", m: match }).link, "/directory/identity-matches?selected=m1");
  const t = items.guestRowActions({ type: "task", t: transfer });
  assert.equal(t.primary, "Take over");
  assert.equal(t.secondary, "End");
  assert.equal(items.guestRowActions({ type: "task", t: transfer }, "suspend").secondary, "Suspend");
  // a task the person may not act on only links to the lifecycle page
  assert.equal(items.guestRowActions({ type: "task", t: { ...transfer, can_act: false } }).link, "/governance/guest-lifecycle?view=tasks");
  // a renewal request can only be dismissed: no destructive secondary
  assert.deepEqual(items.guestRowActions({ type: "task", t: renewal }), { primary: "Dismiss", secondary: undefined });
});

// ------------------------------------------------------------------ lifecycle tiles and api

test("lifecycle tiles flag what needs a person", () => {
  const tiles = lc.kpiTiles({ expiring_14: 4, expiring_3: 1, pending_transfer: 2, renewal_requests: 3, stepup_required: 1, dual_status: 0 });
  assert.deepEqual(tiles.map((t) => [t.bucket, t.value, t.tone]), [["expiring_14", 4, "warning"], ["pending_transfer", 2, "critical"], ["renewal_requests", 3, undefined], ["dual_status", 0, undefined]]);
  const quiet = lc.kpiTiles({});
  assert.deepEqual(quiet.map((t) => [t.value, t.tone]), [[0, undefined], [0, undefined], [0, undefined], [0, undefined]]);
});

test("recovery and registration calls use the registered paths", async () => {
  await api.guests.recover(7, "lost phone");
  await api.guestRecoveries.cancel("c/1", "no longer needed");
  await api.registrationRequests.newCode();
  assert.deepEqual(calls.map((c) => [c.method, c.url, c.body]), [
    ["POST", "/api/guests/7/recovery", { reason: "lost phone" }],
    ["POST", "/api/guest-recoveries/c%2F1/cancel", { reason: "no longer needed" }],
    ["POST", "/api/guest-registrations/code", {}],
  ]);
});
