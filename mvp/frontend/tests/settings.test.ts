// Configurable settings (issue #298): preferences, step-up per action, SoD page, review types, organization
// settings. The server decides; these cover the helpers the pages use. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();
const prefs = await import("../src/prefs.ts");
const api = await import("../src/api.ts");
const stepUp = await import("../src/features/admin/stepUpModel.ts");
const sodView = await import("../src/features/insights/sodViewModel.ts");
const reviewTypes = await import("../src/features/governance/reviewTypeModel.ts");
const orgModel = await import("../src/features/directory/orgSettingsModel.ts");

const NOON = new Date("2026-10-21T23:30:00Z");

test("dates follow the user's time zone and format", () => {
  const p = { ...prefs.NO_PREFERENCES };
  assert.equal(prefs.formatDay(NOON, { ...p, date_format: "iso", time_zone: "UTC" }), "2026-10-21");
  // 23:30 UTC is already the next day in Tokyo and still the same day in Los Angeles
  assert.equal(prefs.formatDay(NOON, { ...p, date_format: "iso", time_zone: "Asia/Tokyo" }), "2026-10-22");
  assert.equal(prefs.formatDay(NOON, { ...p, date_format: "iso", time_zone: "America/Los_Angeles" }), "2026-10-21");
  assert.equal(prefs.formatDay(NOON, { ...p, date_format: "dmy", time_zone: "UTC" }), "21/10/2026");
  assert.equal(prefs.formatDay(NOON, { ...p, date_format: "mdy", time_zone: "UTC" }), "10/21/2026");
  assert.match(prefs.formatDay(NOON, { ...p, date_format: "long", time_zone: "UTC", locale: "en-GB" }), /^21 Oct(ober)? 2026$/);
  assert.match(prefs.formatDateTime(NOON, { ...p, date_format: "iso", time_zone: "Asia/Tokyo" }), /^2026-10-22, .*8:30/);
});

test("the default is the browser's rendering, and a bad zone or locale never breaks a page", () => {
  assert.equal(prefs.formatDay(NOON, prefs.NO_PREFERENCES), NOON.toLocaleDateString(undefined, { dateStyle: "medium" }));
  assert.doesNotThrow(() => prefs.formatDay(NOON, { ...prefs.NO_PREFERENCES, time_zone: "Mars/Olympus", date_format: "iso" }));
  assert.doesNotThrow(() => prefs.formatDateTime(NOON, { ...prefs.NO_PREFERENCES, locale: "not a locale!!" }));
});

test("fmtDate and fmtDay use the signed-in user's preferences", () => {
  prefs.setDisplayPrefs({ ...prefs.NO_PREFERENCES, date_format: "iso", time_zone: "Asia/Tokyo" });
  try {
    assert.equal(api.fmtDay("2026-10-21T23:30:00"), "2026-10-22");
    assert.match(api.fmtDate("2026-10-21T23:30:00Z"), /^2026-10-22, /);
    assert.equal(api.fmtDay(null), "Never");
  } finally {
    prefs.setDisplayPrefs(prefs.NO_PREFERENCES);
  }
  assert.equal(prefs.getDisplayPrefs().date_format, "");
});

test("the landing page applies only from the root, from the server's own list", () => {
  const allowed = ["/", "/inbox", "/access/mine"];
  const p = (landing_page: string) => ({ ...prefs.NO_PREFERENCES, landing_page });
  assert.equal(prefs.landingTarget(p("/inbox"), "/", allowed), "/inbox");
  assert.equal(prefs.landingTarget(p("/inbox"), "/access/mine", allowed), null, "only when arriving at the root");
  assert.equal(prefs.landingTarget(p(""), "/", allowed), null);
  assert.equal(prefs.landingTarget(p("/"), "/", allowed), null);
  assert.equal(prefs.landingTarget(p("/admin/users"), "/", allowed), null, "not on the list");
  assert.equal(prefs.landingTarget(p("//evil.example"), "/", ["//evil.example"]), null);
  assert.equal(prefs.landingTarget(p("https://evil.example"), "/", ["https://evil.example"]), null);
  assert.equal(api.preferencesPath, "/me/preferences");
});

const PHR = "urn:tessera:acr:phr";
const AAL2 = "urn:tessera:acr:aal2";
const PHRH = "urn:tessera:acr:phrh";
const view = (over: object = {}) => ({
  version: 1, acrs: [AAL2, PHR, PHRH], min_max_age_s: 60, max_max_age_s: 3600, allow_weaker: false, can_manage: true,
  actions: [
    { action: "catalog.manage", floor: { acr: PHR, max_age_s: 900 }, unguarded: false, routes: 2, policy: null, effective: { acr: PHR, max_age_s: 900 } },
    { action: "requests.create", floor: null, unguarded: true, routes: 3, policy: { acr: AAL2, max_age_s: 600 }, effective: { acr: AAL2, max_age_s: 600 } },
  ],
  ...over,
}) as any;

test("step-up drafts: an entry can add or tighten, never weaken the floor", () => {
  const v = view();
  const d = stepUp.draftsOf(v);
  assert.deepEqual(d["requests.create"], { acr: AAL2, minutes: "10" });
  assert.deepEqual(d["catalog.manage"], { acr: "", minutes: "" });
  assert.deepEqual(stepUp.entriesOf(v, d), { entries: { "requests.create": { acr: AAL2, max_age_s: 600 } }, problem: null });
  assert.equal(stepUp.entriesOf(v, { ...d, "catalog.manage": { acr: PHRH, minutes: "5" } }).problem, null, "stricter is fine");
  assert.match(stepUp.entriesOf(v, { ...d, "catalog.manage": { acr: AAL2, minutes: "5" } }).problem ?? "", /not weaken/, "a weaker level");
  assert.match(stepUp.entriesOf(v, { ...d, "catalog.manage": { acr: PHR, minutes: "30" } }).problem ?? "", /not weaken/, "an older sign-in");
  assert.match(stepUp.entriesOf(v, { ...d, "requests.create": { acr: PHR, minutes: "0.5" } }).problem ?? "", /1 to 60 minutes/);
  assert.match(stepUp.entriesOf(v, { ...d, "requests.create": { acr: PHR, minutes: "" } }).problem ?? "", /minutes old/);
  // the dev switch lifts the check, and an action with an unguarded route may add below its guarded floor
  assert.equal(stepUp.entriesOf(view({ allow_weaker: true }), { ...d, "catalog.manage": { acr: AAL2, minutes: "30" } }).problem, null);
  const mixed = view({ actions: [{ action: "x", floor: { acr: PHR, max_age_s: 900 }, unguarded: true, routes: 2, policy: null, effective: null }] });
  assert.equal(stepUp.entriesOf(mixed, { x: { acr: AAL2, minutes: "30" } }).problem, null);
  assert.ok(stepUp.sameEntries(stepUp.savedEntries(v), { "requests.create": { acr: AAL2, max_age_s: 600 } }));
});

test("step-up wording", () => {
  assert.equal(stepUp.acrLabel(PHR), "Phishing-resistant sign-in");
  assert.equal(stepUp.requirementText(null), "None");
  assert.equal(stepUp.requirementText({ acr: PHR, max_age_s: 900 }), "Phishing-resistant sign-in, within 15 min");
  assert.equal(stepUp.ageText(90), "90 s");
  assert.ok(stepUp.rank(PHRH) > stepUp.rank(PHR) && stepUp.rank(PHR) > stepUp.rank(AAL2));
  assert.equal(api.stepUpPolicyPath, "/stepup-policy");
});

test("the SoD page shows what the tenant chose, and everything by default", () => {
  const items = [{ key: "risk" as const, n: 1 }, { n: 2 }, { key: "ruleset" as const, n: 3 }, { key: "mitigating_control" as const, n: 4 }];
  assert.deepEqual(sodView.visible(items, ["risk", "mitigating_control"]).map((i) => i.n), [1, 2, 4], "an entry with no key is always shown");
  assert.deepEqual(sodView.visible(items, sodView.ALL_VISIBLE.columns).map((i) => i.n), [1, 2, 3, 4]);
  assert.deepEqual(sodView.visible(items, []).map((i) => i.n), [2]);
  assert.equal(sodView.sodViewProblem([]), "Show at least one column.");
  assert.equal(sodView.sodViewProblem(["risk"]), null);
  assert.equal(sodView.SOD_VIEW_KEYS.length, 6);
  assert.equal(api.sodViewPath, "/sod/view-settings");
});

test("review type settings are checked before they are sent", () => {
  const ok = { enabled: true, reviewer_source: "owner", reviewer_id: null, fallback_reviewer_id: null, on_incomplete: "revoke", escalation_days: 7 } as any;
  assert.equal(reviewTypes.reviewTypeProblem(ok), null);
  assert.match(reviewTypes.reviewTypeProblem({ ...ok, reviewer_source: "fixed" }) ?? "", /Choose the person/);
  assert.match(reviewTypes.reviewTypeProblem({ ...ok, on_incomplete: "escalate" }) ?? "", /fallback/);
  assert.match(reviewTypes.reviewTypeProblem({ ...ok, on_incomplete: "escalate", fallback_reviewer_id: 3, escalation_days: 0 }) ?? "", /1 to 30/);
  assert.equal(reviewTypes.reviewTypeProblem({ ...ok, on_incomplete: "keep" }), null);
  assert.equal(reviewTypes.summary({ reviewer_source: "fixed", reviewer_person: { id: 1, name: "Carol" }, reviewer: "x" } as any), "Carol");
  assert.match(reviewTypes.summary({ reviewer_source: "owner_or_backup", reviewer: "the application's owner" } as any), /backup/);
  assert.equal(api.reviewTypesPath, "/review-types");
});

test("organization policies: drafts round-trip and bad values are caught", () => {
  const empty = { default_stages: null, default_escalate_hours: null, justification_required: null, justification_min_length: null, default_hours: null, max_hours: null };
  const d = orgModel.draftPolicies(empty);
  assert.deepEqual(orgModel.policiesOf(d), { policies: empty, problem: null });
  const set = orgModel.policiesOf({ ...d, stages: ["manager", "decider"], escalate: "24", requireJustification: true, minLength: "40", maxHours: "8", defaultHours: "4" });
  assert.deepEqual(set.policies, { default_stages: ["manager", "decider"], default_escalate_hours: 24, justification_required: true, justification_min_length: 40, default_hours: 4, max_hours: 8 });
  assert.equal(set.problem, null);
  assert.ok(orgModel.samePolicies(orgModel.policiesOf(orgModel.draftPolicies(set.policies)).policies, set.policies));
  assert.ok(!orgModel.samePolicies(set.policies, empty));
  assert.match(orgModel.policiesOf({ ...d, defaultHours: "10", maxHours: "5" }).problem ?? "", /cannot exceed/);
  assert.match(orgModel.policiesOf({ ...d, minLength: "0" }).problem ?? "", /1 to 1000/);
  assert.match(orgModel.policiesOf({ ...d, maxHours: "abc" }).problem ?? "", /between 0 and/);
  assert.match(orgModel.policiesOf({ ...d, stages: ["manager"], escalate: "99999" }).problem ?? "", /0 to 720/);
  // escalation without stages is dropped, not sent
  assert.equal(orgModel.policiesOf({ ...d, escalate: "24" }).policies.default_escalate_hours, null);
  assert.equal(api.orgSettingsPath("dept-0123456789"), "/orgs/dept-0123456789/settings");
  assert.equal(api.orgSettingsPath("a/b"), "/orgs/a%2Fb/settings");
  assert.equal(api.orgHierarchySourcePath, "/org-hierarchy-source");
});
