// Renamed terms (Admin > Branding & labels) and the Identity rules client: the words are swapped whole, singular and
// plural, keeping the capital; the tenant's language is the fallback locale of a person who chose none.
// Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();

const calls: { url: string; method: string; body: any }[] = [];
(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: true, status: 200, statusText: "", json: async () => ({}) };
};

const l = await import("../src/labels.ts");
const prefs = await import("../src/prefs.ts");
const api = await import("../src/api.ts");

test("a renamed term is swapped, singular and plural, keeping the capital", () => {
  const labels = { entitlement: "permission set" };
  assert.equal(l.applyLabels("Entitlements", labels), "Permission sets");
  assert.equal(l.applyLabels("Entitlement", labels), "Permission set");
  assert.equal(l.applyLabels("new entitlement for you", labels), "new permission set for you");
  assert.equal(l.applyLabels("ENTITLEMENTS", labels), "PERMISSION SETS");
});

test("only whole words are swapped", () => {
  assert.equal(l.applyLabels("Grouping and subgroups", { group: "team" }), "Grouping and subgroups");
  assert.equal(l.applyLabels("Groups", { group: "team" }), "Teams");
});

test("a multi-word term and the longest key wins", () => {
  assert.equal(l.applyLabels("Access reviews", { "access review": "certification", group: "team" }), "Certifications");
  assert.equal(l.applyLabels("Group access", { group: "team", "group access": "membership" }), "Membership");
});

test("plurals", () => {
  assert.equal(l.pluralOf("policy"), "policies");
  assert.equal(l.pluralOf("class"), "classes");
  assert.equal(l.pluralOf("day"), "days");
  assert.equal(l.pluralOf("permission set"), "permission sets");
});

test("nothing renamed leaves the text alone, and a label is never read as a pattern", () => {
  assert.equal(l.applyLabels("Groups", {}), "Groups");
  assert.equal(l.applyLabels("a.b", { "a.b": "$&" }), "$&");
  l.setLabels({ guest: "visitor" });
  assert.equal(l.applyLabels("Guests"), "Visitors");
  l.setLabels(null);
  assert.equal(l.applyLabels("Guests"), "Guests");
});

test("the preferences carry the tenant's labels, and the language is the fallback locale", () => {
  prefs.setDisplayPrefs({ ...prefs.NO_PREFERENCES, tenant_language: "de-DE", labels: { group: "team" } });
  assert.equal(l.applyLabels("Groups"), "Teams");
  const d = new Date(Date.UTC(2026, 9, 21, 12));
  assert.ok(prefs.formatDay(d).includes("21.10.2026") || prefs.formatDay(d).includes("21. Okt"), prefs.formatDay(d));
  // the person's own locale wins over the tenant's
  assert.ok(prefs.formatDay(d, { ...prefs.NO_PREFERENCES, locale: "en-US" }).includes("Oct"), "en-US");
  prefs.setDisplayPrefs(prefs.NO_PREFERENCES);
  assert.equal(l.applyLabels("Groups"), "Groups");
});

test("label and identity-rules calls", async () => {
  await api.labelsApi.save({ version: 2, default_language: "fr-FR", email_logo: true, labels: { group: "équipe" } });
  assert.deepEqual(calls.at(-1), { url: "/api/admin/labels", method: "PUT", body: { version: 2, default_language: "fr-FR", email_logo: true, labels: { group: "équipe" } } });
  const body = { version: 1, correlation_order: ["email"], authoritative: { title: "workday" }, dormant_service_days: 45, dormant_ai_agent_days: 10 };
  await api.identityRulesApi.save(body);
  assert.deepEqual(calls.at(-1), { url: "/api/admin/identity-rules", method: "PUT", body });
});
