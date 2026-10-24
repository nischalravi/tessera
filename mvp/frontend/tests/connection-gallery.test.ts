// New connection, step 1: the app-gallery filter model. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

import { CATEGORIES, GALLERY_META, filterGallery, groupGallery, nextIndex } from "../src/features/admin/connections/gallery.ts";

// mirrors CONNECTOR_TYPES in shared.tsx (that module pulls in React, so the ids are listed here and checked below)
const T = [
  ["demo-ad", "Active Directory (demo)", "Simulated forest", true], ["demo-okta", "Okta (demo)", "The demo Okta org", true],
  ["demo-workday", "Workday (demo)", "The demo HR source", true], ["ad", "Active Directory", "Through the Directory Agent", false],
  ["ldap", "OpenLDAP / 389-DS", "Generic LDAP", false], ["entra", "Microsoft Entra ID", "Microsoft Graph", false],
  ["okta", "Okta", "OAuth service app", false], ["google", "Google Workspace", "Domain-wide delegation", false],
  ["workday", "Workday", "Integration system user", false], ["scim_app", "SCIM 2.0 application", "Any SCIM service", false], ["scim:auth0", "Auth0", "Enterprise connection", false],
].map(([id, label, blurb, demo]) => ({ id, label, blurb, demo })) as { id: string; label: string; blurb: string; demo: boolean }[];
const none = { q: "", category: "" as const, capability: "" as const };
const ids = (f: Partial<typeof none>) => filterGallery(T, { ...none, ...f }).map((t) => t.id);

test("every type has gallery metadata", () => {
  for (const t of T) assert.ok(GALLERY_META[t.id], t.id);
});

test("no filter shows everything", () => assert.equal(ids({}).length, T.length));

test("search matches name, description and publisher, ignoring case and padding", () => {
  assert.deepEqual(ids({ q: "  OKTA " }), ["demo-okta", "okta"]);
  assert.deepEqual(ids({ q: "ldap" }), ["ldap"]);
  assert.deepEqual(ids({ q: "graph" }), ["entra"]); // description
  assert.deepEqual(ids({ q: "7644" }), ["scim_app"]); // publisher
  assert.deepEqual(ids({ q: "nothing like this" }), []);
});

test("chips filter by category and capability, and combine with search", () => {
  assert.deepEqual(ids({ category: "Demo / simulated" }), ["demo-ad", "demo-okta", "demo-workday"]);
  assert.deepEqual(ids({ capability: "HR source" }), ["demo-workday", "workday"]);
  assert.deepEqual(ids({ capability: "Provisioning target", category: "Cloud & SaaS" }), ["okta", "google", "scim_app"]);
  assert.deepEqual(ids({ capability: "HR source", q: "demo" }), ["demo-workday"]);
});

test("groups follow category order and drop empty ones", () => {
  const all = groupGallery(T);
  assert.deepEqual(all.map((g) => g.category), CATEGORIES);
  assert.equal(all.reduce((n, g) => n + g.items.length, 0), T.length);
  assert.deepEqual(groupGallery(filterGallery(T, { ...none, q: "scim" })).map((g) => g.category), ["Cloud & SaaS"]);
  assert.deepEqual(groupGallery([]), []);
});

test("arrow keys wrap, Home and End jump, other keys stay put, empty list has no target", () => {
  assert.equal(nextIndex("ArrowRight", 2, 3), 0);
  assert.equal(nextIndex("ArrowDown", 0, 3), 1);
  assert.equal(nextIndex("ArrowLeft", 0, 3), 2);
  assert.equal(nextIndex("ArrowUp", 2, 3), 1);
  assert.equal(nextIndex("Home", 2, 3), 0);
  assert.equal(nextIndex("End", 0, 3), 2);
  assert.equal(nextIndex("x", 1, 3), 1);
  assert.equal(nextIndex("ArrowRight", 0, 0), -1);
});


test("Salesforce is an identity source and provisioning target in Cloud & SaaS", () => {
  assert.deepEqual(GALLERY_META.salesforce, { vendor: "salesforce", publisher: "Salesforce", category: "Cloud & SaaS", capabilities: ["Identity source", "Provisioning target"] });
});
