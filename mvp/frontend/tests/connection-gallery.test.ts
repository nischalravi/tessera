// New connection, step 1: the app-gallery filter model. Run with `npm test`.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { CATEGORIES, GALLERY_META, filterGallery, groupGallery, nextIndex } from "../src/features/admin/connections/gallery.ts";

// mirrors CONNECTOR_TYPES in shared.tsx (that module pulls in React, so the ids are listed here and checked below)
const T = [
  ["demo-ad", "Active Directory (demo)", "Simulated forest", true], ["demo-okta", "Okta (demo)", "The demo Okta org", true],
  ["demo-workday", "Workday (demo)", "The demo HR source", true], ["ad", "Active Directory", "Through the Directory Agent", false],
  ["ldap", "OpenLDAP / 389-DS", "Generic LDAP", false], ["entra", "Microsoft Entra ID", "Microsoft Graph", false],
  ["okta", "Okta", "OAuth service app", false], ["google", "Google Workspace", "Domain-wide delegation", false],
  ["workday", "Workday", "Integration system user", false],
  ["servicenow", "ServiceNow", "Users, groups and roles through the Table API", false],
  ["atlassian", "Atlassian Jira and Confluence", "Groups, project roles and product access", false], ["scim_app", "SCIM 2.0 application", "Any SCIM service", false], ["scim:auth0", "Auth0", "Enterprise connection", false],
  ["awsorg", "AWS Organizations and IAM", "Reader role in each account", false],
  ["azurerbac", "Azure RBAC", "Role assignments of subscriptions", false], ["gcpiam", "Google Cloud IAM", "IAM policies of an organization", false], ["kubernetes", "Kubernetes and OpenShift", "Roles, cluster roles, their bindings", false], ["unixssh", "Unix/Linux host (SSH)", "Local accounts, groups and sudoers rules", false], ["sftpdrop", "SFTP file drop (CSV)", "Accounts and entitlements CSV files", false], ["racf", "RACF (z/OS)", "Users, groups, connects and the SPECIAL attributes through the z/OS LDAP (SDBM) interface", false], ["ibmi", "IBM i", "User profiles, group profiles and special authorities", false], ["githubscan", "GitHub (code scan)", "Reads MCP configuration", false],
  ["sap", "SAP", "Roles and transaction codes", false], ["oracle", "Oracle Fusion Applications", "Roles of Oracle Fusion", false],
  ["cyberark", "CyberArk Privileged Access Manager", "Safes and vaulted accounts", false], ["beyondtrust", "BeyondTrust Password Safe", "Smart rules", false],
  ["delinea", "Delinea Secret Server", "Folders and secrets", false], ["vault", "HashiCorp Vault", "ACL policies, auth method roles", false], ["fieldglass", "SAP Fieldglass", "Contractor assignments", false],
  ["beeline", "Beeline", "Contractor assignments", false], ["csvfeed", "Contractor CSV feed", "A contractor file", false],
  ["agentcore", "AWS Bedrock AgentCore", "Agent runtimes", false],
  ["rest_generic", "Generic REST API", "Any HTTP/JSON system, mapped by a declarative spec", false],
  ["sql", "Database (SQL)", "PostgreSQL, MySQL, SQL Server or Oracle", false],
  ["successfactors", "SAP SuccessFactors", "Employee Central as an HR source", false],
].map(([id, label, blurb, demo]) => ({ id, label, blurb, demo })) as { id: string; label: string; blurb: string; demo: boolean }[];
const none = { q: "", category: "" as const, capability: "" as const };
const ids = (f: Partial<typeof none>) => filterGallery(T, { ...none, ...f }).map((t) => t.id);

test("every type has gallery metadata", () => {
  for (const t of T) assert.ok(GALLERY_META[t.id], t.id);
});

test("no filter shows everything", () => assert.equal(ids({}).length, T.length));

test("search matches name, description and publisher, ignoring case and padding", () => {
  assert.deepEqual(ids({ q: "  OKTA " }), ["demo-okta", "okta"]);
  assert.deepEqual(ids({ q: "ldap" }), ["ldap", "racf"]); // RACF is read through z/OS LDAP
  assert.deepEqual(ids({ q: "graph" }), ["entra"]); // description
  assert.deepEqual(ids({ q: "7644" }), ["scim_app"]); // publisher
  assert.deepEqual(ids({ q: "oracle" }), ["oracle", "sql"]); // the Oracle ERP tile and the database tile
  assert.deepEqual(ids({ category: "Databases", capability: "Provisioning target" }), ["sql"]);
  assert.deepEqual(ids({ q: "json" }), ["rest_generic"]); // description and publisher
  assert.deepEqual(ids({ q: "nothing like this" }), []);
});

test("chips filter by category and capability, and combine with search", () => {
  assert.deepEqual(ids({ category: "Demo / simulated" }), ["demo-ad", "demo-okta", "demo-workday"]);
  assert.deepEqual(ids({ capability: "HR source" }), ["demo-workday", "workday", "successfactors"]);
  assert.deepEqual(ids({ capability: "Provisioning target", category: "Cloud & SaaS" }), ["okta", "google", "servicenow", "atlassian", "scim_app", "rest_generic"]);
  assert.deepEqual(ids({ capability: "HR source", q: "demo" }), ["demo-workday"]);
});

test("the connectors the server already had are in the gallery under their categories", () => {
  const want: Record<string, string[]> = {
    "Cloud & IaaS": ["awsorg", "azurerbac", "gcpiam", "kubernetes"], "Servers & hosts": ["unixssh", "sftpdrop", "racf", "ibmi"], "Source code": ["githubscan"], ERP: ["sap", "oracle"], "Privileged access": ["cyberark", "beyondtrust", "delinea", "vault"],
    "Contractor & VMS": ["fieldglass", "beeline", "csvfeed"], "AI agents": ["agentcore"],
  };
  for (const [category, types] of Object.entries(want)) {
    assert.ok(CATEGORIES.includes(category as never), category);
    assert.deepEqual(ids({ category: category as never }), types, category);
  }
  assert.deepEqual(ids({ capability: "Agent discovery" }), ["githubscan", "agentcore"]);
  assert.deepEqual(ids({ capability: "Contractor source" }), ["fieldglass", "beeline", "csvfeed"]);
  assert.deepEqual(ids({ capability: "Access inventory", category: "Privileged access" }), ["cyberark", "beyondtrust", "delinea", "vault"]);
  assert.deepEqual(ids({ q: "fieldglass" }), ["fieldglass"]);
  assert.deepEqual(ids({ capability: "Access inventory", category: "Cloud & IaaS" }), ["awsorg", "azurerbac", "gcpiam", "kubernetes"]);
  assert.deepEqual(ids({ q: "azure" }), ["azurerbac"]);
  assert.deepEqual(ids({ q: "google cloud" }), ["gcpiam"]);
  assert.deepEqual(ids({ q: "sudoers" }), ["unixssh"]);
  assert.deepEqual(ids({ q: "sftp" }), ["sftpdrop"]);
  assert.deepEqual(ids({ capability: "Access inventory", category: "Servers & hosts" }), ["unixssh"]);
  assert.deepEqual(ids({ q: "racf" }), ["racf"]);
  assert.deepEqual(ids({ q: "special authorities" }), ["ibmi"]);
  assert.deepEqual(ids({ capability: "Identity source", category: "Servers & hosts" }), ["sftpdrop", "racf", "ibmi"]);
  assert.deepEqual(ids({ q: "  privileged " }), ["cyberark"]);
});

test("every type has a logo: a simple-icons mark or an original glyph", () => {
  const src = readFileSync(new URL("../src/components/VendorLogo.tsx", import.meta.url), "utf8");
  for (const t of T) {
    const vendor = GALLERY_META[t.id].vendor;
    assert.match(src, new RegExp(`^\\s+${vendor}: \\{`, "m"), `${t.id}: no mark or glyph for ${vendor}`);
  }
  assert.match(src, /siSap\b/, "the SAP mark");
  assert.match(src, /siGithub\b/, "the GitHub mark");
  assert.match(src, /siGooglecloud\b/, "the Google Cloud mark");
  assert.match(src, /siLinux\b/, "the Linux mark");
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

test("ServiceNow and Atlassian are identity sources and provisioning targets in Cloud & SaaS, each with a logo and a picker entry", () => {
  assert.deepEqual(GALLERY_META.servicenow, { vendor: "servicenow", publisher: "ServiceNow", category: "Cloud & SaaS", capabilities: ["Identity source", "Provisioning target"] });
  assert.deepEqual(GALLERY_META.atlassian, { vendor: "atlassian", publisher: "Atlassian", category: "Cloud & SaaS", capabilities: ["Identity source", "Provisioning target"] });
  assert.deepEqual(ids({ q: "table api" }), ["servicenow"]);
  assert.deepEqual(ids({ q: "project roles" }), ["atlassian"]);
  const logo = readFileSync(new URL("../src/components/VendorLogo.tsx", import.meta.url), "utf8");
  assert.match(logo, /siAtlassian\b/, "the Atlassian mark");
  assert.doesNotMatch(logo, /siServicenow\b/, "simple-icons 16.30.0 has no ServiceNow mark: an original glyph is used");
  const picker = readFileSync(new URL("../src/features/admin/connections/shared.tsx", import.meta.url), "utf8");
  for (const id of ["servicenow", "atlassian"]) assert.match(picker, new RegExp(`id: "${id}", label: "[^"]+", template: "${id}"`), id);
  const gov = readFileSync(new URL("../src/features/admin/connections/governed.ts", import.meta.url), "utf8");
  for (const id of ["servicenow", "atlassian"]) assert.match(gov, new RegExp(`^  ${id}: \\{`, "m"), `${id} has a connect form`);
});

test("IBM i is marked as a preview that cannot sync yet, on its tile and in the wizard", () => {
  const shared = readFileSync(new URL("../src/features/admin/connections/shared.tsx", import.meta.url), "utf8");
  const ibmi = shared.split("\n").findIndex((l) => l.includes('{ id: "ibmi"'));
  assert.ok(ibmi >= 0);
  assert.match(shared.split("\n").slice(ibmi, ibmi + 2).join("\n"), /preview: "Preview: IBM i cannot sync yet/);
  const wizard = readFileSync(new URL("../src/features/admin/connections/Wizard.tsx", import.meta.url), "utf8");
  assert.match(wizard, /t\.preview && <Badge/);
});

test("Kubernetes and Vault are read-only access inventories with a logo, a picker entry and a connect form", () => {
  assert.deepEqual(GALLERY_META.kubernetes, { vendor: "kubernetes", publisher: "Kubernetes and Red Hat OpenShift", category: "Cloud & IaaS", capabilities: ["Access inventory"] });
  assert.deepEqual(GALLERY_META.vault, { vendor: "vault", publisher: "HashiCorp", category: "Privileged access", capabilities: ["Access inventory"] });
  assert.deepEqual(ids({ q: "openshift" }), ["kubernetes"]);
  assert.deepEqual(ids({ q: "hashicorp" }), ["vault"]);
  const logo = readFileSync(new URL("../src/components/VendorLogo.tsx", import.meta.url), "utf8");
  assert.match(logo, /siKubernetes\b/, "the Kubernetes mark");
  assert.match(logo, /siVault\b/, "the Vault mark");
  const picker = readFileSync(new URL("../src/features/admin/connections/shared.tsx", import.meta.url), "utf8");
  for (const id of ["kubernetes", "vault"]) assert.match(picker, new RegExp(`id: "${id}", label: "[^"]+", template: "${id}"`), id);
  const gov = readFileSync(new URL("../src/features/admin/connections/governed.ts", import.meta.url), "utf8");
  for (const id of ["kubernetes", "vault"]) assert.match(gov, new RegExp(`^  ${id}: \\{`, "m"), `${id} has a connect form`);
});
