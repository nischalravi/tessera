// Group loaders (GR-10): the API client's requests and the pure logic behind the loader screens. Run with `npm test`.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import * as m from "../src/features/directory/groups/loaderModel.ts";

const calls: { url: string; method: string; body: unknown }[] = [];
let answer: unknown = { items: [] };
(globalThis as any).window = Object.assign(new EventTarget(), { location: { pathname: "/", search: "" } });
(globalThis as any).sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
(globalThis as any).fetch = async (url: string, init: any) => {
  calls.push({ url, method: init.method, body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: true, status: 200, statusText: "", json: async () => answer };
};
const { groupLoaders, loaderPending, setCsrfToken } = await import("../src/api.ts");

beforeEach(() => {
  calls.length = 0;
  answer = { items: [] };
  setCsrfToken("csrf-1");
});

test("every loader route has a typed call with the right method and path", async () => {
  await groupLoaders.list();
  await groupLoaders.get("l 1");
  await groupLoaders.create({ name: "n", type: "csv", config: {}, target_folder: "f" });
  await groupLoaders.update("l1", { status: "disabled", version: 3 });
  await groupLoaders.run("l1", "preview");
  await groupLoaders.runs("l1", { limit: 5, offset: 10 });
  await groupLoaders.runDetail("l1", "r1");
  await groupLoaders.approve("l1", "r1");
  await groupLoaders.reject("l1", "r1");
  await groupLoaders.unresolved("l1");
  await groupLoaders.tasks();
  assert.deepEqual(calls.map((c) => `${c.method} ${c.url}`), [
    "GET /api/groups/loaders?limit=500",
    "GET /api/groups/loaders/l%201",
    "POST /api/groups/loaders",
    "PATCH /api/groups/loaders/l1",
    "POST /api/groups/loaders/l1/run",
    "GET /api/groups/loaders/l1/runs?limit=5&offset=10",
    "GET /api/groups/loaders/l1/runs/r1",
    "POST /api/groups/loaders/l1/runs/r1/approve",
    "POST /api/groups/loaders/l1/runs/r1/reject",
    "GET /api/groups/loaders/l1/unresolved?limit=50",
    "GET /api/groups/loader-tasks?limit=200",
  ]);
  assert.deepEqual(calls[4].body, { kind: "preview" });
  assert.deepEqual(calls[3].body, { status: "disabled", version: 3 });
});

test("a SQL create answers pending approval, which the client tells apart from a loader", async () => {
  answer = { status: "pending_approval", change_request_id: "c1", type: "groups.loader.save", loader_id: null, expires_at: "", detail: "" };
  assert.equal(loaderPending(await groupLoaders.create({ name: "n", type: "sql_simple", config: {}, target_folder: "f" })), true);
  assert.equal(loaderPending({ status: "enabled" } as any), false);
});

const csv = () => ({ ...m.emptyForm("f1"), type: "csv" as const, name: " staff ", csvPath: "staff.csv", group: "staff", subjectColumn: "email" });

test("the form becomes the spec the server's strict decoder accepts", () => {
  const f = csv();
  const spec = m.buildSpec(f);
  assert.equal(spec.name, "staff");
  assert.deepEqual(spec.config, { path: "staff.csv", group: "staff", subject_column: "email" });
  assert.equal(spec.target_folder, "f1");
  assert.equal(spec.schedule, "@daily");
  assert.equal(spec.status, "disabled"); // a source that is not SQL is saved off and previewed first
  assert.deepEqual(spec.failsafe, { max_removed_percent: 20, max_removed: 500, max_groups_emptied_percent: 5, max_unresolved_percent: 2 });
  assert.equal(spec.name_template, undefined);
  assert.equal("secret" in spec, false);

  const url = m.buildSpec({ ...f, csvFrom: "url", csvUrl: "https://x.example/s.csv", csvSecret: "tok", csvGroupBy: "column", groupColumn: "grp", subjectSource: "email" });
  assert.deepEqual(url.config, { url: "https://x.example/s.csv", group_column: "grp", subject_column: "email", subject_source: "email" });
  assert.equal(url.secret, "tok");
  const acct = m.buildSpec({ ...f, subjectSource: "account", accountSystem: "okta" });
  assert.equal((acct.config as any).subject_source, "okta");
  const col = m.buildSpec({ ...f, sourceColumn: "src", subjectSource: "email" });
  assert.equal((col.config as any).source_column, "src");
  assert.equal("subject_source" in col.config, false);
});

test("each type builds its own config", () => {
  const base = m.emptyForm("f");
  assert.deepEqual(m.buildConfig({ ...base, type: "sql_simple", database: "hr.db", query: " SELECT 1 ", group: "staff" }), { database: "hr.db", query: "SELECT 1", group: "staff" });
  assert.deepEqual(m.buildConfig({ ...base, type: "sql_group_list", database: "hr.db", query: "SELECT 1", groupsQuery: "SELECT 2", incrementalQuery: "SELECT 3 @cursor" }),
    { database: "hr.db", query: "SELECT 1", groups_query: "SELECT 2", incremental_query: "SELECT 3 @cursor" });
  assert.deepEqual(m.buildConfig({ ...base, type: "connector_groups", namePrefix: "okta_" }), { name_prefix: "okta_" });
  assert.deepEqual(m.buildConfig({ ...base, type: "attribute", attribute: "title", onlyActive: false }), { attribute: "title", only_active: false });
  assert.deepEqual(m.buildConfig({ ...base, type: "recent_memberships", sourceGroup: "app:staff", days: "30", includeCurrent: true, group: "recent" }),
    { source_group: "app:staff", days: 30, include_current: true, group: "recent" });
  const sql = m.buildSpec({ ...base, type: "sql_simple", name: "n", database: "a.db", query: "SELECT 1", group: "g", incrementalSecs: "60", startEnabled: true });
  assert.equal(sql.incremental_secs, undefined); // no incremental query, so no interval
  assert.equal(sql.status, "enabled");
});

test("the step checks mirror the server's", () => {
  const f = m.emptyForm();
  assert.equal(m.stepProblems("type", f).length, 1);
  assert.deepEqual(m.stepProblems("source", csv()), []);
  assert.match(m.stepProblems("source", { ...csv(), targetFolder: "" }).join(), /folder/);
  assert.match(m.stepProblems("source", { ...csv(), csvPath: "../etc/passwd" }).join(), /loader data directory/);
  assert.match(m.stepProblems("source", { ...csv(), csvFrom: "url", csvUrl: "ftp://x" }).join(), /https/);
  assert.match(m.stepProblems("source", { ...csv(), group: "a b" }).join(), /not allowed/);
  const sql = { ...m.emptyForm("f"), type: "sql_simple" as const, name: "n", database: "hr.db", group: "g", query: "SELECT id AS subject_id FROM t" };
  assert.deepEqual(m.stepProblems("source", sql), []);
  assert.match(m.stepProblems("source", { ...sql, query: "DELETE FROM t" }).join(), /SELECT or WITH/);
  assert.match(m.stepProblems("source", { ...sql, query: "SELECT 1; DROP TABLE t" }).join(), /one statement/);
  assert.deepEqual(m.stepProblems("source", { ...sql, query: "WITH x AS (SELECT 1) SELECT * FROM x;" }), []);
  assert.match(m.stepProblems("source", { ...sql, query: "-- c\nSELECT 1" }).join(), /comments/);
  assert.match(m.stepProblems("source", { ...sql, incrementalQuery: "SELECT 1", incrementalSecs: "60" }).join(), /@cursor/);
  assert.match(m.stepProblems("source", { ...sql, incrementalQuery: "SELECT @cursor", incrementalSecs: "5" }).join(), /30 to 86400/);
  assert.match(m.stepProblems("people", { ...csv(), nameTemplate: "x" }).join(), /one/);
  assert.match(m.stepProblems("people", { ...csv(), subjectSource: "account" }).join(), /system/);
  assert.match(m.stepProblems("schedule", { ...csv(), schedule: "custom", cron: "* *" }).join(), /five/);
  assert.match(m.stepProblems("schedule", { ...csv(), failsafe: { ...csv().failsafe, maxRemovedPercent: "120" } }).join(), /0 to 100/);
  assert.match(m.stepProblems("source", { ...m.emptyForm("f"), type: "recent_memberships", name: "n", sourceGroup: "g", days: "400", group: "x" }).join(), /1 to 366/);
  assert.match(m.stepProblems("source", { ...m.emptyForm("f"), type: "connector_groups", name: "n" }).join(), /connection/);
});

test("SQL types say a second admin approves; the others do not", () => {
  assert.deepEqual(m.LOADER_TYPES.filter((t) => t.sql).map((t) => t.id), ["sql_simple", "sql_group_list"]);
  assert.equal(m.isSqlType("csv"), false);
  assert.equal(m.typeLabel("nope"), "nope");
});

test("words for runs, trips, schedules and state", () => {
  assert.equal(m.runSummary({ status: "applied", adds: 3, removes: 1, unresolved: 2, error: null }), "3 added, 1 removed, 2 unresolved");
  assert.equal(m.runSummary({ status: "failed", adds: null, removes: null, unresolved: null, error: "boom" }), "boom");
  assert.equal(m.tripText({ rule: "max_removed", value: 9, limit: 5, detail: "app:staff: 9 members would be removed (limit 5)" }), "app:staff: 9 members would be removed (limit 5)");
  assert.equal(m.scheduleText("@daily"), "every day at 00:00 UTC");
  assert.equal(m.scheduleText("15 2 * * 1-5"), "cron 15 2 * * 1-5 (UTC)");
  assert.deepEqual(m.loaderState({ status: "held", job: null }), { label: "Held", tone: "warning" });
  assert.deepEqual(m.loaderState({ status: "disabled", job: null }), { label: "Off", tone: "neutral" });
  assert.equal(m.loaderState({ status: "enabled", job: { last_run: { status: "failed" } } as any }).label, "Last run failed");
  assert.equal(m.loaderState({ status: "enabled", job: null }).label, "On");
  assert.equal(m.lagText(null), "never loaded");
  assert.equal(m.lagText(600), "10 min ago");
  assert.equal(m.lagText(7200), "2 h ago");
  assert.equal(m.loaderOfGroup([{ id: "a" }, { id: "b" }], { loader_id: "b" })?.id, "b");
  assert.equal(m.loaderOfGroup([{ id: "a" }], {}), null);
});

test("SCIM, LDAP and Postgres sources build their config and carry their credential as the secret", () => {
  const base = m.emptyForm("f");
  const scim = m.buildSpec({ ...base, type: "scim", name: "idp", scimUrl: "https://scim.example.com/scim/v2", scimSecret: "tok", scimSubject: "email", scimGroupFilter: 'displayName sw "e"', scimOnlyActive: false });
  assert.deepEqual(scim.config, { base_url: "https://scim.example.com/scim/v2", subject_attr: "email", group_filter: 'displayName sw "e"', only_active: false });
  assert.equal(scim.secret, "tok");
  const cc = m.buildConfig({ ...base, type: "scim", scimUrl: "https://s.example", scimAuth: "client_credentials", scimTokenUrl: "https://s.example/t", scimClientId: "c", scimScope: "scim" });
  assert.equal(cc.auth, "client_credentials");
  assert.equal(cc.client_id, "c");
  const ldap = m.buildSpec({ ...base, type: "ldap_group_list", name: "d", ldapUrl: "ldaps://ldap.example.com", ldapBindDn: "cn=r,dc=x", ldapSecret: "pw", ldapBaseDn: "dc=x", ldapFilter: "(objectClass=groupOfNames)", ldapMemberRdn: "uid" });
  assert.deepEqual(ldap.config, { url: "ldaps://ldap.example.com", bind_dn: "cn=r,dc=x", base_dn: "dc=x", filter: "(objectClass=groupOfNames)", member_rdn: "uid" });
  assert.equal(ldap.secret, "pw");
  const one = m.buildConfig({ ...base, type: "ldap_simple", ldapUrl: "ldap://h", ldapBindDn: "cn=r", ldapBaseDn: "dc=x", ldapSubjectAttr: "mail", group: "staff", ldapScope: "one" });
  assert.equal(one.scope, "one");
  assert.equal(one.group, "staff");
  const pg = m.buildSpec({ ...base, type: "sql_group_list", name: "p", sqlEngine: "postgres", dsn: "postgres://u:p@h/db", query: "SELECT 1", startEnabled: true });
  assert.deepEqual(pg.config, { engine: "postgres", query: "SELECT 1" });
  assert.equal(pg.secret, "postgres://u:p@h/db");
  assert.equal(m.needsSecret({ type: "sql_simple", sqlEngine: "file" }), false);
  assert.equal(m.needsSecret({ type: "scim", sqlEngine: "file" }), true);
});

test("the checks of the new sources", () => {
  const base = m.emptyForm("f");
  const scim = { ...base, type: "scim" as const, name: "n" };
  assert.match(m.stepProblems("source", scim).join(), /URL/);
  assert.match(m.stepProblems("source", { ...scim, scimUrl: "https://x.example/scim" }).join(), /token or client secret/);
  assert.deepEqual(m.stepProblems("source", { ...scim, scimUrl: "https://x.example/scim", scimSecret: "t" }), []);
  assert.match(m.stepProblems("source", { ...scim, scimUrl: "https://x.example", scimSecret: "t", scimAuth: "client_credentials" }).join(), /token URL/);
  const ldap = { ...base, type: "ldap_simple" as const, name: "n", ldapUrl: "ldaps://h.example", ldapBindDn: "cn=r,dc=x", ldapSecret: "p", ldapBaseDn: "dc=x", group: "g" };
  assert.deepEqual(m.stepProblems("source", ldap), []);
  assert.match(m.stepProblems("source", { ...ldap, ldapUrl: "ldap://h.example:3268" }).join(), /URL/);
  assert.match(m.stepProblems("source", { ...ldap, ldapFilter: "objectClass=person" }).join(), /parentheses/);
  const sql = { ...base, type: "sql_simple" as const, name: "n", group: "g", query: "SELECT 1", sqlEngine: "postgres" as const };
  assert.match(m.stepProblems("source", sql).join(), /connection string/);
  assert.deepEqual(m.stepProblems("source", { ...sql, dsn: "postgres://u:p@db.example.com/hr" }), []);
});

test("SQL, SCIM and LDAP sources say a second admin approves; the others do not", () => {
  assert.deepEqual(m.LOADER_TYPES.filter((t) => t.approval).map((t) => t.id), ["sql_simple", "sql_group_list", "scim", "ldap_simple", "ldap_group_list"]);
  assert.equal(m.needsApproval("csv"), false);
  assert.equal(m.needsApproval("scim"), true);
  assert.equal(m.isSqlType("scim"), false);
});
