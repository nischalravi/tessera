// The native groups client in src/api.ts: the requests it makes, and the repo rules for the groups screens
// (api.ts is the only place that calls fetch; every route is lazy). Run with `npm test`.
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, test } from "node:test";

const calls: { url: string; method: string; headers: Record<string, string>; body: unknown }[] = [];
(globalThis as any).window = Object.assign(new EventTarget(), { location: { pathname: "/", search: "" } });
(globalThis as any).sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
(globalThis as any).fetch = async (url: string, init: any) => {
  calls.push({ url, method: init.method, headers: init.headers, body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: true, status: 200, statusText: "", json: async () => ({ items: [] }) };
};

const { groups, setCsrfToken } = await import("../src/api.ts");

beforeEach(() => {
  calls.length = 0;
  setCsrfToken("csrf-1");
});

test("reads are GETs with the filters as query parameters, and empty ones are left out", async () => {
  await groups.members("g 1", { filter: "indirect", q: "ali", enabled: undefined, page: 2, limit: 50, sort: "name" });
  assert.equal(calls[0].method, "GET");
  assert.equal(calls[0].url, "/api/groups/g%201/members?filter=indirect&q=ali&page=2&limit=50&sort=name");
  await groups.listGroups({ folder: "f1", scope: "sub", q: "" });
  assert.equal(calls[1].url, "/api/groups/native?limit=500&folder=f1&scope=sub");
  await groups.listFolders();
  assert.equal(calls[2].url, "/api/groups/folders?limit=500");
  await groups.members("g", { filter: "direct", enabled: false });
  assert.equal(calls[3].url, "/api/groups/g/members?filter=direct&enabled=false");
});

test("history questions go to the members route with as_of or between", async () => {
  await groups.asOf("g", "2026-10-01T00:00:00.000Z");
  assert.equal(calls[0].url, "/api/groups/g/members?as_of=2026-10-01T00%3A00%3A00.000Z&filter=effective&limit=500");
  await groups.between("g", "2026-09-01T00:00:00.000Z", "2026-10-01T00:00:00.000Z");
  assert.equal(calls[1].url, "/api/groups/g/members?between=2026-09-01T00%3A00%3A00.000Z%2C2026-10-01T00%3A00%3A00.000Z&limit=500");
  await groups.trace("g", 12);
  assert.equal(calls[2].url, "/api/groups/g/members/12?trace=true");
});

test("a batch carries the CSRF token and an Idempotency-Key; reads carry neither", async () => {
  await groups.batch("g", { add: [{ identity: 4 }], remove: ["7"] }, "key-1");
  const c = calls[0];
  assert.equal(c.url, "/api/groups/g/members:batch");
  assert.equal(c.method, "POST");
  assert.equal(c.headers["idempotency-key"], "key-1");
  assert.equal(c.headers["x-tessera-csrf"], "csrf-1");
  assert.deepEqual(c.body, { add: [{ identity: 4 }], remove: ["7"] });
  await groups.group("g");
  assert.equal(calls[1].headers["idempotency-key"], undefined);
  assert.equal(calls[1].headers["x-tessera-csrf"], undefined);
});

test("the preview posts the changes to the simulate route and nothing else", async () => {
  await groups.simulate([{ kind: "remove_member", group: "g", member: "4" }]);
  assert.equal(calls[0].url, "/api/groups:simulate");
  assert.deepEqual(calls[0].body, { changes: [{ kind: "remove_member", group: "g", member: "4" }] });
});

test("privileges and attributes use the folder or group route by kind", async () => {
  await groups.privileges("folder", "f");
  await groups.privileges("group", "g");
  await groups.grant("folder", "f", { privilege: "read", holder_type: "everyone", applies_to: "groups", scope: "sub" });
  await groups.revoke("group", "g", "p1");
  await groups.effectivePrivileges("group", "g", 9);
  await groups.effectivePrivileges("folder", "f");
  await groups.setObjectTypes("folder", "f", ["app"]);
  await groups.assignments("group", "g");
  assert.deepEqual(calls.map((c) => `${c.method} ${c.url}`), [
    "GET /api/groups/folders/f/privileges",
    "GET /api/groups/g/privileges",
    "POST /api/groups/folders/f/privileges",
    "DELETE /api/groups/g/privileges/p1",
    "GET /api/groups/g/privileges/effective?identity=9",
    "GET /api/groups/folders/f/privileges/effective",
    "PUT /api/groups/folders/f/object-types",
    "GET /api/groups/attr-assignments?owner_type=group&owner=g&limit=500",
  ]);
});

test("a composite is set with PUT and a conversion with POST", async () => {
  await groups.setComposite("g", { op: "union", factors: ["a", "b"] });
  await groups.convertToComposite("g", { op: "union", factors: ["a", "b"], discard_members: true });
  assert.deepEqual(calls.map((c) => `${c.method} ${c.url}`), ["PUT /api/groups/g/composite", "POST /api/groups/g/convert-to-composite"]);
});

// ---------------------------------------------------------------- repo rules

const SRC = new URL("../src/", import.meta.url).pathname;
function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

test("api.ts is the only file that calls fetch", () => {
  const offenders = walk(SRC).filter((f) => /\.(ts|tsx)$/.test(f) && !f.endsWith("/api.ts") && /\bfetch\s*\(/.test(readFileSync(f, "utf8")));
  assert.deepEqual(offenders, []);
});

test("the groups screens are reached only through lazy routes", () => {
  const app = readFileSync(join(SRC, "app/App.tsx"), "utf8");
  for (const page of ["GroupsRoute", "GroupPage", "FolderPage"]) assert.ok(app.includes(`named(() => import("../features/directory/groups/${page}"), "${page}")`), page);
  assert.ok(!/^import .* from "\.\.\/features\/directory\/groups\//m.test(app), "no static import of the groups screens");
  // nothing in the main bundle imports them statically
  const static_ = walk(SRC).filter((f) => !f.includes("/directory/groups/") && /from "\.\.?\/(\.\.\/)*(features\/)?directory\/groups\/(GroupPage|FolderPage|ManagedGroups|GroupsRoute)"/.test(readFileSync(f, "utf8")));
  assert.deepEqual(static_, []);
});

test("the managed groups screens carry no Preview badge or mock data", () => {
  const dir = join(SRC, "features/directory/groups");
  for (const f of walk(dir).filter((x) => /\.(ts|tsx)$/.test(x))) {
    const text = readFileSync(f, "utf8");
    assert.ok(!/PreviewBadge|from "\.\.\/\.\.\/\.\.\/mocks/.test(text), f);
  }
});
