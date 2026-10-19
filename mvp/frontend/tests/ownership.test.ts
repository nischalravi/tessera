// Ownership client (issue #167): the routes, verbs and bodies the API expects, and finding one
// object's row in a kind's listing. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();

const calls: { url: string; method: string; body: any }[] = [];
(globalThis as any).fetch = async (url: string, init: any = {}) => {
  calls.push({ url, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
  return { ok: true, status: 200, statusText: "", json: async () => ({ updated: 1 }) };
};

const api = await import("../src/api.ts");

test("setOwnership PUTs one object, escaping the key", async () => {
  await api.setOwnership("app", "aws/prod", { primary_owner_id: 4, backup_owner_id: null, owner_group_id: null, purpose: "billing" });
  const c = calls.at(-1)!;
  assert.equal(c.method, "PUT");
  assert.equal(c.url, "/api/ownership/app/aws%2Fprod");
  assert.deepEqual(c.body, { primary_owner_id: 4, backup_owner_id: null, owner_group_id: null, purpose: "billing" });
});

test("bulkSetOwnership POSTs the objects with the owners", async () => {
  await api.bulkSetOwnership([{ kind: "identity", key: "11" }], { primary_owner_id: 9, backup_owner_id: 3, owner_group_id: null });
  const c = calls.at(-1)!;
  assert.equal(c.method, "POST");
  assert.equal(c.url, "/api/ownership/bulk");
  assert.deepEqual(c.body, { objects: [{ kind: "identity", key: "11" }], primary_owner_id: 9, backup_owner_id: 3, owner_group_id: null });
});

test("ownedObject matches numeric and string keys", () => {
  const row = { kind: "group", key: "12", label: "okta:eng", primary_owner: null, backup_owner: null, owner_group: null, purpose: "", source: null, updated_at: null } as const;
  const list = { kind: "group", counts: {} as any, items: [row] } as any;
  assert.equal(api.ownedObject(list, 12), row);
  assert.equal(api.ownedObject(list, "12"), row);
  assert.equal(api.ownedObject(list, 13), null);
  assert.equal(api.ownedObject(null, 12), null);
  assert.equal(api.ownershipPath("identity"), "/ownership?kind=identity");
});
