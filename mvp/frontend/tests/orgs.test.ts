// Organization client paths. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();
const api = await import("../src/api.ts");

test("org paths are encoded", () => {
  assert.equal(api.orgsPath, "/orgs");
  assert.equal(api.orgPath("dept-0123456789"), "/orgs/dept-0123456789");
  assert.equal(api.orgPath("a/b"), "/orgs/a%2Fb");
});
