// Activity feed client path. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();
const api = await import("../src/api.ts");

test("the activity path carries the limit", () => {
  assert.equal(api.activityPath(), "/activity?limit=10");
  assert.equal(api.activityPath(8), "/activity?limit=8");
});
