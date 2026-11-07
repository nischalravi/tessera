// Config import preview: a SIEM sink imported without a target is flagged in the notes (#905).
import assert from "node:assert/strict";
import { test } from "node:test";

(globalThis as any).window = new EventTarget();
const api = await import("../src/api.ts");

test("a plan item that needs a target says so, after any server notes", () => {
  assert.deepEqual(api.planItemNotes({ notes: ["new sink"], needs_target: true }), ["new sink", api.NEEDS_TARGET_NOTE]);
  assert.deepEqual(api.planItemNotes({ needs_target: true }), [api.NEEDS_TARGET_NOTE]);
  assert.ok(api.NEEDS_TARGET_NOTE.startsWith("Needs target after import"));
});

test("other items keep their notes unchanged", () => {
  assert.deepEqual(api.planItemNotes({ notes: ["a"] }), ["a"]);
  assert.deepEqual(api.planItemNotes({}), []);
  assert.deepEqual(api.planItemNotes({ needs_target: false }), []);
});
