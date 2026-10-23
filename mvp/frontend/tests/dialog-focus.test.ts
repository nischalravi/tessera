// Modal focus target (issue #533): where focus lands on open and after a dialog swaps to its success state.
import assert from "node:assert/strict";
import { test } from "node:test";

const { focusTarget } = await import("../src/components/overlay.ts");

test("focusTarget prefers autofocus, then first focusable, then the container", () => {
  const cases: [string, string | null, string[], string][] = [
    ["autofocus wins", "close", ["a", "b"], "close"],
    ["first focusable", null, ["a", "b"], "a"],
    ["container fallback", null, [], "dialog"],
  ];
  for (const [name, auto, items, want] of cases) assert.equal(focusTarget(auto, items, "dialog"), want, name);
});
