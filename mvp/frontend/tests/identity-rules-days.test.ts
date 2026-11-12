// Dormancy days in Admin > Identity rules (people, service identities, AI agents), and the section's roadmap list.
// Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";
import { daysOk, parseDays } from "../src/features/admin/identityRulesDays.ts";
import { ADMIN_SECTIONS } from "../src/mocks/data.ts";

test("dormancy days are whole numbers within the bounds", () => {
  for (const [v, ok] of [["90", true], [" 1 ", true], ["3650", true], ["0", false], ["3651", false], ["-5", false], ["9.5", false], ["", false], ["abc", false]] as const) {
    assert.equal(daysOk(parseDays(v), 1, 3650), ok, v);
  }
});

test("identity rules no longer lists people dormancy as not yet built", () => {
  const s = ADMIN_SECTIONS.find((x) => x.id === "identity-rules");
  assert.ok(s);
  assert.deepEqual(s.will, []);
});
