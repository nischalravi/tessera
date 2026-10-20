// The left rail shows only what the session may open (issue #310). Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";

const { RAIL, visibleRail } = await import("../src/app/nav.ts");
const { inactiveRoleHint } = await import("../src/app/roles.ts");

const ids = (can: (p: string) => boolean) => visibleRail(can).flatMap((g) => g.items.map((i) => i.id));

test("Guests I sponsor needs guests.sponsor", () => {
  assert.equal(RAIL.flatMap((g) => g.items).find((i) => i.id === "guests")?.perm, "guests.sponsor");
  assert.equal(ids(() => true).includes("guests"), true);
  assert.equal(ids((p) => p !== "guests.sponsor").includes("guests"), false);
});

test("items without a permission stay for everyone; no group is left empty", () => {
  const none = visibleRail(() => false);
  assert.ok(none.length > 0);
  assert.ok(none.every((g) => g.items.length > 0));
  assert.equal(ids(() => false).includes("request"), true);
});

test("an inactive role explains what to do, by reason", () => {
  assert.match(inactiveRoleHint("viewer", "multi_factor_authentication_required"), /one-time code/);
  assert.match(inactiveRoleHint("tenant_admin", "phishing_resistant_authentication_required"), /passkey/);
  assert.doesNotMatch(inactiveRoleHint("viewer", "multi_factor_authentication_required"), /passkey to use it/);
});
