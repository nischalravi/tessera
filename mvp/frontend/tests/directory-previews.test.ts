import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// "Part of these roles" reads GET /roles (real business roles), so it must not claim to be a Preview.
test("entitlement panel roles section is backed by the roles API, not a Preview", () => {
  const src = readFileSync(new URL("../src/features/directory/Panels.tsx", import.meta.url), "utf8");
  assert.match(src, /useApi<RolesView>\("\/roles"\)/);
  assert.doesNotMatch(src, /Part of these roles <PreviewBadge/);
  assert.doesNotMatch(src, /\bPreviewBadge\b/);
});

// Registering a machine identity files a service-account request through the real API (issue #915); no Preview mock is left.
test("machine identity registration uses the service-account request flow, not a preview mock", () => {
  const read = (p: string) => readFileSync(new URL(p, import.meta.url), "utf8");
  const lists = read("../src/features/directory/Lists.tsx");
  assert.match(lists, /REGISTER_PATH = "\/access\/request\/service-account"/);
  assert.doesNotMatch(lists, /PreviewFormDrawer/);
  const shared = read("../src/features/directory/shared.tsx");
  assert.doesNotMatch(shared, /PreviewFormDrawer|mockObjects|PreviewBadge|\(preview\)/);
  assert.doesNotMatch(read("../src/mocks/index.ts"), /mockObjects/);
});
