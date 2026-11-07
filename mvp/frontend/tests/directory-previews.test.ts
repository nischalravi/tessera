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
