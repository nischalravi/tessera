// Directory "Reset password" opens the Help desk's verified reset flow (issue #915).
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";

test("the action opens the Help desk's New reset case dialog for the identity, with no mock", async () => {
  const src = readFileSync(new URL("../src/app/actions.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(src, /mockIdentityOps/);
  assert.match(src, /helpdeskResetHref\(i\.id\)/);
  assert.match(src, /\/helpdesk\?new=1&identity=\$\{identityId\}&kind=password/);
});
