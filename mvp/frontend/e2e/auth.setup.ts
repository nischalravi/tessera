import { test as setup } from "@playwright/test";
import { ALICE, signIn } from "./helpers";

// One dev sign-in per run, reused by the route checks (signing in per test
// would hit the /api/auth rate limit).


setup("sign in as Alice", async ({ page }) => {
  await signIn(page, "Alice");
  await page.context().storageState({ path: ALICE });
});
