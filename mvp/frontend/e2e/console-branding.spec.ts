import { expect, test } from "@playwright/test";

import { ALICE, report, seriousViolations, settle } from "./helpers";

// Issue #611: what an admin saves under Admin > Branding & labels shows in the console at once, no reload.
test.use({ storageState: ALICE, reducedMotion: "reduce" });

for (const scheme of ["light", "dark"] as const) {
  test(`saving branding changes the top bar, the tab title and the button colour (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto("/admin/branding");
    await settle(page);
    const name = `Acme ${scheme}`;
    const colour = scheme === "light" ? "#0f6cbd" : "#5aa0f0"; // the light-theme blue is too close to the dark surface (see consoleBrandStyle)
    await page.getByLabel("Product name").fill(name);
    await page.getByLabel("Button colour picker").fill(colour);
    await page.getByRole("button", { name: "Save branding" }).click();
    await expect(page.getByText("Branding saved")).toBeVisible();
    await expect(page.locator(".topbar .brand-name")).toHaveText(name);
    await expect(page.getByRole("link", { name: `${name} home` })).toBeVisible();
    await expect(page).toHaveTitle(new RegExp(` · ${name}$`));
    const accent = await page.evaluate(() => document.documentElement.style.getPropertyValue("--accent"));
    expect(accent).toBe(colour);
    const found = await seriousViolations(page, `/admin/branding (${scheme})`);
    expect(found, report(found)).toEqual([]);
  });
}
