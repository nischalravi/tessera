import { expect, test } from "@playwright/test";

import { GALLERY_META } from "../src/features/admin/connections/gallery";
import { ALICE, report, seriousViolations, settle } from "./helpers";

// one tile per connector type: counted from the gallery's own metadata, so a new type does not break the spec
const TILES = Object.keys(GALLERY_META).length;
const META = Object.values(GALLERY_META);
// expected counts of the filters the search and chip test uses, derived from the same metadata
const OKTA = META.filter((m) => m.vendor === "okta").length;
const HR = META.filter((m) => m.capabilities.includes("HR source")).length;
const HR_DEMO = META.filter((m) => m.capabilities.includes("HR source") && m.category === "Demo / simulated").length;

// New connection, step 1: the app-gallery picker. A radiogroup of tiles (roving tabindex), filter chips, search.

test.use({ storageState: ALICE, reducedMotion: "reduce" });

for (const scheme of ["light", "dark"] as const) {
  test(`gallery has no serious WCAG violations (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto("/admin/connections/new");
    await settle(page);
    const found = await seriousViolations(page, `new-connection-${scheme}`);
    expect(found, report(found)).toEqual([]);
  });
}

test("tiles are one radio group: arrows move and select, Space selects, one tab stop", async ({ page }) => {
  await page.goto("/admin/connections/new");
  await settle(page);
  const group = page.getByRole("radiogroup", { name: "Connector type" });
  await expect(group.getByRole("radio")).toHaveCount(TILES);
  await expect(group.getByRole("radio", { name: "Active Directory (demo)" })).toBeChecked();
  await group.getByRole("radio", { name: "Active Directory (demo)" }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(group.getByRole("radio", { name: "Okta (demo)" })).toBeChecked();
  await expect(group.getByRole("radio", { name: "Okta (demo)" })).toBeFocused();
  await page.keyboard.press("End");
  // End and ArrowLeft by position, so adding a tile does not break the spec
  await expect(group.getByRole("radio").last()).toBeChecked();
  await page.keyboard.press("ArrowLeft");
  await expect(group.getByRole("radio").nth(TILES - 2)).toBeChecked();
  await page.keyboard.press("Space");
  await expect(group.getByRole("radio", { checked: true })).toHaveCount(1);
  expect(await group.locator('[role="radio"][tabindex="0"]').count()).toBe(1);
  // the focus ring is drawn
  const outline = await group.getByRole("radio", { checked: true }).evaluate((e) => getComputedStyle(e).outlineStyle);
  expect(outline).not.toBe("none");
});

test("search and chips narrow the tiles, and an empty result says so", async ({ page }) => {
  await page.goto("/admin/connections/new");
  await settle(page);
  const radios = page.getByRole("radiogroup", { name: "Connector type" }).getByRole("radio");
  await page.getByRole("searchbox", { name: "Search connector types" }).fill("okta");
  await expect(radios).toHaveCount(OKTA);
  await page.getByRole("searchbox", { name: "Search connector types" }).fill("");
  await page.getByRole("button", { name: "HR source" }).click();
  await expect(radios).toHaveCount(HR);
  await page.getByRole("button", { name: "Demo / simulated" }).click();
  await expect(radios).toHaveCount(HR_DEMO);
  await page.getByRole("searchbox", { name: "Search connector types" }).fill("zzz");
  await expect(page.getByRole("heading", { name: "No systems match" })).toBeVisible();
  await page.getByRole("button", { name: "Clear search and filters" }).click();
  await expect(radios).toHaveCount(TILES);
});
