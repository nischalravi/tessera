import { expect, test } from "@playwright/test";

import { ALICE, Finding, report, seriousViolations, settle } from "./helpers";

// Every route of src/app/App.tsx (redirect-only routes excluded). Routes with
// parameters get real ids from the API after sign-in.
const STATIC_ROUTES = [
  "/", "/inbox", "/access/request", "/access/mine", "/access/requests", "/access/jit",
  "/directory/people", "/directory/machine", "/directory/accounts", "/directory/roles", "/directory/entitlements",
  "/directory/apps", "/directory/orgs", "/directory/groups",
  "/insights/risk", "/insights/graph", "/insights/least-privilege", "/insights/sod", "/insights/deployment-health",
  "/governance/policies", "/governance/reviews", "/governance/lifecycle", "/governance/workflows",
  "/admin", "/admin/connections", "/admin/connections/new", "/admin/jobs", "/admin/audit", "/admin/authentication",
  // issue #420: OAuth apps, the settings pages, preferences and service-account requests
  "/security/oauth-apps", "/admin/request-settings", "/admin/step-up", "/admin/sod-page", "/governance/review-types",
  "/account/preferences", "/access/request/service-account",
];

test.use({ colorScheme: "light", reducedMotion: "reduce" });

test.describe("signed out", () => {
  test.use({ storageState: { cookies: [], origins: [] } });
  test("sign-in page has no serious or critical WCAG 2.2 AA violations", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Organization").waitFor();
  const found = await seriousViolations(page, "sign-in");
  expect(found, report(found)).toEqual([]);
  });
});

test.describe("signed in", () => {
test.use({ storageState: ALICE });

for (const route of STATIC_ROUTES) {
  test(`${route} has no serious or critical WCAG 2.2 AA violations`, async ({ page }) => {
    await page.goto(route);
    await settle(page);
    const found = await seriousViolations(page, route);
    expect(found, report(found)).toEqual([]);
  });
}

test("detail pages have no serious or critical WCAG 2.2 AA violations", async ({ page }) => {
  await page.goto("/");
  const api = async (p: string) => page.evaluate(async (u) => (await fetch(u)).json(), p);
  const ids: any[] = await api("/api/identities");
  const conns: any[] = await api("/api/connections");
  const conn = conns.find((c) => !c.legacy && c.id);
  const all: Finding[] = [];
  for (const route of [ids[0] && `/directory/identities/${ids[0].id}`, conn && `/admin/connections/${conn.id}`, conn && `/admin/connections/${conn.id}?step=guard`].filter(Boolean) as string[]) {
    await page.goto(route);
    await settle(page);
    all.push(...(await seriousViolations(page, route)));
  }
  expect(all, report(all)).toEqual([]);
});

test("the deletion guard is step 7 of a connection, before review and activate, laid out beside the stepper", async ({ page }) => {
  await page.goto("/");
  const conns: any[] = await page.evaluate(async () => (await fetch("/api/connections")).json());
  const conn = conns.find((c) => !c.legacy && c.id && !c.retired_at);
  test.skip(!conn, "no connection seeded");
  await page.goto(`/admin/connections/${conn.id}?step=guard`);
  await settle(page);
  const form = page.getByRole("form", { name: /Deletion guard for/ });
  await expect(form.getByRole("heading", { name: "7. Deletion guard" })).toBeVisible();
  // the guard takes the step column, not the stepper's 220px one
  const box = await form.boundingBox();
  expect(box!.width).toBeGreaterThan(400);
  await expect(page.getByRole("list", { name: "Steps" }).getByText("Review and activate")).toBeVisible();
  await page.screenshot({ path: "test-results/deletion-guard-step.png", fullPage: true });
});

// The dev stack serves stateful fakes of the four providers (issue #417): sync, then check the
// page with apps and grants on it, the filled-in state the empty-state route check above cannot see.
test("OAuth apps with a synced inventory has no serious or critical WCAG 2.2 AA violations", async ({ page }) => {
  await page.goto("/security/oauth-apps");
  await settle(page);
  await page.getByRole("button", { name: "Sync now" }).click();
  await expect(page.getByText("Inventory refreshed").first()).toBeVisible({ timeout: 30_000 });
  await settle(page);
  const found = await seriousViolations(page, "/security/oauth-apps (synced)");
  expect(found, report(found)).toEqual([]);
});

test.describe("dark theme", () => {
  test.use({ colorScheme: "dark" });
  test("main pages have no serious or critical WCAG 2.2 AA violations", async ({ page }) => {
    const all: Finding[] = [];
    for (const route of ["/", "/directory/people", "/access/request", "/admin/connections", "/inbox"]) {
      await page.goto(route);
      await settle(page);
      all.push(...(await seriousViolations(page, `${route} (dark)`)));
    }
    expect(all, report(all)).toEqual([]);
  });
});
});
