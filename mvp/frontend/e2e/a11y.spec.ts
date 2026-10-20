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
  for (const route of [ids[0] && `/directory/identities/${ids[0].id}`, conn && `/admin/connections/${conn.id}`].filter(Boolean) as string[]) {
    await page.goto(route);
    await settle(page);
    all.push(...(await seriousViolations(page, route)));
  }
  expect(all, report(all)).toEqual([]);
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
