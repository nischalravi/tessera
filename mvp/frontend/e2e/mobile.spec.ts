import { Page, TestInfo, expect, test } from "@playwright/test";
import { ALICE, settle } from "./helpers";

// Mobile layout (issue #174): at 360, 400 and 768 CSS px the sign-in,
// rate-limited, step-up, inbox and request pages need no horizontal scroll
// (WCAG 1.4.10), every control is at least 44 x 44 px, the rail is a menu and
// side panels are full-screen sheets. Each case attaches a full-page screenshot
// to the report (not a pixel baseline: fonts differ between machines).

const WIDTHS = [360, 400, 768];
test.use({ reducedMotion: "reduce" });

const noHorizontalScroll = () => document.documentElement.scrollWidth <= window.innerWidth + 1;

/** Visible controls smaller than 44 x 44 px (a checkbox or radio counts its label's box). */
async function smallTargets(page: Page, within = "body") {
  return page.evaluate((sel) => {
    const root = document.querySelector(sel) ?? document.body;
    const out: string[] = [];
    const els = root.querySelectorAll<HTMLElement>('button, a.btn, input:not([type="hidden"]), select, textarea, [role="button"], [role="tab"], .fchip');
    for (const el of els) {
      if (el.closest("[inert], [aria-hidden='true'], .rail") && !el.closest(".shell.drawer-open .rail")) continue;
      const s = getComputedStyle(el);
      if (s.visibility === "hidden" || s.display === "none") continue;
      const target = (el as HTMLInputElement).type === "checkbox" || (el as HTMLInputElement).type === "radio" ? el.closest("label") ?? el : el;
      const r = target.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue;
      if (r.bottom < 0 || r.top > window.innerHeight * 3) continue; // first screens only
      if (r.width < 43.5 || r.height < 43.5) {
        const name = (el.getAttribute("aria-label") || el.innerText || (el as HTMLInputElement).placeholder || el.tagName).trim().slice(0, 30);
        out.push(`${el.tagName.toLowerCase()} "${name}" ${Math.round(r.width)}x${Math.round(r.height)}`);
      }
    }
    return [...new Set(out)];
  }, within);
}

async function shoot(page: Page, info: TestInfo, name: string) {
  await info.attach(name, { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });
}

async function checkPage(page: Page, info: TestInfo, name: string, within = "body") {
  await shoot(page, info, name);
  expect(await page.evaluate(noHorizontalScroll), `${name}: horizontal scroll`).toBe(true);
  expect(await smallTargets(page, within), `${name}: targets under 44 px`).toEqual([]);
}

for (const width of WIDTHS) {
  test.describe(`${width} px`, () => {
    test.use({ viewport: { width, height: 800 } });

    test.describe("signed out", () => {
      test.use({ storageState: { cookies: [], origins: [] } });

      test("sign-in page", async ({ page }, info) => {
        await page.goto("/");
        await page.getByLabel("Organization").waitFor();
        await checkPage(page, info, `sign-in-${width}`);
        // the organization's connections, once named
        await page.getByLabel("Organization").fill("larkspur");
        await page.getByRole("button", { name: "Continue" }).click();
        await expect(page.getByRole("button", { name: /^Sign in with/ }).first()).toBeVisible();
        await checkPage(page, info, `sign-in-connections-${width}`);
      });

      test("rate-limited sign-in explains the wait and offers a retry", async ({ page }, info) => {
        await page.route("**/api/auth/session", (r) => r.fulfill({ status: 429, headers: { "Retry-After": "2" }, contentType: "application/json", body: '{"error":"rate_limited"}' }));
        await page.goto("/");
        await expect(page.getByRole("heading", { name: "Too many sign-in attempts" })).toBeVisible();
        await expect(page.getByRole("status")).toContainText(/Trying again/);
        await checkPage(page, info, `rate-limited-${width}`);
        await page.unroute("**/api/auth/session");
        await page.getByRole("button", { name: "Try again now" }).click();
        await expect(page.getByLabel("Organization")).toBeVisible({ timeout: 10_000 });
      });
    });

    test.describe("signed in", () => {
      test.use({ storageState: ALICE });

      for (const [name, path] of [["inbox", "/inbox"], ["request-access", "/access/request"], ["my-requests", "/access/requests"], ["home", "/"]] as const) {
        test(`${name}`, async ({ page }, info) => {
          await page.goto(path);
          await settle(page);
          await checkPage(page, info, `${name}-${width}`, "main");
        });
      }

      test("step-up notice is a sheet with full-size buttons", async ({ page }, info) => {
        await page.goto("/inbox");
        await settle(page);
        await page.evaluate(() => window.dispatchEvent(new CustomEvent("tessera:step-up", { detail: { error: "step_up_required", max_age: 300 } })));
        const sheet = page.getByRole("alertdialog", { name: "Confirm it's you" });
        await expect(sheet).toBeVisible();
        await expect(page.getByRole("button", { name: "Continue" })).toBeFocused();
        const box = (await sheet.boundingBox())!;
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width).toBeLessThanOrEqual(width + 1);
        await checkPage(page, info, `step-up-${width}`, ".stepup");
      });

      test("the rail is a menu", async ({ page }, info) => {
        await page.goto("/");
        await settle(page);
        const toggle = page.getByRole("button", { name: "Open navigation" });
        await expect(toggle).toBeVisible();
        await expect(page.locator("#rail")).toBeHidden();
        await toggle.click();
        await expect(page.locator("#rail")).toBeVisible();
        await expect(page.getByRole("button", { name: "Close navigation" })).toHaveAttribute("aria-expanded", "true");
        await shoot(page, info, `menu-${width}`);
        expect(await smallTargets(page, "#rail"), "rail items under 44 px").toEqual([]);
        await page.locator("#rail a.rail-item", { hasText: "Inbox" }).click();
        await expect(page).toHaveURL(/\/inbox/);
        await expect(page.locator("#rail")).toBeHidden();
      });

      test("side panels are full-screen sheets", async ({ page }, info) => {
        await page.goto("/directory/people");
        await settle(page);
        await page.locator("tbody tr.click").first().click();
        const panel = page.locator("aside.panel[role='dialog']");
        await expect(panel).toBeVisible();
        await panel.evaluate((el) => Promise.all(el.getAnimations().map((a) => a.finished)));
        const box = (await panel.boundingBox())!;
        expect(box.x, `panel starts at the left edge: ${JSON.stringify(box)}`).toBeLessThanOrEqual(2);
        expect(box.y, "panel covers the top bar").toBeLessThanOrEqual(2);
        expect(box.width).toBeGreaterThanOrEqual(width - 1);
        await checkPage(page, info, `panel-${width}`, "aside.panel");
        await page.keyboard.press("Escape");
        await expect(panel).toBeHidden();
      });
    });
  });
}
