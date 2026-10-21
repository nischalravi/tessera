import { expect, test } from "@playwright/test";
import { ALICE, settle } from "./helpers";

// WCAG 2.2 AA checks axe does not make (issue #173): reflow at 320 CSS px
// (1.4.10, also 400 % zoom of a 1280 px window), text spacing (1.4.12) and
// focus not obscured by the sticky top bar (2.4.11).
test.use({ storageState: ALICE, reducedMotion: "reduce" });

const ROUTES = [
  "/", "/inbox", "/access/request", "/directory/people", "/insights/risk", "/governance/reviews", "/admin/connections",
  // issue #420: the pages added since
  "/governance/workflows", "/security/oauth-apps", "/admin/request-settings", "/admin/step-up", "/admin/sod-page",
  "/governance/review-types", "/account/preferences", "/access/request/service-account",
];

const noHorizontalScroll = () => document.documentElement.scrollWidth <= window.innerWidth + 1;

test.describe("reflow at 320 CSS px", () => {
  test.use({ viewport: { width: 320, height: 800 } });
  for (const route of ROUTES) {
    test(`${route} needs no horizontal scrolling`, async ({ page }) => {
      await page.goto(route);
      await settle(page);
      expect(await page.evaluate(noHorizontalScroll), `${route} scrolls sideways at 320 px`).toBe(true);
    });
  }
});

test("text spacing overrides do not break the layout", async ({ page }) => {
  for (const route of ROUTES) {
    await page.goto(route);
    await settle(page);
    await page.addStyleTag({ content: "* { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; } p { margin-bottom: 2em !important; }" });
    expect(await page.evaluate(noHorizontalScroll), `${route} scrolls sideways with text spacing`).toBe(true);
  }
});

test("a focused element is never hidden under the sticky top bar", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 600 });
  for (const route of ["/directory/people", "/governance/reviews"]) {
    await page.goto(route);
    await settle(page);
    const forward = Array.from({ length: 40 }, () => "Tab");
    const back = Array.from({ length: 25 }, () => "Shift+Tab");
    for (const key of [...forward, ...back]) {
      await page.keyboard.press(key);
      // hidden: what is drawn at the element's centre is the top bar, not the element
      const hidden = await page.evaluate(() => {
        const a = document.activeElement as HTMLElement | null;
        if (!a || a === document.body || a.closest(".topbar")) return "";
        const r = a.getBoundingClientRect();
        const top = document.elementFromPoint(r.left + r.width / 2, r.top + Math.min(r.height / 2, 8));
        const covered = !!top && !a.contains(top) && !!top.closest(".topbar");
        return covered ? `${a.tagName}.${a.className} "${(a.innerText || a.getAttribute("aria-label") || "").slice(0, 40)}" top=${Math.round(r.top)}` : "";
      });
      expect(hidden, `${route}: focus hidden under the top bar after ${key}`).toBe("");
    }
  }
});
