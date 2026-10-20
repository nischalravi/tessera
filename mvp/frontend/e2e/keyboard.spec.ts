import { Page, expect, test } from "@playwright/test";

// Keyboard-only walkthrough of the main flows (issue #173): sign in,
// request access, approve, review. Only the keyboard is used once a page has
// loaded: Tab / Shift+Tab to move, Enter / Space / arrows to act, typing into
// fields. Every stop must show a visible focus indicator.

test.use({ reducedMotion: "reduce" });

/** Presses Tab until the focused element matches, at most max times. */
async function tabTo(page: Page, match: (el: { tag: string; name: string; type: string; role: string }) => boolean, max = 80) {
  for (let i = 0; i < max; i++) {
    await page.keyboard.press("Tab");
    const el = await focused(page);
    if (match(el)) {
      await expectFocusVisible(page);
      return el;
    }
  }
  throw new Error("focus never reached the target");
}

async function focused(page: Page) {
  return page.evaluate(() => {
    const a = document.activeElement as HTMLElement | null;
    const name = (a?.getAttribute("aria-label") ?? a?.innerText ?? (a as HTMLInputElement | null)?.value ?? "").trim();
    return { tag: a?.tagName.toLowerCase() ?? "", name, type: a?.getAttribute("type") ?? "", role: a?.getAttribute("role") ?? "" };
  });
}

/** The focused element draws an outline or a focus ring (box-shadow). */
async function expectFocusVisible(page: Page) {
  const ring = await page.evaluate(() => {
    const a = document.activeElement as HTMLElement;
    const s = getComputedStyle(a);
    return (s.outlineStyle !== "none" && parseFloat(s.outlineWidth) > 0) || (s.boxShadow !== "none" && s.boxShadow !== "");
  });
  expect(ring, "the focused element has no visible focus indicator").toBe(true);
}

async function toasts(page: Page) {
  return (await page.locator(".toast, [role='status'], [role='alert']").allInnerTexts()).join(" | ");
}

async function signInByKeyboard(page: Page, who: string) {
  await page.goto("/");
  // the organization field has focus on load: type it and submit
  await expect(page.getByLabel("Organization")).toBeFocused();
  await page.keyboard.type("larkspur");
  await page.keyboard.press("Enter");
  // the organization's sign-in connections
  await page.getByRole("button", { name: /^Sign in with/ }).first().waitFor();
  await tabTo(page, (e) => e.tag === "button" && /^sign in with/i.test(e.name));
  await page.keyboard.press("Enter");
  // the dev IdP's page: Tab to the user's strongest method (a passkey, else password + OTP)
  await page.waitForSelector("fieldset");
  for (let i = 0; ; i++) {
    if (i === 80) throw new Error("focus never reached the user's sign-in method button");
    await page.keyboard.press("Tab");
    const legend = await page.evaluate(() => document.activeElement?.closest("fieldset")?.querySelector("legend")?.textContent ?? "");
    const el = await focused(page);
    if (el.tag === "button" && /^(Passkey|Password \+ OTP)/.test(el.name) && legend.includes(who)) {
      await expectFocusVisible(page);
      await page.keyboard.press("Enter");
      break;
    }
  }
  await expect(page.locator("main h1").first()).toBeVisible({ timeout: 20_000 });
}

test("skip link is the first stop and moves focus to the content", async ({ page }) => {
  await signInByKeyboard(page, "Alice");
  await page.goto("/directory/people");
  await expect(page.locator("main h1").first()).toBeVisible();
  await page.keyboard.press("Tab");
  expect((await focused(page)).name).toMatch(/skip to content/i);
  await expectFocusVisible(page);
  await page.keyboard.press("Enter");
  expect(await page.evaluate(() => document.activeElement?.id)).toBe("main");
});

test("request access with the keyboard only", async ({ page }) => {
  await signInByKeyboard(page, "Olu");
  await page.goto("/access/request");
  await expect(page.locator("main h1").first()).toBeVisible();
  // the search box has focus on arrival
  await page.keyboard.type("read");
  await tabTo(page, (e) => e.tag === "button" && /^add /i.test(e.name));
  await page.keyboard.press("Enter");
  await tabTo(page, (e) => e.tag === "textarea");
  await page.keyboard.type("Quarterly report, ticket OPS-123");
  await tabTo(page, (e) => e.tag === "button" && /^submit/i.test(e.name));
  await page.keyboard.press("Enter");
  await expect(page.getByText(/Submitted \d+ request/)).toBeVisible({ timeout: 15_000 });
});

test("approve and review from the inbox with the keyboard only", async ({ page }) => {
  await signInByKeyboard(page, "Pat"); // policy admin: jit.decide and reviews.decide
  await page.goto("/inbox");
  await expect(page.locator("main h1").first()).toBeVisible();
  const rows = page.locator('[aria-label="Inbox items"] [role="listitem"]');
  await expect(rows.first()).toBeVisible({ timeout: 15_000 });
  // approve an approval: Tab to its Approve button and press Enter
  await tabTo(page, (e) => e.tag === "button" && /^approve/i.test(e.name) && e.role === "", 200);
  const rowId = await page.evaluate(() => document.activeElement?.closest('[role="listitem"]')?.id ?? "");
  expect(rowId).not.toBe("");
  await page.keyboard.press("Enter");
  await expect(page.locator(`[id="${rowId}"]`), await toasts(page)).toHaveCount(0, { timeout: 15_000 });

  // a review decision: the review filter, then Keep with the keyboard
  await page.goto("/inbox?filter=review");
  await expect(rows.first()).toBeVisible({ timeout: 15_000 });
  await tabTo(page, (e) => e.tag === "button" && /^keep/i.test(e.name), 200);
  const reviewId = await page.evaluate(() => document.activeElement?.closest('[role="listitem"]')?.id ?? "");
  await page.keyboard.press("Enter");
  // privileged access needs a reason: the dialog opens with focus in it
  const dialog = page.locator('[role="dialog"], [role="alertdialog"]');
  if (await dialog.waitFor({ timeout: 2_000 }).then(() => true, () => false)) {
    if (await dialog.locator("textarea, input").count()) await page.keyboard.type("On-call for payments");
    await tabTo(page, (e) => e.tag === "button" && /keep access/i.test(e.name), 10);
    await page.keyboard.press("Enter");
  }
  await expect(page.locator(`[id="${reviewId}"]`), await toasts(page)).toHaveCount(0, { timeout: 15_000 });
});

test("dialogs trap focus and Escape closes them", async ({ page }) => {
  await signInByKeyboard(page, "Alice");
  await page.goto("/directory/people");
  await expect(page.locator("main h1").first()).toBeVisible();
  // the command palette
  await page.keyboard.press("Control+k");
  const palette = page.locator('[role="dialog"]').first();
  await expect(palette).toBeVisible();
  for (let i = 0; i < 15; i++) {
    await page.keyboard.press("Tab");
    const inside = await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]'));
    expect(inside, "focus left the open dialog").toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(palette).toBeHidden();
});
