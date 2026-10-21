import { Page, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

/** WCAG 2.0/2.1/2.2 A and AA rules. */
export const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

/**
 * Sign in as one of the seeded dev IdP users, with a passkey (else password + OTP): the sign-in
 * page asks for the organization, lists its connections, and the dev IdP's page picks the user
 * and the authentication method.
 */
export async function signIn(page: Page, who = "Alice", tenant = "larkspur", path = "/") {
  await page.goto(path);
  await page.getByLabel("Organization").fill(tenant);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: /^Sign in with/ }).first().click();
  // the dev IdP's own page (a different origin): one fieldset per user
  await page.locator("fieldset", { hasText: who }).first().getByRole("button", { name: /^(Passkey|Password \+ OTP)/ }).first().click();
  await expect(page.locator("main h1").first()).toBeVisible({ timeout: 20_000 });
}

export interface Finding { route: string; id: string; impact: string; help: string; nodes: string[] }

/** Runs axe on the page and returns serious and critical violations. */
export async function seriousViolations(page: Page, route: string): Promise<Finding[]> {
  const res = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  return res.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => ({ route, id: v.id, impact: v.impact!, help: v.help, nodes: v.nodes.slice(0, 5).map((n) => n.target.join(" ")) }));
}

export function report(findings: Finding[]): string {
  if (process.env.A11Y_SUMMARY) {
    const by = new Map<string, Finding[]>();
    for (const f of findings) by.set(f.id, [...(by.get(f.id) ?? []), f]);
    return [...by].map(([id, fs]) => `${id} (${fs[0].impact}) ${fs[0].help}\n  ${fs.map((f) => `${f.route}: ${f.nodes.join(" | ")}`).join("\n  ")}`).join("\n");
  }
  return findings.map((f) => `${f.route}  [${f.impact}] ${f.id}: ${f.help}\n    ${f.nodes.join("\n    ")}`).join("\n");
}

/** Waits for a route to settle: its heading is shown and loading spinners are gone. */
export async function settle(page: Page) {
  await expect(page.locator("main h1").first()).toBeVisible({ timeout: 20_000 });
  // pages that poll never go network-idle, so that wait is only a hint; the settled state is
  // that every loading placeholder (.skeleton, .skel, aria-busy) is gone and animations are done
  await page.waitForLoadState("networkidle", { timeout: 5_000 }).catch(() => {});
  await expect(page.locator(".skeleton, .skel, [aria-busy='true']")).toHaveCount(0, { timeout: 20_000 });
  await page.evaluate(() => Promise.all(document.getAnimations().filter((a) => a.effect?.getTiming().iterations !== Infinity).map((a) => a.finished.catch(() => undefined))));
}

/** The setup project's saved session (e2e/auth.setup.ts). */
export const ALICE = "test-results/.auth/alice.json";
