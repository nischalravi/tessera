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
  // pages that poll never go network-idle; wait a bounded time, then for skeletons to go
  await page.waitForLoadState("networkidle", { timeout: 5_000 }).catch(() => {});
  await page.locator(".skeleton, [aria-busy='true']").first().waitFor({ state: "detached", timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(150); // let entrance transitions finish (reduced motion makes them instant)
}

/** The setup project's saved session (e2e/auth.setup.ts). */
export const ALICE = "test-results/.auth/alice.json";
