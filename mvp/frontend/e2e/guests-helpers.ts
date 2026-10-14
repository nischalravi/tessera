import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { Browser, BrowserContext, Page, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

/** WCAG 2.0/2.1/2.2 A and AA rules. */
export const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

/** Is the stack up? Probed once; every spec skips when it is not. */
export async function stackIsUp(baseURL: string): Promise<boolean> {
  try {
    const r = await fetch(`${baseURL}/api/health`, { signal: AbortSignal.timeout(3000) });
    return r.ok;
  } catch {
    return false;
  }
}

/** Dev sign-in as one of the dev IdP users, with a passkey (phishing-resistant, so changes need no step-up). */
export async function signIn(page: Page, who: string, path = "/") {
  await page.goto(path);
  await page.waitForSelector("select");
  const sel = page.locator("select").first();
  const value = await sel.locator("option", { hasText: who }).first().getAttribute("value");
  await sel.selectOption(value!);
  await page.locator('input[name="method"]').first().check();
  await page.locator('button[type="submit"]').click();
  await expect(page.locator("main h1").first()).toBeVisible({ timeout: 20_000 });
}

export async function signedInContext(browser: Browser, who: string): Promise<{ ctx: BrowserContext; page: Page }> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await signIn(page, who);
  return { ctx, page };
}

/**
 * The dev mail sink appends every email to var/dev-mail.jsonl next to the database file (nothing is sent in
 * development). GUESTS_DEV_MAIL names that file; by default it is next to GUESTS_DB, which is
 * /tmp/guests-e2e.db unless you started the stack with another TESSERA_DB.
 */
export const devMailPath = () =>
  process.env.GUESTS_DEV_MAIL ?? join(dirname(process.env.GUESTS_DB ?? "/tmp/guests-e2e.db"), "var", "dev-mail.jsonl");

/** The body of the newest email to `to` whose subject matches, recorded at or after `after` (ms). Polls: the outbox dispatches within a second or two. */
export async function mailTo(to: string, subject: RegExp, after = 0): Promise<string> {
  for (let i = 0; i < 40; i++) {
    if (existsSync(devMailPath())) {
      const lines = readFileSync(devMailPath(), "utf8").split("\n").filter(Boolean).reverse();
      for (const l of lines) {
        const m = JSON.parse(l) as { at: string; to: string; subject: string; body: string };
        if (m.to === to && subject.test(m.subject) && Date.parse(m.at) >= after - 1000) return m.body;
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`no email to ${to} matching ${subject} in ${devMailPath()}`);
}

export interface Finding { route: string; id: string; impact: string; help: string; nodes: string[] }

/**
 * axe on the page: serious and critical violations only. `known` names rule ids that are already fixed on
 * another branch and are skipped for that route until it merges (see the inbox in guests.spec.ts).
 */
export async function seriousViolations(page: Page, route: string, known: string[] = []): Promise<Finding[]> {
  const res = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  return res.violations
    .filter((v) => (v.impact === "serious" || v.impact === "critical") && !known.includes(v.id))
    .map((v) => ({ route, id: v.id, impact: v.impact!, help: v.help, nodes: v.nodes.slice(0, 5).map((n) => n.target.join(" ")) }));
}

export const describe = (fs: Finding[]) => fs.map((f) => `${f.route} [${f.impact}] ${f.id}: ${f.help}\n    ${f.nodes.join("\n    ")}`).join("\n");

/** Waits for a route to settle: its heading is shown and loading placeholders are gone. */
export async function settle(page: Page) {
  await expect(page.locator("main h1").first()).toBeVisible({ timeout: 20_000 });
  await page.waitForLoadState("networkidle", { timeout: 5_000 }).catch(() => {});
  await page.locator(".skeleton, [aria-busy='true']").first().waitFor({ state: "detached", timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(150);
}

export const dayFromNow = (n: number) => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);
