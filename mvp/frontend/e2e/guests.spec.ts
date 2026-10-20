import { Browser, BrowserContext, Page, expect, test } from "@playwright/test";
import { dayFromNow, describe, mailTo, seriousViolations, settle, signedInContext, stackIsUp } from "./guests-helpers";

/**
 * Guest UI flows (issue #76, design §9.4 and §11 GU-13) against a running stack (see
 * playwright.guests.config.ts). The flows share one contractor and run in order:
 *   1 the sponsor invites a contractor
 *   2 the contractor claims: confirms the email, then identity verification (IAL 1); a visitor goes on
 *     through "existing account", terms and the sign-in
 *   3 the sponsor renews
 *   4 the sponsor leaves and the transfer task appears in the Inbox
 * and the screens are checked with axe (WCAG 2.2 AA, serious and critical).
 * Pat (policy admin) is the sponsor, and also the person who leaves (policy admins may run a leaver plan). The emails are read from the dev
 * mail sink file (see devMailPath in guests-helpers.ts).
 */
test.describe.configure({ mode: "serial" });

const stamp = Date.now().toString(36);
const guest = { given: "Casey", family: `Claim${stamp}`, email: `casey.${stamp}@contractor.example`, purpose: `Payments audit ${stamp}` };
let up = false;

test.beforeAll(async ({ baseURL }) => {
  up = await stackIsUp(baseURL!);
});
test.beforeEach(() => {
  test.skip(!up, "no stack on GUESTS_UI_PORT: start one as described in playwright.guests.config.ts");
});

interface Person { given: string; family: string; email: string; purpose: string }
const visitor: Person = { given: "Vera", family: `Visit${stamp}`, email: `vera.${stamp}@visitor.example`, purpose: `Guest lecture ${stamp}` };

const emailRe = (e: string) => new RegExp(e.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));

/** Opens a guest's side panel from the list (the name, not the row's checkbox). */
const openRow = (page: Page, who: Person) => page.getByRole("row", { name: emailRe(who.email) }).locator(".name-link").click();

/** Pat invites someone from Access → Guests I sponsor. */
async function invite(browser: Browser, who: Person, population: "contractor" | "visitor", days: number) {
  const { ctx, page } = await signedInContext(browser, "Pat");
  await page.goto("/access/guests");
  await settle(page);
  await page.getByRole("button", { name: "Invite guest" }).first().click();
  const drawer = page.getByRole("dialog", { name: "Invite a guest" });
  await expect(drawer).toBeVisible();
  await drawer.getByLabel("Population").selectOption(population);
  await drawer.getByLabel("Given name").fill(who.given);
  await drawer.getByLabel("Family name").fill(who.family);
  await drawer.getByLabel("Email").fill(who.email);
  await drawer.getByLabel(/^Ends/).fill(dayFromNow(days));
  await drawer.getByLabel("Purpose").fill(who.purpose);
  await drawer.getByRole("button", { name: "Invite", exact: true }).click();
  await expect(page.getByText(`Invited ${who.given} ${who.family}`)).toBeVisible();
  // the row shows with its state, and its panel says the invitation went out
  await page.getByRole("button", { name: "Refresh" }).click();
  await openRow(page, who);
  await expect(page.getByText("Sent", { exact: true })).toBeVisible();
  await ctx.close();
}

/** The guest opens the emailed link and confirms the address with the emailed code. */
async function openAndVerify(browser: Browser, who: Person): Promise<{ ctx: BrowserContext; page: Page }> {
  const invitation = await mailTo(who.email, /invited/i);
  const m = /\/claim#t=([A-Za-z0-9_-]{43})/.exec(invitation);
  expect(m, "the invitation email carries the claim link").not.toBeNull();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(`/claim#t=${m![1]}`);
  await expect(page.getByRole("heading", { level: 1 })).toContainText(`Hello ${who.given}`);
  // the token is gone from the address bar at once
  expect(page.url()).not.toContain("#t=");
  expect(await seriousViolations(page, "/claim (verify contact)")).toEqual([]);

  const sent = Date.now();
  await page.getByRole("button", { name: "Send me a code" }).click();
  await expect(page.getByLabel("Six-digit code")).toBeFocused();
  const code = /\b(\d{6})\b/.exec(await mailTo(who.email, /code|confirm/i, sent))?.[1];
  expect(code, "the confirmation email carries a six-digit code").toBeTruthy();
  // a wrong code is announced
  await page.getByLabel("Six-digit code").fill(code === "000000" ? "111111" : "000000");
  await page.getByRole("button", { name: "Check the code" }).click();
  await expect(page.getByRole("alert")).toContainText(/did not work/, { timeout: 15_000 });
  await page.getByLabel("Six-digit code").fill(code!);
  await page.getByRole("button", { name: "Check the code" }).click();
  return { ctx, page };
}

test("1 the sponsor invites a contractor", async ({ browser }) => {
  await invite(browser, guest, "contractor", 20);
});

test("2 the contractor confirms the email and is taken to identity verification (IAL 1)", async ({ browser }) => {
  const { ctx, page } = await openAndVerify(browser, guest);
  const h1 = page.getByRole("heading", { level: 1 });
  await expect(h1).toContainText("Your identity needs to be verified");
  await expect(h1).toBeFocused();
  await expect(page.getByRole("heading", { level: 2, name: "Visit a proofing agent" })).toBeVisible();
  expect(await seriousViolations(page, "/claim (verify identity)")).toEqual([]);
  // Completing IAL 1 needs an identity-verification provider (GU-7), which the local stack does not have:
  // the claim is meant to wait here, with the invitation still open.
  await ctx.close();
});

test("2b a visitor claims: existing-account question, terms, sign-in", async ({ browser }) => {
  await invite(browser, visitor, "visitor", 7);
  const { ctx, page } = await openAndVerify(browser, visitor);
  const h1 = page.getByRole("heading", { level: 1 });
  // "do you already have an account?" is asked of everyone
  await expect(h1).toContainText("already have an account");
  await expect(h1).toBeFocused();
  expect(await seriousViolations(page, "/claim (existing account)")).toEqual([]);
  await page.getByLabel("No, I do not").check();
  await page.getByRole("button", { name: "Continue" }).click();

  // terms, when the tenant has published some, then the sign-in
  await expect(h1).toContainText(/Before you sign in|Choose how you sign in/);
  if (/Before you sign in/.test((await h1.textContent()) ?? "")) {
    expect(await seriousViolations(page, "/claim (terms)")).toEqual([]);
    for (const box of await page.getByRole("checkbox", { name: /I have read and accept/ }).all()) await box.check();
    await page.getByRole("button", { name: /Accept and continue|Continue/ }).click();
    await expect(h1).toContainText("Choose how you sign in");
  }
  expect(await seriousViolations(page, "/claim (credential)")).toEqual([]);
  await page.getByRole("button", { name: "Continue to sign-in" }).click();
  // The sign-in goes to the credential authority. With none configured (the production default) the page says
  // the organization will finish it and keeps the invitation open; with the dev IdP it leaves for the IdP.
  const pending = page.getByText(/organization will finish setting up your sign-in/);
  const left = page.waitForURL((u) => !u.pathname.startsWith("/claim"), { timeout: 10_000 }).then(() => "authority");
  const outcome = await Promise.race([left, pending.waitFor({ timeout: 10_000 }).then(() => "pending")]);
  expect(["authority", "pending"]).toContain(outcome);
  await ctx.close();
});

test("3 the sponsor renews", async ({ browser }) => {
  const { ctx, page } = await signedInContext(browser, "Pat");
  await page.goto("/access/guests");
  await settle(page);
  await openRow(page, guest);
  await page.getByRole("button", { name: "Renew" }).click();
  const drawer = page.getByRole("dialog", { name: /Renew the sponsorship/ });
  await drawer.getByLabel(/New end date/).fill(dayFromNow(24));
  await drawer.getByLabel("Fresh justification").fill("Audit extended by a week");
  await drawer.getByRole("button", { name: "Renew", exact: true }).click();
  await expect(page.getByText(`Renewed the sponsorship of ${guest.given} ${guest.family}`)).toBeVisible();
  await ctx.close();
});

test("4 the sponsor leaves and the transfer task appears in the Inbox", async ({ browser }) => {
  // Pat holds the permissions to record and run a leaver plan, and is the sponsor who leaves
  const admin = await signedInContext(browser, "Pat");
  // HR records Pat as a leaver: Governance → Lifecycle
  await admin.page.goto("/governance/lifecycle");
  await settle(admin.page);
  // the sponsor's name as the invitation email gave it ("<name> has invited you ...")
  const sponsor = /^(.+?) has invited you/m.exec(await mailTo(guest.email, /invited/i))?.[1];
  expect(sponsor, "the invitation names the sponsor").toBeTruthy();
  await admin.page.getByRole("group", { name: "Event type" }).getByRole("button", { name: "Leaver" }).click();
  const employee = admin.page.getByLabel("Employee");
  await employee.selectOption(await employee.locator("option", { hasText: sponsor! }).first().getAttribute("value"));
  await admin.page.getByRole("button", { name: "Create event and build plan" }).click();
  // the plan for the person just recorded, not the first pending leaver the page shows by default
  await expect(admin.page.getByRole("heading", { name: `Leaver: ${sponsor}` })).toBeVisible();
  await admin.page.getByRole("button", { name: /Execute plan/ }).click();
  await admin.page.getByRole("alertdialog").getByRole("button", { name: "Execute plan" }).click();
  await expect(admin.page.getByText(/plan executed/i)).toBeVisible();
  await admin.ctx.close(); // executing the plan ends the leaver's own sessions

  // the guest's sponsorship now waits for someone to take it over: it is in the Inbox as a guest task (seen by a second admin)
  const other = await signedInContext(browser, "Ivan");
  await other.page.goto("/inbox?filter=guest");
  await settle(other.page);
  const row = other.page.getByRole("listitem").filter({ hasText: new RegExp(`Take over sponsorship: ${guest.given} ${guest.family}`) });
  await expect(row).toBeVisible();
  await other.ctx.close();
});

/**
 * Findings in lists that predate this work and are fixed by the accessibility and mobile PRs (#173, #174), which
 * are not in this branch: the inbox and HRIS lists nest controls inside options, the inbox's filter chip counts and
 * checkboxes and the HRIS feed's links are too small or low contrast. Drop these skips when those PRs merge.
 */
const KNOWN_ELSEWHERE: [string, string[]][] = [
  ["/inbox", ["nested-interactive", "color-contrast", "target-size"]],
  ["/governance/lifecycle", ["nested-interactive", "target-size"]],
];

test("the guest screens have no serious accessibility violations", async ({ browser }) => {
  const { ctx, page } = await signedInContext(browser, "Ivan"); // Pat left in test 4
  const routes = ["/access/guests", "/access/guests?tab=registrations", "/inbox?filter=guest", "/governance/guest-lifecycle", "/governance/lifecycle", "/governance/terms", "/admin/guests", "/directory/identity-matches"];
  const found = [];
  for (const r of routes) {
    await page.goto(r);
    await settle(page);
    found.push(...(await seriousViolations(page, r, KNOWN_ELSEWHERE.find(([prefix]) => r.startsWith(prefix))?.[1] ?? [])));
  }
  // the guest's person page, with its guest sections
  await page.goto("/directory/people");
  await settle(page);
  await page.getByPlaceholder("Search name, email, team…").fill(guest.family);
  await page.getByRole("row", { name: emailRe(guest.email) }).locator(".name-link").click();
  await page.getByRole("link", { name: /Open full page/ }).click();
  const affiliations = page.getByRole("tab", { name: /Affiliations/ });
  await expect(async () => { // the page may still be loading its profile when the tab is first clicked
    await affiliations.click();
    await expect(page.getByRole("heading", { name: "Lifecycle and assurance" })).toBeVisible({ timeout: 2_000 });
  }).toPass({ timeout: 20_000 });
  for (const h of ["Lifecycle and assurance", "Affiliations", "Identifiers", "Sponsorships", "Source records", "Terms accepted", "Match and merge history"]) {
    await expect(page.getByRole("heading", { name: h })).toBeVisible();
  }
  found.push(...(await seriousViolations(page, "person page (guest sections)")));
  expect(found, describe(found)).toEqual([]);
  await ctx.close();
  // public pages: no sign-in
  const pub = await browser.newContext();
  const p = await pub.newPage();
  const publicFound = [];
  for (const r of ["/register", "/renew", "/claim"]) {
    await p.goto(r);
    await expect(p.getByRole("heading", { level: 1 })).toBeVisible();
    publicFound.push(...(await seriousViolations(p, r)));
  }
  expect(publicFound, describe(publicFound)).toEqual([]);
  await pub.close();
});

test("the public pages work at 360px", async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 360, height: 740 } });
  const page = await ctx.newPage();
  for (const r of ["/register", "/renew", "/claim"]) {
    await page.goto(r);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `${r} scrolls sideways`).toBeLessThanOrEqual(0);
  }
  await ctx.close();
});

