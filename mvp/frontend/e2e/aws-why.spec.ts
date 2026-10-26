import { expect, test } from "@playwright/test";

import { ALICE, report, seriousViolations, settle } from "./helpers";

// The AWS "Why?" side panel (issue #642). The seeded demo tenant has no AWS snapshot, so the two
// API calls are answered here with the shapes internal/api/aws_eval.go sends.
const ID = "a".repeat(64);
const STMT = {
  policy_id: "p-1234", policy_kind: "scp", source_arn: "arn:aws:organizations::111111111111:policy/o-x/service_control_policy/p-1234",
  version_id: "", statement_index: 0, sid: "DenyS3", span: { start_line: 3, start_col: 5, end_line: 9, end_col: 6 }, attachment_path: null, org_level: "ou-ab12",
};
const DECISION = {
  outcome: "deny", deny_kind: "explicit", residual: false, fidelity: "approximate",
  fidelity_reasons: [{ code: "VPCE_POLICY_UNKNOWN", detail: "the endpoint policy was not collected", outcome_sensitive: true }],
  steps: [
    { stage: "explicit_deny", result: "deny", statement: STMT, matched_on: { action: "s3:*" }, condition_trace: null, residual: null, note: "", decisive: true },
    { stage: "final", result: "deny", statement: null, matched_on: null, condition_trace: null, residual: null, note: "an explicit deny wins", decisive: false },
  ],
  decisive: [STMT],
  request: { principal_arn: "arn:aws:iam::111111111111:user/alice", action: "s3:GetObject", resource_arn: "arn:aws:s3:::b/k", mode: "concrete" },
  engine_version: "e1", catalog_version: "c1", snapshot_id: "f".repeat(64),
};

test.use({ storageState: ALICE, colorScheme: "light", reducedMotion: "reduce" });

test.beforeEach(async ({ page }) => {
  await page.route("**/api/aws/can?*", (r) => r.fulfill({ json: {
    decision: DECISION, explanation_id: ID, summary: "Denied by an SCP", narrative: "* explicit_deny deny\n", profile: "default",
    snapshot: { id: "f".repeat(64), taken_at: "2026-10-25T00:00:00Z" }, collection_gaps: [],
  } }));
  await page.route(`**/api/aws/explanations/${ID}`, (r) => r.fulfill({ json: { id: ID, decision: DECISION } }));
});

async function ask(page: import("@playwright/test").Page) {
  await page.goto("/insights/aws");
  await settle(page);
  await page.getByLabel("Principal ARN").fill("arn:aws:iam::111111111111:user/alice");
  await page.getByRole("button", { name: "Evaluate" }).click();
  await expect(page.getByText("APPROXIMATE").first()).toBeVisible();
  await expect(page.getByText("Profile: default")).toBeVisible();
}

test("the Why? panel shows the trace, passes axe, and keeps focus with the keyboard", async ({ page }) => {
  await ask(page);
  const why = page.getByRole("button", { name: /^Why\?/ });
  await why.focus();
  await page.keyboard.press("Enter");
  const panel = page.getByRole("dialog", { name: "Why this answer?" });
  await expect(panel.getByRole("heading", { name: "Evaluation, step by step" })).toBeVisible();
  await expect(panel.getByRole("listitem").filter({ hasText: /Explicit deny/ })).toContainText("DECISIVE");
  await expect(panel.getByText("scp p-1234, statement 1 (DenyS3), at ou-ab12, lines 3 to 9").first()).toBeVisible();
  const found = await seriousViolations(page, "/insights/aws?why");
  expect(found, report(found)).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(panel).toHaveCount(0);
  await expect(why).toBeFocused();
});

test("the Why? panel fits 360px without sideways scroll", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 740 });
  await ask(page);
  await page.getByRole("button", { name: /^Why\?/ }).click();
  const panel = page.getByRole("dialog", { name: "Why this answer?" });
  await expect(panel.getByRole("heading", { name: "Evaluation, step by step" })).toBeVisible();
  const over = await page.evaluate(() => {
    const p = document.querySelector(".panel-body")!;
    return [document.documentElement.scrollWidth - innerWidth, p.scrollWidth - p.clientWidth];
  });
  expect(over[0]).toBeLessThanOrEqual(0);
  expect(over[1]).toBeLessThanOrEqual(0);
});
