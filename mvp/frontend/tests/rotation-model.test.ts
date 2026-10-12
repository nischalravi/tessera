// The pure helpers of the secret-rotation screens. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ADAPTER_FIELDS, ageText, bulkProgressText, evidenceLines, graceText, identityRotation, jobActions, planHeadline, rotatable, secretStatus, stateCounts, summarizePlan,
} from "../src/features/rotation/model.ts";

const job = (state: string) => ({ state }) as any;
const row = (over: Record<string, unknown> = {}) =>
  ({ secret_id: 1, name: "AKIA", system: "aws", kind: "access_key", account: "svc", owner: null, age_days: 10, max_age_days: 90, overdue: false, mode: "scheduled", action: "rotate", adapter: "sim", active_job: null, last_job: null, ...over }) as any;

test("a secret's status follows what it is doing, then how old it is", () => {
  assert.equal(secretStatus(row()), "ok");
  assert.equal(secretStatus(row({ overdue: true })), "overdue");
  assert.equal(secretStatus(row({ overdue: true, last_job: { state: "failed" } })), "failed");
  assert.equal(secretStatus(row({ overdue: true, active_job: { state: "handed_over" } })), "rotating");
  assert.equal(secretStatus(row({ action: "manual" })), "manual");
  assert.equal(secretStatus(row({ action: "blocked" })), "manual");
  assert.equal(secretStatus(row({ last_job: { state: "old_deleted" } })), "ok");
});

test("age and grace wording", () => {
  assert.equal(ageText({ age_days: 37, max_age_days: 90 }), "37 / 90 d");
  assert.equal(ageText({ age_days: 400, max_age_days: null }), "400 d (no max age)");
  assert.equal(graceText(0), "none");
  assert.equal(graceText(1), "1 h");
  assert.equal(graceText(24), "1 day");
  assert.equal(graceText(72), "3 days");
  assert.equal(graceText(30), "30 h");
});

test("a plan is summarised and only rotatable secrets are queued", () => {
  const items = [{ action: "rotate", secret_id: 1 }, { action: "rotate", secret_id: 2 }, { action: "manual", secret_id: 3 }, { action: "blocked", secret_id: 4 }, { action: "in_flight", secret_id: 5 }] as any[];
  assert.deepEqual(summarizePlan(items), { rotate: 2, manual: 1, blocked: 1, in_flight: 1 });
  assert.deepEqual(rotatable(items), [1, 2]);
  assert.equal(planHeadline(summarizePlan(items)), "2 will be rotated, 1 already rotating, 1 needs a manual rotation, 1 blocked");
  assert.equal(planHeadline(summarizePlan([])), "Nothing to rotate");
  assert.equal(planHeadline(summarizePlan([{ action: "manual" }, { action: "manual" }] as any[])), "2 need a manual rotation");
});

test("the recorded re-read is explained in sentences", () => {
  const base = { checked_at: "2026-10-12T09:00:00Z", verdict: "ok", evidence: "age_and_last_use", old_exists: true, old_active: false, old_created_at: "2026-06-04T00:00:00Z", old_age_days: 130, old_last_used_at: "2026-10-10T08:15:00Z", last_used_known: true, disabled_at: "2026-10-11T09:00:00Z" } as any;
  assert.deepEqual(evidenceLines(base), ["Key age: 130 days.", "Last use: 2026-10-10 08:15:00 UTC.", "The old credential is not in use."]);
  assert.match(evidenceLines({ ...base, old_last_used_at: null })[1], /never/);
  assert.match(evidenceLines({ ...base, last_used_known: false })[1], /does not report it/);
  const bad = evidenceLines({ ...base, verdict: "used_after_disable", detail: "a consumer still signs" });
  assert.match(bad[2], /used after the grace period/);
  assert.equal(bad[3], "a consumer still signs");
  assert.match(evidenceLines({ ...base, old_exists: false, old_age_days: null })[1], /already gone/);
  assert.equal(evidenceLines({ ...base, old_age_days: 1 })[0], "Key age: 1 day.");
});

test("which job actions are offered", () => {
  assert.deepEqual(jobActions(job("failed")), { retry: true, cancel: false });
  assert.deepEqual(jobActions(job("pending")), { retry: false, cancel: true });
  assert.deepEqual(jobActions(job("handed_over")), { retry: false, cancel: false });
  assert.deepEqual(jobActions(job("old_deleted")), { retry: false, cancel: false });
});

test("state counts and bulk progress", () => {
  const c = stateCounts([job("failed"), job("failed"), job("pending"), job("old_deleted")]);
  assert.equal(c.failed, 2);
  assert.equal(c.pending, 1);
  assert.equal(c.verified, 0);
  assert.equal(bulkProgressText({ old_deleted: 3, failed: 1, handed_over: 1 }, 5), "3 of 5 done · 1 running · 1 failed");
  assert.equal(bulkProgressText({ old_deleted: 2 }, 2), "2 of 2 done");
});

test("every adapter type the API offers has a form, and secrets are marked", () => {
  for (const t of ["aws_iam", "aws_secretsmanager", "vault", "github", "fake"]) assert.ok(ADAPTER_FIELDS[t], t);
  assert.ok(ADAPTER_FIELDS.vault.credential.every((f) => f.secret));
  assert.ok(ADAPTER_FIELDS.aws_iam.credential.find((f) => f.id === "secret_access_key")?.secret);
  assert.equal(ADAPTER_FIELDS.fake.credential.length, 0);
});

test("an identity shows the worst status among its secrets", () => {
  assert.equal(identityRotation([]), null);
  assert.deepEqual(identityRotation([row(), row()]), { key: "ok", count: 2 });
  assert.deepEqual(identityRotation([row(), row({ overdue: true })]), { key: "overdue", count: 1 });
  assert.deepEqual(identityRotation([row({ overdue: true }), row({ active_job: { state: "pending" } })]), { key: "rotating", count: 1 });
  assert.deepEqual(identityRotation([row({ active_job: { state: "pending" } }), row({ last_job: { state: "failed" } })]), { key: "failed", count: 1 });
  assert.deepEqual(identityRotation([row({ action: "manual" }), row({ action: "manual" }), row()]), { key: "manual", count: 2 });
});
