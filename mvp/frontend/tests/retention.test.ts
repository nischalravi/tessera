// Log retention settings and the archive in the UI (issue #298): the payload an edited form files, the
// floors it checks before asking anyone to approve, and the words for a segment. The server enforces the
// floors itself. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { ArchiveSegment, RetentionSetting } from "../src/api.ts";
import { checkDays, describeDays, draftChange, exportName, fmtBytes, rangeLabel, summarize } from "../src/features/admin/retentionModel.ts";

const setting = (class_: RetentionSetting["class"], days: number, min: number, label: string): RetentionSetting => ({
  class: class_, label, days, custom: false, default_days: days, min_days: min, max_days: 3650, basis: "",
});
const SETTINGS: RetentionSetting[] = [
  setting("audit", 730, 365, "Audit events"),
  setting("review_campaigns", 730, 365, "Closed review campaigns"),
  setting("requests", 730, 365, "Closed and expired requests"),
  setting("job_runs", 90, 30, "Job runs"),
  setting("notifications", 90, 30, "Notification outbox"),
];

test("days are described in the unit a person thinks in", () => {
  assert.equal(describeDays(365), "1 year");
  assert.equal(describeDays(730), "2 years");
  assert.equal(describeDays(90), "90 days");
  assert.equal(describeDays(400), "400 days");
  assert.equal(describeDays(1), "1 day");
});

test("a retention below its floor, above its ceiling or not a number is refused", () => {
  const audit = SETTINGS[0];
  assert.equal(checkDays(audit, "365"), null);
  assert.equal(checkDays(audit, " 3650 "), null);
  assert.match(checkDays(audit, "364")!, /at least 1 year/);
  assert.match(checkDays(audit, "3651")!, /at most 10 years/);
  for (const bad of ["", "abc", "-5", "1.5", "1e3", "0", "100000"]) assert.notEqual(checkDays(audit, bad), null, bad);
  assert.equal(checkDays(SETTINGS[3], "30"), null);
  assert.notEqual(checkDays(SETTINGS[3], "29"), null);
});

test("an edited form files only what changed, under the field names the API takes", () => {
  const d = draftChange(SETTINGS, { audit: "365", job_runs: "45", requests: "730", notifications: "  ", review_campaigns: undefined });
  assert.deepEqual(d.payload, { audit_days: 365, job_runs_days: 45 });
  assert.deepEqual(d.changed, ["audit", "job_runs"]);
  assert.deepEqual(d.errors, {});
  assert.equal(summarize(SETTINGS, d), "Audit events 2 years → 1 year, Job runs 90 days → 45 days");
});

test("a class edited below its floor is an error and is left out of the payload", () => {
  const d = draftChange(SETTINGS, { audit: "100", job_runs: "60" });
  assert.deepEqual(d.payload, { job_runs_days: 60 });
  assert.match(d.errors.audit!, /Audit events are kept online for at least 1 year/);
  assert.equal(d.errors.job_runs, undefined);
  assert.deepEqual(draftChange(SETTINGS, {}).payload, {});
});

const seg = (o: Partial<ArchiveSegment>): ArchiveSegment => ({
  id: "s1", class: "audit", status: "purged", count: 25, seq_from: 1, seq_to: 25, range_from: "2022-03-01T09:00:00Z", range_to: "2022-03-01T09:24:00Z",
  sha256: "0".repeat(64), size_bytes: 2048, location: "local", created_at: "2026-10-20T09:00:00Z", verified_at: null, purged_at: null, ...o,
});

test("a segment says what it covers", () => {
  assert.equal(rangeLabel(seg({})), "events 1–25, 2022-03-01");
  assert.equal(rangeLabel(seg({ range_to: "2022-04-02T00:00:00Z" })), "events 1–25, 2022-03-01 to 2022-04-02");
  assert.equal(rangeLabel(seg({ class: "job_runs", seq_from: undefined, seq_to: undefined })), "2022-03-01");
  assert.equal(rangeLabel(seg({ class: "requests", range_from: "-", range_to: "-" })), "—");
});

test("sizes and file names", () => {
  assert.equal(fmtBytes(512), "512 B");
  assert.equal(fmtBytes(2048), "2.0 KiB");
  assert.equal(fmtBytes(5 * 1024 * 1024), "5.0 MiB");
  assert.equal(exportName({ class: "audit", id: "abc" }), "tessera-archive-audit-abc.ndjson");
});
