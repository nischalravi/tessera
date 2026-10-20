// Log retention and the archive, as the UI needs them (issue #298): turning the form into the
// retention.update payload, checking it against the floors, and the words for what the archive holds.
// Pure functions, so `npm test` covers them. The server enforces every floor itself (a change below
// one is a 422 before anyone is asked to approve); these only keep an admin from filing one.
import type { ArchiveSegment, RetentionClass, RetentionSetting, SegmentStatus } from "../../api";

/** The payload field of each class in a retention.update request. */
export const PAYLOAD_FIELD: Record<RetentionClass, string> = {
  audit: "audit_days",
  review_campaigns: "review_campaigns_days",
  requests: "requests_days",
  job_runs: "job_runs_days",
  notifications: "notifications_days",
};

export const CLASS_LABEL: Record<RetentionClass, string> = {
  audit: "Audit events",
  review_campaigns: "Closed review campaigns",
  requests: "Closed and expired requests",
  job_runs: "Job runs",
  notifications: "Notification outbox",
};

/** "1 year", "2 years", "90 days": days in the unit a person thinks in. */
export function describeDays(days: number): string {
  if (days >= 365 && days % 365 === 0) {
    const y = days / 365;
    return y === 1 ? "1 year" : `${y} years`;
  }
  return days === 1 ? "1 day" : `${days} days`;
}

/** What is wrong with a typed number of days for a class, or null. */
export function checkDays(s: Pick<RetentionSetting, "min_days" | "max_days" | "label">, raw: string): string | null {
  const t = raw.trim();
  if (!/^\d{1,5}$/.test(t)) return "Enter a whole number of days.";
  const n = Number(t);
  if (n < s.min_days) return `${s.label} are kept online for at least ${describeDays(s.min_days)} (${s.min_days} days).`;
  if (n > s.max_days) return `${s.label} are kept online for at most ${describeDays(s.max_days)} (${s.max_days} days).`;
  return null;
}

export interface RetentionDraft {
  /** The retention.update payload: only the classes that changed. */
  payload: Record<string, number>;
  /** An error per class that was edited to something unacceptable. */
  errors: Partial<Record<RetentionClass, string>>;
  /** The classes that changed, for the summary line. */
  changed: RetentionClass[];
}

/** The change an edited form asks for. A field left as it is, or empty, asks for nothing. */
export function draftChange(settings: RetentionSetting[], edits: Partial<Record<RetentionClass, string>>): RetentionDraft {
  const out: RetentionDraft = { payload: {}, errors: {}, changed: [] };
  for (const s of settings) {
    const raw = edits[s.class];
    if (raw === undefined || raw.trim() === "") continue;
    const err = checkDays(s, raw);
    if (err) {
      out.errors[s.class] = err;
      continue;
    }
    const n = Number(raw.trim());
    if (n === s.days) continue;
    out.payload[PAYLOAD_FIELD[s.class]] = n;
    out.changed.push(s.class);
  }
  return out;
}

/** "Audit events 2 years → 1 year, Job runs 90 days → 45 days". */
export function summarize(settings: RetentionSetting[], draft: RetentionDraft): string {
  return draft.changed
    .map((c) => {
      const s = settings.find((x) => x.class === c)!;
      return `${CLASS_LABEL[c]} ${describeDays(s.days)} → ${describeDays(draft.payload[PAYLOAD_FIELD[c]])}`;
    })
    .join(", ");
}

export const SEGMENT_TONE: Record<SegmentStatus, "ok" | "info" | "warning" | "critical"> = {
  purged: "ok", verified: "info", written: "warning", failed: "critical",
};

export const SEGMENT_LABEL: Record<SegmentStatus, string> = {
  purged: "Archived", verified: "Verified, removing", written: "Written, verifying", failed: "Failed, kept online",
};

/** What a segment covers: the chain range of an audit segment, the dates of the others. */
export function rangeLabel(g: Pick<ArchiveSegment, "class" | "seq_from" | "seq_to" | "range_from" | "range_to">): string {
  const day = (s: string) => s.slice(0, 10);
  const dates = g.range_from === "-" ? "" : g.range_from.slice(0, 10) === g.range_to.slice(0, 10) ? day(g.range_from) : `${day(g.range_from)} to ${day(g.range_to)}`;
  if (g.class === "audit") return `events ${g.seq_from}–${g.seq_to}${dates ? `, ${dates}` : ""}`;
  return dates || "—";
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

/** The download name of an exported segment. */
export const exportName = (g: Pick<ArchiveSegment, "class" | "id">) => `tessera-archive-${g.class}-${g.id}.ndjson`;
