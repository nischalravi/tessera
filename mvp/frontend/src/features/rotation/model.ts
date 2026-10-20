/**
 * Pure helpers for the secret-rotation screens: labels, status roll-ups and the wording of the
 * recorded re-read. No React and no fetch here, so `npm test` covers them.
 */
import type { RotationAction, RotationJob, RotationOrigin, RotationPlanItem, RotationSecretStatus, RotationState, RotationVerification } from "../../api";

export type Tone = "neutral" | "critical" | "warning" | "ok" | "info" | "accent" | "outline";

export const STATE_LABEL: Record<RotationState, string> = {
  pending: "Queued",
  created: "New credential created",
  handed_over: "Handed over",
  old_disabled: "Old disabled",
  verified: "Verified",
  old_deleted: "Done",
  failed: "Failed",
  cancelled: "Cancelled",
};

export const STATE_TONE: Record<RotationState, Tone> = {
  pending: "neutral",
  created: "info",
  handed_over: "info",
  old_disabled: "info",
  verified: "accent",
  old_deleted: "ok",
  failed: "critical",
  cancelled: "outline",
};

export const STATE_ORDER: RotationState[] = ["failed", "pending", "created", "handed_over", "old_disabled", "verified", "old_deleted", "cancelled"];

/** The states in which a job still has work to do. */
export const IN_FLIGHT: RotationState[] = ["pending", "created", "handed_over", "old_disabled", "verified"];
export const isInFlight = (s: RotationState) => IN_FLIGHT.includes(s);

export const ORIGIN_LABEL: Record<RotationOrigin, string> = {
  manual: "Rotate now",
  policy: "Policy (max age)",
  vendor_compromise: "Vendor compromised",
  jml: "Leaver",
};

export const ACTION_LABEL: Record<RotationAction, string> = {
  rotate: "Tessera rotates it",
  manual: "Owner rotates by hand",
  blocked: "Blocked",
  in_flight: "Rotation running",
};

export const ACTION_TONE: Record<RotationAction, Tone> = { rotate: "ok", manual: "warning", blocked: "critical", in_flight: "info" };

export const MODE_LABEL = { automatic: "Automatic", scheduled: "On request", manual: "Manual", none: "No policy" } as const;

/** What a secret row is doing right now, for the status filter. */
export type SecretStatusKey = "rotating" | "failed" | "overdue" | "manual" | "ok";

export function secretStatus(r: RotationSecretStatus): SecretStatusKey {
  if (r.active_job) return "rotating";
  if (r.last_job?.state === "failed") return "failed";
  if (r.overdue) return "overdue";
  if (r.action === "manual" || r.action === "blocked") return "manual";
  return "ok";
}

export const SECRET_STATUS_LABEL: Record<SecretStatusKey, string> = {
  rotating: "Rotating",
  failed: "Last rotation failed",
  overdue: "Overdue",
  manual: "Needs manual rotation",
  ok: "Within policy",
};

export const SECRET_STATUS_TONE: Record<SecretStatusKey, Tone> = { rotating: "info", failed: "critical", overdue: "warning", manual: "outline", ok: "ok" };

/** "37 / 90 days" or "37 days (no policy)". */
export function ageText(r: { age_days: number; max_age_days: number | null }): string {
  return r.max_age_days == null ? `${r.age_days} d (no max age)` : `${r.age_days} / ${r.max_age_days} d`;
}

export function graceText(hours: number): string {
  if (hours <= 0) return "none";
  if (hours % 24 === 0) return `${hours / 24} day${hours === 24 ? "" : "s"}`;
  return `${hours} h`;
}

export interface PlanSummary { rotate: number; manual: number; blocked: number; in_flight: number }

export function summarizePlan(items: Pick<RotationPlanItem, "action">[]): PlanSummary {
  const s: PlanSummary = { rotate: 0, manual: 0, blocked: 0, in_flight: 0 };
  for (const i of items) s[i.action]++;
  return s;
}

/** One line for the plan's footer: "2 will be rotated, 1 needs a manual rotation". */
export function planHeadline(s: PlanSummary): string {
  const parts: string[] = [];
  if (s.rotate) parts.push(`${s.rotate} will be rotated`);
  if (s.in_flight) parts.push(`${s.in_flight} already rotating`);
  if (s.manual) parts.push(`${s.manual} need${s.manual === 1 ? "s" : ""} a manual rotation`);
  if (s.blocked) parts.push(`${s.blocked} blocked`);
  return parts.length ? parts.join(", ") : "Nothing to rotate";
}

/** Secrets of a plan that the Rotate action can queue. */
export const rotatable = (items: Pick<RotationPlanItem, "action" | "secret_id">[]) => items.filter((i) => i.action === "rotate").map((i) => i.secret_id);

/** "2026-10-12T19:23:26.562581Z" as "2026-10-12 19:23 UTC". */
export const utcMinute = (s: string) => s.replace(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}):\d{2}(?:\.\d+)?Z?$/, "$1 $2 UTC");

const VERDICT_TEXT: Record<RotationVerification["verdict"], string> = {
  ok: "The old credential is not in use.",
  still_active: "The old credential was still active after it was disabled.",
  used_after_disable: "The old credential was used after the grace period: a consumer has not moved to the new one.",
  missing_evidence: "The provider did not report the old credential's age.",
};

/** The recorded re-read of the old credential, in sentences. */
export function evidenceLines(v: RotationVerification): string[] {
  const lines: string[] = [];
  lines.push(v.old_age_days == null ? "Key age: not reported." : `Key age: ${v.old_age_days} day${v.old_age_days === 1 ? "" : "s"}.`);
  if (!v.old_exists) lines.push("The old credential was already gone when it was re-read.");
  else if (!v.last_used_known) lines.push("Last use: this provider does not report it, so only the key age was checked.");
  else if (!v.old_last_used_at) lines.push("Last use: never.");
  else lines.push(`Last use: ${utcMinute(v.old_last_used_at)}.`);
  lines.push(VERDICT_TEXT[v.verdict]);
  if (v.detail && v.verdict !== "ok") lines.push(v.detail);
  return lines;
}

/** Which job actions make sense in this state. */
export function jobActions(j: Pick<RotationJob, "state">): { retry: boolean; cancel: boolean } {
  return { retry: j.state === "failed", cancel: j.state === "pending" };
}

/** Counts by state, for the filter chips of the jobs list. */
export function stateCounts(jobs: Pick<RotationJob, "state">[]): Record<RotationState, number> {
  const c = Object.fromEntries(STATE_ORDER.map((s) => [s, 0])) as Record<RotationState, number>;
  for (const j of jobs) c[j.state]++;
  return c;
}

/** Progress of a bulk run as "3 of 5 done · 1 failed". */
export function bulkProgressText(progress: Partial<Record<RotationState, number>>, total: number): string {
  const done = progress.old_deleted ?? 0;
  const failed = progress.failed ?? 0;
  const running = total - done - failed - (progress.cancelled ?? 0);
  const parts = [`${done} of ${total} done`];
  if (running > 0) parts.push(`${running} running`);
  if (failed > 0) parts.push(`${failed} failed`);
  return parts.join(" · ");
}

/** Policy form: dest_path placeholders the server expands. */
export const DEST_PLACEHOLDERS = ["{system}", "{kind}", "{name}", "{account}"] as const;

/** What the API takes for an adapter type: its settings and credential fields. */
export const ADAPTER_FIELDS: Record<string, { config: { id: string; label: string; placeholder?: string; required?: boolean }[]; credential: { id: string; label: string; secret?: boolean; required?: boolean }[]; help: string }> = {
  aws_iam: {
    config: [{ id: "region", label: "Region", placeholder: "us-east-1" }, { id: "endpoint", label: "Endpoint (optional)", placeholder: "https://iam.amazonaws.com" }],
    credential: [{ id: "access_key_id", label: "Access key id", required: true }, { id: "secret_access_key", label: "Secret access key", secret: true, required: true }, { id: "session_token", label: "Session token (optional)", secret: true }],
    help: "Rotates an IAM user's access key. The adapter's own key needs iam:CreateAccessKey, UpdateAccessKey, DeleteAccessKey, ListAccessKeys and GetAccessKeyLastUsed on the users it rotates.",
  },
  aws_secretsmanager: {
    config: [{ id: "region", label: "Region", placeholder: "eu-west-1" }, { id: "endpoint", label: "Endpoint (optional)" }],
    credential: [{ id: "access_key_id", label: "Access key id", required: true }, { id: "secret_access_key", label: "Secret access key", secret: true, required: true }, { id: "session_token", label: "Session token (optional)", secret: true }],
    help: "Rotates a Secrets Manager secret in place (through its rotation function when it has one) and can receive new credentials from other adapters.",
  },
  vault: {
    config: [{ id: "address", label: "Vault address", placeholder: "https://vault.example.com:8200", required: true }, { id: "namespace", label: "Namespace (optional)" }],
    credential: [{ id: "token", label: "Vault token", secret: true, required: true }],
    help: "Rotates AppRole SecretIDs and receives new credentials in KV v2. The token needs access to the role's secret-id endpoints and write access to the destination paths.",
  },
  github: {
    config: [{ id: "api_url", label: "API URL (optional)", placeholder: "https://api.github.com" }],
    credential: [{ id: "token", label: "Token", secret: true, required: true }],
    help: "Rotates repository deploy keys. GitHub has no API for personal access tokens or App private keys, so those stay manual.",
  },
  fake: {
    config: [{ id: "fail_at", label: "Fail at (demo)", placeholder: "create, handover, disable, observe or delete" }, { id: "consumer_still_uses", label: "Consumer still uses old key (demo)", placeholder: "true or false" }],
    credential: [],
    help: "A simulated provider for the dev stack: it calls nothing. Use the demo settings to see a failed or blocked rotation.",
  },
};

export const ADAPTER_TYPE_LABEL: Record<string, string> = {
  aws_iam: "AWS IAM access keys",
  aws_secretsmanager: "AWS Secrets Manager",
  vault: "HashiCorp Vault",
  github: "GitHub deploy keys",
  fake: "Simulated (dev)",
};

/** The worst rotation status among an identity's secrets, for the Machine identities list. */
export function identityRotation(rows: Pick<RotationSecretStatus, "active_job" | "last_job" | "overdue" | "action">[]): { key: SecretStatusKey; count: number } | null {
  if (rows.length === 0) return null;
  const order: SecretStatusKey[] = ["failed", "rotating", "overdue", "manual", "ok"];
  const keys = rows.map((r) => secretStatus(r as RotationSecretStatus));
  const key = order.find((k) => keys.includes(k)) ?? "ok";
  return { key, count: keys.filter((k) => k === key).length };
}
