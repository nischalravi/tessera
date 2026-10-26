// Two-admin changes (issues #511, #520, #521, #526): when the API answers 409 two_admin_change_required, the form's values
// become the payload of an admin change request. Pure helpers, no React, so `npm test` covers the mapping.

/** The change types a 409 two_admin_change_required can name. */
export type TwoAdminType = "siem.sink.filter" | "siem.sink.target" | "alerts.rule.loosen" | "breach.item.attest" | "provisioning.write_back.enable";

const TYPES: readonly string[] = ["siem.sink.filter", "siem.sink.target", "alerts.rule.loosen", "breach.item.attest", "provisioning.write_back.enable"];

/** The change type to file when `err` is the API's 409 two_admin_change_required, else null. */
export function twoAdminType(err: unknown): TwoAdminType | null {
  const e = err as { status?: number; code?: string | null; body?: { change_type?: unknown } } | null;
  if (!e || e.status !== 409 || e.code !== "two_admin_change_required") return null;
  const t = e.body?.change_type;
  return typeof t === "string" && TYPES.includes(t) ? (t as TwoAdminType) : null;
}

const sameSet = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((x) => b.includes(x));

/**
 * siem.sink.filter: only what the form changed (omitted keeps the current value on the server). event_filter [] is every event.
 * Returns null when neither differs from the sink.
 */
export function siemFilterPayload(
  sink: { id: string; event_filter: string[]; include_http: boolean },
  form: { event_filter: string[]; include_http: boolean },
): { sink_id: string; event_filter?: string[]; include_http?: boolean } | null {
  const p: { sink_id: string; event_filter?: string[]; include_http?: boolean } = { sink_id: sink.id };
  if (!sameSet(sink.event_filter, form.event_filter)) p.event_filter = form.event_filter;
  if (sink.include_http !== form.include_http) p.include_http = form.include_http;
  return p.event_filter === undefined && p.include_http === undefined ? null : p;
}

/** siem.sink.target: the new destination, as typed. */
export const siemTargetPayload = (sinkId: string, target: string) => ({ sink_id: sinkId, target: target.trim() });

/** breach.item.attest: the plan, the item and what the person did (the server checks all three). */
export const breachAttestPayload = (planId: string, itemId: string, note: string) => ({ plan_id: planId, item_id: itemId, note: note.trim() });

/** alerts.rule.loosen: the full rule the form holds (the server compares it with the current one). */
export function alertLoosenPayload(ruleId: string, f: { enabled: boolean; severity: string; threshold: number; window_minutes: number }) {
  return { rule_id: ruleId, enabled: f.enabled, severity: f.severity, threshold: f.threshold, window_minutes: f.window_minutes };
}

/** provisioning.write_back.enable: the target and the fingerprint of the configuration the admin reviewed (the server refuses a stale one). */
export const provWriteBackPayload = (connectionId: string, configHash: string) => ({ connection_id: connectionId, config_hash: configHash });

/** What the dialog tells the admin the request is for. */
export const TWO_ADMIN_TITLE: Record<TwoAdminType, string> = {
  "siem.sink.filter": "Narrowing what this sink receives needs a second admin",
  "siem.sink.target": "Moving this sink to another destination needs a second admin",
  "alerts.rule.loosen": "Loosening a security alert rule needs a second admin",
  "breach.item.attest": "Attesting a breach item needs a second admin",
  "provisioning.write_back.enable": "Turning on write-back needs a second admin",
};

/** The pause length for a protected schedule: a whole number of hours, 1 to 24. NaN when the text is not one. */
export function pauseHours(text: string): number {
  const t = text.trim();
  if (!/^\d{1,2}$/.test(t)) return NaN;
  const n = Number(t);
  return n >= 1 && n <= 24 ? n : NaN;
}

export const MAX_PAUSE_REASON = 500;

/** Why a protected pause cannot be sent yet, or null. */
export function pauseProblem(reason: string, hoursText: string): string | null {
  if (!reason.trim()) return "Say why: the reason is kept in the audit log.";
  if (reason.trim().length > MAX_PAUSE_REASON) return `The reason can be at most ${MAX_PAUSE_REASON} characters.`;
  if (Number.isNaN(pauseHours(hoursText))) return "Pause for a whole number of hours from 1 to 24.";
  return null;
}
