// Two-admin changes (issues #511, #520, #521, #526): when the API answers 409 two_admin_change_required, the form's values
// become the payload of an admin change request. Pure helpers, no React, so `npm test` covers the mapping.

/** The change types a 409 two_admin_change_required can name. */
export type TwoAdminType = "siem.sink.filter" | "siem.sink.target" | "siem.sink.disable" | "siem.sink.delete" | "alerts.rule.loosen" | "alerts.channel.disable" | "alerts.channel.delete" | "alerts.channel.target" | "alerts.channel.severity" | "alerts.channel.rotate_secret" | "breach.item.attest" | "provisioning.write_back.enable";

const TYPES: readonly string[] = ["siem.sink.filter", "siem.sink.target", "siem.sink.disable", "siem.sink.delete", "alerts.rule.loosen", "alerts.channel.disable", "alerts.channel.delete", "alerts.channel.target", "alerts.channel.severity", "alerts.channel.rotate_secret", "breach.item.attest", "provisioning.write_back.enable"];

/** The change type to file when `err` is the API's 409 two_admin_change_required, else null. */
export function twoAdminType(err: unknown): TwoAdminType | null {
  const e = err as { status?: number; code?: string | null; body?: { change_type?: unknown } } | null;
  if (!e || e.status !== 409 || e.code !== "two_admin_change_required") return null;
  const t = e.body?.change_type;
  return typeof t === "string" && TYPES.includes(t) ? (t as TwoAdminType) : null;
}

/**
 * Every change type a 409 two_admin_change_required names (issue #973): change_types when the API sends it (one save can need
 * several), else the single change_type. Unknown names are kept so the caller can say they were not filed. [] for any other error.
 */
export function twoAdminTypes(err: unknown): string[] {
  const e = err as { status?: number; code?: string | null; body?: { change_type?: unknown; change_types?: unknown } } | null;
  if (!e || e.status !== 409 || e.code !== "two_admin_change_required") return [];
  const list = Array.isArray(e.body?.change_types) ? e.body!.change_types.filter((x): x is string => typeof x === "string") : [];
  if (list.length) return list;
  return typeof e.body?.change_type === "string" ? [e.body.change_type] : [];
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

/** siem.sink.disable and siem.sink.delete: the sink. */
export const siemSinkPayload = (sinkId: string) => ({ sink_id: sinkId });

/** alerts.channel.disable and alerts.channel.delete: the channel (issue #968). */
export const alertChannelPayload = (channelId: string) => ({ channel_id: channelId });

/** alerts.channel.target: the new recipient list, as typed (an email channel; a webhook URL goes by proposal). */
export const alertChannelTargetPayload = (channelId: string, target: string) => ({ channel_id: channelId, target: target.trim() });

/** alerts.channel.severity: the higher min_severity. */
export const alertChannelSeverityPayload = (channelId: string, minSeverity: string) => ({ channel_id: channelId, min_severity: minSeverity });

/** alerts.channel.rotate_secret: the channel only. The new secret goes as client_secret, never in the payload. */
export const alertChannelRotatePayload = alertChannelPayload;

/** One change an alert channel save needs filed. `secret` is the new signing secret to send as client_secret (rotate only). */
export interface ChannelChange { type: TwoAdminType; payload: Record<string, unknown>; what: string; secret?: string }

/**
 * Turns the change types a 409 named into the requests to file (issue #973): every one the UI can file, in the API's order, and a
 * line for each it cannot (a webhook URL carries a token, so it is never put in a change request).
 */
export function alertChannelChanges(
  types: readonly string[], channelId: string, form: { target: string; min: string }, newSecret: () => string,
): { items: ChannelChange[]; notFiled: string[] } {
  const items: ChannelChange[] = [];
  const notFiled: string[] = [];
  for (const type of new Set(types)) {
    switch (type) {
      case "alerts.channel.disable":
        items.push({ type, payload: alertChannelPayload(channelId), what: "Turn the channel off" });
        break;
      case "alerts.channel.target":
        items.push({ type, payload: alertChannelTargetPayload(channelId, form.target), what: `Send its alerts to ${form.target.trim()}` });
        break;
      case "alerts.channel.severity":
        items.push({ type, payload: alertChannelSeverityPayload(channelId, form.min), what: `Raise the minimum severity to ${form.min}` });
        break;
      case "alerts.channel.rotate_secret":
        items.push({ type, payload: alertChannelRotatePayload(channelId), what: "Issue a new signing secret", secret: newSecret() });
        break;
      case "config.proposal":
        notFiled.push("The new webhook URL: it carries a token, so it cannot go in a change request. Add a channel with the new URL and delete this one (needs a second admin), or have a machine client propose it.");
        break;
      default:
        notFiled.push(`${type}: this form cannot file it.`);
    }
  }
  return { items, notFiled };
}

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
  "siem.sink.disable": "Turning this sink off needs a second admin",
  "siem.sink.delete": "Deleting this sink needs a second admin",
  "alerts.channel.disable": "Turning this channel off needs a second admin",
  "alerts.channel.delete": "Deleting this channel needs a second admin",
  "alerts.channel.target": "Sending this channel's alerts to other recipients needs a second admin",
  "alerts.channel.severity": "Raising this channel's minimum severity needs a second admin",
  "alerts.channel.rotate_secret": "Issuing a new signing secret for this channel needs a second admin",
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
