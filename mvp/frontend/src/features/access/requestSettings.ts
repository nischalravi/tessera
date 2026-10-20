/**
 * View logic for the tenant's request settings (issue #298): what the request form asks for, and the
 * admin page's checks. The server enforces every one of these on submit (internal/requests); the
 * form only reads them so people see the limits before they hit them. Pure functions; `npm test`
 * covers them.
 */
import type { RequestForOthers, RequestHistoryVisibility, RequestSettings } from "../../api";

/** What a tenant that never saved settings gets (the behaviour before the settings existed). */
export const DEFAULT_REQUEST_SETTINGS: RequestSettings = {
  justification_required: true,
  justification_min_length: 1,
  default_hours: null,
  max_hours: null,
  attachments_allowed: false,
  history_visibility: "readers",
  for_others: "permission",
};

export const FOR_OTHERS: { id: RequestForOthers; label: string; hint: string }[] = [
  { id: "permission", label: "Anyone with the permission", hint: "People who hold requests.create_for_others may request for anyone" },
  { id: "managers", label: "Managers only", hint: "A person may request for themselves and for the people who report to them" },
  { id: "nobody", label: "Nobody", hint: "Everyone requests for themselves only" },
];

export const HISTORY: { id: RequestHistoryVisibility; label: string; hint: string }[] = [
  { id: "readers", label: "Also people who can read the graph", hint: "Auditors and other readers see everyone's requests" },
  { id: "involved", label: "Only people involved", hint: "The requester, the beneficiary, approvers and deciders" },
];

export const MAX_ATTACHMENTS = 5;
export const MAX_ATTACHMENT_REF = 300;

/** The words on the form for what a justification must be. */
export function justificationHint(s: RequestSettings): string {
  if (!s.justification_required) return "Optional. Approvers see it if you add one.";
  return s.justification_min_length <= 1 ? "Approvers see this. Say what it is for." : `Approvers see this. At least ${s.justification_min_length} characters.`;
}

/** Why a justification cannot be submitted, or null. */
export function justificationError(s: RequestSettings, text: string, maxLen = 1000): string | null {
  const t = text.trim();
  if (t.length > maxLen) return `A justification is at most ${maxLen} characters`;
  if (s.justification_required && t.length < Math.max(1, s.justification_min_length)) {
    return t.length === 0 ? "A justification is required" : `Write at least ${s.justification_min_length} characters (${t.length} so far)`;
  }
  return null;
}

/**
 * The longest a request may last: the shorter of the tenant's maximum and the items' (null: no limit).
 * With a tenant maximum "until removed" is not an option, so the form must name a duration.
 */
export const effectiveMaxHours = (itemMax: number | null, s: RequestSettings): number | null =>
  itemMax == null ? s.max_hours : s.max_hours == null ? itemMax : Math.min(itemMax, s.max_hours);

/**
 * Duration choices the form offers: nothing above the limit. The empty choice ("each item's default")
 * is offered unless a tenant maximum leaves it with no default to fall back on.
 */
export function durationChoices<T extends [string, number | null]>(all: T[], itemMax: number | null, s: RequestSettings, itemsHaveDefaults = false): T[] {
  const max = effectiveMaxHours(itemMax, s);
  const open = s.max_hours == null || s.default_hours != null || itemsHaveDefaults;
  return all.filter(([, h]) => (h === null ? open : max === null || h <= max));
}

/** What the empty choice means on the form. */
export function defaultDurationLabel(s: RequestSettings, hoursLabel: (h: number) => string): string {
  return s.default_hours != null ? `Each item's default, else ${hoursLabel(s.default_hours)}` : "Each item's default";
}

/** Whether a duration has to be chosen before submitting (a tenant maximum, and neither it nor every item has a default). */
export const durationRequired = (s: RequestSettings, itemsHaveDefaults = false): boolean => s.max_hours != null && s.default_hours == null && !itemsHaveDefaults;

/** Attachment references typed one per line. */
export const parseAttachments = (text: string): string[] => text.split("\n").map((l) => l.trim()).filter(Boolean);

export function attachmentError(s: RequestSettings, refs: string[]): string | null {
  if (refs.length === 0) return null;
  if (!s.attachments_allowed) return "Attachments are turned off for requests";
  if (refs.length > MAX_ATTACHMENTS) return `At most ${MAX_ATTACHMENTS} attachments`;
  if (refs.some((r) => r.length > MAX_ATTACHMENT_REF)) return `An attachment is a reference of at most ${MAX_ATTACHMENT_REF} characters`;
  return null;
}

/** The note under "Who is this for" when the tenant limits requests for others. */
export function forOthersNote(s: RequestSettings): string | null {
  if (s.for_others === "nobody") return "Your organization allows requests for yourself only.";
  if (s.for_others === "managers") return "You can request for people who report to you. The server refuses anyone else.";
  return null;
}

/** The first problem with an admin draft, or null. Mirrors the server's checks. */
export function settingsError(s: RequestSettings, maxHoursLimit = 24 * 365, maxJustification = 1000): string | null {
  if (!Number.isInteger(s.justification_min_length) || s.justification_min_length < 1 || s.justification_min_length > maxJustification) {
    return `The minimum justification length is a whole number from 1 to ${maxJustification}`;
  }
  for (const [label, h] of [["default", s.default_hours], ["maximum", s.max_hours]] as const) {
    if (h !== null && !(h > 0 && h <= maxHoursLimit)) return `The ${label} duration is between 0 and ${maxHoursLimit} hours`;
  }
  if (s.default_hours !== null && s.max_hours !== null && s.default_hours > s.max_hours) return "The default duration cannot be longer than the maximum";
  return null;
}

/** An hours field: empty means no value; anything else must be a positive number. */
export function parseHours(text: string): number | null | "invalid" {
  const t = text.trim();
  if (t === "") return null;
  const n = Number(t);
  return Number.isFinite(n) && n > 0 ? n : "invalid";
}

/** Settings equal, ignoring field order (to enable Save only after a change). */
export const sameSettings = (a: RequestSettings, b: RequestSettings): boolean =>
  a.justification_required === b.justification_required && a.justification_min_length === b.justification_min_length &&
  a.default_hours === b.default_hours && a.max_hours === b.max_hours && a.attachments_allowed === b.attachments_allowed &&
  a.history_visibility === b.history_visibility && a.for_others === b.for_others;
