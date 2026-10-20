/** Labels and pure helpers of the Guest lifecycle page (issue #74). */
import type { GuestLifecycleBucket, GuestLifecycleItem, GuestLifecycleSettings, GuestTaskAction } from "../../api";

export const BUCKET_LABEL: Record<GuestLifecycleBucket, string> = {
  expiring_30: "Ending in 30 days",
  expiring_14: "Ending in 14 days",
  expiring_3: "Ending in 3 days",
  renewal_requests: "Renewal requested",
  stepup_required: "Step-up required",
  pending_transfer: "Pending transfer",
  auto_ended: "Ended by sponsor departure",
  suspended: "Suspended",
  dual_status: "Dual status asked",
  in_grace: "In grace period",
  deprovisioned: "Deprovisioned",
  purged: "Purged",
};

export const BUCKET_HELP: Record<GuestLifecycleBucket, string> = {
  expiring_30: "Active sponsorships that end within 30 days. The sponsor is reminded at 30, 14 and 3 days.",
  expiring_14: "Active sponsorships that end within 14 days. The guest is reminded and can ask for a renewal.",
  expiring_3: "Active sponsorships that end within 3 days.",
  renewal_requests: "Guests asked their sponsor to renew. The sponsor renews it, or leaves it to end.",
  stepup_required: "A renewal is recorded but held: the guest's identity assurance is below what the access now needs. Access does not extend until they verify at that level.",
  pending_transfer: "A sponsor left or moved. Their manager or a sponsor admin must take each sponsorship over before the deadline, or it ends (or is suspended).",
  auto_ended: "Sponsorships that ended or were suspended because nobody took them over after their sponsor left.",
  suspended: "Held after a sponsor left. They give no access; a sponsor admin can end them, and they end at their own end date.",
  dual_status: "A guest or contractor was hired. The sponsorship ends at the deadline unless the sponsor confirms they keep both roles.",
  in_grace: "The last affiliation ended and access was removed. After the grace period accounts are deleted or left disabled per target, ownership moves and the person becomes deprovisioned.",
  deprovisioned: "Past the grace period. Personal data is kept until the retention period ends.",
  purged: "Personal data reduced to a tombstone: the ID, affiliation history and dates stay. The audit log is not changed.",
};

export const TASK_KIND_LABEL: Record<string, string> = {
  sponsor_transfer: "Take over sponsorship",
  renewal_request: "Renewal request",
  dual_status: "Dual status",
};

export const TRIGGER_LABEL: Record<string, string> = {
  leaver: "Sponsor left",
  mover: "Sponsor moved",
  ineligible: "Sponsor no longer eligible",
  guest_request: "Guest asked",
  conversion: "Hired",
};

export const OUTCOME_LABEL: Record<string, string> = {
  transferred: "Transferred", ended: "Ended", suspended: "Suspended", renewed: "Renewed", dismissed: "Dismissed", confirmed: "Confirmed",
};

/** What a decision on a task is called and asks, by kind. */
export function taskActions(it: GuestLifecycleItem, onDeparture: "end" | "suspend"): { action: GuestTaskAction; label: string; primary?: boolean; danger?: boolean; title: string; body: string }[] {
  const stop = onDeparture === "suspend" ? "suspend it" : "end it";
  switch (it.task_kind) {
    case "sponsor_transfer":
      return [
        { action: "accept", label: "Take over", primary: true, title: `Sponsor ${it.guest.name} yourself?`, body: "You become the sponsor after a fresh policy check as you: you must be an eligible sponsor within your limits." },
        ...(it.trigger === "mover" ? [{ action: "keep" as GuestTaskAction, label: "Keep sponsor", title: "Keep the sponsor?", body: "They stay the sponsor, if they are still eligible." }] : []),
        { action: "decline", label: onDeparture === "suspend" ? "Suspend" : "End", danger: true, title: `Not taking over: ${stop}?`, body: `The sponsorship of ${it.guest.name} stops now and their access under it is removed.` },
      ];
    case "dual_status":
      return [
        { action: "confirm", label: "Keep both roles", primary: true, title: `Keep ${it.guest.name}'s sponsorship?`, body: "The sponsorship continues next to their employment." },
        { action: "decline", label: "End sponsorship", danger: true, title: "End the contractor sponsorship?", body: "Their employee affiliation stays; the sponsorship and its access end now." },
      ];
    case "renewal_request":
      return [{ action: "dismiss", label: "Dismiss", title: "Dismiss the request?", body: "The sponsorship is not renewed and ends at its end date. Renew it from Guests I sponsor to grant it." }];
    default:
      return [];
  }
}

/** Days as "3 days" / "today". */
export const inDays = (n?: number) => (n === undefined ? "" : n === 0 ? "today" : n === 1 ? "1 day" : `${n} days`);

/** A settings form's draft, checked the way the API checks it. Returns a message, or null when valid. */
export function settingsProblem(s: Omit<GuestLifecycleSettings, "updated_at">): string | null {
  const days = s.sponsor_reminder_days;
  if (days.length > 5 || days.some((d) => !Number.isInteger(d) || d < 1 || d > 365)) return "Reminders are up to 5 whole numbers of days, each 1 to 365.";
  if (!Number.isInteger(s.guest_reminder_days) || s.guest_reminder_days < 0 || s.guest_reminder_days > 365) return "The guest reminder is 0 (off) to 365 days.";
  if (!Number.isInteger(s.transfer_deadline_days) || s.transfer_deadline_days < 1 || s.transfer_deadline_days > 90) return "The transfer deadline is 1 to 90 days.";
  for (const [k, v] of Object.entries(s.grace_days)) if (!Number.isInteger(v) || v < 0 || v > 365) return `The ${k} grace period is 0 to 365 days.`;
  for (const v of [s.retention_days, s.retention_days_visitor]) if (!Number.isInteger(v) || v < 1 || v > 36500) return "Retention is 1 to 36500 days.";
  return null;
}

/** "30, 14, 3" → [30, 14, 3]; anything else → NaN entries, which settingsProblem refuses. */
export const parseDays = (s: string): number[] => s.split(/[,\s]+/).filter(Boolean).map(Number);

/** The tiles on Governance → Lifecycle: bucket, label, count and what the number means. A tile that needs action is flagged. */
export function kpiTiles(counts: Partial<Record<GuestLifecycleBucket, number>>): { bucket: GuestLifecycleBucket; label: string; value: number; sub: string; tone?: "critical" | "warning" }[] {
  const n = (b: GuestLifecycleBucket) => counts[b] ?? 0;
  return [
    { bucket: "expiring_14", label: "Ending in 14 days", value: n("expiring_14"), sub: `${n("expiring_3")} within 3 days`, tone: n("expiring_3") > 0 ? "warning" : undefined },
    { bucket: "pending_transfer", label: "Pending transfer", value: n("pending_transfer"), sub: "a sponsor left; someone must take over", tone: n("pending_transfer") > 0 ? "critical" : undefined },
    { bucket: "renewal_requests", label: "Renewal requests", value: n("renewal_requests"), sub: `${n("stepup_required")} held for step-up` },
    { bucket: "dual_status", label: "Hired, sponsorship open", value: n("dual_status"), sub: "keep both roles, or end the sponsorship" },
  ];
}
