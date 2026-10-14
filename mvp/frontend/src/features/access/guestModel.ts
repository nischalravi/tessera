import type { BundleItem, BundleItemState, BundleState, BulkRowStatus, CatalogEntry, GuestPopulationInfo, GuestPopulationKey, InvitationState, InviteInput, Sponsorship, SponsorshipState } from "../../api";

/** Labels and rules for guest sponsorships (issue #65). No React, so `npm test` can import it. */

export const POPULATION_LABEL: Record<GuestPopulationKey, string> = {
  visitor: "Visitor",
  contractor: "Contractor",
  volunteer: "Volunteer",
  partner: "Partner",
};
export const POPULATIONS = Object.keys(POPULATION_LABEL) as GuestPopulationKey[];

export const STATE_LABEL: Record<SponsorshipState, string> = {
  requested: "Requested",
  pending_approval: "Waiting for approval",
  active: "Active",
  upcoming: "Not started",
  ending: "Ending soon",
  transfer_pending: "Transfer pending",
  suspended: "Suspended",
  ended: "Ended",
  revoked: "Revoked",
  rejected: "Rejected",
};

export type Tone = "ok" | "warning" | "critical" | "neutral" | "info";
export const STATE_TONE: Record<SponsorshipState, Tone> = {
  requested: "info",
  pending_approval: "warning",
  active: "ok",
  upcoming: "info",
  ending: "warning",
  transfer_pending: "warning",
  suspended: "warning",
  ended: "neutral",
  revoked: "critical",
  rejected: "critical",
};

export const ROW_LABEL: Record<BulkRowStatus, string> = {
  ok: "Will be invited",
  needs_approval: "Will wait for approval",
  created: "Invited",
  refused: "Refused",
};

/** The IAL a bundle item needs: privileged and high-risk access needs IAL 2. */
export const itemSensitive = (i: Pick<BundleItem, "privileged" | "risk">) => i.privileged || i.risk === "high";
export const itemIal = (i: Pick<BundleItem, "privileged" | "risk">) => (itemSensitive(i) ? 2 : 0);

/** The IAL a population and bundle need together (the policy forbids less). */
export function requiredIal(pop: Pick<GuestPopulationInfo, "default_ial"> | undefined, items: Pick<BundleItem, "privileged" | "risk">[]): number {
  return Math.max(pop?.default_ial ?? 0, ...items.map(itemIal));
}

/** Whether a contractor-style population will wait for a second approver with this bundle. */
export const needsApproval = (pop: Pick<GuestPopulationInfo, "approval_with_sensitive_bundle"> | undefined, items: Pick<BundleItem, "privileged" | "risk">[]) =>
  !!pop?.approval_with_sensitive_bundle && items.some(itemSensitive);

/** Catalog entries a sponsor may put in a bundle: requestable and open to people. */
export const bundleChoices = (items: CatalogEntry[]) =>
  items.filter((e) => e.requestable && (e.eligible_types.length === 0 || e.eligible_types.includes("human")));

/** A YYYY-MM-DD day, UTC. */
export const dayOf = (d: Date) => d.toISOString().slice(0, 10);
export const addDays = (day: string, n: number) => {
  const d = new Date(`${day}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return dayOf(d);
};

/**
 * The latest end day a form may offer: `maxDays` after the start day (blank: today, the guest starts
 * now). The API checks again; this only keeps the date picker honest.
 */
export const maxEndDay = (startDay: string, todayDay: string, maxDays: number) => addDays(startDay || todayDay, maxDays);

/** An end day as the instant the access stops: the start of that day, UTC. */
export const endInstant = (day: string) => new Date(`${day}T00:00:00Z`).toISOString();

export interface InviteForm {
  given_name: string;
  family_name: string;
  email: string;
  population: GuestPopulationKey;
  purpose: string;
  starts: string; // a day, or "" for now
  ends: string; // a day
  bundle: number[];
}

export const emptyInvite = (population: GuestPopulationKey = "visitor"): InviteForm => ({
  given_name: "", family_name: "", email: "", population, purpose: "", starts: "", ends: "", bundle: [],
});

const EMAIL = /^[^\s@]+@[^\s@]+$/;

/** What is missing before the form can be sent (empty: ready). */
export function inviteProblems(f: InviteForm, pop: GuestPopulationInfo | undefined, todayDay: string): string[] {
  const out: string[] = [];
  if (!f.given_name.trim()) out.push("a given name");
  if (!EMAIL.test(f.email.trim())) out.push("an email address");
  if (!f.purpose.trim()) out.push("a purpose");
  if (!f.ends) out.push("an end date");
  else {
    if (f.ends <= (f.starts || todayDay)) out.push("an end date after the start");
    if (pop && f.ends > maxEndDay(f.starts, todayDay, pop.max_days)) out.push(`an end date within ${pop.max_days} days of the start`);
  }
  return out;
}

export function invitePayload(f: InviteForm): InviteInput {
  const body: InviteInput = {
    given_name: f.given_name.trim(),
    family_name: f.family_name.trim(),
    email: f.email.trim(),
    population: f.population,
    purpose: f.purpose.trim(),
    ends_at: endInstant(f.ends),
  };
  if (f.starts) body.starts_at = endInstant(f.starts);
  if (f.bundle.length) body.bundle = [...f.bundle];
  return body;
}

export const CSV_HEADER = ["email", "given_name", "family_name", "population", "starts_at", "ends_at", "purpose"];
export const MAX_BULK_ROWS = 500;

/** A file to start from: the header and one example row. */
export const csvTemplate = (day: string) => `${CSV_HEADER.join(",")}\nada@example.org,Ada,Lovelace,visitor,,${addDays(day, 14)},Guest lecture\n`;

/** Rows in the pasted text (lines after the header that are not blank), to warn before sending. */
export function csvRowCount(text: string): number {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== "");
  return Math.max(0, lines.length - 1);
}

export const csvTooLong = (text: string) => csvRowCount(text) > MAX_BULK_ROWS;

/** Days left, in words. */
export function daysLeftLabel(s: Pick<Sponsorship, "days_left" | "status">): string {
  if (s.days_left === null) return "";
  if (s.days_left === 0) return "Ends today";
  return `${s.days_left} day${s.days_left === 1 ? "" : "s"} left`;
}

/** A person needs to act on this sponsorship (accept it, or approve it). */
export const needsMe = (s: Pick<Sponsorship, "can_accept_transfer" | "can_approve">) => s.can_accept_transfer || s.can_approve;

// ---------------------------------------------------------------- the invitation (issue #69)

export const INVITATION_LABEL: Record<InvitationState, string> = {
  ready: "Not sent",
  sent: "Sent",
  claiming: "Guest is setting up",
  expired: "Expired",
  claimed: "Claimed",
  revoked: "Revoked",
};

export const INVITATION_TONE: Record<InvitationState, Tone> = {
  ready: "neutral",
  sent: "info",
  claiming: "info",
  expired: "warning",
  claimed: "ok",
  revoked: "critical",
};

/** What the sponsor should know about the invitation, in a sentence. */
export function invitationNote(s: Pick<Sponsorship, "invitation" | "invitation_expires_at">, fmt: (iso: string) => string): string {
  switch (s.invitation) {
    case "ready":
      return "No claim link has been sent: it needs the claim to be set up for this organization.";
    case "sent":
      return s.invitation_expires_at ? `The guest has an email with a one-time link that works until ${fmt(s.invitation_expires_at)}.` : "The guest has an email with a one-time link.";
    case "claiming":
      return "The guest opened the link and is setting up their sign-in.";
    case "expired":
      return "The link ran out before the guest used it. Send a new one.";
    case "claimed":
      return "The guest set up their sign-in.";
    case "revoked":
      return "The invitation was cancelled; its links no longer work.";
  }
}

/** Access bundle state (issue #75). */
export const BUNDLE_STATE_LABEL: Record<BundleState, string> = {
  pending: "Pending",
  granted: "Granted",
  failed: "Failed",
  removing: "Being removed",
  removed: "Removed",
};
export const BUNDLE_STATE_TONE: Record<BundleState, Tone> = {
  pending: "info",
  granted: "ok",
  failed: "critical",
  removing: "warning",
  removed: "neutral",
};

/** One line for a bundle: how many items are in each state, worst first. */
export function bundleSummary(items: Pick<BundleItemState, "state">[]): string {
  if (items.length === 0) return "No access bundle";
  const order: BundleState[] = ["failed", "pending", "removing", "granted", "removed"];
  const parts = order
    .map((st) => [st, items.filter((i) => i.state === st).length] as const)
    .filter(([, n]) => n > 0)
    .map(([st, n]) => `${n} ${BUNDLE_STATE_LABEL[st].toLowerCase()}`);
  return parts.join(", ");
}

/** Whether an item needs somebody to look at it (a provisioning operation failed). */
export const bundleNeedsAttention = (items: Pick<BundleItemState, "state">[]) => items.some((i) => i.state === "failed");
