import type { GuestLifecycleItem, IdentityMatchItem, RegistrationRequest, Sponsorship } from "../../api";
import { taskActions } from "../governance/guestLifecycleModel.ts";
import type { InboxItem } from "./model";

/** Guest work as inbox items (guest accounts design §9.4). No React, so `npm test` can import it. */

/** The four kinds of guest work an inbox row can be. */
export type GuestInboxItem =
  | { type: "sponsorship"; s: Sponsorship }
  | { type: "registration"; r: RegistrationRequest }
  | { type: "match"; m: IdentityMatchItem }
  | { type: "task"; t: GuestLifecycleItem };

/** Turns the four guest sources into inbox items; a missing source (not permitted, not loaded) adds none. */
export function guestInboxItems(src: {
  sponsorships?: Sponsorship[] | null; registrations?: RegistrationRequest[] | null; matches?: IdentityMatchItem[] | null; tasks?: GuestLifecycleItem[] | null;
}): InboxItem[] {
  const out: InboxItem[] = [];
  (src.sponsorships ?? []).forEach((s) => out.push({ kind: "guest", key: `gsp-${s.id}`, at: s.created_at, guest: { type: "sponsorship", s } }));
  (src.registrations ?? []).forEach((r) => out.push({ kind: "guest", key: `greg-${r.id}`, at: r.created_at, guest: { type: "registration", r } }));
  (src.matches ?? []).forEach((m) => out.push({ kind: "guest", key: `gmatch-${m.id}`, at: m.received_at, guest: { type: "match", m } }));
  (src.tasks ?? []).forEach((t, i) => out.push({ kind: "guest", key: `gtask-${t.task_id ?? t.sponsorship_id ?? i}`, at: t.deadline ?? "", guest: { type: "task", t } }));
  return out;
}

/**
 * What the row buttons of a guest item do. A match and the tasks other than a transfer are decided on
 * their own pages, where the evidence and the consequences are shown, so their row only links there.
 */
export function guestRowActions(g: GuestInboxItem, departure: "end" | "suspend" = "end"): { primary?: string; secondary?: string; link?: string } {
  switch (g.type) {
    case "sponsorship": return { primary: "Approve", secondary: "Reject" };
    case "registration": return { primary: "Approve", secondary: "Deny" };
    case "match": return { link: `/directory/identity-matches?selected=${encodeURIComponent(g.m.id)}` };
    case "task": {
      const a = g.t.can_act ? taskActions(g.t, departure) : [];
      return a.length ? { primary: a.find((x) => x.primary)?.label ?? a[0].label, secondary: a.find((x) => x.danger)?.label } : { link: "/governance/guest-lifecycle?view=tasks" };
    }
  }
}
