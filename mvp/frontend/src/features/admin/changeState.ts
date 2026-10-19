// What an admin may do with a change request, and what the persistent banner says about the open
// ones (design §15.2). Pure functions, so `npm test` covers them. The API enforces every rule
// itself; these only decide which buttons to offer.
import type { AdminChange, AdminRecovery } from "../../api";

const utc = (s: string) => new Date(s.endsWith("Z") ? s : s + "Z").getTime();

/** A second admin approves: never the requester, and only a two-person request that still waits. */
export const canApprove = (c: AdminChange, me: string) => c.status === "pending_approval" && c.two_person && c.requested_by.id !== me;

/** Any other admin rejects a request that waits for approval; the requester cancels instead. */
export const canReject = canApprove;

/** Any admin cancels a request that waits or is cooling off. */
export const canCancel = (c: AdminChange) => c.status === "pending_approval" || c.status === "cooling_off";

/** A cooling-off request can be applied by hand once its effective time has passed. */
export const canApply = (c: AdminChange, now: number) => c.status === "cooling_off" && !!c.effective_at && utc(c.effective_at) <= now;

/** "in 3 h 20 min", "in 45 min", "now": the time left until an ISO timestamp. */
export function timeLeft(iso: string, now: number): string {
  const ms = utc(iso) - now;
  if (ms <= 0) return "now";
  const min = Math.ceil(ms / 60000);
  if (min < 60) return `in ${min} min`;
  const h = Math.floor(min / 60);
  const m = min % 60;
  return h >= 96 ? `in ${Math.round(h / 24)} d` : m ? `in ${h} h ${m} min` : `in ${h} h`;
}

export interface BannerItem {
  id: string;
  tone: "warn" | "bad" | "neutral";
  text: string;
  /** Where to act on it. */
  to: string;
}

/**
 * The banner lines for the changes that are pending or cooling off and the recovery in flight,
 * most urgent first: a recovery nobody asked for outranks everything.
 */
export function bannerItems(changes: AdminChange[], recoveries: AdminRecovery[], me: string, now: number): BannerItem[] {
  const out: BannerItem[] = [];
  for (const r of recoveries) {
    if (r.status !== "pending") continue;
    out.push({
      id: `recovery:${r.id}`, tone: "bad", to: "/admin/change-requests",
      text: `Operator recovery requested (ticket ${r.ticket}). A recovery invitation becomes usable ${timeLeft(r.not_before, now)}. If you did not expect this, cancel it.`,
    });
  }
  for (const c of changes) {
    if (c.status === "pending_approval") {
      out.push({
        id: c.id, tone: "warn", to: `/admin/change-requests?selected=${c.id}`,
        text: c.requested_by.id === me
          ? `Your request is waiting for a second admin: ${c.summary}. It expires ${timeLeft(c.expires_at, now)}.`
          : `Needs your review: ${c.summary} (requested by ${c.requested_by.display_name}). It expires ${timeLeft(c.expires_at, now)}.`,
      });
    } else if (c.status === "cooling_off" && c.effective_at) {
      out.push({
        id: c.id, tone: "neutral", to: `/admin/change-requests?selected=${c.id}`,
        text: `${c.summary} takes effect ${timeLeft(c.effective_at, now)}. Any admin can cancel it until then.`,
      });
    }
  }
  return out;
}

/** The label of a status. */
export const STATUS_LABEL: Record<AdminChange["status"], string> = {
  pending_approval: "Awaiting approval", cooling_off: "Cooling off", applied: "Applied", rejected: "Rejected",
  cancelled: "Cancelled", expired: "Expired", failed: "Failed",
};
