/**
 * The signed-in user's notifications (issue #189): the inbox behind the top-bar bell.
 * It refreshes every minute and whenever the tab regains focus; any write also refreshes it
 * (useApi listens for those), so approving a request updates the count at once.
 */
import { useEffect } from "react";
import { NOTIFICATIONS_PATH, NotificationList, useApi } from "../../api";

const POLL_MS = 60_000;

export function useNotifications() {
  const q = useApi<NotificationList>(NOTIFICATIONS_PATH);
  const { reload } = q;
  useEffect(() => {
    const tick = window.setInterval(() => reload(), POLL_MS);
    const focus = () => document.visibilityState === "visible" && reload();
    document.addEventListener("visibilitychange", focus);
    return () => {
      window.clearInterval(tick);
      document.removeEventListener("visibilitychange", focus);
    };
  }, [reload]);
  return q;
}

/** What a notification kind is about, for the icon-less label in lists. */
export const KIND_LABEL: Record<string, string> = {
  "request.approval_needed": "Approval needed",
  "request.approved": "Approved",
  "request.denied": "Denied",
  "request.expiring": "Access ending",
  "approval.escalated": "Escalated",
  "approval.delegated": "Delegated to you",
  "review.launched": "Access review",
  "review.reminder": "Review reminder",
  "review.closed": "Review closed",
  "jit.granted": "Just-in-time",
  "jit.denied": "Just-in-time",
  "jit.expiring": "Just-in-time",
  "access.ending": "End date",
  "security.alert": "Security alert",
};
