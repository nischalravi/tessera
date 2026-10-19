import { useNavigate } from "react-router-dom";
import { AppNotification, markNotificationsRead } from "../../api";
import { useToast } from "../../components/Toast";

/** Open a notification: mark it read, then go where it points. */
export function useOpenNotification() {
  const nav = useNavigate();
  const toast = useToast();
  return async (n: AppNotification) => {
    if (!n.read_at) {
      try {
        await markNotificationsRead({ ids: [n.id] });
      } catch (e) {
        toast((e as Error).message, { kind: "error" });
      }
    }
    if (n.link) nav(n.link);
  };
}
