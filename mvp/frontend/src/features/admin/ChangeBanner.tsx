import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { AdminChange, AdminRecovery, BreakGlassOverview, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { unexplainedItems } from "./breakGlassState";
import { bannerItems } from "./changeState";

const SHOWN = 3;

/**
 * The persistent banner of design §15.2: while an admin change waits for approval or is cooling off,
 * or an operator recovery is pending, every admin sees it on every page, with what it is, when it
 * takes effect and where to cancel it. A break-glass sign-in nobody has explained yet stays on it
 * until an admin says why it happened (§15.4).
 */
export function ChangeBanner() {
  const { session } = useSession();
  const changes = useApi<{ change_requests: AdminChange[] }>("/admin/change-requests?status=open");
  const recoveries = useApi<{ recoveries: AdminRecovery[] }>("/admin/recovery");
  const glass = useApi<BreakGlassOverview>("/admin/break-glass");
  const [now, setNow] = useState(Date.now());
  const reloadChanges = changes.reload;
  const reloadRecoveries = recoveries.reload;
  const reloadGlass = glass.reload;
  useEffect(() => {
    const t = window.setInterval(() => { setNow(Date.now()); reloadChanges?.(); reloadRecoveries?.(); reloadGlass?.(); }, 60_000);
    return () => window.clearInterval(t);
  }, [reloadChanges, reloadRecoveries, reloadGlass]);
  const items = [
    ...unexplainedItems(glass.data?.uses ?? []),
    ...bannerItems(changes.data?.change_requests ?? [], recoveries.data?.recoveries ?? [], session.user.id, now),
  ];
  if (items.length === 0) return null;
  const urgent = items.some((i) => i.tone === "bad");
  return (
    <section className={`callout ${urgent ? "bad" : "warn"}`} role={urgent ? "alert" : "status"} aria-label="Admin items needing attention" style={{ marginBottom: 12 }}>
      <ShieldAlert size={16} aria-hidden />
      <div className="grow">
        <b>{items.length === 1 ? "One admin item needs attention" : `${items.length} admin items need attention`}</b>
        <ul className="small" style={{ margin: "4px 0 0", paddingLeft: 18 }}>
          {items.slice(0, SHOWN).map((i) => (
            <li key={i.id}>{i.text} <Link to={i.to}>Review</Link></li>
          ))}
        </ul>
        {items.length > SHOWN && <div className="small" style={{ marginTop: 4 }}><Link to="/admin/change-requests">and {items.length - SHOWN} more</Link></div>}
      </div>
    </section>
  );
}
