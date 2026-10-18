import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { AdminChange, AdminRecovery, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { bannerItems } from "./changeState";

const SHOWN = 3;

/**
 * The persistent banner of design §15.2: while an admin change waits for approval or is cooling off,
 * or an operator recovery is pending, every admin sees it on every page, with what it is, when it
 * takes effect and where to cancel it.
 */
export function ChangeBanner() {
  const { session } = useSession();
  const changes = useApi<{ change_requests: AdminChange[] }>("/admin/change-requests?status=open");
  const recoveries = useApi<{ recoveries: AdminRecovery[] }>("/admin/recovery");
  const [now, setNow] = useState(Date.now());
  const reloadChanges = changes.reload;
  const reloadRecoveries = recoveries.reload;
  useEffect(() => {
    const t = window.setInterval(() => { setNow(Date.now()); reloadChanges?.(); reloadRecoveries?.(); }, 60_000);
    return () => window.clearInterval(t);
  }, [reloadChanges, reloadRecoveries]);
  const items = bannerItems(changes.data?.change_requests ?? [], recoveries.data?.recoveries ?? [], session.user.id, now);
  if (items.length === 0) return null;
  const urgent = items.some((i) => i.tone === "bad");
  return (
    <section className={`callout ${urgent ? "bad" : "warn"}`} role={urgent ? "alert" : "status"} aria-label="Admin changes in progress" style={{ marginBottom: 12 }}>
      <ShieldAlert size={16} aria-hidden />
      <div className="grow">
        <b>{items.length === 1 ? "An admin change is in progress" : `${items.length} admin changes are in progress`}</b>
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
