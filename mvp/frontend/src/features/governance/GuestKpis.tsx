import { GuestLifecycleOverview, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Kpi } from "../../components";
import { kpiTiles } from "./guestLifecycleModel";

/**
 * Guests at a glance on Governance → Lifecycle (guest accounts design §9.4): what is about to end, what
 * waits for a person, who was hired and who is in their grace period. Each tile opens that list on the
 * Guest lifecycle page. Counts come from the same endpoint as that page, so they always agree.
 */
export function GuestKpis() {
  const { can } = useSession();
  const { data } = useApi<GuestLifecycleOverview>(can("guests.read") ? "/guest-lifecycle" : null);
  if (!data) return null;
  return (
    <section aria-label="Guests" className="mt">
      <h2 className="h3" style={{ marginBottom: 8 }}>Guests</h2>
      <div className="grid g4">
        {kpiTiles(data.counts).map((t) => <Kpi key={t.bucket} label={t.label} value={t.value} sub={t.sub} tone={t.tone} to={`/governance/guest-lifecycle?view=${t.bucket}`} />)}
      </div>
    </section>
  );
}
