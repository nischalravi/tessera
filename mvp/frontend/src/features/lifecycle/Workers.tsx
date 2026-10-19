/**
 * Contractors & guests (issue #159): everyone who is not a plain employee, with their sponsor and
 * end date. "Ending soon" is the default view; "Sponsored by me" lists the people the signed-in
 * user is accountable for. Ending a term runs the leaver plan.
 */
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { CalendarClock, Plus, Timer } from "lucide-react";
import { Lifecycle, LifecycleList, fmtDay, lifecycle, useApi } from "../../api";
import { Column, DataTable, EmptyState, Page, SidePanel, Tabs, useSelected, useToast } from "../../components";
import { LifecycleSection, SetLifecycleDrawer, StateBadge, WORKER_LABEL } from "./parts";

type Tab = "ending" | "all" | "sponsored";

const cols: Column<Lifecycle>[] = [
  { id: "person", header: "Person", sort: (l) => l.person.name, cell: (l) => <span className="name-link">{l.person.name}</span> },
  { id: "type", header: "Worker type", sort: (l) => l.worker_type, cell: (l) => <span className="small">{WORKER_LABEL[l.worker_type]}</span> },
  { id: "org", header: "Organization", sort: (l) => l.organization ?? "", cell: (l) => <span className="small">{l.organization ?? <span className="faint">-</span>}</span>, hideNarrow: true },
  { id: "sponsor", header: "Sponsor", sort: (l) => l.sponsor?.name ?? "", cell: (l) => <span className="small">{l.sponsor?.name ?? <span className="faint">-</span>}</span>, hideNarrow: true },
  { id: "ends", header: "Ends", sort: (l) => l.ends_at ?? "9999", csv: (l) => l.ends_at ?? "", cell: (l) => <span className="small nowrap">{l.ends_at ? fmtDay(l.ends_at) : "-"}</span> },
  { id: "state", header: "Status", sort: (l) => l.days_left ?? 99999, csv: (l) => l.state, cell: (l) => <StateBadge l={l} /> },
];

export function Workers() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") ?? "ending") as Tab;
  const all = useApi<LifecycleList>(tab === "sponsored" ? null : lifecycle.paths.list(tab === "ending" ? "ending" : undefined));
  const mine = useApi<Lifecycle[]>(tab === "sponsored" ? lifecycle.paths.sponsored : null);
  const rows = tab === "sponsored" ? mine.data : (all.data?.rows.filter((l) => l.worker_type !== "employee" || l.ends_at) ?? null);
  const error = tab === "sponsored" ? mine.error : all.error;
  const reload = tab === "sponsored" ? mine.reload : all.reload;
  const canManage = all.data?.can_manage ?? false;
  const [selected, setSelected] = useSelected();
  const open = rows?.find((l) => String(l.person.id) === selected);
  const [adding, setAdding] = useState(false);
  const toast = useToast();
  const sweep = async () => {
    try {
      const r = await lifecycle.sweep();
      toast(`Sweep done: ${r.warned} warning${r.warned === 1 ? "" : "s"} sent, ${r.ended} term${r.ended === 1 ? "" : "s"} ended`);
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    }
  };
  return (
    <Page title="Contractors & guests" crumbs={[["Identity"], ["Contractors & guests"]]}
      sub="People who are not employees, or whose access ends on a date. Sponsors are warned 14, 7 and 1 days before; on the end date the leaver plan runs.">
      <Tabs label="Views" value={tab} onChange={(v) => setParams(v === "ending" ? {} : { tab: v })}
        tabs={[{ id: "ending", label: "Ending soon" }, { id: "all", label: "Everyone" }, { id: "sponsored", label: "Sponsored by me" }]} />
      <DataTable
        id={`workers-${tab}`}
        rows={rows}
        error={error}
        rowKey={(l) => String(l.person.id)}
        columns={cols}
        initialSort={["state", 1]}
        searchText={(l) => `${l.person.name} ${l.organization ?? ""} ${l.sponsor?.name ?? ""} ${l.worker_type}`}
        searchPlaceholder="Search people, organizations or sponsors…"
        filters={[
          { id: "type", label: "Worker type", options: Object.entries(WORKER_LABEL).map(([value, label]) => ({ value, label })), get: (l) => l.worker_type },
          { id: "state", label: "Status", options: [{ value: "upcoming", label: "Not started" }, { value: "active", label: "Active" }, { value: "ending", label: "Ending soon" }, { value: "ended", label: "Ended" }], get: (l) => l.state },
        ]}
        commands={[
          canManage && { label: "Add contractor or guest", icon: <Plus size={16} />, onClick: () => setAdding(true) },
          canManage && { label: "Run expiry sweep", icon: <Timer size={16} />, onClick: sweep, title: "Send due warnings and end due terms now (the background sweeper also does this)" },
        ]}
        onRefresh={reload}
        rowLabel={(l) => l.person.name}
        onRowClick={(l) => setSelected(String(l.person.id))}
        activeKey={selected}
        empty={tab === "sponsored"
          ? <EmptyState title="You sponsor nobody" icon={<CalendarClock size={18} />}>People you are accountable for (contractors, partners, guests) show here, with their end dates.</EmptyState>
          : <EmptyState title={tab === "ending" ? "Nobody ends in the next 14 days" : "No contractors or guests"} icon={<CalendarClock size={18} />}>Set a worker type and end date on a person, or import them from the HRIS.</EmptyState>}
      />
      {open && (
        <SidePanel title={open.person.name} sub={<><span className="small">{WORKER_LABEL[open.worker_type]}</span><StateBadge l={open} /></>} onClose={() => setSelected(null)}
          fullHref={`/directory/identities/${open.person.id}`}>
          <LifecycleSection id={open.person.id} />
        </SidePanel>
      )}
      {adding && <SetLifecycleDrawer onClose={() => setAdding(false)} />}
    </Page>
  );
}
