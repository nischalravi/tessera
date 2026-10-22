import { useState } from "react";
import { Link } from "react-router-dom";
import { Plus } from "lucide-react";
import { GrpLoader, groupLoaders } from "../../../api";
import { useSession } from "../../../app/auth";
import { Badge, Callout, DataTable, Page, SidePanel, useSelected } from "../../../components";
import { useLoad } from "./hooks";
import { LoaderPanel } from "./LoaderPanel";
import { LoaderWizard } from "./LoaderWizard";
import { RUN_STATUS_LABEL, lagText, loaderState, runSummary, scheduleText, typeLabel } from "./loaderModel";

/**
 * Directory → Groups → Loaders: every membership source the caller may see, with its status. Held runs are called
 * out first, since a person has to decide them. A row opens the loader in a side panel.
 */
export function LoadersPage() {
  const { can } = useSession();
  const [selected, setSelected] = useSelected();
  const [adding, setAdding] = useState(false);
  const list = useLoad(() => groupLoaders.list(), "loaders");
  const rows = list.data?.items ?? null;
  const open = rows?.find((l) => l.id === selected) ?? null;
  const held = (rows ?? []).filter((l) => l.status === "held" || l.job?.state === "held");

  return (
    <Page title="Membership sources" crumbs={[["Identity"], ["Groups", "/directory/groups"], ["Loaders"]]}
      sub="Loaders read a database, a CSV file, a connected system or an identity attribute on a schedule and keep groups in sync.">
      <div className="stack">
        {held.length > 0 && (
          <Callout tone="warn">
            {held.length === 1 ? `${held[0].name} has` : `${held.length} loaders have`} a run held by a failsafe. Nothing was applied; open {held.length === 1 ? "it" : "each"} to approve or reject it.
          </Callout>
        )}
        <DataTable<GrpLoader>
          id="group-loaders"
          rows={rows}
          error={list.error}
          onRefresh={list.reload}
          rowKey={(l) => l.id}
          activeKey={open?.id}
          onRowClick={(l) => setSelected(l.id)}
          rowLabel={(l) => l.name}
          commands={[can("groups.loader.admin") && { label: "Add a source", icon: <Plus size={16} />, onClick: () => setAdding(true) }]}
          columns={[
            { id: "name", header: "Loader", sort: (l) => l.name, cell: (l) => <b>{l.name}</b> },
            { id: "type", header: "Kind", sort: (l) => l.type, hideNarrow: true, cell: (l) => <span className="small">{typeLabel(l.type)}{l.requires_approval && <> <Badge tone="warning" title="Changes need a second admin">SQL</Badge></>}</span> },
            { id: "folder", header: "Folder", sort: (l) => l.target_folder, hideNarrow: true, cell: (l) => <span className="sys small">{l.target_folder || "(root)"}</span> },
            { id: "status", header: "State", sort: (l) => loaderState(l).label, cell: (l) => { const s = loaderState(l); return <Badge tone={s.tone} dot>{s.label}</Badge>; } },
            { id: "last", header: "Last run", hideNarrow: true, csv: (l) => (l.job?.last_run ? `${l.job.last_run.status} ${runSummary(l.job.last_run)}` : ""),
              sort: (l) => l.job?.last_run?.started_at ?? "",
              cell: (l) => l.job?.last_run ? <span className="small">{RUN_STATUS_LABEL[l.job.last_run.status] ?? l.job.last_run.status}: {runSummary(l.job.last_run)}</span> : <span className="faint small">No run yet</span> },
            { id: "loaded", header: "Loaded", hideNarrow: true, sort: (l) => l.job?.lag_seconds ?? Number.MAX_SAFE_INTEGER, cell: (l) => <span className="small">{lagText(l.job?.lag_seconds)}</span> },
            { id: "schedule", header: "Schedule", hideNarrow: true, sort: (l) => l.schedule, cell: (l) => <span className="small">{scheduleText(l.schedule)}</span> },
          ]}
          searchText={(l) => `${l.name} ${l.type} ${typeLabel(l.type)} ${l.target_folder}`}
          searchPlaceholder="Search loaders…"
          filters={[
            { id: "state", label: "State", options: [{ value: "On", label: "On" }, { value: "Off", label: "Off" }, { value: "Held", label: "Held" }, { value: "Last run failed", label: "Last run failed" }], get: (l) => loaderState(l).label },
            { id: "type", label: "Kind", options: ["sql_simple", "sql_group_list", "csv", "connector_groups", "attribute", "recent_memberships"].map((value) => ({ value, label: typeLabel(value) })), get: (l) => l.type },
          ]}
          empty={<>No loaders yet. Open a group's Source tab, or choose Add a source. Hand-edited groups are listed under <Link to="/directory/groups">Groups</Link>.</>}
        />
      </div>
      {open && (
        <SidePanel title={open.name} sub={<span className="row tight">{typeLabel(open.type)}</span>} fullHref={`/directory/groups?folder=${open.target_folder_id}`} fullLabel="Open the folder" onClose={() => setSelected(null)}>
          <LoaderPanel loader={open} onChanged={list.reload} />
        </SidePanel>
      )}
      {adding && <LoaderWizard onClose={() => setAdding(false)} onSaved={() => list.reload()} />}
    </Page>
  );
}
