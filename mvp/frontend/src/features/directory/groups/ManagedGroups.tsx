import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AppWindow, Folder, FolderPlus, Plus, Users } from "lucide-react";
import { GrpFolder, GrpGroup, groups } from "../../../api";
import { useSession } from "../../../app/auth";
import { Badge, Callout, Column, Crumb, DataTable, Loading, Page, SidePanel, Tabs, useSelected } from "../../../components";
import { GroupBadges, RecomputeBanner, fmtWhen } from "./common";
import { NewApplicationDrawer, NewFolderDrawer, NewGroupDrawer } from "./forms";
import { useLoad } from "./hooks";
import { childFolders, folderLabel, folderTrail, indexFolders } from "./model";
import { ViewToggle } from "./ViewToggle";

type Row = { key: string; kind: "folder"; f: GrpFolder; items: number } | { key: string; kind: "group"; g: GrpGroup };
const LIMIT = 500;

const nameOf = (r: Row) => (r.kind === "folder" ? r.f.name : r.g.name);
const labelOf = (r: Row) => (r.kind === "folder" ? folderLabel(r.f) : r.g.display_extension || r.g.extension);

/**
 * Directory → Groups, managed view: a folder browser (breadcrumb, children with type badges and member counts) over
 * the native groups. The API returns only what the signed-in person may view, so nothing else is listed.
 */
export function ManagedGroups() {
  const { can } = useSession();
  const [params, setParams] = useSearchParams();
  const folderId = params.get("folder");
  const everywhere = params.get("all") === "1";
  const [selected, setSelected] = useSelected();
  const [creating, setCreating] = useState<"group" | "folder" | "app" | null>(null);

  const folders = useLoad(() => groups.listFolders({ limit: LIMIT }), "folders");
  const ix = useMemo(() => indexFolders(folders.data?.items ?? []), [folders.data]);
  const current = folderId ? ix.byId.get(folderId) ?? null : null;
  // the groups of the open folder (and below it when searching everywhere); at the top, those of the root folder
  const topId = ix.root?.id;
  const fetchGroups = useLoad(
    folders.data
      ? () => folderId ? groups.listGroups({ folder: folderId, scope: everywhere ? "sub" : "one", limit: LIMIT })
        : everywhere ? groups.listGroups({ limit: LIMIT })
        : topId ? groups.listGroups({ folder: topId, limit: LIMIT }) : Promise.resolve({ items: [], limit: LIMIT, offset: 0 })
      : null,
    `native:${folderId ?? "top"}:${everywhere}:${topId ?? ""}:${folders.data ? "ready" : "wait"}`,
  );

  const rows = useMemo<Row[] | null>(() => {
    if (!folders.data || !fetchGroups.data) return null;
    const shown = everywhere
      ? folders.data.items.filter((f) => (current ? f.name.startsWith(`${current.name}:`) : f.name !== ""))
      : childFolders(ix, folderId);
    const fs: Row[] = shown.map((f) => ({ key: `f:${f.id}`, kind: "folder", f, items: ix.children.get(f.id)?.length ?? 0 }));
    const gs: Row[] = fetchGroups.data.items.map((g) => ({ key: `g:${g.id}`, kind: "group", g }));
    const byName = (a: Row, b: Row) => nameOf(a).localeCompare(nameOf(b));
    return [...fs.sort(byName), ...gs.sort(byName)];
  }, [folders.data, fetchGroups.data, ix, current, folderId, everywhere]);

  const trail = folderTrail(ix, folderId);
  const crumbs: Crumb[] = [["Identity"], trail.length ? ["Groups", "/directory/groups"] : ["Groups"],
    ...trail.map((f, i): Crumb => (i < trail.length - 1 ? [folderLabel(f), `/directory/groups?folder=${f.id}`] : [folderLabel(f)]))];
  const open = rows?.find((r) => r.key === selected) ?? null;
  const writable = can("groups.write");
  const setParam = (k: string, v: string | null) => setParams((p) => { const n = new URLSearchParams(p); if (v === null) n.delete(k); else n.set(k, v); n.delete("selected"); return n; }, { replace: true });

  const cols: Column<Row>[] = [
    {
      id: "name", header: "Name", sort: (r) => nameOf(r).toLowerCase(), csv: (r) => nameOf(r),
      cell: (r) => r.kind === "folder"
        ? <Link to={`/directory/groups?folder=${r.f.id}`} className="row tight" onClick={(e) => e.stopPropagation()}><Folder size={14} aria-hidden /><span>{labelOf(r)}</span></Link>
        : <Link to={`/directory/groups/${r.g.id}`} className="row tight" onClick={(e) => e.stopPropagation()}><Users size={14} aria-hidden /><span>{labelOf(r)}</span></Link>,
    },
    { id: "kind", header: "Type", sort: (r) => (r.kind === "folder" ? "0" : r.g.definition), cell: (r) => r.kind === "folder" ? <Badge tone="outline">Folder</Badge> : <span className="row tight"><GroupBadges g={r.g} /></span> },
    { id: "members", header: "Members", num: true, sort: (r) => (r.kind === "group" ? r.g.effective_count : -1), csv: (r) => (r.kind === "group" ? r.g.effective_count : ""), cell: (r) => r.kind === "group" ? r.g.effective_count.toLocaleString("en-US") : <span className="faint">{r.items} {r.items === 1 ? "folder" : "folders"}</span> },
    { id: "path", header: "Full name", sort: (r) => nameOf(r), cell: (r) => <span className="sys xs truncate" style={{ maxWidth: 360 }}>{nameOf(r)}</span>, hideNarrow: true },
  ];

  return (
    <Page
      title="Groups"
      count={rows ? `${rows.length}${fetchGroups.data && fetchGroups.data.items.length >= LIMIT ? "+" : ""} ${rows.length === 1 ? "item" : "items"}` : undefined}
      crumbs={crumbs}
      sub="Managed groups live in folders. Open a folder to browse it, or a group to see its members."
    >
      <DataTable<Row>
        id="managed-groups"
        rows={rows}
        error={folders.error ?? fetchGroups.error}
        rowKey={(r) => r.key}
        columns={cols}
        searchText={(r) => `${nameOf(r)} ${r.kind === "group" ? r.g.display_name + " " + r.g.description : r.f.display_name + " " + r.f.description}`}
        searchPlaceholder={everywhere ? "Search every folder below here…" : "Search this folder…"}
        filters={[
          { id: "kind", label: "Type", options: [{ value: "folder", label: "Folders" }, { value: "group", label: "Groups and roles" }], get: (r) => r.kind },
          { id: "def", label: "Definition", options: [{ value: "basic", label: "Basic" }, { value: "composite", label: "Composite" }, { value: "policy", label: "Policy" }], get: (r) => (r.kind === "group" ? r.g.definition : null) },
          { id: "role", label: "Group or role", options: [{ value: "group", label: "Group" }, { value: "role", label: "Role" }], get: (r) => (r.kind === "group" ? r.g.type : null) },
          { id: "status", label: "Status", options: [{ value: "active", label: "Active" }, { value: "disabled", label: "Disabled" }], get: (r) => (r.kind === "group" ? r.g.status : null) },
        ]}
        commands={[
          writable && { label: "New group", icon: <Plus size={16} />, onClick: () => setCreating("group"), disabled: !current, title: current ? undefined : "Open a folder first" },
          writable && { label: "New folder", icon: <FolderPlus size={16} />, onClick: () => setCreating("folder") },
          writable && { label: "New application", icon: <AppWindow size={16} />, onClick: () => setCreating("app"), title: "Create the standard folders and groups of an application" },
        ]}
        onRefresh={() => { folders.reload(); fetchGroups.reload(); }}
        rowLabel={nameOf}
        onRowClick={(r) => setSelected(r.key)}
        activeKey={selected}
        toolbarExtra={
          <>
            <ViewToggle />
            <label className="row tight small">
              <input type="checkbox" style={{ width: 24, height: 24 }} checked={everywhere} onChange={(e) => setParam("all", e.target.checked ? "1" : null)} />
              <span>{current ? "Include subfolders" : "Search every folder"}</span>
            </label>
          </>
        }
        empty={<EmptyFolder writable={writable} inFolder={!!current} />}
      />
      {fetchGroups.data && fetchGroups.data.items.length >= LIMIT && <Callout tone="warn">Only the first {LIMIT} groups are listed. Open a folder to narrow the list.</Callout>}
      {open && <Panel row={open} onClose={() => setSelected(null)} />}
      {creating === "folder" && <NewFolderDrawer parent={current} onClose={() => setCreating(null)} />}
      {creating === "group" && current && <NewGroupDrawer folder={current} onClose={() => setCreating(null)} />}
      {creating === "app" && <NewApplicationDrawer parent={current} onClose={() => setCreating(null)} />}
    </Page>
  );
}

function EmptyFolder({ writable, inFolder }: { writable: boolean; inFolder: boolean }) {
  return (
    <div className="empty" style={{ padding: 24, textAlign: "center" }}>
      <h2 style={{ fontSize: "var(--fs-xl)" }}>{inFolder ? "This folder is empty" : "No managed groups yet"}</h2>
      <p className="muted">{writable ? "Create a folder or a group, or start from the standard layout with New application." : "Folders and groups you are allowed to view appear here."}</p>
    </div>
  );
}

/** The side panel of a row: a short summary; the full page has every tab. */
function Panel({ row, onClose }: { row: Row; onClose: () => void }) {
  if (row.kind === "folder") {
    const f = row.f;
    return (
      <SidePanel title={folderLabel(f)} sub={<><Badge tone="outline">Folder</Badge><span className="sys">{f.name}</span></>} onClose={onClose} fullHref={`/directory/groups/folders/${f.id}`} fullLabel="Open folder page">
        <p className="muted">{f.description || "No description."}</p>
        <dl className="kv">
          <dt>Full name</dt><dd className="sys">{f.name}</dd>
          <dt>Subfolders</dt><dd>{row.items}</dd>
          <dt>Owner</dt><dd>{f.data_owner ?? "None"}</dd>
          <dt>Managed by</dt><dd>{f.managed_by.replace(/_/g, " ")}</dd>
          <dt>Created</dt><dd>{fmtWhen(f.created_at)}</dd>
        </dl>
        <p><Link to={`/directory/groups?folder=${f.id}`}>Browse this folder</Link></p>
      </SidePanel>
    );
  }
  return <GroupPanel g={row.g} onClose={onClose} />;
}

function GroupPanel({ g, onClose }: { g: GrpGroup; onClose: () => void }) {
  const [tab, setTab] = useState<"overview" | "members">("overview");
  const members = useLoad(tab === "members" ? () => groups.members(g.id, { filter: "effective", limit: 10, sort: "name" }) : null, `panelmembers:${g.id}`);
  return (
    <SidePanel
      title={g.display_name || g.extension}
      sub={<><GroupBadges g={g} /></>}
      onClose={onClose}
      fullHref={`/directory/groups/${g.id}`}
      fullLabel="Open group page"
      tabs={<Tabs label="Group summary" value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "members", label: "Members" }]} />}
    >
      {tab === "overview" ? (
        <div className="stack">
          <RecomputeBanner state={g.recompute_state} />
          <p className="muted">{g.description || "No description."}</p>
          <dl className="kv">
            <dt>Full name</dt><dd className="sys">{g.name}</dd>
            <dt>Members</dt><dd>{g.effective_count.toLocaleString("en-US")}</dd>
            <dt>Owner</dt><dd>{g.data_owner ?? "None"}</dd>
            <dt>Requestable</dt><dd>{g.requestable ? "Yes" : "No"}</dd>
            <dt>Created</dt><dd>{fmtWhen(g.created_at)}</dd>
          </dl>
        </div>
      ) : !members.data ? <Loading error={members.error} kind="block" /> : (
        <div className="stack-sm">
          <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {(members.data.items as { identity_id: number; name: string }[]).map((m) => <li key={m.identity_id} className="small" style={{ padding: "3px 0" }}>{m.name}</li>)}
          </ul>
          {members.data.items.length === 0 && <p className="muted">No members.</p>}
          {members.data.total > 10 && <p className="small faint">and {(members.data.total - 10).toLocaleString("en-US")} more. <Link to={`/directory/groups/${g.id}`}>See all</Link></p>}
        </div>
      )}
    </SidePanel>
  );
}
