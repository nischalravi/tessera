import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { AppWindow, Folder, FolderPlus, Plus, RotateCcw, Trash2, Users } from "lucide-react";
import { ApiError, GrpFolder, GrpGroup, groups } from "../../../api";
import { useSession } from "../../../app/auth";
import { Badge, Button, Callout, Column, Crumb, DataTable, Loading, Page, SidePanel, Tabs, useConfirm, useSelected, useToast } from "../../../components";
import { GroupBadges, RecomputeBanner, fmtWhen } from "./common";
import { NewApplicationDrawer, NewFolderDrawer, NewGroupDrawer } from "./forms";
import { failureOf, useDeleteTree, usePurgeGroups } from "./deletes";
import { errText, useLoad } from "./hooks";
import { childFolders, deleteBody, deleteTitle, failureSummary, folderLabel, folderTrail, indexFolders, isNotEmpty, planDeleted, planDelete } from "./model";
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
  const toast = useToast();
  const confirm = useConfirm();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const folderId = params.get("folder");
  const everywhere = params.get("all") === "1";
  const showDeleted = params.get("deleted") === "1";
  const [selected, setSelected] = useSelected();
  const [creating, setCreating] = useState<"group" | "folder" | "app" | null>(null);
  // folders a delete left in place because they still hold something: offered "delete everything in it"
  const [notEmpty, setNotEmpty] = useState<GrpFolder[]>([]);
  const purge = usePurgeGroups();
  const deleteTree = useDeleteTree();

  const folders = useLoad(() => groups.listFolders({ limit: LIMIT }), "folders");
  const ix = useMemo(() => indexFolders(folders.data?.items ?? []), [folders.data]);
  const current = folderId ? ix.byId.get(folderId) ?? null : null;
  // the groups of the open folder (and below it when searching everywhere); at the top, those of the root folder
  const topId = ix.root?.id;
  const fetchGroups = useLoad(
    folders.data
      ? () => folderId ? groups.listGroups({ folder: folderId, scope: everywhere ? "sub" : "one", deleted: showDeleted, limit: LIMIT })
        : everywhere ? groups.listGroups({ deleted: showDeleted, limit: LIMIT })
        : topId ? groups.listGroups({ folder: topId, deleted: showDeleted, limit: LIMIT }) : Promise.resolve({ items: [], limit: LIMIT, offset: 0 })
      : null,
    `native:${folderId ?? "top"}:${everywhere}:${showDeleted}:${topId ?? ""}:${folders.data ? "ready" : "wait"}`,
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

  /** Delete what was picked: groups first (soft delete), then folders deepest first; one toast for the failures. */
  const deleteRows = async (picked: Row[]) => {
    const plan = planDelete(picked);
    if (plan.groups.length + plan.folders.length === 0) {
      toast(`Nothing to delete here: ${plan.skipped.join(", ")} ${plan.skipped.length === 1 ? "is" : "are"} already deleted or managed elsewhere. Use Delete permanently to remove a deleted group.`, { kind: "error" });
      return;
    }
    const ok = await confirm({ title: deleteTitle(plan), body: deleteBody(plan), confirmLabel: "Delete", danger: true });
    if (ok === null) return;
    const failed: { name: string; message: string }[] = [];
    const stuck: GrpFolder[] = [];
    let done = 0;
    for (const g of plan.groups) {
      try { await groups.deleteGroup(g.id); done++; } catch (e) { failed.push(failureOf(g.name, e)); }
    }
    for (const f of plan.folders) {
      try { await groups.deleteFolder(f.id); done++; } catch (e) {
        failed.push(failureOf(f.name, e));
        if (e instanceof ApiError && isNotEmpty(e.code)) stuck.push(f);
      }
    }
    if (failed.length) toast(`${done ? `Deleted ${done}. ` : ""}Could not delete ${failed.length}: ${failureSummary(failed)}`, { kind: "error" });
    else toast(done === 1 ? "Deleted" : `Deleted ${done} items`);
    setNotEmpty(stuck);
    setSelected(null);
    folders.reload();
    fetchGroups.reload();
  };
  /** Restore or permanently delete the deleted groups among the picked rows. */
  const restoreRows = async (picked: Row[]) => {
    const plan = planDeleted(picked.map((r) => (r.kind === "folder" ? { kind: "folder" as const, f: r.f } : { kind: "group" as const, g: r.g })));
    if (plan.groups.length === 0) {
      toast("Nothing to restore: only a deleted group can be restored. Turn on Show deleted to find them.", { kind: "error" });
      return;
    }
    const failed: { name: string; message: string }[] = [];
    let done = 0;
    for (const g of plan.groups) {
      try { await groups.restoreGroup(g.id); done++; } catch (e) { failed.push(failureOf(g.name, e)); }
    }
    if (failed.length) toast(`${done ? `Restored ${done}. ` : ""}Could not restore ${failed.length}: ${failureSummary(failed)}`, { kind: "error" });
    else toast(done === 1 ? "Group restored" : `${done} groups restored`);
    setSelected(null);
    fetchGroups.reload();
  };
  const purgeRows = async (picked: Row[]) => {
    const plan = planDeleted(picked.map((r) => (r.kind === "folder" ? { kind: "folder" as const, f: r.f } : { kind: "group" as const, g: r.g })));
    const res = await purge(plan.groups, plan.skipped);
    if (res === null) return;
    setSelected(null);
    folders.reload();
    fetchGroups.reload();
  };
  const deleteTreeOf = async (f: GrpFolder) => {
    const res = await deleteTree(f);
    if (!res) return;
    setNotEmpty((l) => l.filter((x) => x.id !== f.id));
    setSelected(null);
    if (res === "deleted" && current && (current.id === f.id || current.name.startsWith(`${f.name}:`))) {
      const parent = f.parent_id ? ix.byId.get(f.parent_id) : null;
      nav(parent && parent.name !== "" ? `/directory/groups?folder=${parent.id}` : "/directory/groups");
    }
    folders.reload();
    fetchGroups.reload();
  };
  const restoreGroup = async (g: GrpGroup) => {
    try {
      await groups.restoreGroup(g.id);
      toast("Group restored");
      setSelected(null);
      fetchGroups.reload();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };
  const deleteCurrent = async () => {
    if (!current) return;
    const parent = current.parent_id ? ix.byId.get(current.parent_id) : null;
    await deleteRows([{ key: `f:${current.id}`, kind: "folder", f: current, items: 0 }]);
    const left = await groups.listFolders({ limit: LIMIT }).catch(() => null);
    if (left && !left.items.some((f) => f.id === current.id)) nav(parent && parent.name !== "" ? `/directory/groups?folder=${parent.id}` : "/directory/groups");
  };
  const managedByUi = (r: Row) => (r.kind === "folder" ? r.f.managed_by : r.g.managed_by) === "ui";

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
          { id: "status", label: "Status", options: [{ value: "active", label: "Active" }, { value: "disabled", label: "Disabled" }, ...(showDeleted ? [{ value: "deleted", label: "Deleted" }] : [])], get: (r) => (r.kind === "group" ? r.g.status : null) },
        ]}
        commands={[
          writable && { label: "New group", icon: <Plus size={16} />, onClick: () => setCreating("group"), disabled: !current, title: current ? undefined : "Open a folder first" },
          writable && { label: "New folder", icon: <FolderPlus size={16} />, onClick: () => setCreating("folder") },
          writable && { label: "New application", icon: <AppWindow size={16} />, onClick: () => setCreating("app"), title: "Create the standard folders and groups of an application" },
          writable && current && { label: "Delete this folder", icon: <Trash2 size={16} />, danger: true, onClick: deleteCurrent, disabled: current.managed_by !== "ui", title: current.managed_by !== "ui" ? `Managed by ${current.managed_by.replace(/_/g, " ")}, so changed there` : "Only an empty folder can be deleted" },
          writable && current && { label: "Delete folder and everything in it…", icon: <Trash2 size={16} />, danger: true, onClick: () => deleteTreeOf(current), disabled: current.managed_by !== "ui", title: current.managed_by !== "ui" ? `Managed by ${current.managed_by.replace(/_/g, " ")}, so changed there` : "Delete this folder with its subfolders and groups" },
        ]}
        bulkActions={writable ? [
          { label: "Delete", icon: <Trash2 size={16} />, danger: true, run: deleteRows },
          ...(showDeleted ? [
            { label: "Restore", icon: <RotateCcw size={16} />, run: restoreRows },
            { label: "Delete permanently", icon: <Trash2 size={16} />, danger: true, run: purgeRows },
          ] : []),
        ] : undefined}
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
            <label className="row tight small">
              <input type="checkbox" style={{ width: 24, height: 24 }} checked={showDeleted} onChange={(e) => setParam("deleted", e.target.checked ? "1" : null)} />
              <span>Show deleted</span>
            </label>
          </>
        }
        empty={<EmptyFolder writable={writable} inFolder={!!current} />}
      />
      {notEmpty.map((f) => (
        <Callout key={f.id} tone="warn">
          <div className="row" style={{ justifyContent: "space-between", gap: 12 }}>
            <span><strong className="sys">{f.name}</strong> was not deleted because it still holds something. Remove it together with everything in it, or restore or delete its groups first.</span>
            <Button variant="danger" icon={<Trash2 size={16} />} onClick={() => deleteTreeOf(f)}>Delete folder and everything in it…</Button>
          </div>
        </Callout>
      ))}
      {fetchGroups.data && fetchGroups.data.items.length >= LIMIT && <Callout tone="warn">Only the first {LIMIT} groups are listed. Open a folder to narrow the list.</Callout>}
      {open && <Panel row={open} onClose={() => setSelected(null)} canDelete={writable && managedByUi(open)} onDelete={() => deleteRows([open])} onDeleteTree={writable && open.kind === "folder" && managedByUi(open) ? () => deleteTreeOf(open.f) : undefined}
        onRestore={writable && open.kind === "group" && open.g.status === "deleted" && managedByUi(open) ? () => restoreGroup(open.g) : undefined}
        onPurge={writable && open.kind === "group" && open.g.status === "deleted" && managedByUi(open) ? () => purgeRows([open]) : undefined} />}
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
interface PanelActions { canDelete: boolean; onDelete: () => void; onRestore?: () => void; onPurge?: () => void; onDeleteTree?: () => void }

function PanelActions({ canDelete, onDelete, onRestore, onPurge, onDeleteTree, managedBy }: PanelActions & { managedBy: string }) {
  if (onRestore || onPurge) {
    return (
      <div className="row" style={{ flexWrap: "wrap" }}>
        {onRestore && <Button icon={<RotateCcw size={16} />} onClick={onRestore}>Restore</Button>}
        {onPurge && <Button variant="danger" icon={<Trash2 size={16} />} onClick={onPurge}>Delete permanently</Button>}
      </div>
    );
  }
  if (!canDelete) return managedBy !== "ui" ? <p className="small muted">Managed by {managedBy.replace(/_/g, " ")}, so it is changed there, not here.</p> : null;
  return (
    <div className="row" style={{ flexWrap: "wrap" }}>
      <Button variant="danger" icon={<Trash2 size={16} />} onClick={onDelete}>Delete</Button>
      {onDeleteTree && <Button variant="danger" icon={<Trash2 size={16} />} onClick={onDeleteTree}>Delete folder and everything in it…</Button>}
    </div>
  );
}

function Panel({ row, onClose, ...act }: { row: Row; onClose: () => void } & PanelActions) {
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
        <PanelActions {...act} managedBy={f.managed_by} />
      </SidePanel>
    );
  }
  return <GroupPanel g={row.g} onClose={onClose} {...act} />;
}

function GroupPanel({ g, onClose, ...act }: { g: GrpGroup; onClose: () => void } & PanelActions) {
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
          <PanelActions {...act} managedBy={g.managed_by} />
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
