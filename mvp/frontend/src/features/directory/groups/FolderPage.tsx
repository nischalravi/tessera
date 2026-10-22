import { FormEvent, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { AppWindow, FolderPlus, Plus, Trash2 } from "lucide-react";
import { ApiError, GrpFolder, groups } from "../../../api";
import { useSession } from "../../../app/auth";
import { Badge, Button, Callout, CommandBar, Crumb, EmptyState, Loading, Page, Tabs, useConfirm, useToast } from "../../../components";
import { AttributesTab } from "./AttributesTab";
import { FolderLink, GroupBadges, GroupLink, fmtWhen } from "./common";
import { NewApplicationDrawer, NewFolderDrawer, NewGroupDrawer } from "./forms";
import { useDeleteTree } from "./deletes";
import { errText, useLoad } from "./hooks";
import { isHeld } from "../../admin/deletionGuardModel";
import { childFolders, folderLabel, folderTrail, indexFolders, isNotEmpty, plainReason } from "./model";
import { PrivilegesTab } from "./PrivilegesTab";

type TabId = "contents" | "privileges" | "attributes" | "details";
const TABS: { id: TabId; label: string }[] = [
  { id: "contents", label: "Contents" }, { id: "privileges", label: "Privileges" }, { id: "attributes", label: "Object types and attributes" }, { id: "details", label: "Details" },
];

/** A folder: what it holds, who holds which privileges on it (and what they inherit), object types and attributes. */
export function FolderPage() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const deleteTree = useDeleteTree();
  const { can } = useSession();
  const [params, setParams] = useSearchParams();
  const tab = (TABS.find((t) => t.id === params.get("tab"))?.id ?? "contents") as TabId;
  const [creating, setCreating] = useState<"group" | "folder" | "app" | null>(null);
  const [treeOffer, setTreeOffer] = useState(false);
  const folder = useLoad(() => groups.folder(id), `folder:${id}`);
  const folders = useLoad(() => groups.listFolders(), "folders");
  const inside = useLoad(() => groups.listGroups({ folder: id, deleted: true, limit: 500 }), `folder-groups:${id}`);
  const ix = useMemo(() => indexFolders(folders.data?.items ?? []), [folders.data]);
  const f = folder.data && folder.data.id === id ? folder.data : null;

  if (!f) {
    return (
      <Page title={folder.error ? "Folder not found" : "Loading…"} crumbs={[["Identity"], ["Groups", "/directory/groups"]]}>
        {folder.error ? <EmptyState title="This folder is not available">{folder.error}</EmptyState> : <Loading kind="page" />}
      </Page>
    );
  }
  const trail = folderTrail(ix, f.id);
  const crumbs: Crumb[] = [["Identity"], ["Groups", "/directory/groups"], ...trail.map((t, i): Crumb => (i < trail.length - 1 ? [folderLabel(t), `/directory/groups/folders/${t.id}`] : [folderLabel(t)]))];
  const writable = can("groups.write") && f.managed_by === "ui";
  const kids = childFolders(ix, f.id);

  const remove = async () => {
    const ok = await confirm({ title: `Delete ${f.name}?`, body: "Only an empty folder can be deleted.", confirmLabel: "Delete", danger: true });
    if (ok === null) return;
    try {
      const res = await groups.deleteFolder(f.id);
      if (isHeld(res)) {
        toast(`${res.message}. The folder stays until a second admin releases it.`, { kind: "info", action: { label: "Open held deletion", run: () => nav(`/admin/held-deletions?selected=${encodeURIComponent(res.hold_id)}`) } });
        return;
      }
      toast("Folder deleted");
      nav("/directory/groups");
    } catch (e) {
      toast(e instanceof ApiError ? `Could not delete ${f.name}: ${plainReason(e.code, e.message, e.body)}` : errText(e), { kind: "error" });
      if (e instanceof ApiError && isNotEmpty(e.code)) setTreeOffer(true);
    }
  };
  const removeTree = async () => {
    const res = await deleteTree(f);
    if (res === "deleted") nav("/directory/groups");
    if (res) setTreeOffer(false);
  };

  return (
    <Page
      title={f.display_name || f.display_extension || f.extension}
      crumbs={crumbs}
      sub={<span className="row tight"><span className="sys">{f.name}</span><Badge tone="outline">Folder</Badge>{f.managed_by !== "ui" && <Badge tone="info">{f.managed_by.replace(/_/g, " ")}</Badge>}</span>}
      commands={
        <CommandBar label={`Actions for ${f.name}`} items={[
          writable && { label: "New group", icon: <Plus size={16} />, onClick: () => setCreating("group") },
          writable && { label: "New folder", icon: <FolderPlus size={16} />, onClick: () => setCreating("folder") },
          writable && { label: "New application", icon: <AppWindow size={16} />, onClick: () => setCreating("app"), title: "Create the standard folders and groups of an application here" },
          writable && { label: "Delete folder", icon: <Trash2 size={16} />, danger: true, onClick: remove, title: "Only an empty folder can be deleted" },
          writable && { label: "Delete folder and everything in it…", icon: <Trash2 size={16} />, danger: true, onClick: removeTree },
        ]} />
      }
      tabs={<Tabs<TabId> label="Folder sections" value={tab} onChange={(t) => setParams({ tab: t }, { replace: true })} tabs={TABS} />}
    >
      <div className="stack" role="tabpanel">
        {treeOffer && (
          <Callout tone="warn">
            <div className="row" style={{ justifyContent: "space-between", gap: 12 }}>
              <span>This folder still holds something, so it was not deleted. Remove it together with everything in it, or restore or delete its groups first.</span>
              <Button variant="danger" icon={<Trash2 size={16} />} onClick={removeTree}>Delete folder and everything in it…</Button>
            </div>
          </Callout>
        )}
        {f.managed_by !== "ui" && <Callout tone="info">This folder is managed by {f.managed_by.replace(/_/g, " ")}, so its contents are changed there, not here.</Callout>}
        {tab === "contents" && (
          <>
            {(!folders.data || !inside.data) && <Loading error={folders.error ?? inside.error} kind="block" />}
            {folders.data && inside.data && kids.length === 0 && inside.data.items.length === 0 && <EmptyState title="This folder is empty">{writable ? "Create a folder or a group here, or start from the standard layout with New application." : "Nothing you may view is in this folder."}</EmptyState>}
            {kids.length > 0 && (
              <div className="table-scroll">
                <table>
                  <caption className="sr-only">Folders in {f.name}</caption>
                  <thead><tr><th scope="col">Folder</th><th scope="col">Owner</th><th scope="col">Created</th></tr></thead>
                  <tbody>{kids.map((k) => <tr key={k.id}><td><FolderLink id={k.id}>{folderLabel(k)}</FolderLink></td><td>{k.data_owner ?? <span className="faint">None</span>}</td><td>{fmtWhen(k.created_at)}</td></tr>)}</tbody>
                </table>
              </div>
            )}
            {inside.data && inside.data.items.length > 0 && (
              <div className="table-scroll">
                <table>
                  <caption className="sr-only">Groups in {f.name}</caption>
                  <thead><tr><th scope="col">Group</th><th scope="col">Type</th><th scope="col" className="num">Members</th></tr></thead>
                  <tbody>
                    {inside.data.items.map((g) => (
                      <tr key={g.id}>
                        <td><GroupLink id={g.id}>{g.display_extension || g.extension}</GroupLink></td>
                        <td><span className="row tight"><GroupBadges g={g} /></span></td>
                        <td className="num">{g.effective_count.toLocaleString("en-US")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
        {tab === "privileges" && <PrivilegesTab kind="folder" id={f.id} name={f.name || "the top level"} canWrite={can("groups.write")} />}
        {tab === "attributes" && <AttributesTab kind="folder" id={f.id} name={f.name} canWrite={can("groups.write")} />}
        {tab === "details" && <Details f={f} editable={writable} />}
      </div>
      {creating === "folder" && <NewFolderDrawer parent={f} onClose={() => setCreating(null)} />}
      {creating === "group" && <NewGroupDrawer folder={f} onClose={() => setCreating(null)} />}
      {creating === "app" && <NewApplicationDrawer parent={f} onClose={() => setCreating(null)} />}
    </Page>
  );
}

function Details({ f, editable }: { f: GrpFolder; editable: boolean }) {
  const toast = useToast();
  const [v, setV] = useState({ display_extension: f.display_extension, description: f.description, data_owner: f.data_owner ?? "" });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const dirty = v.display_extension !== f.display_extension || v.description !== f.description || v.data_owner !== (f.data_owner ?? "");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await groups.updateFolder(f.id, { ...v, version: f.version });
      toast("Folder saved");
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="stack" onSubmit={submit} style={{ maxWidth: 560 }}>
      <dl className="kv"><dt>Full name</dt><dd className="sys">{f.name || "(top level)"}</dd><dt>Created</dt><dd>{fmtWhen(f.created_at)}</dd></dl>
      <label className="field"><span>Display name</span><input className="input" value={v.display_extension} disabled={!editable} onChange={(e) => setV({ ...v, display_extension: e.target.value })} /></label>
      <label className="field"><span>Description</span><textarea className="input" value={v.description} disabled={!editable} onChange={(e) => setV({ ...v, description: e.target.value })} /></label>
      <label className="field"><span>Data owner</span><input className="input" value={v.data_owner} disabled={!editable} onChange={(e) => setV({ ...v, data_owner: e.target.value })} /></label>
      {err && <Callout tone="bad">{err}</Callout>}
      {editable && <div><Button type="submit" variant="primary" disabled={!dirty || busy}>{busy ? "Saving…" : "Save changes"}</Button></div>}
    </form>
  );
}
