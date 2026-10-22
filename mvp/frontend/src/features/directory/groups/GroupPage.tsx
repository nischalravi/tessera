import { FormEvent, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Pencil, RotateCcw, Trash2 } from "lucide-react";
import { GrpGroup, groups } from "../../../api";
import { useSession } from "../../../app/auth";
import { Button, Callout, CommandBar, Drawer, EmptyState, Loading, Page, Tabs, useConfirm, useToast } from "../../../components";
import { AttributesTab } from "./AttributesTab";
import { DefinitionTab } from "./DefinitionTab";
import { GroupBadges, GroupLink, RecomputeBanner } from "./common";
import { HistoryTab } from "./HistoryTab";
import { usePurgeGroups } from "./deletes";
import { errText, useLoad } from "./hooks";
import { MembersTab } from "./MembersTab";
import { isHeld } from "../../admin/deletionGuardModel";
import { folderLabel, folderTrail, indexFolders } from "./model";
import { PrivilegesTab } from "./PrivilegesTab";

type TabId = "members" | "definition" | "privileges" | "usage" | "history" | "attributes";
const TABS: { id: TabId; label: string }[] = [
  { id: "members", label: "Members" }, { id: "definition", label: "Definition" }, { id: "privileges", label: "Privileges" },
  { id: "usage", label: "Usage" }, { id: "history", label: "History" }, { id: "attributes", label: "Attributes" },
];

/** A managed group: members, definition, privileges, usage, history and attributes (design §10.13). */
export function GroupPage() {
  const { id = "" } = useParams();
  const toast = useToast();
  const confirm = useConfirm();
  const nav = useNavigate();
  const purge = usePurgeGroups();
  const { can } = useSession();
  const [params, setParams] = useSearchParams();
  const tab = (TABS.find((t) => t.id === params.get("tab"))?.id ?? "members") as TabId;
  const [edit, setEdit] = useState(false);
  const group = useLoad(() => groups.group(id), `group:${id}`);
  const folders = useLoad(() => groups.listFolders(), "folders");
  const ix = useMemo(() => indexFolders(folders.data?.items ?? []), [folders.data]);
  const g = group.data && group.data.id === id ? group.data : null;

  if (!g) {
    return (
      <Page title={group.error ? "Group not found" : "Loading…"} crumbs={[["Identity"], ["Groups", "/directory/groups"]]}>
        {group.error ? <EmptyState title="This group is not available">{group.error}</EmptyState> : <Loading kind="page" />}
      </Page>
    );
  }
  const deleted = g.status === "deleted";
  // the API checks every change against the group's privileges; this only hides controls that cannot work
  const handEdited = g.managed_by === "ui";
  const canWrite = can("groups.write") && !deleted && handEdited;
  const trail = folderTrail(ix, g.folder_id);

  const remove = async () => {
    const ok = await confirm({ title: `Delete ${g.name}?`, body: "The group is deleted and its members stop counting. It can be restored afterwards.", confirmLabel: "Delete", danger: true });
    if (ok === null) return;
    try {
      const res = await groups.deleteGroup(g.id);
      if (isHeld(res)) toast(`${res.message}. The group stays until a second admin releases it.`, { kind: "info", action: { label: "Open held deletion", run: () => nav(`/admin/held-deletions?selected=${encodeURIComponent(res.hold_id)}`) } });
      else toast("Group deleted");
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };
  const purgeNow = async () => {
    const res = await purge([g]);
    if (res && res.done) nav("/directory/groups");
  };
  const restore = async () => {
    try {
      await groups.restoreGroup(g.id);
      toast("Group restored");
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };

  return (
    <Page
      title={g.display_name || g.display_extension || g.extension}
      crumbs={[["Identity"], ["Groups", "/directory/groups"], ...trail.map((f) => [folderLabel(f), `/directory/groups/folders/${f.id}`] as [string, string]), [g.extension]]}
      sub={<span className="row tight"><span className="sys">{g.name}</span><GroupBadges g={g} /></span>}
      commands={
        <CommandBar label={`Actions for ${g.name}`} items={[
          can("groups.write") && !deleted && { label: "Edit details", icon: <Pencil size={16} />, onClick: () => setEdit(true), disabled: !handEdited },
          can("groups.write") && !deleted && { label: "Delete", icon: <Trash2 size={16} />, danger: true, onClick: remove, disabled: !handEdited },
          can("groups.write") && deleted && { label: "Restore", icon: <RotateCcw size={16} />, onClick: restore },
          can("groups.write") && deleted && { label: "Delete permanently", icon: <Trash2 size={16} />, danger: true, onClick: purgeNow, disabled: !handEdited },
        ]} />
      }
      tabs={<Tabs<TabId> label="Group sections" value={tab} onChange={(t) => setParams({ tab: t }, { replace: true })} tabs={TABS} />}
    >
      <div className="stack" role="tabpanel">
        <RecomputeBanner state={g.recompute_state} />
        {deleted && <Callout tone="warn">This group is deleted. It has no members until it is restored. Delete it permanently to remove it for good.</Callout>}
        {!handEdited && !deleted && <Callout tone="info">This group is managed by {g.managed_by.replace(/_/g, " ")}, so it is changed there, not here.</Callout>}
        {tab === "members" && (
          <>
            <dl className="kv">
              <dt>Effective members</dt><dd>{g.effective_count.toLocaleString("en-US")}</dd>
              {g.description && <><dt>Description</dt><dd>{g.description}</dd></>}
              {g.data_owner && <><dt>Owner</dt><dd>{g.data_owner}</dd></>}
              {g.member_description && <><dt>Members are</dt><dd>{g.member_description}</dd></>}
            </dl>
            <MembersTab g={g} canWrite={canWrite} />
          </>
        )}
        {tab === "definition" && <DefinitionTab g={g} canWrite={canWrite} />}
        {tab === "privileges" && <PrivilegesTab kind="group" id={g.id} name={g.name} canWrite={can("groups.write") && !deleted} />}
        {tab === "usage" && <Usage g={g} />}
        {tab === "history" && <HistoryTab g={g} />}
        {tab === "attributes" && <AttributesTab kind="group" id={g.id} name={g.name} canWrite={can("groups.write") && !deleted} />}
      </div>
      {edit && <EditGroup g={g} onClose={() => setEdit(false)} />}
    </Page>
  );
}

function Usage({ g }: { g: GrpGroup }) {
  const factors = g.factors ?? [];
  return (
    <div className="stack">
      <section className="stack-sm">
        <h3 style={{ fontSize: "var(--fs-lg)" }}>Built from</h3>
        {factors.length === 0
          ? <p className="muted">{g.definition === "basic" ? "A basic group is built from its direct members, including any groups nested in it. See the Members tab." : "No factors."}</p>
          : <ul className="stack-sm" style={{ listStyle: "none", padding: 0 }}>{factors.map((f) => <li key={f}><GroupLink id={f}>{f}</GroupLink></li>)}</ul>}
      </section>
      <section className="stack-sm">
        <h3 style={{ fontSize: "var(--fs-lg)" }}>Used by</h3>
        <EmptyState title="Where this group is used is not available yet">Parent groups, policy groups, provisioned targets and the downstream entitlements in the access graph appear here once the services that record them are in place.</EmptyState>
      </section>
    </div>
  );
}

function EditGroup({ g, onClose }: { g: GrpGroup; onClose: () => void }) {
  const toast = useToast();
  const [v, setV] = useState({ display_extension: g.display_extension, description: g.description, data_owner: g.data_owner ?? "", member_description: g.member_description ?? "", requestable: g.requestable });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await groups.updateGroup(g.id, { ...v, version: g.version });
      toast("Group saved");
      onClose();
    } catch (x) {
      setErr(errText(x));
      setBusy(false);
    }
  };
  return (
    <Drawer title="Edit group" sub={g.name} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="edit-group" variant="primary" disabled={busy}>{busy ? "Saving…" : "Save changes"}</Button></>}>
      <form id="edit-group" className="stack" onSubmit={submit}>
        <label className="field"><span>Display name</span><input className="input" value={v.display_extension} onChange={(e) => setV({ ...v, display_extension: e.target.value })} data-autofocus /></label>
        <label className="field"><span>Description</span><textarea className="input" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} /></label>
        <label className="field"><span>Data owner</span><input className="input" value={v.data_owner} onChange={(e) => setV({ ...v, data_owner: e.target.value })} /></label>
        <label className="field"><span>What the members are</span><input className="input" value={v.member_description} onChange={(e) => setV({ ...v, member_description: e.target.value })} /></label>
        <label className="row tight"><input type="checkbox" checked={v.requestable} onChange={(e) => setV({ ...v, requestable: e.target.checked })} /><span>People can request membership</span></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}
