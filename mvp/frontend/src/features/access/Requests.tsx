import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Check, FileText, Pencil, Plus, Trash2, Undo2, X } from "lucide-react";
import { RequestLine, approveRequest, cancelRequest, denyRequest, fmtDate, relTime, removeRequest, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { usePersona } from "../../app/persona";
import {
  Button, ButtonLink, Column, DataTable, EmptyState, MyAccessTabs, Page, PreviewBadge, SidePanel, Status, Tabs, useConfirm, useSelected, useToast,
} from "../../components";
import { mockRequests, useMockState } from "../../mocks";

/**
 * Access requests (issue #164): your requests and the ones made for you, the approval queue for
 * people who decide, every request, and drafts (saved in this browser). Each request line is one
 * person and one item; its history shows who requested, who decided and when it ended.
 */
type Tab = "mine" | "approvals" | "all" | "drafts";

const durationLabel = (h: number | null) => (h == null ? "Until removed" : h % 24 === 0 && h >= 48 ? `${h / 24} days` : `${h} h`);

export function Requests() {
  const [params, setParams] = useSearchParams();
  const { can } = useSession();
  const decider = can("requests.decide");
  const tab = (params.get("tab") ?? "mine") as Tab;
  const scope = tab === "approvals" ? "pending" : tab === "all" ? "all" : "mine";
  const { data, error, reload } = useApi<RequestLine[]>(tab === "drafts" ? null : `/requests?scope=${scope}`);
  const pending = useApi<RequestLine[]>(decider ? "/requests?scope=pending" : null);
  const { actor } = usePersona();
  const mock = useMockState();
  const drafts = mock.requests.filter((r) => r.status === "draft" && r.requester === actor);
  const previews = mock.requests.filter((r) => r.status !== "draft" && r.requester === actor);
  const tabs: { id: Tab; label: string }[] = [
    { id: "mine", label: "My requests" },
    ...(decider ? [{ id: "approvals" as Tab, label: `Approvals${pending.data ? ` (${pending.data.length})` : ""}` }, { id: "all" as Tab, label: "All requests" }] : []),
    { id: "drafts", label: `Drafts (${drafts.length})` },
  ];
  return (
    <Page
      tabs={<MyAccessTabs />}
      title="Requests"
      crumbs={[["Access"], ["Requests"]]}
      sub="Each line is one person and one item. Just-in-time elevations are on the Just-in-time page."
      actions={<ButtonLink to="/access/request" variant="primary" icon={<Plus size={15} />}>New request</ButtonLink>}
    >
      <Tabs label="Request views" value={tab} onChange={(v) => setParams(v === "mine" ? {} : { tab: v })} tabs={tabs} />
      {tab === "drafts" ? <Drafts drafts={drafts} /> : <Lines rows={data} error={error} reload={reload} tab={tab} />}
      {tab === "mine" && previews.length > 0 && (
        <p className="small muted mt">
          {previews.length} business-role request{previews.length === 1 ? "" : "s"} saved in this browser <PreviewBadge what="Business roles have no backend yet" />
        </p>
      )}
    </Page>
  );
}

function Lines({ rows, error, reload, tab }: { rows: RequestLine[] | null; error: string | null; reload: () => void; tab: Tab }) {
  const [selected, setSelected] = useSelected();
  const open = rows?.find((r) => r.id === selected);
  const cols: Column<RequestLine>[] = [
    { id: "what", header: "Access", sort: (r) => `${r.group.system}:${r.group.name}`, cell: (r) => <span className="sys name-link">{r.group.system}:{r.group.name}</span> },
    { id: "for", header: "For", sort: (r) => r.beneficiary.name, cell: (r) => <span className="small">{r.beneficiary.name}</span> },
    { id: "by", header: "Requested by", sort: (r) => r.requested_by.display_name, cell: (r) => <span className="small">{r.requested_by.display_name}</span>, hideNarrow: true },
    { id: "dur", header: "Duration", sort: (r) => r.duration_hours ?? Infinity, cell: (r) => <span className="small nowrap">{durationLabel(r.duration_hours)}</span>, hideNarrow: true },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <span className="nowrap"><Status s={r.status} />{r.decided_by && <div className="xs faint">by {r.decided_by.display_name}</div>}</span> },
    { id: "at", header: "Requested", sort: (r) => r.requested_at, cell: (r) => <span className="small faint nowrap" title={fmtDate(r.requested_at)}>{relTime(r.requested_at)}</span> },
  ];
  const statuses = ["pending", "approved", "denied", "cancelled", "expired", "removed"];
  return (
    <>
      <DataTable
        id={`requests-${tab}`}
        rows={rows}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        searchText={(r) => `${r.group.system}:${r.group.name} ${r.beneficiary.name} ${r.requested_by.display_name} ${r.justification}`}
        searchPlaceholder="Search access, people or justification…"
        filters={[
          { id: "status", label: "Status", options: statuses.map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) })), get: (r) => r.status },
          { id: "system", label: "System", options: [...new Set((rows ?? []).map((r) => r.group.system))].sort().map((s) => ({ value: s, label: s })), get: (r) => r.group.system },
        ]}
        onRefresh={reload}
        rowLabel={(r) => `${r.group.system}:${r.group.name} for ${r.beneficiary.name}`}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        empty={tab === "approvals"
          ? <EmptyState title="Nothing to approve" icon={<Check size={18} />}>Requests waiting for a decision show here.</EmptyState>
          : <EmptyState title="No requests yet" icon={<FileText size={18} />} action={<ButtonLink to="/access/request" size="sm">Browse the catalog</ButtonLink>}>Requests you submit, or that are made for you, show here with their status.</EmptyState>}
      />
      {open && <LinePanel id={open.id} onClose={() => setSelected(null)} />}
    </>
  );
}

function LinePanel({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: l, error } = useApi<RequestLine>(`/requests/${encodeURIComponent(id)}`);
  const confirm = useConfirm();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const act = async (o: { title: string; body?: string; label: string; danger?: boolean; reason?: "required" | "optional"; run: (reason: string) => Promise<unknown>; done: string }) => {
    const reason = await confirm({
      title: o.title, body: o.body, confirmLabel: o.label, danger: o.danger,
      reason: o.reason ? { label: o.reason === "required" ? "Reason (the requester sees it)" : "Note (optional)", required: o.reason === "required" } : undefined,
    });
    if (reason == null) return;
    setBusy(true);
    try {
      await o.run(reason);
      toast(o.done);
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const what = l ? `${l.group.system}:${l.group.name}` : "Request";
  return (
    <SidePanel title={what} sub={l && <span className="small muted">for {l.beneficiary.name} · <Status s={l.status} /></span>} onClose={onClose}
      footer={l && (l.can_approve || l.can_cancel || l.can_remove) && (
        <div className="row tight">
          {l.can_approve && <Button variant="primary" size="sm" icon={<Check size={14} />} disabled={busy}
            onClick={() => act({ title: `Approve ${what} for ${l.beneficiary.name}?`, body: `Tessera grants it now${l.duration_hours ? ` for ${durationLabel(l.duration_hours)}` : ", until someone removes it"}.`, label: "Approve", reason: "optional", run: (r) => approveRequest(l.id, r || undefined), done: "Approved and granted" })}>Approve</Button>}
          {l.can_approve && <Button size="sm" variant="danger" icon={<X size={14} />} disabled={busy}
            onClick={() => act({ title: `Deny ${what} for ${l.beneficiary.name}?`, label: "Deny", danger: true, reason: "required", run: (r) => denyRequest(l.id, r), done: "Denied" })}>Deny</Button>}
          {l.can_cancel && <Button size="sm" icon={<Undo2 size={14} />} disabled={busy}
            onClick={() => act({ title: "Cancel this request?", label: "Cancel request", run: () => cancelRequest(l.id), done: "Request cancelled" })}>Cancel request</Button>}
          {l.can_remove && <Button size="sm" variant="danger" icon={<Trash2 size={14} />} disabled={busy}
            onClick={() => act({ title: `Remove ${what} from ${l.beneficiary.name} now?`, body: "The access ends immediately.", label: "Remove access", danger: true, reason: "optional", run: (r) => removeRequest(l.id, r || undefined), done: "Access removed" })}>Remove access</Button>}
        </div>
      )}
    >
      {!l ? <p className="small muted">{error ?? "Loading…"}</p> : (
        <>
          <dl className="kv">
            <dt>For</dt><dd><Link to={`/directory/identities/${l.beneficiary.id}`}>{l.beneficiary.name}</Link></dd>
            <dt>Account</dt><dd className="sys">{l.account.system}:{l.account.username}</dd>
            <dt>Requested by</dt><dd>{l.requested_by.display_name}, {fmtDate(l.requested_at)}</dd>
            <dt>Duration</dt><dd>{durationLabel(l.duration_hours)}{l.expires_at && ` (until ${fmtDate(l.expires_at)})`}</dd>
            <dt>Justification</dt><dd>{l.justification}</dd>
            {l.decided_by && <><dt>Decided by</dt><dd>{l.decided_by.display_name}, {fmtDate(l.decided_at)}</dd></>}
            {l.decision_reason && <><dt>Reason</dt><dd>{l.decision_reason}</dd></>}
          </dl>
          <h3 className="mt">History</h3>
          <ol className="timeline">
            {(l.events ?? []).map((e, i) => (
              <li key={i}>
                <b>{e.event[0].toUpperCase() + e.event.slice(1)}</b> by {e.actor} <span className="faint" title={fmtDate(e.at)}>{relTime(e.at)}</span>
                {e.note && <div className="small muted">{e.note}</div>}
              </li>
            ))}
          </ol>
        </>
      )}
    </SidePanel>
  );
}

function Drafts({ drafts }: { drafts: ReturnType<typeof useMockState>["requests"] }) {
  const nav = useNavigate();
  const confirm = useConfirm();
  const rows = useMemo(() => drafts, [drafts]);
  return (
    <div className="card flush">
      {rows.length === 0 ? (
        <EmptyState title="No drafts" icon={<Pencil size={18} />}>Use “Save draft” on Request access to come back to a request later.</EmptyState>
      ) : (
        <table>
          <thead><tr><th>Items</th><th>For</th><th>Saved</th><th /></tr></thead>
          <tbody>
            {rows.map((d) => (
              <tr key={d.id}>
                <td><b className="sys">{d.items.map((i) => i.name).join(", ")}</b></td>
                <td className="small">{d.beneficiaries.map((b) => b.name).join(", ")}</td>
                <td className="small faint">{relTime(d.createdAt)}</td>
                <td className="actions-cell">
                  <Button size="sm" icon={<Pencil size={14} />} onClick={() => nav(`/access/request?draft=${d.id}`)}>Resume</Button>{" "}
                  <Button size="sm" variant="ghost" icon={<Trash2 size={14} />} label="Delete draft" onClick={async () => { if ((await confirm({ title: "Delete this draft?", confirmLabel: "Delete", danger: true })) !== null) mockRequests.remove(d.id); }} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
