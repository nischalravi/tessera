import { FormEvent, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Check, FileText, Pencil, Plus, Trash2, Undo2, X } from "lucide-react";
import { ApiError, ApprovalDelegation, ApprovalItem, RequestLine, RoleRequest, UserRef, approveRequest, cancelRequest, createDelegation, denyRequest, fmtDate, relTime, removeRequest, revokeDelegation, roles as roleApi, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { usePersona } from "../../app/persona";
import {
  Badge, Button, ButtonLink, Column, DataTable, EmptyState, MyAccessTabs, Page, SidePanel, Status, Tabs, useConfirm, useSelected, useToast,
} from "../../components";
import { mockRequests, useMockState } from "../../mocks";
import { Stages } from "./stages";

/**
 * Access requests (issue #164): your requests and the ones made for you, the approval queue for
 * people who decide, every request, and drafts (saved in this browser). Each request line is one
 * person and one item; its history shows who requested, who decided and when it ended.
 */
type Tab = "mine" | "approvals" | "all" | "delegations" | "drafts";

const durationLabel = (h: number | null) => (h == null ? "Until removed" : h % 24 === 0 && h >= 48 ? `${h / 24} days` : `${h} h`);

export function Requests() {
  const [params, setParams] = useSearchParams();
  const { can } = useSession();
  const decider = can("requests.decide");
  const tab = (params.get("tab") ?? "mine") as Tab;
  const scope = tab === "all" ? "all" : "mine";
  const listed = useApi<RequestLine[]>(tab === "mine" || tab === "all" ? `/requests?scope=${scope}` : null);
  // what the API routed to you: manager and owner stages, delegations, and access-approver stages
  const inbox = useApi<ApprovalItem[]>("/approvals/inbox");
  const approvals = useMemo(() => inbox.data?.map((a) => a.line) ?? null, [inbox.data]);
  // business role requests (issue #161) are decided by requests.decide, not routed by stage
  const rolesPending = useApi<RoleRequest[]>(decider ? "/role-requests?scope=pending" : null);
  const { data, error, reload } = tab === "approvals" ? { data: approvals, error: inbox.error, reload: inbox.reload } : listed;
  const { actor } = usePersona();
  const mock = useMockState();
  const drafts = mock.requests.filter((r) => r.status === "draft" && r.requester === actor);
  const tabs: { id: Tab; label: string }[] = [
    { id: "mine", label: "My requests" },
    { id: "approvals", label: `Approvals${approvals && (!decider || rolesPending.data) ? ` (${approvals.length + (rolesPending.data?.length ?? 0)})` : ""}` },
    ...(decider ? [{ id: "all" as Tab, label: "All requests" }] : []),
    { id: "delegations", label: "Delegations" },
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
      {tab === "drafts" ? <Drafts drafts={drafts} /> : tab === "delegations" ? <Delegations /> : <Lines rows={data} error={error} reload={reload} tab={tab} />}
      {(tab === "mine" || tab === "all" || (tab === "approvals" && decider)) && (
        <RoleRequests scope={tab === "approvals" ? "pending" : scope} onChange={rolesPending.reload} />
      )}
    </Page>
  );
}

function Lines({ rows, error, reload, tab }: { rows: RequestLine[] | null; error: ApiError | null; reload: () => void; tab: Tab }) {
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
      {!l ? <p className="small muted">{error?.message ?? "Loading…"}</p> : (
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
          {l.stages.length > 0 && <><h3 className="mt">Approval stages</h3><Stages stages={l.stages} /></>}
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

/** Business role requests (issue #161): one per person and role; approval assigns the role. */
function RoleRequests({ scope, onChange }: { scope: string; onChange: () => void }) {
  const { data, error, reload } = useApi<RoleRequest[]>(`/role-requests?scope=${scope}`);
  const confirm = useConfirm();
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const act = async (q: RoleRequest, o: { title: string; body?: string; label: string; danger?: boolean; reason?: "required" | "optional"; run: (reason: string) => Promise<unknown>; done: string }) => {
    const reason = await confirm({
      title: o.title, body: o.body, confirmLabel: o.label, danger: o.danger,
      reason: o.reason ? { label: o.reason === "required" ? "Reason (the requester sees it)" : "Note (optional)", required: o.reason === "required" } : undefined,
    });
    if (reason == null) return;
    setBusy(q.id);
    try {
      await o.run(reason);
      toast(o.done);
      reload();
      onChange();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  if (data && data.length === 0 && !error) return null;
  const cols: Column<RoleRequest>[] = [
    { id: "role", header: "Role", sort: (q) => q.role.name, cell: (q) => <span><Link to={`/directory/roles/${q.role.id}`}>{q.role.name}</Link>{q.role.risk !== "low" && <> <Badge tone={q.role.risk === "high" ? "critical" : "warning"}>{q.role.risk} risk</Badge></>}</span> },
    { id: "for", header: "For", sort: (q) => q.beneficiary.name, cell: (q) => <span className="small">{q.beneficiary.name}</span> },
    { id: "by", header: "Requested by", sort: (q) => q.requested_by.display_name, cell: (q) => <span className="small">{q.requested_by.display_name}<div className="xs faint truncate" style={{ maxWidth: 260 }}>{q.justification}</div></span>, hideNarrow: true },
    { id: "status", header: "Status", sort: (q) => q.status, cell: (q) => <span className="nowrap"><Status s={q.status} />{q.decided_by && <div className="xs faint">by {q.decided_by.display_name}</div>}</span> },
    { id: "at", header: "Requested", sort: (q) => q.requested_at, cell: (q) => <span className="small faint nowrap" title={fmtDate(q.requested_at)}>{relTime(q.requested_at)}</span> },
    { id: "act", header: "Actions", cell: (q) => (
      <span className="row tight" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
        {q.can_approve && <Button size="sm" variant="primary" icon={<Check size={14} />} disabled={busy === q.id}
          onClick={() => act(q, { title: `Approve ${q.role.name} for ${q.beneficiary.name}?`, body: "Tessera assigns the role now and grants each entitlement in it.", label: "Approve", reason: "optional", run: (r) => roleApi.approve(q.id, r || undefined), done: "Approved: role assigned" })}>Approve</Button>}
        {q.can_approve && <Button size="sm" variant="danger" icon={<X size={14} />} disabled={busy === q.id}
          onClick={() => act(q, { title: `Deny ${q.role.name} for ${q.beneficiary.name}?`, label: "Deny", danger: true, reason: "required", run: (r) => roleApi.deny(q.id, r), done: "Denied" })}>Deny</Button>}
        {q.can_cancel && <Button size="sm" icon={<Undo2 size={14} />} disabled={busy === q.id}
          onClick={() => act(q, { title: "Cancel this role request?", label: "Cancel request", run: () => roleApi.cancel(q.id), done: "Request cancelled" })}>Cancel</Button>}
      </span>
    ) },
  ];
  return (
    <section className="mt" aria-labelledby="role-requests-h">
      <h2 id="role-requests-h" className="h3">Role requests</h2>
      <DataTable
        id={`role-requests-${scope}`}
        rows={data}
        error={error}
        rowKey={(q) => q.id}
        columns={cols}
        searchText={(q) => `${q.role.name} ${q.beneficiary.name} ${q.requested_by.display_name} ${q.justification}`}
        searchPlaceholder="Search roles or people…"
        onRefresh={reload}
        rowLabel={(q) => `${q.role.name} for ${q.beneficiary.name}`}
      />
    </section>
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

/** Hand your approvals to someone while you're away (issue #165). They decide what is routed to you, never their own requests. */
function Delegations() {
  const { data, error, reload } = useApi<ApprovalDelegation[]>("/approvals/delegations");
  const { data: people } = useApi<UserRef[]>("/approvals/delegates");
  const toast = useToast();
  const confirm = useConfirm();
  const today = new Date().toISOString().slice(0, 10);
  const [to, setTo] = useState("");
  const [from, setFrom] = useState(today);
  const [until, setUntil] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      // whole days in the viewer's time zone: from the start of the first day to the end of the last
      await createDelegation({ to_user_id: to, starts_at: new Date(`${from}T00:00:00`).toISOString(), ends_at: new Date(`${until}T23:59:59`).toISOString(), reason: reason.trim() });
      toast("Delegation saved");
      setTo(""); setUntil(""); setReason("");
      reload();
    } catch (err: any) {
      toast(String(err.message ?? err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="split request-split mt">
      <div className="card flush">
        {!data ? <p className="small muted" style={{ padding: 16 }}>{error?.message ?? "Loading…"}</p> : data.length === 0 ? (
          <EmptyState title="No delegations" icon={<Undo2 size={18} />}>Delegate your approvals before you go on leave; they come back to you when it ends.</EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>From</th><th>To</th><th>When</th><th className="hide-narrow">Reason</th><th>State</th><th /></tr></thead>
              <tbody>
                {data.map((d) => (
                  <tr key={d.id}>
                    <td className="small">{d.from.display_name}</td>
                    <td className="small">{d.to.display_name}</td>
                    <td className="small nowrap">{fmtDate(d.starts_at)} – {fmtDate(d.ends_at)}</td>
                    <td className="small hide-narrow">{d.reason}</td>
                    <td><Status s={d.revoked_at ? "revoked" : d.active ? "active" : new Date(d.ends_at) < new Date() ? "expired" : "scheduled"} /></td>
                    <td className="actions-cell">
                      {!d.revoked_at && new Date(d.ends_at) > new Date() && (
                        <Button size="sm" variant="ghost" icon={<X size={14} />} onClick={async () => {
                          if ((await confirm({ title: "End this delegation now?", confirmLabel: "End delegation", danger: true })) === null) return;
                          try { await revokeDelegation(d.id); toast("Delegation ended"); reload(); } catch (err: any) { toast(String(err.message ?? err), { kind: "error" }); }
                        }}>End</Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <form className="card stack" onSubmit={submit} aria-label="Delegate your approvals">
        <h2>Delegate your approvals</h2>
        <label className="field">To
          <select className="input" value={to} onChange={(e) => setTo(e.target.value)} required>
            <option value="">Choose a person…</option>
            {(people ?? []).map((p) => <option key={p.id} value={p.id}>{p.display_name}</option>)}
          </select>
        </label>
        <div className="row">
          <label className="field" style={{ flex: 1 }}>From<input className="input" type="date" value={from} min={today} onChange={(e) => setFrom(e.target.value)} required /></label>
          <label className="field" style={{ flex: 1 }}>Until<input className="input" type="date" value={until} min={from} onChange={(e) => setUntil(e.target.value)} required /></label>
        </div>
        <label className="field">Reason<input className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} placeholder="Annual leave" required /></label>
        <p className="small muted">They approve what is routed to you as a manager or owner, for at most 90 days. Never their own requests, and never yours.</p>
        <div className="row"><Button type="submit" variant="primary" disabled={busy || !to || !until || !reason.trim()}>{busy ? "Saving…" : "Delegate"}</Button></div>
      </form>
    </div>
  );
}
