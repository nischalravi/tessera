import { FormEvent, useEffect, useState } from "react";
import { Ban, CheckCheck, Plus, Play, ThumbsDown } from "lucide-react";
import { AdminChange, AdminUser, ChangeType, adminChanges, relTime, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Button, Callout, DataTable, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { canApply, canApprove, canCancel, canReject, timeLeft } from "./changeState";
import { Fact, StatusBadge, errText, outcome, when } from "./common";

const ROLES = ["viewer", "operator", "auditor", "policy_admin", "tenant_admin"];

/** Types the generic form can submit. A new connection needs a client secret: Authentication has its own form. */
const FORM_TYPES: { id: ChangeType; label: string; example?: string }[] = [
  { id: "role.grant", label: "Grant a role" },
  { id: "role.revoke", label: "Revoke a role" },
  { id: "tenant.settings.update", label: "Change tenant settings", example: '{\n  "require_phr_for_all": true\n}' },
  { id: "tenant.security_contacts.update", label: "Replace security contacts", example: '{\n  "contacts": [\n    { "name": "Jane Doe", "email": "jane@example.com" },\n    { "name": "Raj Patel", "email": "raj@example.com" }\n  ]\n}' },
  { id: "retention.update", label: "Change log retention", example: '{\n  "audit_days": 730,\n  "job_runs_days": 90\n}' },
  { id: "idp_connection.update_trust", label: "Change an IdP connection's trust settings", example: '{\n  "connection_id": "",\n  "group_role_mapping": { "Tessera Viewers": "viewer" }\n}' },
  { id: "idp_connection.update_cosmetic", label: "Rename an IdP connection or edit its domains", example: '{\n  "connection_id": "",\n  "name": ""\n}' },
  { id: "idp_connection.disable", label: "Disable an IdP connection", example: '{\n  "connection_id": ""\n}' },
];

export function ChangeRequests() {
  const { data, error, reload } = useApi<{ change_requests: AdminChange[] }>("/admin/change-requests");
  const { session, can } = useSession();
  const [selected, setSelected] = useSelected();
  const [creating, setCreating] = useState(false);
  const rows = data?.change_requests ?? null;
  const current = rows?.find((r) => r.id === selected) ?? null;
  // re-read every minute: cooling-off ends and requests expire without anyone clicking
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = window.setInterval(() => { setNow(Date.now()); reload?.(); }, 60_000);
    return () => window.clearInterval(t);
  }, [reload]);
  return (
    <Page
      title="Change requests"
      crumbs={[["Settings"], ["Admin", "/admin"], ["Change requests"]]}
      sub="Changes that widen trust or privilege need a second admin, a fresh passkey sign-in and a cooling-off period. Narrowing changes apply at once. Every step is audited and told to all admins and security contacts."
    >
      <div className="stack">
        {creating && <NewRequest onDone={() => { setCreating(false); reload?.(); }} onCancel={() => setCreating(false)} />}
        <DataTable
          id="admin-changes"
          rows={rows}
          error={error}
          rowKey={(r) => r.id}
          activeKey={selected}
          onRowClick={(r) => setSelected(r.id)}
          onRefresh={reload}
          initialSort={["requested", -1]}
          rowLabel={(r) => r.summary}
          commands={[can("admin.change.request") && { label: "New request", icon: <Plus size={14} />, onClick: () => setCreating(true) }]}
          columns={[
            { id: "summary", header: "Request", sort: (r) => r.summary, cell: (r) => <div><b>{r.summary}</b><div className="xs faint"><code>{r.type}</code></div></div> },
            { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <StatusBadge status={r.status} /> },
            { id: "requested", header: "Requested", sort: (r) => r.requested_at, cell: (r) => <span className="small">{r.requested_by.display_name}<div className="xs faint">{relTime(r.requested_at.replace("Z", ""))}</div></span> },
            { id: "approval", header: "Approval", hideNarrow: true, cell: (r) => (r.two_person ? <span className="small">{r.approved_by ? r.approved_by.display_name : "Needs a second admin"}</span> : <span className="small faint">One admin</span>) },
            { id: "effective", header: "Takes effect", hideNarrow: true, sort: (r) => r.effective_at ?? "", cell: (r) => <span className="small">{r.status === "cooling_off" && r.effective_at ? timeLeft(r.effective_at, now) : r.status === "applied" ? when(r.applied_at) : "—"}</span> },
          ]}
          searchText={(r) => `${r.summary} ${r.type} ${r.status} ${r.requested_by.display_name}`}
          searchPlaceholder="Search requests…"
          filters={[
            { id: "status", label: "Status", options: ["pending_approval", "cooling_off", "applied", "rejected", "cancelled", "expired", "failed"].map((s) => ({ value: s, label: s.replace("_", " ") })), get: (r) => r.status },
            { id: "type", label: "Type", options: [...new Set((rows ?? []).map((r) => r.type))].sort().map((t) => ({ value: t, label: t })), get: (r) => r.type },
          ]}
          empty="No change requests yet."
        />
      </div>
      {current && <Detail id={current.id} me={session.user.id} now={now} onClose={() => setSelected(null)} onChanged={() => reload?.()} />}
    </Page>
  );
}

/** The side panel of one request: facts, payload, notifications and the actions this admin may take. */
function Detail({ id, me, now, onClose, onChanged }: { id: string; me: string; now: number; onClose: () => void; onChanged: () => void }) {
  const { data: c, reload } = useApi<AdminChange>(`/admin/change-requests/${id}`);
  const confirm = useConfirm();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  if (!c) return <SidePanel title="Change request" onClose={onClose}><div className="small muted">Loading…</div></SidePanel>;
  const run = async (f: () => Promise<AdminChange | unknown>, done: string) => {
    setBusy(true);
    try {
      await f();
      toast(done);
      reload?.();
      onChanged();
    } catch (e) {
      toast(errText(e), { kind: "error" });
      reload?.();
      onChanged();
    } finally {
      setBusy(false);
    }
  };
  const approve = async () => {
    const reviewed = await confirm({
      title: "Approve this change?",
      body: <>You are the second admin for <b>{c.summary}</b>. You approve exactly the payload below (hash <code>{c.payload_hash.slice(0, 12)}…</code>); if it changes, the approval is refused. It then waits {c.cooling_off_seconds ? `${c.cooling_off_seconds / 3600} h` : "no time"} before it takes effect, and any admin can cancel it meanwhile.<pre className="sys small" style={{ maxHeight: 160, overflow: "auto" }}>{JSON.stringify(c.payload, null, 2)}</pre></>,
      confirmLabel: "Approve",
    });
    if (reviewed !== null) await run(() => adminChanges.approve(c.id, c.payload_hash), "Approved.");
  };
  const reject = async () => {
    if ((await confirm({ title: "Reject this change?", body: "It will not be applied. The requester is told.", confirmLabel: "Reject", danger: true })) !== null) await run(() => adminChanges.reject(c.id), "Rejected.");
  };
  const cancel = async () => {
    if ((await confirm({ title: "Cancel this change?", body: "It will never be applied. Everyone who was told about it is told it was cancelled.", confirmLabel: "Cancel the change", danger: true })) !== null) await run(() => adminChanges.cancel(c.id), "Cancelled.");
  };
  return (
    <SidePanel
      title={c.summary}
      sub={<><StatusBadge status={c.status} /> <code>{c.type}</code></>}
      onClose={onClose}
      commands={
        <div className="cmdbar" role="toolbar" aria-label="Request actions">
          {canApprove(c, me) && <Button size="sm" variant="primary" icon={<CheckCheck size={13} />} disabled={busy} onClick={approve}>Approve</Button>}
          {canReject(c, me) && <Button size="sm" icon={<ThumbsDown size={13} />} disabled={busy} onClick={reject}>Reject</Button>}
          {canApply(c, now) && <Button size="sm" icon={<Play size={13} />} disabled={busy} onClick={() => run(() => adminChanges.apply(c.id), "Applied.")}>Apply now</Button>}
          {canCancel(c) && <Button size="sm" variant="danger" icon={<Ban size={13} />} disabled={busy} onClick={cancel}>Cancel</Button>}
        </div>
      }
    >
      <div className="stack">
        {c.status === "pending_approval" && c.requested_by.id === me && <Callout tone="info">You made this request, so a different admin has to approve it. It expires {timeLeft(c.expires_at, now)}.</Callout>}
        {c.status === "failed" && <Callout tone="bad">It could not be applied: {c.failure}</Callout>}
        {c.status === "cooling_off" && c.effective_at && <Callout tone="warn">Takes effect {timeLeft(c.effective_at, now)} ({when(c.effective_at)}). Cancel it before then if it is unexpected.</Callout>}
        <div className="grid g2">
          <Fact label="Requested by">{c.requested_by.display_name} · {when(c.requested_at)}</Fact>
          <Fact label="Approved by">{c.two_person ? (c.approved_by ? `${c.approved_by.display_name} · ${when(c.approved_at)}` : "Not yet") : "Not required"}</Fact>
          <Fact label="Cooling-off">{c.cooling_off_seconds ? `${c.cooling_off_seconds / 3600} h` : "None"}</Fact>
          <Fact label={c.decided_by ? (c.status === "rejected" ? "Rejected by" : "Cancelled by") : "Expires"}>{c.decided_by ? `${c.decided_by.display_name} · ${when(c.decided_at)}` : when(c.expires_at)}</Fact>
        </div>
        <div>
          <div className="xs faint">Payload (hash <code>{c.payload_hash.slice(0, 16)}…</code>)</div>
          <pre className="sys small card" style={{ margin: 0, overflow: "auto", maxHeight: 220 }}>{JSON.stringify(c.payload, null, 2)}</pre>
        </div>
        <div>
          <div className="xs faint">Notifications queued ({c.notifications?.length ?? 0})</div>
          {(c.notifications ?? []).length === 0 ? <div className="small faint">None</div> : (
            <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
              {c.notifications!.map((n) => <li key={n.id}>{n.kind.replace("admin.change.", "")} → {n.recipient} <span className="faint">({n.recipient_type})</span></li>)}
            </ul>
          )}
        </div>
      </div>
    </SidePanel>
  );
}

/** The generic new-request form: a role grant or revoke, or the JSON diff of another type. */
function NewRequest({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [type, setType] = useState<ChangeType>("role.grant");
  const [userId, setUserId] = useState("");
  const [role, setRole] = useState("viewer");
  const [json, setJson] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const { data: users } = useApi<{ users: AdminUser[] }>("/admin/users");
  const isRole = type === "role.grant" || type === "role.revoke";
  const pick = (t: ChangeType) => {
    setType(t);
    setJson(FORM_TYPES.find((x) => x.id === t)?.example ?? "");
  };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    let payload: Record<string, unknown>;
    try {
      payload = isRole ? { user_id: userId, role } : JSON.parse(json);
    } catch {
      toast("The payload is not valid JSON.", { kind: "error" });
      return;
    }
    setBusy(true);
    try {
      toast(outcome(await adminChanges.submit(type, payload)));
      onDone();
    } catch (err) {
      toast(errText(err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card stack-sm" onSubmit={submit} aria-label="New change request">
      <h2>New change request</h2>
      <label className="field">Type
        <select className="input" value={type} onChange={(e) => pick(e.target.value as ChangeType)}>
          {FORM_TYPES.map((t) => <option key={t.id} value={t.id}>{t.label} ({t.id})</option>)}
        </select>
      </label>
      {isRole ? (
        <div className="row">
          <label className="field grow">User
            <select className="input" required value={userId} onChange={(e) => setUserId(e.target.value)}>
              <option value="">Choose a user…</option>
              {(users?.users ?? []).filter((u) => u.status === "active" && !u.is_break_glass).map((u) => <option key={u.id} value={u.id}>{u.display_name}{u.email ? ` (${u.email})` : ""}</option>)}
            </select>
          </label>
          <label className="field">Role
            <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
          </label>
        </div>
      ) : (
        <label className="field">Payload (JSON)
          <textarea className="input sys" rows={8} required value={json} onChange={(e) => setJson(e.target.value)} spellCheck={false} />
        </label>
      )}
      <p className="small muted" style={{ margin: 0 }}>
        {type === "role.grant" && "Admin roles need a second admin and wait 24 hours. Viewer, operator and auditor apply at once."}
        {type === "role.revoke" && "Removing another admin's admin role needs a second admin; it cannot leave fewer than the tenant's minimum number of admins."}
        {type.startsWith("idp_connection") && "Trust changes need a second admin and 24 hours, and sign out everyone who came through the connection."}
        {type.startsWith("tenant.") && "Weakening a setting, or changing the security contacts, needs a second admin and 24 hours."}
      </p>
      <div className="row">
        <Button type="submit" variant="primary" disabled={busy}>{busy ? "Submitting…" : "Submit request"}</Button>
        <Button onClick={onCancel}>Close</Button>
      </div>
    </form>
  );
}
