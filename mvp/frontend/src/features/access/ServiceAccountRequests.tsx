import { useState } from "react";
import { Check, Undo2, X } from "lucide-react";
import { ServiceAccountRequest, fmtDate, relTime, serviceAccountRequests, serviceAccountRequestsPath, useApi } from "../../api";
import { Badge, Button, Column, DataTable, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { Stages } from "./stages";
import { AnswersView } from "./Answers";
import { KIND_LABEL, STATUS_LABEL, ownerSummary, statusTone, waitingFor } from "./serviceAccountModel";

/**
 * Service-account requests on the Requests page (issue #298): your requests, the ones waiting for
 * you (an owner, a group member, a delegate or an access approver) and, for deciders, all of them.
 * A row opens a detail panel with the owners, the workflow's stages, the answers and the actions
 * the server allows. Approval is the workflow's: the last approval makes the change.
 */
export function ServiceAccountRequestsSection({ scope, onChange }: { scope: "mine" | "pending" | "all"; onChange?: () => void }) {
  const { data, error, reload } = useApi<ServiceAccountRequest[]>(`${serviceAccountRequestsPath}?scope=${scope}`);
  const [selected, setSelected] = useSelected();
  if (data && data.length === 0 && !error) return null;
  const open = data?.find((r) => r.id === selected) ?? null;
  const cols: Column<ServiceAccountRequest>[] = [
    { id: "what", header: "Service account", sort: (r) => r.name, cell: (r) => <span><span className="name-link">{r.name}</span> <Badge tone="outline">{KIND_LABEL[r.kind]}</Badge></span> },
    { id: "owners", header: "Owners", sort: (r) => r.primary_owner.name, cell: (r) => <span className="small">{ownerSummary(r)}</span>, hideNarrow: true },
    { id: "by", header: "Requested by", sort: (r) => r.requested_by.display_name, cell: (r) => <span className="small">{r.requested_by.display_name}</span>, hideNarrow: true },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <span className="nowrap"><Badge tone={statusTone(r.status)} dot>{STATUS_LABEL[r.status]}</Badge>{waitingFor(r) && <div className="xs faint">{waitingFor(r)}</div>}</span> },
    { id: "at", header: "Requested", sort: (r) => r.requested_at, cell: (r) => <span className="small faint nowrap" title={fmtDate(r.requested_at)}>{relTime(r.requested_at)}</span> },
  ];
  return (
    <section className="mt" aria-labelledby={`sa-requests-h-${scope}`}>
      <h2 id={`sa-requests-h-${scope}`} className="h3">Service-account requests</h2>
      <DataTable
        id={`sa-requests-${scope}`}
        rows={data}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        searchText={(r) => `${r.name} ${r.kind} ${r.primary_owner.name} ${r.requested_by.display_name} ${r.justification}`}
        searchPlaceholder="Search service accounts or people…"
        filters={[{ id: "status", label: "Status", options: Object.entries(STATUS_LABEL).map(([value, label]) => ({ value, label })), get: (r) => r.status }]}
        onRefresh={reload}
        rowLabel={(r) => `${KIND_LABEL[r.kind]} ${r.name}`}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={open?.id ?? null}
      />
      {open && <Detail r={open} onClose={() => setSelected(null)} onChanged={() => { reload(); onChange?.(); }} />}
    </section>
  );
}

function Detail({ r, onClose, onChanged }: { r: ServiceAccountRequest; onClose: () => void; onChanged: () => void }) {
  const confirm = useConfirm();
  const toast = useToast();
  const full = useApi<ServiceAccountRequest>(`${serviceAccountRequestsPath}/${encodeURIComponent(r.id)}`);
  const view = full.data ?? r;
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
      full.reload();
      onChanged();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const person = (p: { name: string } | null) => (p ? p.name : <span className="faint">None</span>);
  return (
    <SidePanel
      title={`${KIND_LABEL[view.kind]} ${view.name}`}
      sub={<span className="small muted"><Badge tone={statusTone(view.status)} dot>{STATUS_LABEL[view.status]}</Badge>{waitingFor(view) && <> · {waitingFor(view)}</>}</span>}
      onClose={onClose}
      footer={(view.can_approve || view.can_cancel) && (
        <div className="row tight">
          {view.can_approve && <Button size="sm" variant="primary" icon={<Check size={14} />} disabled={busy}
            onClick={() => act({ title: `Approve ${view.name}?`, body: "Approving the last stage makes the change in Tessera and asks the target system through provisioning.", label: "Approve", reason: "optional", run: (x) => serviceAccountRequests.approve(view.id, x || undefined), done: "Approved" })}>Approve</Button>}
          {view.can_approve && <Button size="sm" variant="danger" icon={<X size={14} />} disabled={busy}
            onClick={() => act({ title: `Deny ${view.name}?`, label: "Deny", danger: true, reason: "required", run: (x) => serviceAccountRequests.deny(view.id, x), done: "Denied" })}>Deny</Button>}
          {view.can_cancel && <Button size="sm" icon={<Undo2 size={14} />} disabled={busy}
            onClick={() => act({ title: "Cancel this request?", label: "Cancel request", run: () => serviceAccountRequests.cancel(view.id), done: "Request cancelled" })}>Cancel request</Button>}
        </div>
      )}
    >
      <div className="stack">
        <dl className="kv">
          <dt>Request</dt><dd>{KIND_LABEL[view.kind]} a service account{view.kind === "create" && view.system ? <> in <span className="sys">{view.system}</span> as <span className="sys">{view.username}</span></> : null}</dd>
          {view.kind === "transfer" && <><dt>Old owner</dt><dd>{person(view.previous_primary_owner)}</dd></>}
          <dt>{view.kind === "transfer" ? "New primary owner" : "Primary owner"}</dt><dd>{person(view.primary_owner)}</dd>
          <dt>Backup owner</dt><dd>{person(view.backup_owner)}{view.kind !== "create" && view.previous_backup_owner && view.backup_owner && view.previous_backup_owner.id !== view.backup_owner.id && <span className="faint"> (was {view.previous_backup_owner.name})</span>}</dd>
          {view.purpose && <><dt>Purpose</dt><dd style={{ whiteSpace: "pre-wrap" }}>{view.purpose}</dd></>}
          {view.description && <><dt>Description</dt><dd style={{ whiteSpace: "pre-wrap" }}>{view.description}</dd></>}
          <dt>Justification</dt><dd style={{ whiteSpace: "pre-wrap" }}>{view.justification}</dd>
          <dt>Requested</dt><dd>{view.requested_by.display_name}, {fmtDate(view.requested_at)}</dd>
          <dt>Routed by</dt><dd>{view.workflow ? `${view.workflow.name} (v${view.workflow.version})` : "The default: the owners, then an access approver"}</dd>
          {view.decided_by && <><dt>Decided</dt><dd>{view.decided_by.display_name}, {fmtDate(view.decided_at)}{view.decision_reason && <div className="small muted">{view.decision_reason}</div>}</dd></>}
          {view.fulfilled_at && <><dt>Done</dt><dd>{fmtDate(view.fulfilled_at)}</dd></>}
        </dl>
        {view.status === "approved" && <p className="small muted">Approved. The account appears once the target system confirms it.</p>}
        <section aria-label="Approvals">
          <h3 className="h-sm">Approvals</h3>
          <Stages stages={view.stages} />
        </section>
        {full.data?.questionnaires && <AnswersView answered={full.data.questionnaires} />}
      </div>
    </SidePanel>
  );
}
