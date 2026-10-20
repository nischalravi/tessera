/** Rotation jobs: every rotation with its state, and a side panel with the timeline and the re-read evidence. */
import { useEffect } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { RotateCcw, X } from "lucide-react";
import { ApiError, RotationJob, fmtDate, relTime, rotation, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Chip, Column, DataTable, Loading, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { ORIGIN_LABEL, STATE_LABEL, STATE_ORDER, graceText, isInFlight, jobActions } from "./model";
import { Evidence, Facts, JobTimeline, OriginText, RotationTabs, StateBadge } from "./shared";

const uniq = (xs: string[]) => [...new Set(xs)].sort();

export function RotationJobs() {
  const [params, setParams] = useSearchParams();
  const secret = params.get("secret");
  const bulk = params.get("bulk");
  const query = [secret && /^\d+$/.test(secret) ? `secret_id=${secret}` : "", bulk && /^[0-9a-f-]{36}$/.test(bulk) ? `bulk_id=${bulk}` : ""].filter(Boolean).join("&");
  const { data, error, reload } = useApi<RotationJob[]>(rotation.paths.jobs(query ? `?${query}` : ""));
  const [selected, setSelected] = useSelected();
  const live = (data ?? []).some((j) => isInFlight(j.state));
  // the worker moves jobs along on its own: keep the list current while any is running
  useEffect(() => {
    if (!live) return;
    const t = setInterval(reload, 5000);
    return () => clearInterval(t);
  }, [live, reload]);
  const clear = (k: string) => setParams((p) => { const n = new URLSearchParams(p); n.delete(k); return n; }, { replace: true });
  const cols: Column<RotationJob>[] = [
    { id: "secret", header: "Secret", sort: (r) => r.secret.toLowerCase(), csv: (r) => r.secret, cell: (r) => <div><span className="sys name-link">{r.secret}</span><div className="xs faint">{r.kind.replace(/_/g, " ")}</div></div> },
    { id: "system", header: "System", sort: (r) => r.system, cell: (r) => <Chip mono>{r.system}</Chip>, hideNarrow: true },
    { id: "state", header: "State", sort: (r) => STATE_ORDER.indexOf(r.state), csv: (r) => STATE_LABEL[r.state], cell: (r) => <StateBadge state={r.state} /> },
    { id: "origin", header: "Started by", sort: (r) => r.origin, csv: (r) => ORIGIN_LABEL[r.origin], cell: (r) => <OriginText origin={r.origin} />, hideNarrow: true },
    { id: "adapter", header: "Adapter", sort: (r) => r.adapter, cell: (r) => <span className="small">{r.adapter}</span>, hideNarrow: true },
    { id: "when", header: "Started", sort: (r) => r.created_at, csv: (r) => r.created_at, cell: (r) => <span className="small nowrap">{relTime(r.created_at)}</span> },
    { id: "next", header: "Next step / done", sort: (r) => r.completed_at ?? r.next_step_at ?? "", cell: (r) => <span className="small nowrap">{r.completed_at ? fmtDate(r.completed_at) : r.next_step_at ? `due ${relTime(r.next_step_at)}` : "–"}</span>, hideNarrow: true },
  ];
  return (
    <Page
      title="Rotation jobs"
      crumbs={[["Identity"], ["Secret rotation", "/rotation/secrets"], ["Jobs"]]}
      count={data ? `${data.length} job${data.length === 1 ? "" : "s"}` : undefined}
      sub="A job moves a secret through: new credential created, handed over to your vault, old credential disabled after the grace period, old credential re-read, old credential deleted. Failed jobs resume from the step that failed."
      tabs={<RotationTabs />}
    >
      {(query) && (
        <div className="row tight" style={{ marginBottom: 8 }}>
          {secret && <Button size="sm" icon={<X size={14} />} onClick={() => clear("secret")}>Secret {secret}</Button>}
          {bulk && <Button size="sm" icon={<X size={14} />} onClick={() => clear("bulk")}>Bulk run {bulk.slice(0, 8)}</Button>}
        </div>
      )}
      <DataTable<RotationJob>
        id="rotation-jobs"
        rows={data}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        initialSort={["when", -1]}
        searchText={(r) => `${r.secret} ${r.system} ${r.kind} ${r.adapter} ${r.requested_by} ${r.old_ref}`}
        searchPlaceholder="Search jobs…"
        filters={[
          { id: "state", label: "State", options: STATE_ORDER.map((value) => ({ value, label: STATE_LABEL[value] })), get: (r) => r.state },
          { id: "origin", label: "Started by", options: Object.entries(ORIGIN_LABEL).map(([value, label]) => ({ value, label })), get: (r) => r.origin },
          { id: "system", label: "System", options: uniq((data ?? []).map((r) => r.system)).map((value) => ({ value, label: value })), get: (r) => r.system },
        ]}
        onRefresh={reload}
        rowLabel={(r) => `${r.secret} rotation`}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
      />
      {selected && <JobPanel id={selected} onClose={() => setSelected(null)} onChanged={reload} />}
    </Page>
  );
}

function JobPanel({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { data: j, error, reload } = useApi<RotationJob>(rotation.paths.job(id));
  const { can } = useSession();
  const toast = useToast();
  const confirm = useConfirm();
  const allowed = can("secrets.rotate");
  const act = async (what: "retry" | "cancel") => {
    if (what === "cancel" && (await confirm({ title: "Cancel this rotation?", body: "It has not created anything yet, so nothing needs cleaning up.", confirmLabel: "Cancel rotation", danger: true })) === null) return;
    try {
      await (what === "retry" ? rotation.retry(id) : rotation.cancel(id));
      toast(what === "retry" ? "Rotation resumed from the step that failed" : "Rotation cancelled");
      reload();
      onChanged();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : String(e), { kind: "error" });
    }
  };
  if (!j) return <SidePanel title="Rotation job" onClose={onClose}><Loading error={error} kind="block" /></SidePanel>;
  const a = jobActions(j);
  return (
    <SidePanel
      title={j.secret}
      sub={<><StateBadge state={j.state} /><Chip mono>{j.system}</Chip></>}
      onClose={onClose}
      commands={
        <div className="row">
          {a.retry && <Button size="sm" variant="primary" icon={<RotateCcw size={14} />} disabled={!allowed} onClick={() => act("retry")}>Retry</Button>}
          {a.cancel && <Button size="sm" disabled={!allowed} onClick={() => act("cancel")}>Cancel</Button>}
        </div>
      }
      footer={<Link to={`/rotation/secrets?selected=${j.secret_id}`}>Open the secret</Link>}
    >
      {j.state === "failed" && j.last_error && (
        <Callout tone="bad">
          <b>Failed{j.failed_state ? ` at “${STATE_LABEL[j.failed_state]}”` : ""}.</b> {j.last_error}
          <div className="small">Nothing was deleted unless the timeline below says so. Fix the cause, then Retry.</div>
        </Callout>
      )}
      {j.state !== "failed" && j.last_error && <Callout tone="warn">{j.last_error} (attempt {j.attempts}; Tessera retries with a delay)</Callout>}
      <div>
        <h3 style={{ marginBottom: 8 }}>Timeline</h3>
        <JobTimeline job={j} />
      </div>
      {j.verification && (
        <div>
          <h3 style={{ marginBottom: 8 }}>Old credential, re-read before deleting</h3>
          <Evidence v={j.verification} />
        </div>
      )}
      <Facts
        rows={[
          ["Started by", `${ORIGIN_LABEL[j.origin]} (${j.requested_by})`],
          ["Account", j.account],
          ["Adapter", `${j.adapter} (${j.adapter_type.replace(/_/g, " ")})`],
          ["Handed to", j.destination ? `${j.destination}: ${j.dest_path}` : "Rotated in place"],
          ["Grace period", graceText(j.grace_hours)],
          ["Old credential", <span key="o" className="sys">{j.old_ref}</span>],
          ["New credential", j.new_ref ? <span key="n" className="sys">{j.new_ref}</span> : "Not created yet"],
          ["Attempts", j.attempts || ""],
          ["Bulk run", j.bulk_id ? <Link key="b" to={`/rotation/vendor?run=${j.bulk_id}`}>Vendor compromised run</Link> : ""],
          ["Queued", fmtDate(j.created_at)],
        ]}
      />
      <div className="small faint"><Badge tone="outline">No secret material</Badge> The new credential is written to your vault and is never stored by Tessera; only identifiers are shown here.</div>
    </SidePanel>
  );
}
