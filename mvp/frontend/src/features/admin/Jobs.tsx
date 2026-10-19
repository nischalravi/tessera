import { useState } from "react";
import { Play, RotateCcw } from "lucide-react";
import { JobRun, api, fmtDate, jobs, relTime, useApi } from "../../api";
import { Badge, Button, Callout, DataTable, SidePanel, useToast } from "../../components";

const KIND: Record<string, string> = {
  sync: "Connector sync", provision: "Provisioning (leaver/mover)", validation: "Connection validation", dry_run: "Dry run",
  health_rerun: "Deployment health re-run", jit_sweep: "JIT expiry sweep", audit_anchor: "Audit anchoring",
};
const STATUS_TONE: Record<string, "ok" | "critical" | "warning"> = { succeeded: "ok", failed: "critical", running: "warning" };

const duration = (ms: number | null) => (ms == null ? "—" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);

/** Admin → Jobs: run a job now, and the run history with failures (issue #172). */
export function Jobs() {
  const { data, error } = useApi<JobRun[]>("/jobs?limit=500");
  const [open, setOpen] = useState<JobRun | null>(null);
  return (
    <div className="stack">
      <RunNow />
      <DataTable
        id="jobs"
        rows={data}
        error={error}
        rowKey={(r) => r.id}
        initialSort={["started", -1]}
        onRowClick={setOpen}
        activeKey={open?.id}
        rowLabel={(r) => `${KIND[r.kind] ?? r.kind} ${r.status}`}
        columns={[
          { id: "started", header: "Started", sort: (r) => r.started_at, cell: (r) => <span className="small nowrap" title={fmtDate(r.started_at)}>{relTime(r.started_at.replace("Z", ""))}</span> },
          { id: "kind", header: "Job", sort: (r) => r.kind, cell: (r) => <span className="small"><b>{KIND[r.kind] ?? r.kind}</b>{r.trigger !== "manual" && <span className="faint"> · {r.trigger}</span>}</span> },
          { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Badge tone={STATUS_TONE[r.status]}>{r.status}</Badge> },
          { id: "duration", header: "Duration", num: true, sort: (r) => r.duration_ms ?? -1, cell: (r) => <span className="small tnum">{duration(r.duration_ms)}</span>, hideNarrow: true },
          { id: "actor", header: "By", sort: (r) => r.actor, cell: (r) => <span className="small">{r.actor}</span>, hideNarrow: true },
          { id: "error", header: "Error", csv: (r) => r.error ?? "", cell: (r) => r.error ? <span className="xs truncate" style={{ display: "block", maxWidth: 360 }}>{r.error}</span> : <span className="faint xs">—</span>, hideNarrow: true },
        ]}
        searchText={(r) => `${KIND[r.kind] ?? r.kind} ${r.kind} ${r.status} ${r.actor} ${r.error ?? ""} ${r.path ?? ""}`}
        searchPlaceholder="Search job, status, actor or error…"
        chips={2}
        filters={[
          { id: "status", label: "Status", options: [{ value: "failed", label: "Failed" }, { value: "running", label: "Running" }, { value: "succeeded", label: "Succeeded" }], get: (r) => r.status },
          { id: "kind", label: "Job", options: Object.entries(KIND).map(([value, label]) => ({ value, label })), get: (r) => r.kind },
          { id: "trigger", label: "Trigger", options: ["manual", "schedule", "retry"].map((v) => ({ value: v, label: v })), get: (r) => r.trigger },
        ]}
        empty="No job has run yet. Runs of syncs, validations, dry runs, provisioning and the scheduled sweeps appear here."
      />
      {open && <JobPanel job={open} onClose={() => setOpen(null)} onRetried={() => setOpen(null)} />}
    </div>
  );
}

function RunNow() {
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const run = async (id: string, name: string, path: string) => {
    setBusy(id);
    try {
      const out = await api<Record<string, number>>(path, {});
      toast(`${name}: ${Object.entries(out).slice(0, 3).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(", ")}`);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="card stack-sm">
      <h2>Run now</h2>
      <p className="small muted" style={{ margin: 0 }}>The JIT sweeper also runs every 30 seconds and audit anchoring every minute; scheduled runs are listed when they did something or failed.</p>
      <div className="row wrap" style={{ gap: 8 }}>
        <Button size="sm" icon={<Play size={13} />} disabled={busy === "sync"} onClick={() => run("sync", "Connector sync", "/connectors/sync")}>Connector sync</Button>
        <Button size="sm" icon={<Play size={13} />} disabled={busy === "sweep"} onClick={() => run("sweep", "JIT sweep", "/jit/sweep")}>JIT expiry sweep</Button>
      </div>
    </div>
  );
}

function JobPanel({ job, onClose, onRetried }: { job: JobRun; onClose: () => void; onRetried: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const retry = async () => {
    setBusy(true);
    try {
      await jobs.retry(job.id);
      toast("Retried: the new run is at the top of the list");
      onRetried();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <SidePanel
      title={KIND[job.kind] ?? job.kind}
      sub={<span className="row tight"><Badge tone={STATUS_TONE[job.status]}>{job.status}</Badge> <span className="small faint">{fmtDate(job.started_at)}</span></span>}
      onClose={onClose}
      commands={job.retryable ? <Button size="sm" variant="primary" icon={<RotateCcw size={13} />} disabled={busy} onClick={retry}>Retry</Button> : undefined}
    >
      <div className="stack-sm">
        {job.error && <Callout tone="bad"><b>Error.</b> {job.error}</Callout>}
        {!job.retryable && job.status !== "running" && (
          <p className="small muted" style={{ margin: 0 }}>
            {job.kind === "provision" ? "Provisioning changes target systems, so it is not retried from here: re-run the plan from its HRIS event after checking what was applied." : job.kind === "audit_anchor" ? "Anchoring retries itself on the next run of the checkpointer." : "This run cannot be retried from here."}
          </p>
        )}
        <dl className="kv small">
          <dt>Trigger</dt><dd>{job.trigger}{job.retry_of && <> of <code className="xs">{job.retry_of.slice(0, 8)}</code></>}</dd>
          <dt>By</dt><dd>{job.actor}</dd>
          <dt>Duration</dt><dd>{duration(job.duration_ms)}</dd>
          {job.path && <><dt>Call</dt><dd><code className="xs">{job.method} {job.path}</code></dd></>}
          {job.connection_id && <><dt>Connection</dt><dd><code className="xs">{job.connection_id}</code></dd></>}
          <dt>Run id</dt><dd><code className="xs">{job.id}</code></dd>
        </dl>
        {job.result != null && (
          <div>
            <h3 className="small">Result</h3>
            <pre className="xs sys" style={{ whiteSpace: "pre-wrap", margin: 0 }}>{JSON.stringify(job.result, null, 2)}</pre>
          </div>
        )}
      </div>
    </SidePanel>
  );
}
