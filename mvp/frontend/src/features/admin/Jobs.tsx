import { useState } from "react";
import { Play, RotateCcw } from "lucide-react";
import { JobRun, QueueJob, QueueSchedule, QueueWorker, api, fmtDate, jobs, queue, relTime, useApi } from "../../api";
import { Badge, Button, Callout, DataTable, SidePanel, useToast } from "../../components";

const KIND: Record<string, string> = {
  sync: "Connector sync", provision: "Provisioning (leaver/mover)", validation: "Connection validation", dry_run: "Dry run",
  health_rerun: "Deployment health re-run", jit_sweep: "JIT expiry sweep", audit_anchor: "Audit anchoring", guest_lifecycle: "Guest lifecycle",
  sweep_requests: "Access request sweep", sweep_lifecycle: "Lifecycle and sponsorship sweep", sweep_admin_changes: "Admin change sweep",
  containment_retries: "Containment retries", job_maintenance: "Job history upkeep",
  connector_sync: "Connector sync (worker)", provision_push: "Provisioning push (worker)",
};
const QUEUE_TONE: Record<string, "ok" | "critical" | "warning" | "info"> = { succeeded: "ok", dead: "critical", failed: "warning", running: "info", queued: "info" };
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
      <QueueSection />
    </div>
  );
}

/** The durable queue behind the scheduled jobs: its schedules, and its jobs with the dead letters (issue #300). */
function QueueSection() {
  const { data: jobsData, error, reload } = useApi<QueueJob[]>("/queue/jobs?limit=200");
  const { data: schedules, error: schedError } = useApi<QueueSchedule[]>("/queue/schedules");
  const [open, setOpen] = useState<QueueJob | null>(null);
  const dead = (jobsData ?? []).filter((j) => j.status === "dead").length;
  return (
    <div className="stack">
      <div className="card stack-sm">
        <h2>Queue</h2>
        <p className="small muted" style={{ margin: 0 }}>
          Scheduled work runs from a durable queue: a job is leased to one worker at a time, retried with backoff, and set aside as dead after its last attempt.
          {dead > 0 && <> <b>{dead} dead {dead === 1 ? "job needs" : "jobs need"} a look.</b></>}
        </p>
      </div>
      <WorkersTable />
      <DataTable
        id="queue-schedules"
        rows={schedules}
        error={schedError}
        rowKey={(r) => r.name}
        rowLabel={(r) => `${KIND[r.kind] ?? r.kind} schedule`}
        columns={[
          { id: "name", header: "Schedule", sort: (r) => r.name, cell: (r) => <span className="small"><b>{KIND[r.kind] ?? r.kind}</b></span> },
          { id: "spec", header: "Runs", sort: (r) => r.spec, cell: (r) => <code className="xs">{r.spec}</code> },
          { id: "next", header: "Next run", sort: (r) => r.next_run_at, cell: (r) => <span className="small nowrap" title={fmtDate(r.next_run_at)}>{relTime(r.next_run_at.replace("Z", ""))}</span> },
          { id: "last", header: "Last enqueued", hideNarrow: true, sort: (r) => r.last_enqueued_at ?? "", cell: (r) => r.last_enqueued_at ? <span className="small nowrap" title={fmtDate(r.last_enqueued_at)}>{relTime(r.last_enqueued_at.replace("Z", ""))}</span> : <span className="faint xs">never</span> },
          { id: "enabled", header: "State", cell: (r) => <Badge tone={r.enabled ? "ok" : undefined}>{r.enabled ? "enabled" : "disabled"}</Badge>, hideNarrow: true },
        ]}
        searchText={(r) => `${r.name} ${r.kind} ${r.spec}`}
        searchPlaceholder="Search schedules…"
        empty="No schedules yet. They are created for the tenant when the queue worker first runs."
      />
      <DataTable
        id="queue-jobs"
        rows={jobsData}
        error={error}
        rowKey={(r) => r.id}
        initialSort={["created", -1]}
        onRowClick={setOpen}
        activeKey={open?.id}
        rowLabel={(r) => `${KIND[r.kind] ?? r.kind} ${r.status}`}
        columns={[
          { id: "created", header: "Queued", sort: (r) => r.created_at, cell: (r) => <span className="small nowrap" title={fmtDate(r.created_at)}>{relTime(r.created_at.replace("Z", ""))}</span> },
          { id: "kind", header: "Job", sort: (r) => r.kind, cell: (r) => <span className="small"><b>{KIND[r.kind] ?? r.kind}</b></span> },
          { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Badge tone={QUEUE_TONE[r.status]}>{r.status}</Badge> },
          { id: "attempts", header: "Attempts", num: true, sort: (r) => r.attempts, cell: (r) => <span className="small tnum">{r.attempts} / {r.max_attempts}</span>, hideNarrow: true },
          { id: "error", header: "Last error", csv: (r) => r.last_error, cell: (r) => r.last_error ? <span className="xs truncate" style={{ display: "block", maxWidth: 360 }}>{r.last_error}</span> : <span className="faint xs">—</span>, hideNarrow: true },
        ]}
        searchText={(r) => `${KIND[r.kind] ?? r.kind} ${r.kind} ${r.status} ${r.last_error}`}
        searchPlaceholder="Search queued jobs…"
        chips={2}
        filters={[
          { id: "status", label: "Status", options: ["dead", "failed", "running", "queued", "succeeded"].map((v) => ({ value: v, label: v })), get: (r) => r.status },
          { id: "kind", label: "Job", options: Object.entries(KIND).map(([value, label]) => ({ value, label })), get: (r) => r.kind },
        ]}
        empty="The queue is empty."
      />
      {open && <QueueJobPanel job={open} onClose={() => setOpen(null)} onRetried={() => { setOpen(null); reload(); }} />}
    </div>
  );
}

/** The workers that serve the queue, with their last heartbeat (issue #302). A silent one is stale: its jobs return to the queue when their leases expire. */
function WorkersTable() {
  const { data, error } = useApi<QueueWorker[]>("/queue/workers");
  const stale = (data ?? []).filter((w) => w.status === "stale").length;
  return (
    <div className="stack-sm">
      {stale > 0 && <Callout tone="warn">{stale} {stale === 1 ? "worker has" : "workers have"} stopped reporting. Its running jobs return to the queue when their leases expire and another worker takes them.</Callout>}
      <DataTable
        id="queue-workers"
        rows={data}
        error={error}
        rowKey={(r) => r.worker_id}
        initialSort={["beat", -1]}
        rowLabel={(r) => `Worker ${r.worker_id} ${r.status}`}
        columns={[
          { id: "worker", header: "Worker", sort: (r) => r.worker_id, cell: (r) => <span className="small"><b>{r.worker_id}</b><span className="faint"> · {r.mode === "api" ? "API process" : "tessera worker"}</span></span> },
          { id: "status", header: "Health", sort: (r) => r.status, cell: (r) => <Badge tone={r.status === "healthy" ? "ok" : "warning"}>{r.status}</Badge> },
          { id: "beat", header: "Last heartbeat", sort: (r) => r.last_heartbeat_at, cell: (r) => <span className="small nowrap" title={fmtDate(r.last_heartbeat_at)}>{r.lag_seconds < 90 ? `${r.lag_seconds} s ago` : relTime(r.last_heartbeat_at.replace("Z", ""))}</span> },
          { id: "kinds", header: "Runs", csv: (r) => r.kinds.join(" "), cell: (r) => <span className="xs">{r.kinds.map((k) => KIND[k] ?? k).join(", ") || "—"}</span>, hideNarrow: true },
          { id: "load", header: "Running", num: true, sort: (r) => r.running, cell: (r) => <span className="small tnum">{r.running} / {r.concurrency}</span>, hideNarrow: true },
          { id: "host", header: "Host", csv: (r) => `${r.hostname} ${r.pid}`, cell: (r) => <span className="xs">{r.hostname}{r.version && <span className="faint"> · {r.version}</span>}</span>, hideNarrow: true },
        ]}
        searchText={(r) => `${r.worker_id} ${r.hostname} ${r.kinds.join(" ")} ${r.status}`}
        searchPlaceholder="Search workers…"
        empty="No worker has reported yet. Start the API, or run tessera worker, to see it here."
      />
    </div>
  );
}

function QueueJobPanel({ job, onClose, onRetried }: { job: QueueJob; onClose: () => void; onRetried: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const retry = async () => {
    setBusy(true);
    try {
      await queue.retry(job.id);
      toast("Queued again with a fresh set of attempts");
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
      sub={<span className="row tight"><Badge tone={QUEUE_TONE[job.status]}>{job.status}</Badge> <span className="small faint">{fmtDate(job.created_at)}</span></span>}
      onClose={onClose}
      commands={job.status === "dead" ? <Button size="sm" variant="primary" icon={<RotateCcw size={13} />} disabled={busy} onClick={retry}>Retry</Button> : undefined}
    >
      <div className="stack-sm">
        {job.last_error && <Callout tone="bad"><b>Last error.</b> {job.last_error}</Callout>}
        {job.status === "dead" && <p className="small muted" style={{ margin: 0 }}>Every attempt failed. Retrying needs a fresh sign-in check and is recorded in the audit log.</p>}
        <dl className="kv small">
          <dt>Attempts</dt><dd>{job.attempts} of {job.max_attempts}</dd>
          <dt>{job.status === "queued" || job.status === "failed" ? "Runs at" : "Was due"}</dt><dd>{fmtDate(job.run_at)}</dd>
          {job.lease_owner && <><dt>Leased to</dt><dd><code className="xs">{job.lease_owner}</code>{job.lease_expires_at && <> until {fmtDate(job.lease_expires_at)}</>}</dd></>}
          {job.finished_at && <><dt>Finished</dt><dd>{fmtDate(job.finished_at)}</dd></>}
          <dt>Job id</dt><dd><code className="xs">{job.id}</code></dd>
        </dl>
      </div>
    </SidePanel>
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
