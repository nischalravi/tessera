import { useState } from "react";
import { Eye, Play, Power } from "lucide-react";
import { GrpLoader, LoaderRun, fmtDate, groupLoaders, loaderPending } from "../../../api";
import { useSession } from "../../../app/auth";
import { Badge, Callout, CommandBar, Drawer, Loading, useToast } from "../../../components";
import { errText, useLoad } from "./hooks";
import { HeldRun, ImpactView, PlanView, RunRow, Trips } from "./LoaderRuns";
import { lagText, loaderState, runSummary, scheduleText, typeLabel } from "./loaderModel";

/** A pending run's plan in a drawer, from a preview or the history. */
function RunDrawer({ loaderId, run, onClose }: { loaderId: string; run: LoaderRun; onClose: () => void }) {
  const d = useLoad(() => groupLoaders.runDetail(loaderId, run.id), `loader-run:${run.id}`);
  const r = d.data ?? run;
  return (
    <Drawer title={run.kind === "preview" ? "Preview" : `${run.kind[0].toUpperCase()}${run.kind.slice(1)} run`} sub={fmtDate(run.started_at)} onClose={onClose} wide>
      <div className="stack">
        <p>{runSummary(r)}{r.source_hash && <span className="faint small"> · source {r.source_hash.slice(0, 12)}</span>}</p>
        <Trips trips={r.failsafe_tripped} />
        {r.error && <Callout tone="bad">{r.error}</Callout>}
        {!d.data ? <Loading kind="block" error={d.error} /> : (
          <>
            {d.data.impact && <ImpactView impact={d.data.impact} />}
            {d.data.plan && <PlanView plan={d.data.plan} />}
          </>
        )}
      </div>
    </Drawer>
  );
}

/**
 * Everything about one loader: its state and schedule, Run now and Preview, held runs to approve or reject,
 * the people that matched nobody, and the run history. The API checks each action against the folder's privileges;
 * the buttons only hide what cannot work.
 */
export function LoaderPanel({ loader, onChanged }: { loader: GrpLoader; onChanged?: () => void }) {
  const toast = useToast();
  const { can } = useSession();
  const canAdmin = can("groups.loader.admin");
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState<LoaderRun | null>(null);
  const runs = useLoad(() => groupLoaders.runs(loader.id, { limit: 20 }), `loader-runs:${loader.id}:${loader.job?.last_run?.id ?? ""}:${loader.status}`);
  // the definition, the runs' detail and the unresolved people are for those who administer the folder (the API says so by sending `config`)
  const folderAdmin = loader.config !== undefined;
  const unresolved = useLoad(folderAdmin ? () => groupLoaders.unresolved(loader.id, { limit: 20 }) : null, `loader-unresolved:${loader.id}:${loader.job?.last_run?.id ?? ""}`);
  const st = loaderState(loader);
  const held = (runs.data?.items ?? []).filter((r) => r.status === "held");
  const last = loader.job?.last_run ?? null;

  const act = async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    try {
      await fn();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  const run = (kind: "full" | "preview") => act(kind, async () => {
    const r = await groupLoaders.run(loader.id, kind);
    if (!("id" in r)) return toast("Nothing new to load");
    if (kind === "preview") setOpen(await groupLoaders.runDetail(loader.id, r.id));
    else toast(r.status === "held" ? "The run was held: a failsafe tripped" : `Run ${r.status}: ${runSummary(r)}`, r.status === "held" ? { kind: "error" } : undefined);
    onChanged?.();
  });
  const toggle = () => act("toggle", async () => {
    const on = loader.status === "disabled";
    const r = await groupLoaders.update(loader.id, { status: on ? "enabled" : "disabled", version: loader.version });
    toast(loaderPending(r) ? "Sent for a second administrator's approval" : on ? "Source turned on" : "Source turned off");
    onChanged?.();
  });

  return (
    <div className="stack">
      <CommandBar label={`Actions for ${loader.name}`} items={[
        canAdmin && { label: "Run now", icon: <Play size={16} />, onClick: () => run("full"), disabled: busy !== null || loader.status !== "enabled", title: loader.status !== "enabled" ? "Turn the source on first, or decide its held run" : undefined },
        canAdmin && { label: "Preview", icon: <Eye size={16} />, onClick: () => run("preview"), disabled: busy !== null },
        canAdmin && loader.status !== "held" && { label: loader.status === "disabled" ? "Turn on" : "Turn off", icon: <Power size={16} />, onClick: toggle, disabled: busy !== null,
          title: loader.requires_approval && loader.status === "disabled" ? "Turning a SQL source on needs a second administrator" : undefined },
      ]} />
      {loader.requires_approval && <Callout tone="info">This source runs a SQL query, so creating it or changing it needs a second administrator's approval. Turning it off does not.</Callout>}
      <dl className="kv">
        <dt>State</dt><dd><Badge tone={st.tone} dot>{st.label}</Badge></dd>
        <dt>Kind</dt><dd>{typeLabel(loader.type)}</dd>
        <dt>Folder</dt><dd className="sys">{loader.target_folder || "(root)"}</dd>
        <dt>Schedule</dt><dd>{scheduleText(loader.schedule)}{loader.incremental_secs ? `, and every ${loader.incremental_secs} s for changes` : ""}</dd>
        {loader.status === "enabled" && loader.job?.next_full_at && <><dt>Next run</dt><dd>{fmtDate(loader.job.next_full_at)}</dd></>}
        <dt>Last loaded</dt><dd>{lagText(loader.job?.lag_seconds)}{loader.last_full_at && <span className="faint small"> ({fmtDate(loader.last_full_at)})</span>}</dd>
        <dt>Last run</dt><dd>{last ? <><Badge tone={last.status === "failed" ? "critical" : last.status === "held" ? "warning" : "ok"}>{last.status}</Badge> {runSummary(last)}</> : "No run yet"}</dd>
        <dt>If a group is missing</dt><dd>{loader.on_missing_group}</dd>
        {loader.failsafe && <><dt>Failsafe</dt><dd className="small">{loader.failsafe.max_removed_percent}% or {loader.failsafe.max_removed} removed per group, {loader.failsafe.max_groups_emptied_percent}% of groups emptied, {loader.failsafe.max_unresolved_percent}% unresolved{loader.failsafe.min_group_size ? `, at least ${loader.failsafe.min_group_size} per group` : ""}</dd></>}
      </dl>
      {last?.status === "failed" && last.error && <Callout tone="bad">The last run failed: {last.error}</Callout>}

      {held.length > 0 && (
        <section className="stack-sm" aria-label="Held runs">
          <h3 style={{ fontSize: "var(--fs-lg)" }}>Held for approval</h3>
          {held.map((h) => <HeldRun key={h.id} loaderId={loader.id} run={h} canDecide={canAdmin && folderAdmin} onDone={onChanged} />)}
        </section>
      )}

      <section className="stack-sm" aria-label="Unresolved people">
        <h3 style={{ fontSize: "var(--fs-lg)" }}>Unresolved people{unresolved.data ? ` (${unresolved.data.total})` : ""}</h3>
        {!folderAdmin ? <p className="muted">Only an administrator of the folder sees who could not be matched.</p>
          : !unresolved.data ? <Loading kind="block" error={unresolved.error} /> : unresolved.data.items.length === 0
          ? <p className="muted">Everyone the source names matches an identity.</p>
          : (
            <div className="table-scroll">
              <table>
                <caption className="sr-only">People the source names that match no identity</caption>
                <thead><tr><th scope="col">Identifier</th><th scope="col">Matched as</th><th scope="col">Groups</th><th scope="col">First seen</th></tr></thead>
                <tbody>
                  {unresolved.data.items.map((u) => (
                    <tr key={`${u.source}:${u.identifier}`}>
                      <td className="sys">{u.identifier}</td><td>{u.source}</td><td className="small">{(u.groups ?? []).join(", ")}</td><td>{fmtDate(u.first_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </section>

      <section className="stack-sm" aria-label="Run history">
        <h3 style={{ fontSize: "var(--fs-lg)" }}>Run history</h3>
        {!runs.data ? <Loading kind="block" error={runs.error} /> : runs.data.items.length === 0 ? <p className="muted">It has not run yet. Preview it to see what it would do.</p> : (
          <div className="table-scroll">
            <table>
              <caption className="sr-only">Runs of {loader.name}, newest first</caption>
              <thead><tr><th scope="col">Started</th><th scope="col">Kind</th><th scope="col">Result</th><th scope="col">Changes</th><th scope="col" className="num">Rows</th><th scope="col"><span className="sr-only">Details</span></th></tr></thead>
              <tbody>{runs.data.items.map((r) => <RunRow key={r.id} run={r} onOpen={folderAdmin ? () => setOpen(r) : undefined} />)}</tbody>
            </table>
          </div>
        )}
      </section>
      {open && <RunDrawer loaderId={loader.id} run={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
