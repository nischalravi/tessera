import { useState } from "react";
import { Link } from "react-router-dom";
import { Check, X } from "lucide-react";
import { LoaderImpact, LoaderPlan, LoaderRun, LoaderTrip, fmtDate, groupLoaders } from "../../../api";
import { Badge, Button, Callout, Loading, useConfirm, useToast } from "../../../components";
import { errText, useLoad } from "./hooks";
import { RUN_STATUS_LABEL, RUN_TONE, runSummary, tripText } from "./loaderModel";

const ids = (a?: number[]) => {
  if (!a?.length) return "";
  const shown = a.slice(0, 8).map((i) => `#${i}`).join(", ");
  return a.length > 8 ? `${shown} and ${a.length - 8} more` : shown;
};

/** What a run computed (or would): per group, who is added and removed, and the people the source named that match nobody. */
export function PlanView({ plan }: { plan: LoaderPlan }) {
  const groups = plan.groups ?? [];
  return (
    <div className="stack-sm">
      {groups.length === 0 ? <p className="muted">The plan changes nothing: the groups already match the source.</p> : (
        <div className="table-scroll">
          <table>
            <caption className="sr-only">What the run does to each group</caption>
            <thead><tr><th scope="col">Group</th><th scope="col" className="num">Now</th><th scope="col" className="num">After</th><th scope="col">Changes</th></tr></thead>
            <tbody>
              {groups.slice(0, 100).map((g) => (
                <tr key={g.name}>
                  <td><span className="sys">{g.name}</span>{g.create && <> <Badge tone="accent">New</Badge></>}{g.restore && <> <Badge tone="accent">Restored</Badge></>}
                    {g.missing && <> <Badge tone="warning">Not in the source: {g.action}</Badge></>}</td>
                  <td className="num">{g.current}</td>
                  <td className="num">{g.size}</td>
                  <td className="small">
                    {!!g.add?.length && <div><b>+{g.add.length}</b> <span className="muted">{ids(g.add)}</span></div>}
                    {!!g.remove?.length && <div><b>-{g.remove.length}</b> <span className="muted">{ids(g.remove)}</span></div>}
                    {!g.add?.length && !g.remove?.length && <span className="faint">no member changes</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {groups.length > 100 && <p className="small muted">{groups.length - 100} more groups are not shown.</p>}
        </div>
      )}
      {!!plan.unresolved?.length && (
        <Callout tone="warn">
          {plan.unresolved.length} {plan.unresolved.length === 1 ? "person" : "people"} in the source match no identity and are not added:{" "}
          {plan.unresolved.slice(0, 5).map((u) => `${u.identifier} (${u.source})`).join(", ")}{plan.unresolved.length > 5 && ` and ${plan.unresolved.length - 5} more`}.
          They are listed under Unresolved and tried again on every run.
        </Callout>
      )}
    </div>
  );
}

/** The downstream impact of a held run (K7): who loses what, and what else changes with it. */
export function ImpactView({ impact }: { impact: LoaderImpact }) {
  return (
    <div className="stack-sm">
      <dl className="kv">
        <dt>People gaining access</dt><dd>{impact.added_identities}</dd>
        <dt>People losing access</dt><dd>{impact.removed_identities}{impact.removed_used_last_30_days > 0 && <> ({impact.removed_used_last_30_days} used access in the last 30 days)</>}</dd>
        {impact.parent_groups.length > 0 && <><dt>Groups that contain these</dt><dd>{impact.parent_groups.map((g) => <Link key={g.id} to={`/directory/groups/${g.id}`} style={{ marginRight: 8 }}>{g.name}</Link>)}</dd></>}
        {impact.policy_groups.length > 0 && <><dt>Composite and policy groups</dt><dd>{impact.policy_groups.map((g) => <Link key={g.id} to={`/directory/groups/${g.id}`} style={{ marginRight: 8 }}>{g.name}</Link>)}</dd></>}
        {impact.provisioned_targets.length > 0 && <><dt>Provisioned to</dt><dd>{impact.provisioned_targets.join(", ")}</dd></>}
      </dl>
      {impact.note && <p className="small muted">{impact.note}</p>}
    </div>
  );
}

export function Trips({ trips }: { trips: LoaderTrip[] | null | undefined }) {
  if (!trips?.length) return null;
  return (
    <Callout tone="warn">
      <div>
        <b>A failsafe held this run, so nothing was applied.</b>
        <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>{trips.map((t, i) => <li key={`${t.rule}-${t.group ?? ""}-${i}`}>{tripText(t)}</li>)}</ul>
      </div>
    </Callout>
  );
}

/** Approve or reject a held run. Approving applies the plan as it was computed, so the person who decides sees it first. */
export function HeldRun({ loaderId, run, canDecide, onDone }: { loaderId: string; run: LoaderRun; canDecide: boolean; onDone?: () => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const detail = useLoad(() => groupLoaders.runDetail(loaderId, run.id), `loader-run:${run.id}`);
  const d = detail.data;
  const decide = async (approve: boolean) => {
    const ok = await confirm(approve
      ? { title: "Apply this held run?", body: `The plan is applied as it was computed: ${run.adds ?? 0} added, ${run.removes ?? 0} removed. Read the failsafe and the impact first.`, confirmLabel: "Apply the plan" }
      : { title: "Discard this held run?", body: "Nothing is applied. The next scheduled run starts again from the source.", confirmLabel: "Discard", danger: true });
    if (ok === null) return;
    setBusy(true);
    try {
      await (approve ? groupLoaders.approve(loaderId, run.id) : groupLoaders.reject(loaderId, run.id));
      toast(approve ? "Run applied" : "Run discarded");
      onDone?.();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack-sm">
      <Trips trips={d?.failsafe_tripped ?? run.failsafe_tripped} />
      {!d ? <Loading kind="block" error={detail.error} /> : (
        <>
          {d.impact && <ImpactView impact={d.impact} />}
          {d.plan && <PlanView plan={d.plan} />}
        </>
      )}
      {canDecide
        ? (
          <div className="row">
            <Button variant="primary" icon={<Check size={16} />} disabled={busy} onClick={() => decide(true)}>Approve and apply</Button>
            <Button variant="danger" icon={<X size={16} />} disabled={busy} onClick={() => decide(false)}>Reject</Button>
          </div>
        )
        : <p className="small muted">Only an administrator of the loader's folder can decide this run.</p>}
    </div>
  );
}

/** A run's one-line history row. */
export function RunRow({ run, onOpen }: { run: LoaderRun; onOpen?: () => void }) {
  return (
    <tr>
      <td>{fmtDate(run.started_at)}</td>
      <td>{run.kind}</td>
      <td><Badge tone={RUN_TONE[run.status] ?? "neutral"}>{RUN_STATUS_LABEL[run.status] ?? run.status}</Badge></td>
      <td className="small">{runSummary(run)}</td>
      <td className="num">{run.source_rows ?? ""}</td>
      <td>{onOpen && <Button size="sm" variant="ghost" onClick={onOpen}>Details</Button>}</td>
    </tr>
  );
}
