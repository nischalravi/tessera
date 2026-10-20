/** Pieces shared by the secret-rotation screens: badges, the plan preview, the job timeline and the re-read evidence. */
import { ReactNode, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Check, CircleAlert, CircleDashed, Clock, SkipForward } from "lucide-react";
import { RotationJob, RotationJobStep, RotationPlanItem, RotationSecretStatus, RotationVerification, fmtDate, rotation, useApi } from "../../api";
import { Badge, Button, Callout, Chip, Drawer, LinkTabs, Loading, useToast } from "../../components";
import { ACTION_LABEL, ACTION_TONE, ORIGIN_LABEL, SECRET_STATUS_LABEL, SECRET_STATUS_TONE, STATE_LABEL, STATE_TONE, evidenceLines, graceText, planHeadline, rotatable, secretStatus, summarizePlan } from "./model";
import type { RotationOrigin, RotationState } from "../../api";

export const RotationTabs = () => (
  <LinkTabs
    label="Secret rotation"
    tabs={[
      { to: "/rotation/secrets", label: "Secrets" },
      { to: "/rotation/jobs", label: "Rotation jobs" },
      { to: "/rotation/policies", label: "Policies & adapters" },
      { to: "/rotation/vendor", label: "Vendor compromised" },
    ]}
  />
);

export const StateBadge = ({ state }: { state: RotationState }) => <Badge tone={STATE_TONE[state]} dot>{STATE_LABEL[state]}</Badge>;
export const OriginText = ({ origin }: { origin: RotationOrigin }) => <span className="small">{ORIGIN_LABEL[origin]}</span>;
export const ActionBadge = ({ action }: { action: RotationPlanItem["action"] }) => <Badge tone={ACTION_TONE[action]}>{ACTION_LABEL[action]}</Badge>;

/** Key / value rows in the style of the other detail panels. */
export function Facts({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.filter(([, v]) => v !== null && v !== undefined && v !== "").map(([k, v]) => (
        <div key={k} style={{ display: "contents" }}><dt>{k}</dt><dd>{v}</dd></div>
      ))}
    </dl>
  );
}

// ---------------------------------------------------------------- plan

/** What a rotation would do, secret by secret. Nothing is called or written to produce it. */
export function PlanTable({ items }: { items: RotationPlanItem[] }) {
  return (
    <div className="stack-sm">
      {items.map((it) => (
        <details key={it.secret_id} className="card flush plan-item" style={{ padding: "8px 12px" }}>
          <summary className="row" style={{ cursor: "pointer", gap: 10 }}>
            <span className="sys name-link">{it.name}</span>
            <Chip mono>{it.system}</Chip>
            <span className="small faint">{it.kind.replace(/_/g, " ")}</span>
            <span className="grow" />
            <ActionBadge action={it.action} />
          </summary>
          <div className="stack-sm mt-sm">
            <div className="small muted">
              {it.owner ? <>Owner: <b>{it.owner.name}</b>. </> : <>No owner: notifications go to the tenant administrators. </>}
              {it.max_age_days != null ? <>Age {it.age_days} of {it.max_age_days} days{it.overdue ? " (overdue)" : ""}.</> : <>Age {it.age_days} days.</>}
              {it.action === "rotate" && <> Grace period: {graceText(it.grace_hours)}.</>}
            </div>
            {it.reason && <Callout tone={it.action === "blocked" ? "bad" : "warn"} icon={<CircleAlert size={16} />}>{it.reason}</Callout>}
            {it.steps.length > 0 && <ol className="small" style={{ margin: 0, paddingLeft: 20 }}>{it.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>}
            {it.warnings.map((w, i) => <div key={i} className="small faint">{w}</div>)}
          </div>
        </details>
      ))}
    </div>
  );
}

/**
 * Plan preview for the Rotate action: shows what would happen to each secret, then queues the
 * rotations that can run. Needs a fresh phishing-resistant sign-in (the API asks for one).
 */
export function PlanDrawer({ title, secretIds, onClose }: { title: string; secretIds: number[]; onClose: () => void }) {
  const [items, setItems] = useState<RotationPlanItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const nav = useNavigate();
  const key = secretIds.join(",");
  useEffect(() => {
    let alive = true;
    rotation.plan(secretIds).then((p) => alive && setItems(p)).catch((e) => alive && setError(String(e.message ?? e)));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  const todo = items ? rotatable(items) : [];
  const run = async () => {
    setBusy(true);
    let started = 0;
    const failed: string[] = [];
    for (const id of todo) {
      try {
        await rotation.start(id);
        started++;
      } catch (e) {
        failed.push((e as Error).message);
      }
    }
    setBusy(false);
    if (failed.length) toast(`${started} queued, ${failed.length} refused: ${failed[0]}`, { kind: "error" });
    else toast(`${started} rotation${started === 1 ? "" : "s"} queued. The worker runs them within a minute.`, { action: { label: "View jobs", run: () => nav("/rotation/jobs") } });
    if (started) onClose();
  };
  return (
    <Drawer
      title={title}
      sub="Plan preview. Tessera creates the new credential, writes it to your vault (it is never stored by Tessera), waits out the grace period, disables the old one, re-reads it and only then deletes it."
      onClose={onClose}
      wide
      footer={
        <>
          <span className="small muted grow">{items ? planHeadline(summarizePlan(items)) : ""}</span>
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" disabled={busy || todo.length === 0} onClick={run}>{busy ? "Queuing…" : todo.length === 0 ? "Rotate" : `Rotate ${todo.length} secret${todo.length === 1 ? "" : "s"}`}</Button>
        </>
      }
    >
      {!items ? <Loading error={error} kind="block" /> : <PlanTable items={items} />}
    </Drawer>
  );
}

// ---------------------------------------------------------------- jobs

const STEP_LABEL: Record<RotationJobStep["state"], string> = {
  created: "New credential created",
  handed_over: "Handed over to your vault",
  old_disabled: "Old credential disabled",
  verified: "Old credential re-read",
  old_deleted: "Old credential deleted",
};

const STEP_ICON: Record<RotationJobStep["status"], ReactNode> = {
  done: <Check size={14} aria-hidden />,
  current: <Clock size={14} aria-hidden />,
  pending: <CircleDashed size={14} aria-hidden />,
  failed: <CircleAlert size={14} aria-hidden />,
  skipped: <SkipForward size={14} aria-hidden />,
};

export function JobTimeline({ job }: { job: RotationJob }) {
  return (
    <ol className="stack-sm" aria-label="Rotation steps" style={{ listStyle: "none", margin: 0, padding: 0 }}>
      {job.steps.map((s) => (
        <li key={s.state} className="row" style={{ alignItems: "flex-start", gap: 10, opacity: s.status === "pending" ? 0.6 : 1 }}>
          <span style={{ marginTop: 2, color: s.status === "failed" ? "var(--critical)" : s.status === "done" ? "var(--ok)" : undefined }}>{STEP_ICON[s.status]}</span>
          <div className="grow">
            <div>{s.state === "old_deleted" && job.adapter_type === "aws_secretsmanager" ? "Old version retired (deprecated, not deleted)" : STEP_LABEL[s.state]}{s.status === "skipped" && <span className="faint"> (the provider cannot do this)</span>}</div>
            <div className="xs faint">
              {s.at && s.status !== "pending" ? fmtDate(s.at) : s.status === "current" && job.next_step_at ? `due ${fmtDate(job.next_step_at)}` : ""}
              <span className="sr-only">{`, ${s.status}`}</span>
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}

/** The re-read of the old credential that a job needs before it can delete it. */
export function Evidence({ v }: { v: RotationVerification }) {
  return (
    <div className="stack-sm">
      <div className="small faint">Re-read {fmtDate(v.checked_at)}</div>
      {evidenceLines(v).map((l, i) => <div key={i} className="small">{l}</div>)}
    </div>
  );
}

/** Rotation status of every secret by id (one cached request shared by every caller). */
export function useRotationStatus() {
  const { data } = useApi<RotationSecretStatus[]>(rotation.paths.overview);
  return new Map((data ?? []).map((r) => [r.secret_id, r]));
}

/** A secret's rotation status as a badge; nothing until the overview has loaded. */
export function RotationBadge({ status }: { status: RotationSecretStatus | undefined }) {
  if (!status) return null;
  const k = secretStatus(status);
  return <Badge tone={SECRET_STATUS_TONE[k]} dot>{SECRET_STATUS_LABEL[k]}</Badge>;
}
