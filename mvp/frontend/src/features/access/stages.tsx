import { RequestStage, fmtDate } from "../../api";
import { Badge } from "../../components";

/** A request line's approval stages (issue #165): who decides each, and how it went. */
export const STAGE_LABEL: Record<string, string> = { manager: "Manager", owner: "Owner", decider: "Access approver" };

export function Stages({ stages }: { stages: RequestStage[] }) {
  if (!stages.length) return null;
  return (
    <ol className="timeline">
      {stages.map((s) => (
        <li key={s.index}>
          <b>{STAGE_LABEL[s.kind] ?? s.kind}</b>{s.assignee && <> · {s.assignee.name}</>}{" "}
          <Badge tone={s.status === "approved" ? "ok" : s.status === "denied" ? "critical" : s.status === "waiting" ? "info" : "outline"}>{s.status}</Badge>
          {s.escalated && <> <Badge tone="warning">escalated</Badge></>}
          <div className="small muted">
            {s.decided_by ? <>by {s.decided_by.display_name}{s.on_behalf_of && <> for {s.on_behalf_of.display_name}</>}, {fmtDate(s.decided_at)}</>
              : s.status === "waiting" && s.due_at ? <>{s.escalated ? "Any access approver can decide now" : `Escalates ${fmtDate(s.due_at)}`}</>
              : s.status === "queued" ? "After the previous stage" : null}
            {s.reason && <div>{s.reason}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}
