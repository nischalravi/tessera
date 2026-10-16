import { ChevronRight } from "lucide-react";
import { Link } from "react-router-dom";
import { groups } from "../../../api";
import { Badge, Callout, Drawer, EmptyState, Loading } from "../../../components";
import { RecomputeBanner } from "./common";
import { useLoad } from "./hooks";
import { VIA_LABEL } from "./model";

/** Every way one identity is a member of a group: a list of steps from the group down to the row that names the identity. */
export function TraceDrawer({ groupId, identity, name, onClose }: { groupId: string; identity: number; name: string; onClose: () => void }) {
  const { data, error } = useLoad(() => groups.trace(groupId, identity), `trace:${groupId}:${identity}`);
  const paths = data?.paths ?? [];
  return (
    <Drawer title={`Why is ${name} a member?`} sub="Each path is one way the membership arises." onClose={onClose} wide>
      <div className="stack">
        {!data && <Loading error={error} kind="block" />}
        {data && <RecomputeBanner state={data.stale ? "pending" : "clean"} />}
        {data && !data.member && <Callout tone="neutral">{name} is not a member of this group right now.</Callout>}
        {data && data.member && paths.length === 0 && <EmptyState title="No path found">The membership exists but no path could be read; try again after the recalculation finishes.</EmptyState>}
        {paths.length > 0 && (
          <ol className="stack-sm" aria-label="Paths" style={{ listStyle: "none", padding: 0 }}>
            {paths.map((p, i) => (
              <li key={i} className="card" style={{ padding: "10px 12px" }}>
                <div className="small faint">Path {i + 1}</div>
                <div className="row tight wrap" style={{ marginTop: 4 }}>
                  {p.steps.map((s, j) => (
                    <span key={`${s.group_id}-${j}`} className="row tight">
                      {j > 0 && <ChevronRight size={12} aria-hidden />}
                      <Link to={`/directory/groups/${s.group_id}`}>{s.name}</Link>
                      <Badge tone="outline" title={s.op ? `operator: ${s.op}` : undefined}>{s.role ? s.role : (VIA_LABEL[s.via] ?? s.via)}{s.op ? ` · ${s.op}` : ""}</Badge>
                    </span>
                  ))}
                </div>
              </li>
            ))}
          </ol>
        )}
        {data?.truncated && <Callout tone="warn">Only the first paths are shown; there are more.</Callout>}
      </div>
    </Drawer>
  );
}
