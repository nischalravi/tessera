/** Identity-governance specific display components shared across features. */
import { Link } from "react-router-dom";
import { Bot, Server, UserRound } from "lucide-react";
import { IdentityBrief, PathStep, SimResult, ago } from "../api";
import { Badge, Tone } from "./Badge";
import { Callout } from "./Feedback";

export const TYPE_LABEL: Record<string, string> = { human: "Person", service: "Service account", ai_agent: "AI agent" };

export function TypeIcon({ type, size = 14 }: { type: string; size?: number }) {
  if (type === "ai_agent") return <Bot size={size} aria-hidden />;
  if (type === "service") return <Server size={size} aria-hidden />;
  return <UserRound size={size} aria-hidden />;
}

export function TypeBadge({ type }: { type: string }) {
  return <Badge tone={(["human", "service", "ai_agent"].includes(type) ? type : "neutral") as Tone}>{TYPE_LABEL[type] ?? type}</Badge>;
}

const SEV_TONE: Record<string, Tone> = { critical: "critical", high: "warning", medium: "warning", low: "info" };
export function Sev({ s }: { s: string }) {
  return <Badge tone={SEV_TONE[s] ?? "neutral"} dot>{s[0].toUpperCase() + s.slice(1)}</Badge>;
}

const FLAG_LABEL: Record<string, [string, Tone]> = {
  orphaned: ["No owner", "critical"],
  owner_left: ["Owner left", "critical"],
  stale_secret: ["Stale secret", "warning"],
  dormant: ["Dormant", "neutral"],
  privileged: ["Privileged", "warning"],
  pii_access: ["PII access", "critical"],
  unused_30d: ["Unused 30d", "warning"],
  unused_60d: ["Unused 60d", "warning"],
  unused_90d: ["Unused 90d", "warning"],
  privileged_idle: ["Privileged, idle", "warning"],
  policy_violation: ["Policy violation", "critical"],
  terminated_identity: ["Leaver", "critical"],
  orphaned_nhi: ["Orphaned machine identity", "critical"],
};
export const flagLabel = (f: string) => (FLAG_LABEL[f]?.[0] ?? f.replace(/_/g, " "));

export function Flag({ f }: { f: string }) {
  const [label, tone] = FLAG_LABEL[f] ?? [f.replace(/_/g, " "), "neutral" as Tone];
  return <Badge tone={tone}>{label}</Badge>;
}

const STATUS_TONE: Record<string, Tone> = { active: "ok", approved: "ok", pending: "warning", denied: "critical", terminated: "critical", disabled: "neutral", expired: "neutral", revoked: "neutral", executed: "ok", draft: "outline", submitted: "info" };
export function Status({ s }: { s: string }) {
  return <Badge tone={STATUS_TONE[s] ?? "neutral"} dot>{s[0].toUpperCase() + s.slice(1)}</Badge>;
}

export function initials(name: string) {
  return name.split(/[\s._-]+/).filter(Boolean).slice(0, 2).map((x) => x[0]!.toUpperCase()).join("");
}

export function Avatar({ name, type, lg }: { name: string; type?: string; lg?: boolean }) {
  return (
    <span className={`avatar ${lg ? "lg" : ""}`} aria-hidden>
      {type && type !== "human" ? <TypeIcon type={type} size={lg ? 20 : 14} /> : initials(name)}
    </span>
  );
}

export function IdLink({ i }: { i: IdentityBrief | null | undefined }) {
  if (!i) return <span className="faint">None</span>;
  return (
    <Link to={`/directory/identities/${i.id}`}>
      {i.name}
      {i.status === "terminated" && <span style={{ marginLeft: 6 }}><Badge tone="critical">Left</Badge></span>}
    </Link>
  );
}

export function PathView({ steps }: { steps: PathStep[] }) {
  return (
    <div className="path">
      {steps.map((s, i) => (
        <span key={s.key} className="row tight">
          {i > 0 && (
            <span className="arrow" title={s.via?.relation}>
              {s.via?.source === "jit" ? <span className="jit">JIT →</span> : "→"}
            </span>
          )}
          <span className={`node ${s.kind}`}>{s.label}</span>
        </span>
      ))}
    </div>
  );
}

export function SimulationView({ r }: { r: SimResult }) {
  const s = r.summary;
  const breaking = s.removed_recently_used > 0;
  return (
    <div className="stack">
      {r.changes.length > 0 && (
        <div className="stack-sm">
          <h3>Change</h3>
          {r.changes.map((c, i) => (
            <div key={i} className="row small">
              <Badge tone={c.op === "add" ? "info" : "warning"}>{c.op.replace("_", " ")}</Badge> {c.label}
            </div>
          ))}
        </div>
      )}
      <div className="stat-row">
        <div className="s"><b>{s.identities_affected}</b><span>identities affected</span></div>
        <div className="s"><b>{s.permissions_removed}</b><span>permissions removed</span></div>
        <div className="s"><b>{s.permissions_added}</b><span>permissions added</span></div>
        <div className="s"><b style={{ color: breaking ? "var(--critical)" : undefined }}>{s.removed_recently_used}</b><span>used in last 30 days</span></div>
        <div className="s"><b style={{ color: "var(--ok)" }}>{s.violations_resolved}</b><span>violations resolved</span></div>
        <div className="s"><b style={{ color: s.violations_introduced ? "var(--critical)" : undefined }}>{s.violations_introduced}</b><span>violations introduced</span></div>
      </div>
      {s.permissions_removed > 0 &&
        (breaking ? (
          <Callout tone="warn">Blast radius warning: {s.removed_recently_used} permission(s) removed by this change were used in the last 30 days. Expect breakage unless another grant covers them.</Callout>
        ) : (
          <Callout tone="ok">Low risk: none of the permissions removed were used in the last 30 days.</Callout>
        ))}
      {r.identities.map((i) => (
        <div key={i.identity_id} className="card flush">
          <div className="card-h"><b>{i.name}</b><TypeBadge type={i.type} /></div>
          {i.removed.length > 0 && (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Loses</th><th>System</th><th>Last used</th></tr></thead>
                <tbody>
                  {i.removed.map((p) => (
                    <tr key={p.perm_key}>
                      <td>
                        {p.action} <span className="muted">on {p.resource}</span>{" "}
                        {p.privileged && <Badge tone="warning">Privileged</Badge>}{" "}
                        {p.tags.map((t) => <span key={t} className="chip">{t}</span>)}
                      </td>
                      <td className="sys">{p.system}</td>
                      <td className="nowrap">{p.used_last_30d ? <Badge tone="critical">{ago(p.usage.days_since_used)}</Badge> : <span className="muted">{ago(p.usage.days_since_used)}</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {i.added.length > 0 && (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Gains</th><th>Path</th></tr></thead>
                <tbody>
                  {i.added.map((p) => (
                    <tr key={p.perm_key}>
                      <td>{p.action} <span className="muted">on {p.resource}</span> {p.privileged && <Badge tone="warning">Privileged</Badge>}</td>
                      <td className="small muted">{p.path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ))}
      {r.violations.resolved.length > 0 && (
        <div className="stack-sm">
          <h3>Violations resolved</h3>
          {r.violations.resolved.map((v) => (
            <div key={v.key} className="row small"><Badge tone="ok">Resolved</Badge> <Sev s={v.severity} /> {v.message}</div>
          ))}
        </div>
      )}
      {r.violations.introduced.length > 0 && (
        <div className="stack-sm">
          <h3>Violations introduced</h3>
          {r.violations.introduced.map((v) => (
            <div key={v.key} className="row small"><Badge tone="critical">New</Badge> <Sev s={v.severity} /> {v.message}</div>
          ))}
        </div>
      )}
    </div>
  );
}
