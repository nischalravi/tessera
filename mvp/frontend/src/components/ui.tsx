import { ReactNode } from "react";
import { Link } from "react-router-dom";
import { IdentityBrief, PathStep, SimResult, ago } from "../api";

export const TYPE_LABEL: Record<string, string> = { human: "Human", service: "Service", ai_agent: "AI agent" };

export function TypeBadge({ type }: { type: string }) {
  return <span className={`badge ${type}`}>{TYPE_LABEL[type] ?? type}</span>;
}

export function Sev({ s }: { s: string }) {
  return <span className={`badge ${s}`}>{s}</span>;
}

const FLAG_LABEL: Record<string, [string, string]> = {
  orphaned: ["No owner", "bad"],
  owner_left: ["Owner left", "bad"],
  stale_secret: ["Stale secret", "warn"],
  dormant: ["Dormant", "medium"],
  privileged: ["Privileged", "warn"],
  pii_access: ["PII access", "bad"],
  unused_60d: ["Unused 60d", "warn"],
  unused_30d: ["Unused 30d", "warn"],
  unused_90d: ["Unused 90d", "warn"],
  privileged_idle: ["Privileged, idle", "warn"],
  policy_violation: ["Policy violation", "bad"],
  terminated_identity: ["Leaver", "bad"],
  orphaned_nhi: ["Orphaned NHI", "bad"],
};

export function Flag({ f }: { f: string }) {
  const [label, cls] = FLAG_LABEL[f] ?? [f.replace(/_/g, " "), ""];
  return <span className={`badge ${cls}`}>{label}</span>;
}

export function IdLink({ i }: { i: IdentityBrief | null | undefined }) {
  if (!i) return <span className="faint">—</span>;
  return (
    <Link to={`/identities/${i.id}`}>
      {i.name}
      {i.status === "terminated" && <span className="badge bad" style={{ marginLeft: 6 }}>left</span>}
    </Link>
  );
}

export function PathView({ steps }: { steps: PathStep[] }) {
  return (
    <div className="path">
      {steps.map((s, i) => (
        <span key={s.key} className="row" style={{ gap: 4 }}>
          {i > 0 && (
            <span className="arrow" title={s.via?.relation}>
              {s.via?.source === "jit" ? <span className="jit">JIT→</span> : "→"}
            </span>
          )}
          <span className={`node ${s.kind}`}>{s.label}</span>
        </span>
      ))}
    </div>
  );
}

export function Bar({ value, max = 100, risk }: { value: number; max?: number; risk?: boolean }) {
  return (
    <div className={`bar ${risk ? "risk" : ""}`}>
      <i style={{ width: `${Math.min(100, (100 * value) / Math.max(1, max))}%` }} />
    </div>
  );
}

export function Page({ title, sub, actions, children }: { title: string; sub?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <div>
      <div className="page-head">
        <div>
          <h1>{title}</h1>
          {sub && <p>{sub}</p>}
        </div>
        {actions && <div className="row">{actions}</div>}
      </div>
      {children}
    </div>
  );
}

export function Drawer({ title, sub, onClose, children, footer }: { title: ReactNode; sub?: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode }) {
  return (
    <>
      <div className="drawer-bg" onClick={onClose} />
      <div className="drawer" role="dialog">
        <div className="dh">
          <div>
            <h2 style={{ margin: 0 }}>{title}</h2>
            {sub && <div className="muted small" style={{ marginTop: 4 }}>{sub}</div>}
          </div>
          <button className="ghost" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="db">{children}</div>
        {footer && <div className="df">{footer}</div>}
      </div>
    </>
  );
}

export function Loading({ error }: { error?: string | null }) {
  return error ? <div className="card err">Error: {error}</div> : <div className="empty">Loading…</div>;
}

export function SimulationView({ r }: { r: SimResult }) {
  const s = r.summary;
  const breaking = s.removed_recently_used > 0;
  return (
    <div className="stack">
      {r.changes.length > 0 && (
        <div>
          <h3>Change</h3>
          {r.changes.map((c, i) => (
            <div key={i} className="small">
              <span className={`badge ${c.op === "add" ? "info" : "warn"}`}>{c.op.replace("_", " ")}</span> {c.label}
            </div>
          ))}
        </div>
      )}
      <div className="stat-row">
        <div className="s"><b>{s.identities_affected}</b><span>identities affected</span></div>
        <div className="s"><b>{s.permissions_removed}</b><span>permissions removed</span></div>
        <div className="s"><b>{s.permissions_added}</b><span>permissions added</span></div>
        <div className="s"><b style={{ color: breaking ? "var(--crit)" : undefined }}>{s.removed_recently_used}</b><span>used in last 30d</span></div>
        <div className="s"><b style={{ color: "var(--ok)" }}>{s.violations_resolved}</b><span>violations resolved</span></div>
        <div className="s"><b style={{ color: s.violations_introduced ? "var(--crit)" : undefined }}>{s.violations_introduced}</b><span>violations introduced</span></div>
      </div>
      {s.permissions_removed > 0 &&
        (breaking ? (
          <div className="callout warn">Blast radius warning: {s.removed_recently_used} permission(s) removed by this change were used in the last 30 days. Expect breakage unless an alternative grant exists.</div>
        ) : (
          <div className="callout ok">Low risk: none of the permissions removed were used in the last 30 days.</div>
        ))}
      {r.identities.map((i) => (
        <div key={i.identity_id} className="card" style={{ padding: 12 }}>
          <div className="spread">
            <b>{i.name}</b>
            <TypeBadge type={i.type} />
          </div>
          {i.removed.length > 0 && (
            <table className="mt">
              <thead><tr><th>Loses</th><th>System</th><th>Last used</th></tr></thead>
              <tbody>
                {i.removed.map((p) => (
                  <tr key={p.perm_key}>
                    <td>
                      {p.action} <span className="muted">on {p.resource}</span>{" "}
                      {p.privileged && <span className="badge warn">privileged</span>}{" "}
                      {p.tags.map((t) => <span key={t} className="chip">{t}</span>)}
                    </td>
                    <td className="sys">{p.system}</td>
                    <td className="nowrap">
                      {p.used_last_30d ? <span className="badge bad">{ago(p.usage.days_since_used)}</span> : <span className="muted">{ago(p.usage.days_since_used)}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {i.added.length > 0 && (
            <table className="mt">
              <thead><tr><th>Gains</th><th>Path</th></tr></thead>
              <tbody>
                {i.added.map((p) => (
                  <tr key={p.perm_key}>
                    <td>{p.action} <span className="muted">on {p.resource}</span> {p.privileged && <span className="badge warn">privileged</span>}</td>
                    <td className="small muted">{p.path}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      ))}
      {r.violations.resolved.length > 0 && (
        <div>
          <h3>Violations resolved</h3>
          {r.violations.resolved.map((v) => (
            <div key={v.key} className="small" style={{ marginBottom: 4 }}><span className="badge ok">resolved</span> <Sev s={v.severity} /> {v.message}</div>
          ))}
        </div>
      )}
      {r.violations.introduced.length > 0 && (
        <div>
          <h3>Violations introduced</h3>
          {r.violations.introduced.map((v) => (
            <div key={v.key} className="small" style={{ marginBottom: 4 }}><span className="badge bad">new</span> <Sev s={v.severity} /> {v.message}</div>
          ))}
        </div>
      )}
    </div>
  );
}
