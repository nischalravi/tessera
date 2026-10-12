import { CSSProperties, ReactNode } from "react";
import { Link } from "react-router-dom";
import { CircleAlert, Info } from "lucide-react";

export function EmptyState({ icon, title, children, action }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty-state">
      {icon && <div className="ic" aria-hidden>{icon}</div>}
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action && <div className="row mt-sm">{action}</div>}
    </div>
  );
}

export function Skeleton({ w = "100%", h = 14, style }: { w?: number | string; h?: number; style?: CSSProperties }) {
  return <div className="skel" style={{ width: w, height: h, ...style }} aria-hidden />;
}

export function TableSkeleton({ rows = 8, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div role="status" aria-label="Loading" style={{ padding: "8px 12px" }}>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} style={{ display: "grid", gridTemplateColumns: `2fr repeat(${cols - 1}, 1fr)`, gap: 16, padding: "10px 0", borderBottom: "1px solid var(--border)" }}>
          {Array.from({ length: cols }).map((_, c) => <Skeleton key={c} w={c === 0 ? "70%" : "50%"} />)}
        </div>
      ))}
    </div>
  );
}

export function PageSkeleton() {
  return (
    <div role="status" aria-label="Loading">
      <Skeleton w={220} h={24} />
      <Skeleton w={420} h={14} style={{ marginTop: 10 }} />
      <div className="grid g4 mt">
        {[0, 1, 2, 3].map((i) => <div key={i} className="card"><Skeleton w="50%" /><Skeleton w="40%" h={28} style={{ marginTop: 10 }} /></div>)}
      </div>
      <div className="card flush mt"><TableSkeleton /></div>
    </div>
  );
}

/** Loading placeholder that turns into an inline error when `error` is set. */
export function Loading({ error, kind = "table" }: { error?: string | null; kind?: "table" | "page" | "block" }) {
  if (error) return <ErrorNote error={error} />;
  if (kind === "page") return <PageSkeleton />;
  if (kind === "block") return <div style={{ padding: 16 }}><Skeleton /><Skeleton w="60%" style={{ marginTop: 8 }} /></div>;
  return <TableSkeleton />;
}

export function ErrorNote({ error }: { error: string }) {
  return (
    <div className="callout bad" role="alert" style={{ margin: 12 }}>
      <CircleAlert size={16} />
      <span>
        {/^not found$/i.test(error)
          ? "The running API doesn't have this endpoint. It was probably started before an update: restart it with ./run.sh, then reload."
          : /permission|role is inactive|sign in/i.test(error)
            ? `Couldn't load this: ${error}`
            : `Couldn't load this: ${error}. Check that the API is running on :8000, then reload.`}
      </span>
    </div>
  );
}

export function Callout({ tone = "info", children, icon }: { tone?: "info" | "warn" | "bad" | "ok" | "neutral"; children: ReactNode; icon?: ReactNode }) {
  return (
    <div className={`callout ${tone === "info" ? "" : tone}`}>
      {icon ?? <Info size={16} />}
      <div className="grow">{children}</div>
    </div>
  );
}

export function Kpi({ label, value, sub, tone, icon, to }: { label: ReactNode; value: ReactNode; sub?: ReactNode; tone?: "critical" | "warning"; icon?: ReactNode; to?: string }) {
  const body = (
    <>
      <div className="label">{icon}{label}</div>
      <div className="value">{value}</div>
      {sub && <div className="sub">{sub}</div>}
    </>
  );
  return to ? <Link className={`card kpi ${tone ?? ""}`} to={to}>{body}</Link> : <div className={`card kpi ${tone ?? ""}`}>{body}</div>;
}

export function Bar({ value, max = 100, tone, label }: { value: number; max?: number; tone?: "risk" | "ok"; label?: string }) {
  const pct = Math.min(100, (100 * value) / Math.max(1, max));
  const cls = tone === "risk" ? `risk ${pct >= 70 ? "hi" : ""}` : tone ?? "";
  return (
    <div className={`bar ${cls}`} role="meter" aria-label={label ?? (tone === "risk" ? `Risk ${Math.round(value)} of ${max}` : `${Math.round(value)} of ${max}`)} aria-valuenow={Math.round(value)} aria-valuemin={0} aria-valuemax={max}>
      <i style={{ width: `${pct}%` }} />
    </div>
  );
}
