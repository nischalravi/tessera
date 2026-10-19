import { CSSProperties, ReactNode } from "react";
import { Link } from "react-router-dom";
import { CircleAlert, Info } from "lucide-react";
import { ApiError, refetchAll } from "../api";
import { Button } from "./Button";
import { errorCopy } from "./errorCopy";

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
export function Loading({ error, kind = "table", what, onRetry }: { error?: ApiError | string | null; kind?: "table" | "page" | "block"; what?: string; onRetry?: () => void }) {
  if (error) return <ErrorNote error={error} what={what} onRetry={onRetry} />;
  if (kind === "page") return <PageSkeleton />;
  if (kind === "block") return <div style={{ padding: 16 }}><Skeleton /><Skeleton w="60%" style={{ marginTop: 8 }} /></div>;
  return <TableSkeleton />;
}

/**
 * The shared panel for a failed load. It words the error by kind (errorCopy.ts), so a missing
 * record, a bad link, a denial and an unreachable API each read differently. `what` names the
 * thing ("identity", "application"). Retry shows only when trying again can help (network, 5xx);
 * it refetches every mounted query unless `onRetry` says otherwise.
 */
export function ErrorNote({ error, what, onRetry }: { error: ApiError | string; what?: string; onRetry?: () => void }) {
  const copy = typeof error === "string"
    ? { text: `Couldn't load this: ${error}`, detail: undefined, retry: false }
    : errorCopy(error.kind, what, error.serverMessage);
  return (
    <div className="callout bad" role="alert" style={{ margin: 12 }}>
      <CircleAlert size={16} />
      <div className="grow">
        <span>{copy.text}{copy.detail ? ` ${copy.detail}` : ""}</span>
        {copy.retry && <div className="mt-sm"><Button size="sm" onClick={onRetry ?? refetchAll}>Retry</Button></div>}
      </div>
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

export function Bar({ value, max = 100, tone }: { value: number; max?: number; tone?: "risk" | "ok" }) {
  const pct = Math.min(100, (100 * value) / Math.max(1, max));
  const cls = tone === "risk" ? `risk ${pct >= 70 ? "hi" : ""}` : tone ?? "";
  return (
    <div className={`bar ${cls}`} role="meter" aria-valuenow={Math.round(value)} aria-valuemin={0} aria-valuemax={max}>
      <i style={{ width: `${pct}%` }} />
    </div>
  );
}
