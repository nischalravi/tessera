/** The server-side filters of the audit log (GET /api/audit): the actor, the target and a date range. */
export interface AuditQuery {
  actorId: string;
  targetType: string;
  targetId: string;
  /** Dates as yyyy-mm-dd (an <input type="date"> value), read as UTC days. */
  from: string;
  to: string;
  includeHttp: boolean;
}

export const EMPTY_AUDIT_QUERY: AuditQuery = { actorId: "", targetType: "", targetId: "", from: "", to: "", includeHttp: false };

const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** True when no server filter is set. */
export const isUnfiltered = (q: AuditQuery) => !q.actorId && !q.targetType && !q.targetId && !q.from && !q.to;

/** The query string for GET /api/audit. A malformed date is dropped (the date input only makes valid ones). */
export function auditPath(q: AuditQuery, limit = 500): string {
  const p = new URLSearchParams({ limit: String(limit) });
  if (q.actorId.trim()) p.set("actor_id", q.actorId.trim());
  if (q.targetType.trim()) p.set("target_type", q.targetType.trim());
  if (q.targetId.trim()) p.set("target_id", q.targetId.trim());
  if (DAY.test(q.from)) p.set("from", `${q.from}T00:00:00Z`);
  if (DAY.test(q.to)) p.set("to", `${q.to}T23:59:59.999999Z`);
  if (q.includeHttp) p.set("include_http", "true");
  return `/audit?${p.toString()}`;
}
