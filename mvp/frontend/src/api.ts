/**
 * The single client for Tessera's backend API (`/api`, proxied by Vite in dev).
 *
 * GET responses are kept in a small in-memory cache so navigating between pages shows the
 * last data instantly while it refreshes. Any successful write broadcasts a change event and
 * every mounted `useApi` refetches, so counts (Inbox badge, KPIs) stay consistent.
 */
import { useCallback, useEffect, useState } from "react";

const cache = new Map<string, unknown>();
const CHANGED = "tessera:api-changed";

/** An API error with its status and parsed body (gate reports carry `blocking`). */
export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly body: any) {
    super(message);
  }
}

/**
 * Name sent as X-Tessera-User so readiness actions (attest, skip, accept, activate) are
 * attributed. A placeholder until Phase 0 authentication; set from the persona.
 */
let apiActor: string | null = null;
export const setApiActor = (name: string | null) => {
  apiActor = name && /^[A-Za-z0-9._@+ -]{1,120}$/.test(name) ? name : null;
};

export async function api<T = any>(path: string, body?: unknown, method?: string): Promise<T> {
  const m = method ?? (body !== undefined ? "POST" : "GET");
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (apiActor && m !== "GET") headers["x-tessera-user"] = apiActor;
  const res = await fetch(`/api${path}`, {
    method: m,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    let j: any = null;
    try {
      j = await res.json();
      msg = typeof j.detail === "string" ? j.detail : j.error === "activation_blocked" || j.error === "transition_blocked"
        ? `${j.blocking?.length ?? 0} item(s) block this step`
        : JSON.stringify(j.detail ?? j);
    } catch {
      /* ignore */
    }
    throw new ApiError(msg, res.status, j);
  }
  const data = (await res.json()) as T;
  if (m === "GET") cache.set(path, data);
  else window.dispatchEvent(new Event(CHANGED));
  return data;
}

/** Tell mounted views that data changed outside `api()` (e.g. the mock layer). */
export const notifyChanged = () => window.dispatchEvent(new Event(CHANGED));

export function useApi<T = any>(path: string | null) {
  const [data, setData] = useState<T | null>(() => (path ? ((cache.get(path) as T) ?? null) : null));
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const load = useCallback(() => {
    if (!path) return;
    let alive = true;
    setLoading(true);
    api<T>(path)
      .then((d) => {
        if (!alive) return;
        setData(d);
        setError(null);
      })
      .catch((e) => alive && setError(String(e.message ?? e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [path]);
  useEffect(() => {
    setData(path ? ((cache.get(path) as T) ?? null) : null);
    return load();
  }, [load, path]);
  useEffect(() => {
    const on = () => load();
    window.addEventListener(CHANGED, on);
    return () => window.removeEventListener(CHANGED, on);
  }, [load]);
  return { data, error, loading, reload: load };
}

// ------------------------------------------------------------------ types
export type IdentityType = "human" | "service" | "ai_agent";

export interface IdentityBrief {
  id: number;
  name: string;
  type: IdentityType;
  status: string;
  department?: string | null;
  title?: string | null;
}

export interface IdentityRow extends IdentityBrief {
  email: string | null;
  accounts: number;
  systems: string[];
  last_activity: string | null;
  effective?: number;
  unused?: number;
  privileged?: number;
  sensitive?: number;
  violations?: number;
  risk?: number;
}

export interface JitRequest {
  id: number;
  identity: IdentityBrief;
  group: { id: number; name: string; system: string; privileged: boolean };
  account: string;
  justification: string;
  duration_hours: number;
  status: "pending" | "approved" | "denied" | "expired" | "revoked";
  requested_at: string;
  decided_at: string | null;
  decided_by: string | null;
  expires_at: string | null;
}

export interface ReviewItem {
  id: number;
  identity: IdentityBrief;
  grant: string;
  edge_id: number | null;
  reasons: string[];
  context: {
    permissions: number;
    permissions_used: number;
    last_used: string | null;
    days_since_used: number | null;
    events_90d: number;
    privileged: boolean;
    sensitive: string[];
    violations: string[];
    peer_coverage: number | null;
    sample_permissions: string[];
  };
  reviewer: IdentityBrief | null;
  decision: "keep" | "revoke" | null;
  comment: string | null;
  decided_at: string | null;
}

export interface Campaign {
  id: number;
  name: string;
  status: string;
  created_at: string;
  unused_days: number;
  total_grants: number;
  auto_certified: number;
  items: number;
  decided: number;
  revoked: number;
  reasons: Record<string, number>;
  review_items?: ReviewItem[];
}

export interface HrisEvent {
  id: number;
  external_id: string;
  type: "joiner" | "mover" | "leaver";
  status: string;
  effective_at: string;
  executed_at: string | null;
  identity: IdentityBrief | null;
  payload: Record<string, any>;
}

export interface Group {
  id: number;
  key: string;
  system: string;
  name: string;
  kind: string;
  privileged: boolean;
  requestable: boolean;
  description: string | null;
}

export interface ResourceRow {
  id: number;
  system: string;
  name: string;
  kind: string;
  environment: string | null;
  tags: string[];
  identities_with_access: number;
  by_type: Record<string, number>;
}

export interface ConnectorRow { system: string; name: string; type: string; accounts: number; groups: number; resources: number; permissions: number }

export interface AccountRow {
  id: number;
  system: string;
  username: string;
  kind: string;
  status: string;
  created_at: string | null;
  last_login_at: string | null;
  identity: IdentityBrief | null;
}

export interface AuditRow { id: number; at: string; actor: string; action: string; detail: Record<string, unknown> }

export interface PathStep {
  key: string;
  kind: string;
  label: string;
  system?: string;
  via?: { relation: string; edge_id: number | null; source: string; expires_at: string | null };
}

export interface SimResult {
  changes: { op: string; label: string }[];
  summary: Record<string, number>;
  identities: {
    identity_id: number;
    name: string;
    type: string;
    removed: { perm_key: string; action: string; resource: string; system: string; privileged: boolean; tags: string[]; used_last_30d: boolean; usage: { days_since_used: number | null; events_90d: number } }[];
    added: { perm_key: string; action: string; resource: string; system: string; privileged: boolean; tags: string[]; path: string }[];
  }[];
  violations: { resolved: Violation[]; introduced: Violation[] };
  grant?: { edge_id: number; label: string };
  applied?: boolean;
}

export interface Violation {
  policy_id: string;
  policy_name: string;
  severity: string;
  identity_id: number | null;
  identity_name: string;
  key: string;
  message: string;
  evidence: string[];
}

export interface EffectivePermission {
  perm_key: string;
  action: string;
  system: string;
  resource: string;
  resource_id: number;
  environment: string | null;
  tags: string[];
  privileged: boolean;
  standing: boolean;
  usage: { last_used: string | null; days_since_used: number | null; events_90d: number };
  unused: boolean;
  paths: PathStep[][];
}

export interface GrantRow {
  edge_id: number | null;
  src: string;
  dst: string;
  label: string;
  account: string;
  relation: string;
  source: string;
  expires_at: string | null;
  privileged: boolean;
}

export interface SecretRow { id: number; name: string; kind: string; system: string; account: string; age_days: number; last_used_days: number | null; stale: boolean; status: string }

export interface Recommendation {
  edge_id: number;
  kind: "remove" | "right_size" | "role_trim";
  id?: string | number;
  identity_id?: number | null;
  identity_name: string;
  identity_type?: string;
  department?: string | null;
  holders?: string[];
  target: string;
  target_privileged?: boolean;
  grant: string;
  rationale: string;
  unused_examples: string[];
  used_examples: string[];
  sensitive_tags: string[];
  unused_lost: number;
  permissions_lost: number;
  privileged_unused?: number;
  days_since_used: number | null;
  score: number;
}

export interface IdentityDetail extends IdentityBrief {
  email: string | null;
  description: string | null;
  hired_at: string | null;
  terminated_at: string | null;
  manager: IdentityBrief | null;
  owner: IdentityBrief | null;
  accounts: { id: number; system: string; username: string; kind: string; status: string; last_login_at: string | null }[];
  grants: GrantRow[];
  effective_permissions: EffectivePermission[];
  violations: Violation[];
  recommendations: Recommendation[];
  secrets: SecretRow[];
  delegations: { agent: IdentityBrief; principal: IdentityBrief; scopes: string[] }[];
  owned_identities: IdentityBrief[];
  risk: { effective: number; unused: number; privileged: number; sensitive: number; violations: number; risk: number } | null;
}

export interface NhiRow {
  id: number;
  name: string;
  type: "service" | "ai_agent";
  kind: string;
  description: string | null;
  status: string;
  owner: IdentityBrief | null;
  systems: string[];
  oldest_secret_days: number | null;
  effective_permissions: number;
  privileged_permissions: number;
  days_since_activity: number | null;
  flags: string[];
  risk: number;
  delegations: { chain: { name: string; role: string; status: string }[]; scopes: string[]; exceeds_principal: string[] }[];
}

export interface Policy { id: string; name: string; type: string; severity: string; description: string; enabled: boolean; source: string; violations: number }

// -------------------------------------------------------------- actions
/** Placeholder actor until Phase 0 auth: the persona's display name is recorded as the decider. */
export const jitDecide = (id: number, action: "approve" | "deny" | "revoke", approver: string) =>
  api<JitRequest>(`/jit/requests/${id}/${action}`, { approver });

export const jitCreate = (body: { identity_id: number; group_id: number; duration_hours: number; justification: string }) =>
  api<JitRequest>("/jit/requests", body);

export const reviewDecide = (itemId: number, decision: "keep" | "revoke", reviewer: string, comment?: string) =>
  api<{ id: number; decision: string }>(`/reviews/items/${itemId}/decision`, { decision, reviewer, comment: comment || null });

export const hrisExecute = (eventId: number) => api(`/hris/events/${eventId}/execute`, {});

export const simulate = (body: { remove_edge_ids?: number[]; add_edges?: { src: string; dst: string }[]; disable_account_ids?: number[] }) =>
  api<SimResult>("/simulate", { remove_edge_ids: [], add_edges: [], disable_account_ids: [], ...body });

// ------------------------------------------------------------ formatting
const asUtc = (s: string) => new Date(s + (s.endsWith("Z") ? "" : "Z"));
export const fmtDate = (s?: string | null) => (s ? asUtc(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "Never");
export const fmtDay = (s?: string | null) => (s ? asUtc(s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "Never");
export const ago = (days?: number | null) =>
  days === null || days === undefined ? "never" : days === 0 ? "today" : days === 1 ? "1 day ago" : `${days} days ago`;
export function relTime(s?: string | null) {
  if (!s) return "never";
  const ms = Date.now() - asUtc(s).getTime();
  const fut = ms < 0;
  const a = Math.abs(ms);
  const m = Math.round(a / 60000), h = Math.round(a / 3.6e6), d = Math.round(a / 8.64e7);
  const v = m < 1 ? "just now" : m < 60 ? `${m} min` : h < 24 ? `${h} h` : `${d} d`;
  return v === "just now" ? v : fut ? `in ${v}` : `${v} ago`;
}

// ------------------------------------------------------ deployment readiness
export type Level = "required" | "recommended" | "optional";
export type ItemStatus = "pending" | "pass" | "fail" | "blocked" | "stale" | "skipped" | "not_applicable";
export type RevisionState = "draft" | "ready_to_validate" | "validated" | "dry_run_reconciled" | "active" | "degraded" | "retired" | "superseded";

export interface Blocker { item?: string; finding?: string; level?: string; severity?: string; status: string; reason: string }
export interface GateReport { error?: string; state: string; to: string; blocking: Blocker[]; config_hash: string; evaluated_at: string }
export interface NextStep { to: string; action: "transition" | "validate" | "dry_run" | "activate"; blocking: Blocker[] }
export interface Progress { pass: number; total: number; skipped: number }
export interface TemplateRef { id: string; version: string; pin: string; display_name: string; overlay_version: number }

export interface ConnConfig {
  host?: string; port?: number; base_dns?: string[]; user_filter?: string; group_filter?: string; service_account_ous?: string[];
  org_url?: string; tenant_id?: string; cloud?: string; customer?: string; domain?: string; base_url?: string;
  tenant_host?: string; api_version?: string; interface?: string; time_zone?: string;
  correlation_key?: string; hr_id_attribute?: string; technical_owner?: string; business_owner?: string;
  expected_counts?: { users: number; groups: number }; stale_days?: number; sync_schedule?: string;
  write_mode?: "off" | "dry_run" | "scoped"; write_scope?: string[]; hybrid?: boolean; use_dirsync?: boolean;
  privileged_expected?: Record<string, string[]>; demo_fixed_checks?: string[];
}

export interface RevisionView {
  id: string; rev: number; state: RevisionState; template: TemplateRef; config: ConnConfig;
  credential: { present: boolean; kind: string | null; version: string | null };
  config_hash: string; write_mode: string; gate_report: GateReport | null;
  activated_at: string | null; activated_by: string | null; created_by: string; created_at: string; updated_at: string;
}

export interface Connection {
  id: string; name: string; connector_type: string; system: string; role: string; template: TemplateRef;
  simulated: boolean; legacy: false; state: RevisionState; health: string; update_in_progress: boolean;
  technical_owner: string | null; business_owner: string | null;
  active_revision: RevisionView | null; pending_revision: RevisionView | null;
  progress: Record<Level, Progress>; next: NextStep | null; blocking: number;
  score: { score: number; band: Band } | null; latest_validation_id: string | null; latest_dry_run_id: string | null;
  created_at: string; updated_at: string; retired_at: string | null;
}

export interface LegacyConnection { legacy: true; system: string; name: string; type: string; state: "legacy"; governed_by: string | null; connector_type: "legacy" }

export interface Verify { kind: "attestation" | "live" | "data"; check?: string; params?: Record<string, unknown> }
export interface Part { kind: Verify["kind"]; check?: string; status: ItemStatus; reason?: string; simulated?: boolean; run_id?: string; observed?: Record<string, unknown>; message?: string }

export interface ChecklistItem {
  id: string; title: string; category: string; level: Level; template_level?: Level; why: string; verify: Verify[];
  remediation: { hint: string; link?: string }; depends_on?: string[]; config_fields?: string[]; source?: string;
  applicable: boolean; status: ItemStatus; reason?: string; blocked_by?: string[]; live_blocked_by?: string[]; parts: Part[];
  attestation: { actor: string; note: string; at: string; stale: boolean } | null;
  skip: { actor: string; reason: string; review_by: string; at: string; expired: boolean } | null;
}

export interface Checklist {
  connection_id: string; revision_id: string; rev: number; state: RevisionState; template: TemplateRef; simulated: boolean;
  config_hash: string; progress: Record<Level, Progress>; next: NextStep | null; categories: string[]; items: ChecklistItem[];
}

export interface CheckResultView {
  item_id: string; item_title: string; category: string; level: Level; check_id: string; kind: string; status: string;
  message: string; observed: Record<string, unknown>; duration_ms: number; simulated: boolean; fixable: boolean;
  remediation: { hint: string; link?: string };
}

export interface RunView {
  id: string; connection_id: string; revision_id: string; kind: string; status: string; simulated: boolean; scenario?: string;
  config_hash: string; stale: boolean; stale_reason?: string; actor: string; started_at: string; finished_at: string | null;
  duration_ms: number; summary: { passed: number; warned: number; failed: number; errors: number; blocked: number; skipped: number };
  results: CheckResultView[];
}

export interface FindingSample { ref: string; name: string; reason: string }
export interface Finding {
  id: string; run_id: string; code: string; variant: string; title: string; severity: string; status: "open" | "accepted" | "resolved";
  count: number; denominator: number; percent: number; samples: FindingSample[];
  impact: { affected_identities: number; affected_accounts: number; privileged_grants: number; downstream_perms: number; review_items: number; sentence: string };
  cause: { analyser: string; sentence: string; numbers: Record<string, unknown>; fix_item?: string; probable: boolean } | null;
  item_id: string | null; accepted_by: string | null; reason: string | null; expires_at: string | null; first_seen_at: string; last_seen_at: string;
}

export interface DryRunCounts {
  accounts: number; users: number; service: number; groups: number; privileged_groups: number; memberships: number; identities: number;
  tier1: number; tier2: number; proposed: number; ambiguous: number; uncorrelated: number; correlated_pct: number;
}

export interface DryRunView {
  id: string; connection_id: string; revision_id: string; status: string; simulated: boolean; config_hash: string; stale: boolean;
  stale_reason?: string; actor: string; started_at: string; finished_at: string | null; counts: DryRunCounts;
  kpis: { orphans: number; people_without_account: number; privileged_unexpected: number };
  open_by_severity: Record<string, number>; activation_note: string; findings: Finding[]; checks: CheckResultView[];
}

export type Band = "healthy" | "needs_attention" | "at_risk" | "not_ready";

export interface AttentionEntry {
  id: string; kind: "item" | "finding" | "skip"; severity: string; sentence: string; connection_id: string; connection_name: string;
  age_days: number; affected: number; privileged: boolean; blocks_activation: boolean; rank: number; code?: string;
  fix: { kind: "item" | "finding"; item_id?: string; finding_id?: string; href: string };
}

export interface ConnectionHealthRow {
  id: string; name: string; connector_type: string; state: RevisionState; health: string; simulated: boolean; score: number; band: Band;
  counted: boolean; accounts: number; blocking: number; last_validated: string | null; last_dry_run: string | null; drift: unknown;
}

export interface SkippedRow { connection_id: string; connection_name: string; item_id: string; item_title: string; level: string; actor: string; reason: string; skipped_at: string; review_by: string; expired: boolean }

export interface DeploymentHealth {
  generated_at: string;
  tenant: { score: number | null; band: Band | ""; capped: boolean; cap_reason?: string; hr_source: string; connections_counted: number; formula: string };
  kpis: { accounts_correlated_pct?: number; orphans: number; dormant: number; privileged_accounts: number; open_critical_high: number; connections_in_setup: number; degraded: number };
  connections: ConnectionHealthRow[]; needs_attention: AttentionEntry[]; skipped: SkippedRow[]; drift: unknown[];
  schedule: Record<string, string>; scenario: string;
}

export interface ScoreBreakdown {
  score: number; band: Band; uncapped: number; capped: boolean; cap_reason?: string; band_limited: boolean; recommended_skipped_pct: number;
  checklist: { score: number; exact: number; earned: number; possible: number; missing: { item: string; title: string; level: string; status: string; points: number; score_points: number; reason?: string }[] };
  penalty: { total: number; raw: number; capped: boolean; findings: { code: string; title: string; severity: string; status: string; points: number }[] };
}

export interface ReadinessSummary { score: number | null; band: Band | ""; needs_attention: number; draft: number; degraded: number; connections: number; top: AttentionEntry[] }

export const isGateReport = (e: unknown): e is ApiError & { body: GateReport } =>
  e instanceof ApiError && !!e.body && Array.isArray(e.body.blocking);

export const readiness = {
  create: (body: { name: string; connector_type: string; system?: string; config?: ConnConfig }) => api<Connection>("/connections", body),
  patchConfig: (id: string, patch: Partial<ConnConfig> | Record<string, unknown>) =>
    api<{ connection: Connection; new_revision: boolean; invalidated: string[]; fields: { field: string; msg: string }[] }>(`/connections/${id}/config`, patch, "PATCH"),
  setCredential: (id: string, body: { secret?: string; reference?: string }) => api<RevisionView["credential"]>(`/connections/${id}/credential`, body, "PUT"),
  attest: (id: string, item: string, note: string) => api<Checklist>(`/connections/${id}/checklist/${item}/attest`, { note }),
  skip: (id: string, item: string, reason: string, review_by?: string) =>
    api<Checklist>(`/connections/${id}/checklist/${item}/skip`, review_by ? { reason, review_by } : { reason }),
  unskip: (id: string, item: string) => api<Checklist>(`/connections/${id}/checklist/${item}/skip`, undefined, "DELETE"),
  transition: (id: string, to: "ready_to_validate" | "dry_run_reconciled") => api<Connection>(`/connections/${id}/transition`, { to }),
  validate: (id: string) => api<RunView>(`/connections/${id}/validate`, {}),
  dryRun: (id: string) => api<DryRunView>(`/connections/${id}/dry-run`, {}),
  accept: (id: string, findingId: string, reason: string, expires_at?: string) =>
    api<Finding>(`/connections/${id}/findings/${findingId}/accept`, expires_at ? { reason, expires_at } : { reason }),
  activate: (id: string) => api<Connection>(`/connections/${id}/activate`, {}),
  retire: (id: string) => api<Connection>(`/connections/${id}/retire`, { confirm: true }),
  rerun: (reconcile = false) => api<{ results: { connection_id: string; name: string; validation_run_id: string | null; dry_run_id: string | null; skipped?: string }[]; dashboard: DeploymentHealth }>(
    "/insights/deployment-health/rerun", { reconcile }),
};
