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

/** What went wrong, in the terms a screen cares about (components/errorCopy.ts words each one). */
export type ErrorKind = "network" | "not_found" | "validation" | "forbidden" | "conflict" | "server";

/** The kind for an HTTP status; 0 means the request never got an answer. */
export function errorKind(status: number): ErrorKind {
  if (status === 0) return "network";
  if (status === 404) return "not_found";
  if (status === 401 || status === 403) return "forbidden";
  if (status === 409) return "conflict";
  if (status === 408 || status === 429 || status >= 500) return "server";
  return "validation"; // 400, 413, 422 and any other 4xx: the request itself was wrong
}

/**
 * The error code and a plain message from an error body. The API answers `{"detail": "text"}`,
 * `{"error": "code", "detail": "text"}` or, for request validation, `{"detail": [ ...items ]}`
 * (a list is never a message: it is dropped here so raw JSON cannot reach the screen).
 */
export function parseErrorBody(body: any): { code: string | null; message: string | null } {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { code: null, message: null };
  const code = typeof body.error === "string" ? body.error : typeof body.code === "string" ? body.code : null;
  const message = typeof body.detail === "string" ? body.detail : typeof body.message === "string" ? body.message : null;
  return { code, message };
}

/**
 * An API error: HTTP status (0 for a network failure), the server's error `code` and `message`
 * from its JSON body, a `kind`, and the parsed body (gate reports carry `blocking`).
 */
export class ApiError extends Error {
  readonly kind: ErrorKind;
  readonly code: string | null;
  readonly serverMessage: string | null;
  constructor(message: string, readonly status: number, readonly body: any) {
    super(message);
    this.kind = errorKind(status);
    ({ code: this.code, message: this.serverMessage } = parseErrorBody(body));
  }
}

/** True for an id that is a positive integer, the shape the API's numeric routes accept. */
export const isNumericId = (id: string | undefined): id is string => !!id && /^[1-9][0-9]{0,15}$/.test(id);

/** A validation error raised in the browser, before any request, for a link with a bad id. */
export const invalidLink = () => new ApiError("That link isn't valid.", 400, null);

/** A 429 from the per-IP sign-in limit: retry after retryAfter seconds. */
export class RateLimitedError extends ApiError {
  constructor(readonly retryAfter: number) {
    super("Too many sign-in attempts from this network.", 429, null);
  }
}

/** The seconds a Retry-After header asks for (delta-seconds or an HTTP date), 1 to 300; 30 when absent or unreadable. */
export function retryAfterSeconds(header: string | null, now: number = Date.now()): number {
  const clamp = (n: number) => Math.min(300, Math.max(1, Math.ceil(n)));
  if (!header) return 30;
  const v = header.trim();
  if (/^\d+$/.test(v)) return clamp(Number(v));
  const at = Date.parse(v);
  return Number.isNaN(at) ? 30 : clamp((at - now) / 1000);
}

function rateLimited(res: Response): RateLimitedError {
  return new RateLimitedError(retryAfterSeconds(res.headers?.get("Retry-After") ?? null));
}

/**
 * Session handling (design §11, §17). The browser holds only the HttpOnly session cookie,
 * which the API sets at sign-in; this client never sees a token. Every state-changing request
 * carries the session's CSRF token (from GET /api/auth/session) in X-Tessera-CSRF.
 * The actor of every action is the signed-in user: nothing here names one.
 */
let csrfToken: string | null = null;
export const setCsrfToken = (t: string | null) => {
  csrfToken = t;
};

/**
 * Bumped whenever the signed-in session changes. A GET that started under an earlier session
 * does not write its answer into the cache, so another user's data never shows after a switch.
 */
let sessionEpoch = 0;

/**
 * Forget everything tied to the current session: the CSRF token and every cached GET. Called on
 * sign-out, on sign-in and when the API says the session is gone.
 */
export function resetSessionState(): void {
  csrfToken = null;
  cache.clear();
  sessionEpoch++;
}

/** The cached answer for a GET path, if any. */
export const cached = <T = unknown>(path: string): T | undefined => cache.get(path) as T | undefined;

/** Fired when the API says the session is gone (401 login_required): the app shows sign-in. */
export const SIGNED_OUT = "tessera:signed-out";
/** Fired when an action needs a fresh phishing-resistant sign-in (401 step_up_required). */
export const STEP_UP = "tessera:step-up";

/**
 * The message of a step_up_required error. The step-up dialog already explains it, so toasts
 * drop it (components/Toast.tsx) rather than show it twice.
 */
export const STEP_UP_MESSAGE =
  "This action needs a phishing-resistant sign-in in the last few minutes. Sign in again with a passkey, then retry.";

/** A plain-language message for the API's error contract (§16.2). */
function errorMessage(status: number, j: any): string {
  switch (j?.error) {
    case "login_required":
      return "Your session ended. Sign in again.";
    case "step_up_required":
      return STEP_UP_MESSAGE;
    case "role_inactive":
      return "Your admin role is inactive because you signed in without a phishing-resistant method. Sign out and sign in again with a passkey through your organization's identity provider (a GitHub sign-in cannot activate admin roles).";
    case "forbidden":
      return `You don't have permission to do this${j.permission ? ` (needs ${j.permission})` : ""}.`;
    case "csrf_failed":
      return "The request was refused as a possible cross-site request. Reload the page and try again.";
    case "audit_unavailable":
      return "The audit log is unavailable, so Tessera refused the request. Try again shortly.";
    case "activation_blocked":
    case "transition_blocked":
      return `${j.blocking?.length ?? 0} item(s) block this step`;
  }
  if (typeof j?.detail === "string") return j.detail;
  if (Array.isArray(j?.detail) || status === 422) return "That request wasn't valid. Check the values and try again.";
  return j ? JSON.stringify(j.detail ?? j) : `${status}`;
}

/** Call the API. A write refused for step-up is kept so it can resume after re-authentication. */
export function api<T = any>(path: string, body?: unknown, method?: string): Promise<T> {
  const m = method ?? (body !== undefined ? "POST" : "GET");
  return send<T>(path, body, m, () => savePendingAction({ method: m, path, body, label: actionLabel(m, path), at: Date.now() }));
}

/**
 * Call the API with a body that carries a secret. It is never kept for resuming after a step-up: the body
 * never reaches browser storage, and an earlier pending action is dropped so the resume never offers it.
 */
export function apiNoResume<T = any>(path: string, body: unknown, method = "POST"): Promise<T> {
  return send<T>(path, body, method, clearPendingAction);
}

async function send<T>(path: string, body: unknown, m: string, onStepUp: () => void): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (m !== "GET" && m !== "HEAD" && csrfToken) headers["x-tessera-csrf"] = csrfToken;
  const epoch = sessionEpoch;
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method: m,
      headers,
      credentials: "same-origin",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("Tessera can't reach its API right now.", 0, null);
  }
  if (!res.ok) {
    let j: any = null;
    try {
      j = await res.json();
    } catch {
      /* ignore */
    }
    if (res.status === 401 && j?.error === "login_required") {
      resetSessionState();
      window.dispatchEvent(new Event(SIGNED_OUT));
    }
    if (res.status === 401 && j?.error === "step_up_required") {
      // remember what was being done (the request only, never a token) so it can resume after the step-up
      if (m !== "GET" && m !== "HEAD") onStepUp();
      window.dispatchEvent(new CustomEvent(STEP_UP, { detail: j }));
    }
    throw new ApiError(j ? errorMessage(res.status, j) : `${res.status} ${res.statusText}`, res.status, j);
  }
  const data = (await res.json()) as T;
  if (m === "GET") {
    if (epoch === sessionEpoch) cache.set(path, data);
  }
  else window.dispatchEvent(new Event(CHANGED));
  return data;
}

// ------------------------------------------------------------ step-up (design §9.4, §17)

/** An action that needs a fresh sign-in, kept across the IdP round trip (sessionStorage, ten minutes). */
export interface PendingAction { method: string; path: string; body?: unknown; label: string; at: number }

const PENDING = "tessera.pendingAction";
/** A pending action older than this is discarded rather than resumed. */
export const PENDING_TTL_MS = 10 * 60 * 1000;

/**
 * Field names that mark a body as carrying a secret (connection credentials, webhook and SIEM tokens,
 * passwords, keys). A backstop: calls that send a secret also pass { noResume: true }.
 */
const SECRET_KEY = /secret|passw|^pass$|pwd|passphrase|token|private|credential|api[_-]?key|key$|signing|pem|authorization|bearer/i;

/** True when the body, at any depth, has a field whose name marks a secret; a body nested too deep counts as one. */
export function carriesSecret(v: unknown, depth = 0): boolean {
  if (v === null || typeof v !== "object") return false;
  if (depth > 8) return true;
  return Object.entries(v as Record<string, unknown>).some(([k, x]) => SECRET_KEY.test(k) || carriesSecret(x, depth + 1));
}

function savePendingAction(a: PendingAction): void {
  // A request that carries a secret is never written to browser storage: after the step-up the user
  // enters it again, as when storage is unavailable. An earlier pending action is dropped too, so the
  // resume prompt never offers a different action than the one just refused.
  if (carriesSecret(a.body)) {
    clearPendingAction();
    return;
  }
  try {
    sessionStorage.setItem(PENDING, JSON.stringify(a));
  } catch {
    /* storage unavailable: the user retries by hand after the step-up */
  }
}

/** Forget the pending action (the user declined to resume it, or it ran). */
export function clearPendingAction(): void {
  try {
    sessionStorage.removeItem(PENDING);
  } catch {
    /* ignore */
  }
}

/** The pending action, removed from storage; null when none or older than ten minutes. */
export function takePendingAction(now = Date.now()): PendingAction | null {
  let a: PendingAction | null = null;
  try {
    const raw = sessionStorage.getItem(PENDING);
    a = raw ? (JSON.parse(raw) as PendingAction) : null;
  } catch {
    a = null;
  }
  clearPendingAction();
  if (!a || typeof a.path !== "string" || !a.path.startsWith("/") || now - a.at > PENDING_TTL_MS || now < a.at) return null;
  return a;
}

const LABELS: [RegExp, (m: RegExpMatchArray) => string][] = [
  [/^\/jit\/requests\/(\d+)\/approve$/, (m) => `Approve JIT request #${m[1]}`],
  [/^\/reviews\/items\/(\d+)\/decision$/, (m) => `Record the review decision on item #${m[1]}`],
  [/^\/least-privilege\/revoke$/, () => "Revoke the grant"],
  [/^\/hris\/events\/([^/]+)\/execute$/, (m) => `Run the lifecycle plan for event ${m[1]}`],
  [/^\/connections\/([^/]+)\/(config|credential|activate|retire)$/, (m) => `${{ config: "Save the configuration of", credential: "Set the credential of", activate: "Activate", retire: "Retire" }[m[2]]} connection ${m[1]}`],
  [/^\/readiness\/overlays\/([^/]+)$/, (m) => `Save the readiness overlay for ${m[1]}`],
];

/** A plain-language name for an API action, shown before resuming it. */
export function actionLabel(method: string, path: string): string {
  for (const [re, f] of LABELS) {
    const m = path.match(re);
    if (m) return f(m);
  }
  return `${method} ${path}`;
}

/** Where to go to satisfy a step_up_required answer, coming back to the current page. */
export function stepUpHref(challenge: { step_up_url?: string; acr?: string; max_age?: number }): string {
  const base = challenge.step_up_url ?? `/api/auth/step-up?${new URLSearchParams({ acr: challenge.acr ?? "urn:tessera:acr:phr", max_age: String(challenge.max_age ?? 900) })}`;
  const q = new URLSearchParams(window.location.search);
  q.delete("stepup");
  q.delete("request_id");
  const here = safeReturnTo(window.location.pathname + (q.size ? `?${q}` : ""));
  return `${base}${base.includes("?") ? "&" : "?"}return_to=${encodeURIComponent(here)}`;
}

/** Run a resumed action (after a successful step-up). */
export const runPendingAction = (a: PendingAction) => api(a.path, a.body, a.method);

/** Tell mounted views that data changed outside `api()` (e.g. the mock layer). */
export const notifyChanged = () => window.dispatchEvent(new Event(CHANGED));

export function useApi<T = any>(path: string | null) {
  const [data, setData] = useState<T | null>(() => (path ? (cached<T>(path) ?? null) : null));
  const [error, setError] = useState<ApiError | null>(null);
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
      .catch((e) => alive && setError(e instanceof ApiError ? e : new ApiError(String(e?.message ?? e), 0, null)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [path]);
  useEffect(() => {
    setData(path ? (cached<T>(path) ?? null) : null);
    return load();
  }, [load, path]);
  useEffect(() => {
    const on = () => load();
    window.addEventListener(CHANGED, on);
    return () => window.removeEventListener(CHANGED, on);
  }, [load]);
  return { data, error, loading, reload: load };
}

/** Ask every mounted `useApi` to fetch again (the default Retry of an error panel). */
export const refetchAll = () => window.dispatchEvent(new Event(CHANGED));

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

/** One audit ledger event (GET /api/audit). `id` is the per-tenant sequence number. */
export interface AuditRow {
  id: number;
  at: string;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
  event_id?: string;
  seq?: number;
  actor_type?: "user" | "api_client" | "system" | "operator" | "anonymous";
  actor_id?: string | null;
  outcome?: "success" | "denied" | "failure" | "error";
  target?: { type: string | null; id: string | null } | null;
  request_id?: string | null;
  authn?: Record<string, unknown> | null;
  http?: { method: string; route: string | null; status: number; latency_ms: number; query_keys: string[]; path_params: Record<string, string> } | null;
  hash?: string;
  prev_hash?: string;
}

/** POST /api/audit/verify: the chain, checkpoint and anchor check of this tenant. */
export interface AuditVerifyReport {
  tenant: string;
  events: number;
  first_seq: number;
  last_seq: number;
  head_seq: number;
  checkpoints: number;
  anchored: number;
  result: "ok" | "warning" | "failed";
  exit_code: number;
  problems: { code: number; kind: string; seq?: number; detail: string }[];
}

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
/** The decider is the signed-in user (the API records it from the session). */
export const jitDecide = (id: number, action: "approve" | "deny" | "revoke") =>
  api<JitRequest>(`/jit/requests/${id}/${action}`, {});

export const jitCreate = (body: { identity_id: number; group_id: number; duration_hours: number; justification: string }) =>
  api<JitRequest>("/jit/requests", body);

export const reviewDecide = (itemId: number, decision: "keep" | "revoke", comment?: string) =>
  api<{ id: number; decision: string }>(`/reviews/items/${itemId}/decision`, { decision, comment: comment || null });

// -------------------------------------------------------------- session
export interface SessionInfo {
  user: { id: string; email: string | null; display_name: string };
  tenant: { id: string; slug: string; name: string };
  roles: string[];
  active_roles: string[];
  inactive_roles: { role: string; reason: string }[];
  permissions: string[];
  authn: { aal: number; phishing_resistant: boolean; phr_basis: string; acr: string; methods: string[]; auth_time: string };
  session: { id: string; idle_expires_at: string; absolute_expires_at: string };
  csrf_token: string;
}

/** The current session, or null when signed out. Not cached. */
export async function getSession(): Promise<SessionInfo | null> {
  const res = await fetch("/api/auth/session", { credentials: "same-origin" });
  if (res.status === 401) {
    resetSessionState();
    return null;
  }
  if (res.status === 429) throw rateLimited(res);
  if (!res.ok) throw new ApiError(`${res.status} ${res.statusText}`, res.status, null);
  const s = (await res.json()) as SessionInfo;
  setCsrfToken(s.csrf_token);
  return s;
}

export async function logout(): Promise<void> {
  try {
    await api("/auth/logout", {});
  } finally {
    resetSessionState();
  }
}

/** An IdP connection a tenant's users sign in through (GET /api/auth/discover). */
export interface LoginConnection { id: string; name: string; protocol: string; default: boolean }

/**
 * Home-realm discovery: the sign-in connections of the tenant with this slug (optionally only
 * those whose verified domains match the email). An unknown tenant answers the same way with no
 * connections, so the page cannot tell which tenants exist.
 */
export async function discover(tenant: string, email?: string): Promise<LoginConnection[]> {
  const q = new URLSearchParams({ tenant });
  if (email) q.set("email", email);
  const res = await fetch(`/api/auth/discover?${q}`, { credentials: "same-origin" });
  if (res.status === 429) throw rateLimited(res);
  if (!res.ok) throw new ApiError(`${res.status} ${res.statusText}`, res.status, null);
  return ((await res.json()) as { connections: LoginConnection[] }).connections;
}

/** A same-site path to come back to after sign-in (never another origin, never /login). */
export function safeReturnTo(path: string): string {
  if (!path.startsWith("/") || path.startsWith("//") || /[\\\u0000-\u001f\u007f]/.test(path) || path.startsWith("/login")) return "/";
  return path;
}

/**
 * The URL that starts a sign-in through the IdP (the browser navigates there; the API answers
 * with a redirect to the IdP and, afterwards, back to returnTo with the session cookie set).
 */
export function loginUrl(tenant: string, connection: string | null, returnTo: string): string {
  const q = new URLSearchParams({ tenant, return_to: safeReturnTo(returnTo) });
  if (connection) q.set("connection", connection);
  return `/api/auth/login?${q}`;
}

/** Start a sign-in: forget the previous session's state, then leave for the IdP. */
export function startLogin(tenant: string, connection: string | null, returnTo: string): void {
  resetSessionState();
  window.location.assign(loginUrl(tenant, connection, returnTo));
}

/** One of the signed-in user's sessions (GET /api/auth/sessions). */
export interface MySession {
  id: string;
  kind: string;
  status: string;
  current: boolean;
  created_at: string;
  last_activity_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  revoked_at: string | null;
  revoked_reason: string | null;
  ip_first: string | null;
}

export const mySessions = () => api<MySession[]>("/auth/sessions");
export const revokeSession = (id: string) => api<unknown>(`/auth/sessions/${encodeURIComponent(id)}`, undefined, "DELETE");

export const hrisExecute = (eventId: number) => api(`/hris/events/${eventId}/execute`, {});

// ---------------------------------------------------------------- scheduled reviews (issue #166)

export type Recurrence = "once" | "quarterly" | "semiannual" | "annual";
export interface ReviewLaunch {
  id: string; period: string; campaign_id: number; launched_at: string; due_at: string;
  reminded_at: string | null; escalated_at: string | null; closed_at: string | null; revoked: number;
}
export interface ReviewSchedule {
  id: string;
  name: string;
  system: string | null;
  privileged_only: boolean;
  unused_days: number;
  duration_days: number;
  reminder_days: number;
  close_out: "revoke" | "escalate";
  escalation_reviewer: { id: number; name: string } | null;
  escalation_days: number;
  recurrence: Recurrence;
  next_run_at: string | null;
  enabled: boolean;
  updated_at: string;
  launches: ReviewLaunch[];
}
export interface ReviewScheduleInput {
  name: string; system: string | null; privileged_only: boolean; unused_days: number; duration_days: number; reminder_days: number;
  close_out: "revoke" | "escalate"; escalation_identity_id: number | null; escalation_days: number; recurrence: Recurrence;
  first_run_at?: string; enabled: boolean;
}
export const createReviewSchedule = (b: ReviewScheduleInput) => api<ReviewSchedule>("/reviews/schedules", b);
export const updateReviewSchedule = (id: string, b: ReviewScheduleInput) => api<ReviewSchedule>(`/reviews/schedules/${encodeURIComponent(id)}`, b, "PUT");
export const runReviewSchedule = (id: string) => api<ReviewLaunch>(`/reviews/schedules/${encodeURIComponent(id)}/run`, {});

// ---------------------------------------------------------------- account correlation (issue #160)

export interface CorrAccount { id: number; system: string; external_id: string; username: string; kind: string; status: string; identity_id: number | null }
/** A person the account's login proposes. Proposals are never linked automatically. */
export interface MatchCandidate { identity_id: number; name: string; email: string; rule: "email" | "email_local_part" }
export interface MatchItem { account: CorrAccount; candidates: MatchCandidate[] }
export interface LinkDecision {
  account_id: number;
  decision: "link" | "not_person";
  identity_id: number | null;
  previous_identity_id: number | null;
  reason: string;
  decided_by: string;
  decided_at: string;
}
export interface MergeMove { table: string; id: number; column: string }
export interface IdentityMerge {
  id: string;
  survivor_id: number;
  survivor_name: string;
  merged_id: number;
  merged_name: string;
  merged_status: string;
  moves: MergeMove[];
  reason: string;
  merged_by: string;
  merged_at: string;
  unmerge_before: string;
  unmerged_by: string | null;
  unmerged_at: string | null;
  unmerge_reason: string | null;
}
export interface UnmergeResult { merge: IdentityMerge; restored: MergeMove[]; kept: MergeMove[] }

export const linkAccount = (accountId: number, identityId: number, reason: string) =>
  api<{ account: CorrAccount; decision: LinkDecision }>(`/accounts/${accountId}/link`, { identity_id: identityId, reason });
export const markNotPerson = (accountId: number, reason: string) =>
  api<{ account: CorrAccount; decision: LinkDecision }>(`/accounts/${accountId}/not-person`, { reason });
export const releaseAccount = (accountId: number) =>
  api<{ account: CorrAccount; decision: LinkDecision }>(`/accounts/${accountId}/link`, undefined, "DELETE");
export const mergeIdentity = (mergedId: number, survivorId: number, reason: string) =>
  api<IdentityMerge>(`/identities/${mergedId}/merge`, { into: survivorId, reason });
export const unmergeIdentity = (mergeId: string, reason: string) =>
  api<UnmergeResult>(`/identity-merges/${encodeURIComponent(mergeId)}/unmerge`, { reason });

// ------------------------------------------------ affiliations and identifiers (issue #64)

export type AffiliationType = "employee" | "student" | "applicant" | "admit" | "prehire" | "contractor" | "guest_visitor" | "volunteer" | "partner" | "alum" | "retiree";
/** One relationship between a person and the organization. A person has many. */
export interface Affiliation {
  id: string;
  identity_id: number;
  type: AffiliationType;
  source: "hris" | "sis" | "sponsorship" | "partner_org" | "manual";
  source_ref: string | null;
  org_unit: string | null;
  population: string | null;
  starts_at: string;
  ends_at: string | null;
  /** Stored status. */
  status: "pending" | "active" | "ended" | "revoked";
  /** What it is now: an active affiliation past its end reads as ended until the lifecycle sweep runs. */
  effective_status: "pending" | "active" | "ended" | "revoked";
  created_at: string;
  ended_at: string | null;
  end_reason: string | null;
}
/** Lifecycle state as far as affiliations determine it. */
export type PersonState = "unaffiliated" | "prospective" | "active" | "expiring" | "expired" | "revoked" | "merged" | "invited";
export interface PersonAffiliations { identity_id: number; lifecycle_state: PersonState; affiliations: Affiliation[] }
export interface PersonIdentifier {
  id: string;
  type: string;
  issuer: string;
  /** Null for hashed-only identifiers: the value is never stored. */
  value: string | null;
  verified_at: string | null;
  verified_by: "confirmation_code" | "federation" | "authoritative_source" | "proofing_agent" | null;
  status: "active" | "retired";
  source_system: string | null;
}
export interface AddAffiliationInput { type: AffiliationType; org_unit?: string; population?: string; starts_at?: string; ends_at?: string; reason: string }

export const addAffiliation = (identityId: number, body: AddAffiliationInput) =>
  api<Affiliation>(`/identities/${identityId}/affiliations`, body);
export const endAffiliation = (affiliationId: string, reason: string) =>
  api<Affiliation>(`/affiliations/${encodeURIComponent(affiliationId)}/end`, { reason });
// ---------------------------------------------------------------- access requests (issue #164)

export type Risk = "low" | "medium" | "high";
export interface PersonRef { id: number; name: string; type: IdentityType; status: string }
export interface CatalogEntry {
  /** null: the group is not in the catalog (only listed with ?all=1). */
  id: string | null;
  group: { id: number; system: string; name: string; kind: string; privileged: boolean };
  requestable: boolean;
  description: string;
  owner: PersonRef | null;
  risk: Risk;
  eligible_types: string[];
  eligible_departments: string[];
  /** null: until removed. */
  default_hours: number | null;
  /** null: no limit. */
  max_hours: number | null;
  updated_at: string | null;
  /** Approval stages, in order (issue #165), and hours before a stage escalates to deciders. */
  approval: { stages: StageKind[]; escalate_after_hours: number };
}
export type StageKind = "manager" | "owner" | "decider";
export interface RequestStage {
  index: number;
  kind: StageKind;
  status: "queued" | "waiting" | "approved" | "denied" | "closed";
  assignee: PersonRef | null;
  due_at: string | null;
  escalated: boolean;
  decided_by: { id: string; display_name: string } | null;
  on_behalf_of: { id: string; display_name: string } | null;
  decided_at: string | null;
  reason: string | null;
}
/** A request line the signed-in user may decide now (GET /api/approvals/inbox). */
export interface ApprovalItem {
  line: RequestLine;
  stage: number | null;
  kind: StageKind;
  escalated: boolean;
  on_behalf_of: { id: string; display_name: string } | null;
}
export interface UserRef { id: string; display_name: string }
export interface ApprovalDelegation {
  id: string;
  from: UserRef;
  to: UserRef;
  starts_at: string;
  ends_at: string;
  reason: string;
  created_at: string;
  revoked_at: string | null;
  active: boolean;
}
export interface CatalogView {
  /** The person the signed-in user is; null when not linked (they request for others only). */
  me: PersonRef | null;
  can_request_for_others: boolean;
  can_decide: boolean;
  can_manage: boolean;
  items: CatalogEntry[];
}
export type RequestStatus = "pending" | "approved" | "denied" | "cancelled" | "expired" | "removed";
export interface RequestLine {
  id: string;
  batch_id: string;
  status: RequestStatus;
  catalog_item_id: string;
  group: CatalogEntry["group"];
  beneficiary: PersonRef;
  account: { id: number; system: string; username: string };
  requested_by: { id: string; display_name: string };
  justification: string;
  duration_hours: number | null;
  requested_at: string;
  decided_by: { id: string; display_name: string } | null;
  decided_at: string | null;
  decision_reason: string | null;
  expires_at: string | null;
  closed_at: string | null;
  events?: { event: string; actor: string; note: string | null; at: string }[];
  stages: RequestStage[];
  can_approve: boolean;
  can_cancel: boolean;
  can_remove: boolean;
}

export const submitRequest = (body: { beneficiary_ids: number[]; catalog_item_ids: string[]; justification: string; duration_hours?: number | null }) =>
  api<{ batch_id: string; lines: RequestLine[] }>("/requests", body);
const line = (id: string, action: string, body: object = {}) => api<RequestLine>(`/requests/${encodeURIComponent(id)}/${action}`, body);
export const approveRequest = (id: string, reason?: string) => line(id, "approve", reason ? { reason } : {});
export const denyRequest = (id: string, reason: string) => line(id, "deny", { reason });
export const cancelRequest = (id: string) => line(id, "cancel");
export const removeRequest = (id: string, reason?: string) => line(id, "remove", reason ? { reason } : {});
/** One of the signed-in user's own recent changes from the audit ledger (Home > Recent activity). */
export interface ActivityEvent {
  id: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  outcome: string;
  occurred_at: string;
}
export const activityPath = (limit = 10) => `/activity?limit=${limit}`;

/** Organizations (Directory > Organizations): read-only, derived from the departments in the HR data. */
export interface OrgPerson { id: number; name: string; title: string | null; status: string }
export interface OrgRow {
  id: string;
  name: string;
  kind: "tenant" | "department";
  parent_id: string | null;
  /** people in it (the root counts everyone); active is the part who are active */
  members: number;
  active: number;
  children: number;
  /** derived: the person at the top of the department's reporting lines who leads others in it */
  owner: OrgPerson | null;
}
export interface OrgDetail extends OrgRow {
  parent: OrgRow | null;
  owners: OrgPerson[];
  child_orgs: OrgRow[];
  people: (OrgPerson & { manager: OrgPerson | null; email: string | null })[];
}
export const orgsPath = "/orgs";
export const orgPath = (id: string) => `${orgsPath}/${encodeURIComponent(id)}`;

/** A saved, unsubmitted request (Access > Request access > Save draft), private to its user. It never submits by itself. */
export type DraftItem =
  | { kind: "group"; group_id: number; name: string; system: string; privileged: boolean }
  | { kind: "role"; role_id: string; name: string; privileged: boolean };
export interface RequestDraft {
  id: string;
  beneficiaries: { id: number; name: string }[];
  items: DraftItem[];
  duration_hours: number | null;
  justification: string;
  /** people and items the draft named that no longer exist */
  unavailable: number;
  created_at: string;
  updated_at: string;
}
export interface RequestDraftInput {
  beneficiary_ids: number[];
  items: ({ kind: "group"; group_id: number } | { kind: "role"; role_id: string })[];
  duration_hours: number | null;
  justification: string;
}
export const draftsPath = "/request-drafts";
export const draftPath = (id: string) => `${draftsPath}/${encodeURIComponent(id)}`;
export const requestDrafts = {
  /** Creates a draft, or replaces the one named by id. */
  save: (input: RequestDraftInput, id?: string) => (id ? api<RequestDraft>(draftPath(id), input, "PUT") : api<RequestDraft>(draftsPath, input)),
  remove: (id: string) => api<{ id: string; deleted: boolean }>(draftPath(id), undefined, "DELETE"),
};

/** A request to remove one grant (account -> group) a person holds (My access > Request removal). */
export interface RemovalRequest {
  id: string;
  group: CatalogEntry["group"];
  account: { id: number; system: string; username: string };
  beneficiary: PersonRef;
  requested_by: { id: string; display_name: string };
  justification: string;
  status: "pending" | "approved" | "denied" | "cancelled";
  requested_at: string;
  decided_by: { id: string; display_name: string } | null;
  decided_at: string | null;
  decision_reason: string | null;
  /** set on approval: revoked, request_removed (an approved access request was ended) or already_removed */
  outcome: "revoked" | "request_removed" | "already_removed" | null;
  can_approve: boolean;
  can_cancel: boolean;
}
const removalPath = (id: string, action: string) => `/removal-requests/${encodeURIComponent(id)}/${action}`;
export const removals = {
  submit: (edgeId: number, justification: string) => api<RemovalRequest>("/removal-requests", { edge_id: edgeId, justification }),
  approve: (id: string, reason?: string) => api<RemovalRequest>(removalPath(id, "approve"), reason ? { reason } : {}),
  deny: (id: string, reason: string) => api<RemovalRequest>(removalPath(id, "deny"), { reason }),
  cancel: (id: string) => api<RemovalRequest>(removalPath(id, "cancel"), {}),
};
/** scope: mine (default), approvals (what you may decide now), pending or all (requests.decide or graph.read). */
export const removalsPath = (scope: "mine" | "approvals" | "pending" | "all" = "mine") => `/removal-requests?scope=${scope}`;

export const putCatalogItem = (groupId: number, body: Omit<CatalogEntry, "id" | "group" | "owner" | "updated_at" | "approval"> & {
  owner_identity_id: number | null; approval_stages?: StageKind[]; escalate_after_hours?: number;
}) => api<CatalogEntry>(`/catalog/items/${groupId}`, body, "PUT");
export const createDelegation = (body: { to_user_id: string; starts_at: string; ends_at: string; reason: string }) =>
  api<ApprovalDelegation>("/approvals/delegations", body);
export const revokeDelegation = (id: string) => api<ApprovalDelegation>(`/approvals/delegations/${encodeURIComponent(id)}/revoke`, {});

// ---------------------------------------------------------------- notifications (issue #189)

export type NotificationChannel = "off" | "in_app" | "email" | "both" | "digest";
/** One entry of the signed-in user's inbox (the top-bar bell). */
export interface AppNotification {
  id: string;
  kind: string;
  subject: string;
  body: string;
  /** An app path such as /inbox; empty when there is none. */
  link: string;
  created_at: string;
  read_at: string | null;
  /** The email side: none, pending, digest, digested, sent, skipped or dead. */
  delivery: string;
}
export interface NotificationList { unread: number; items: AppNotification[] }
export interface NotificationKindPref {
  kind: string;
  label: string;
  description: string;
  /** Cannot be turned off. */
  mandatory: boolean;
  channel: NotificationChannel;
  default: NotificationChannel;
}
export interface NotificationPrefs {
  /** False when the server sends no email at all (TESSERA_NOTIFY_EMAIL=off). */
  email_available: boolean;
  /** True when email goes to the dev sink, a file, and is not delivered. */
  email_dev_sink: boolean;
  channels: NotificationChannel[];
  kinds: NotificationKindPref[];
}

export const NOTIFICATIONS_PATH = "/notifications?limit=30";
export const markNotificationsRead = (target: { ids: string[] } | { all: true }) =>
  api<{ marked: number; unread: number }>("/notifications/read", target);
export const putNotificationPrefs = (prefs: Record<string, NotificationChannel>) =>
  api<NotificationPrefs>("/notifications/preferences", { prefs }, "PUT");

// ---------------------------------------------------------------- email delivery log (issue #189)

export type EmailStatus = "queued" | "sending" | "accepted" | "deferred" | "rejected" | "failed" | "bounced";
export interface EmailStep { command: string; reply: string; code: number; enhanced?: string }
/** One send attempt with its SMTP transaction. Credentials are redacted and the body is never recorded. */
export interface EmailAttempt {
  started_at: string;
  finished_at: string;
  outcome: EmailStatus;
  banner?: string;
  capabilities?: string[];
  tls?: { version?: string; cipher?: string; server_subject?: string; server_issuer?: string; error?: string };
  steps: EmailStep[];
  mail_from?: string;
  rcpt_to?: string;
  queue_id?: string;
  error?: string;
  truncated?: boolean;
}
export interface EmailMessage {
  id: string;
  notification_id: string;
  kind: string;
  recipient: string;
  subject: string;
  mail_from: string | null;
  rcpt_to: string | null;
  status: EmailStatus;
  /** The relay's queue id from its final 250 reply. */
  queue_id: string | null;
  attempt_count: number;
  created_at: string;
  updated_at: string;
  /** Deferred or failed messages can be sent again. */
  retryable: boolean;
  /** Only in the detail. */
  attempts?: EmailAttempt[];
}
export interface EmailList { statuses: EmailStatus[]; email_mode: string; messages: EmailMessage[] }
export const retryEmail = (id: string) => api<EmailMessage>(`/email/messages/${encodeURIComponent(id)}/retry`, {});

// ---------------------------------------------------------------- business roles (issue #161)

export type GroupRef = CatalogEntry["group"];
export interface RoleRule {
  department: string[];
  type: string[];
  title: string[];
  /** Id of an attribute policy (issue #162) the person must also satisfy; "" or absent: none. */
  policy?: string;
}
export type MemberSource = "rule" | "request" | "manual";
export interface RoleMember {
  person: PersonRef;
  source: MemberSource;
  assigned_by: { id: string; display_name: string } | null;
  assigned_at: string;
  request_id: string | null;
}
export interface BusinessRole {
  id: string;
  name: string;
  description: string;
  owner: PersonRef | null;
  risk: Risk;
  requestable: boolean;
  /** null: no birthright rule (members are assigned or requested). */
  birthright: RoleRule | null;
  status: "active" | "retired";
  version: number;
  entitlements: GroupRef[];
  member_count: number;
  created_at: string;
  updated_by: { id: string; display_name: string } | null;
  updated_at: string;
  /** Only on GET /roles/{id} and after a change. */
  members?: RoleMember[];
  /** The signed-in user holds it / has a pending request for it. */
  held: boolean;
  pending: boolean;
}
export interface RolesView {
  me: PersonRef | null;
  can_manage: boolean;
  can_decide: boolean;
  can_request_for_others: boolean;
  can_read_members: boolean;
  roles: BusinessRole[];
}
export type PlanAction = "add_grant" | "remove_grant" | "keep_grant" | "no_account" | "add_member" | "remove_member";
export interface PlanStep {
  action: PlanAction;
  identity_id: number;
  identity: string;
  role_id?: string;
  role?: string;
  source?: MemberSource;
  group_id?: number;
  group?: string;
  account_id?: number;
  edge_id?: number;
  reason?: string;
}
export interface RolePlan {
  dry_run: boolean;
  steps: PlanStep[];
  grants_added: number;
  grants_removed: number;
  members_added: number;
  members_removed: number;
  no_account: number;
}
export interface RoleChange { role: BusinessRole; plan: RolePlan }
export interface RoleSpec {
  name: string;
  description: string;
  owner_identity_id: number | null;
  risk: Risk;
  requestable: boolean;
  birthright: RoleRule | null;
  entitlement_group_ids: number[];
  note?: string;
}
export interface RoleVersion { version: number; snapshot: Record<string, unknown>; note: string | null; actor: string; changed_at: string }
export interface RoleDrift {
  missing: { person: PersonRef; missing: GroupRef[] }[];
  holders: { person: PersonRef; held: GroupRef[]; holds_all: boolean }[];
}
export interface RoleRequest {
  id: string;
  role: { id: string; name: string; risk: Risk };
  beneficiary: PersonRef;
  requested_by: { id: string; display_name: string };
  justification: string;
  status: "pending" | "approved" | "denied" | "cancelled";
  requested_at: string;
  decided_by: { id: string; display_name: string } | null;
  decided_at: string | null;
  decision_reason: string | null;
  can_approve: boolean;
  can_cancel: boolean;
}

const rolePath = (id: string, rest = "") => `/roles/${encodeURIComponent(id)}${rest}`;
const dry = (d?: boolean) => (d ? "?dry_run=1" : "");
export const roles = {
  create: (spec: RoleSpec, dryRun?: boolean) => api<RoleChange>(`/roles${dry(dryRun)}`, spec),
  update: (id: string, version: number, spec: RoleSpec, dryRun?: boolean) =>
    api<RoleChange>(rolePath(id, dry(dryRun)), { version, ...spec }, "PUT"),
  retire: (id: string, reason: string, dryRun?: boolean) => api<RoleChange>(rolePath(id, "/retire" + dry(dryRun)), { reason }),
  reconcile: (id: string, dryRun?: boolean) => api<RoleChange>(rolePath(id, "/reconcile" + dry(dryRun)), {}),
  assign: (id: string, identityId: number, reason: string, dryRun?: boolean) =>
    api<RoleChange>(rolePath(id, "/members" + dry(dryRun)), { identity_id: identityId, reason }),
  unassign: (id: string, identityId: number, reason: string, dryRun?: boolean) =>
    api<RoleChange>(rolePath(id, `/members/${identityId}/remove` + dry(dryRun)), { reason }),
  request: (roleId: string, beneficiaryId: number, justification: string) =>
    api<RoleRequest>("/role-requests", { role_id: roleId, beneficiary_id: beneficiaryId, justification }),
  approve: (id: string, reason?: string) => api<RoleRequest>(`/role-requests/${encodeURIComponent(id)}/approve`, reason ? { reason } : {}),
  deny: (id: string, reason: string) => api<RoleRequest>(`/role-requests/${encodeURIComponent(id)}/deny`, { reason }),
  cancel: (id: string) => api<RoleRequest>(`/role-requests/${encodeURIComponent(id)}/cancel`, {}),
};
export const rolePaths = { list: "/roles", one: (id: string) => rolePath(id), versions: (id: string) => rolePath(id, "/versions"), drift: (id: string) => rolePath(id, "/drift") };

// ---------------------------------------------------------------- identity lifecycle (issue #159)

export type WorkerType = "employee" | "contractor" | "intern" | "partner" | "vendor" | "guest";
export const WORKER_TYPES: WorkerType[] = ["employee", "contractor", "intern", "partner", "vendor", "guest"];
export type LifecycleState = "upcoming" | "active" | "ending" | "ended";
export interface Lifecycle {
  person: PersonRef;
  worker_type: WorkerType;
  sponsor: PersonRef | null;
  organization: string | null;
  starts_at: string | null;
  ends_at: string | null;
  ended_at: string | null;
  state: LifecycleState;
  /** Whole days until the end date (0 when due); null without one. */
  days_left: number | null;
  /** The smallest warning already sent (14, 7 or 1 days). */
  warned_days: number | null;
  source: "manual" | "hris" | "sponsorship";
  updated_at: string | null;
  /** No lifecycle row: an employee with no end date. */
  default: boolean;
  can_extend: boolean;
  can_manage: boolean;
  events?: { event: "set" | "extended" | "converted" | "warned" | "ended"; worker_type: string | null; ends_at: string | null; note: string | null; actor: string; at: string }[];
}
export interface LifecycleList { can_manage: boolean; rows: Lifecycle[] }
export interface LifecycleSpec {
  worker_type: WorkerType;
  sponsor_identity_id: number | null;
  organization: string | null;
  starts_at: string | null;
  ends_at: string | null;
  reason: string;
}
const lcPath = (id: number, rest = "") => `/identities/${id}/lifecycle${rest}`;
export const lifecycle = {
  paths: { list: (state?: LifecycleState) => `/lifecycle${state ? `?state=${state}` : ""}`, sponsored: "/lifecycle/sponsored", one: (id: number) => lcPath(id) },
  set: (id: number, spec: LifecycleSpec) => api<Lifecycle>(lcPath(id), spec, "PUT"),
  extend: (id: number, endsAt: string, reason: string) => api<Lifecycle>(lcPath(id, "/extend"), { ends_at: endsAt, reason }),
  sweep: () => api<{ warned: number; ended: number }>("/lifecycle/sweep", {}),
};

// ---------------------------------------------------------------- guest sponsorships (issue #65)

export type GuestPopulationKey = "visitor" | "contractor" | "volunteer" | "partner";
export type SponsorshipStatus = "requested" | "pending_approval" | "active" | "transfer_pending" | "ended" | "revoked" | "rejected";
/** The status, with a running sponsorship told apart as upcoming, active or ending (within 14 days). */
export type SponsorshipState = SponsorshipStatus | "upcoming" | "ending";
export interface BundleItem { group_id: number; system: string; name: string; risk: Risk; privileged: boolean }
export interface SponsorshipEvent {
  event: string;
  from_status: SponsorshipStatus | null;
  to_status: SponsorshipStatus;
  note: string | null;
  policy_version: string;
  actor: string;
  at: string;
}
export interface Sponsorship {
  id: string;
  status: SponsorshipStatus;
  state: SponsorshipState;
  guest: PersonRef & { email: string | null };
  sponsor: PersonRef;
  population: GuestPopulationKey;
  purpose: string;
  bundle: BundleItem[];
  required_ial: number;
  required_aal: number;
  starts_at: string;
  ends_at: string;
  /** Whole days until the end; null once it is over. */
  days_left: number | null;
  /** The version of the sponsor policy that made the last decision. */
  policy_version: string;
  created_by: UserRef | null;
  created_at: string;
  approved_by: UserRef | null;
  approved_at: string | null;
  transfer_to: PersonRef | null;
  transfer_deadline: string | null;
  ended_at: string | null;
  end_reason: string | null;
  /** "ready" until the claim flow (GU-6) sends the invitation. */
  invitation: "ready" | "sent" | "claimed" | "revoked";
  can_renew: boolean;
  can_end: boolean;
  can_transfer: boolean;
  can_accept_transfer: boolean;
  can_approve: boolean;
  events?: SponsorshipEvent[];
}
export interface GuestPopulationInfo {
  key: GuestPopulationKey;
  name: string;
  max_days: number;
  max_active: number;
  default_ial: number;
  default_aal: number;
  approval_with_sensitive_bundle: boolean;
}
export interface GuestList {
  rows: Sponsorship[];
  populations: GuestPopulationInfo[];
  policy_version: string;
  max_invites_per_day: number;
  transfer_deadline_days: number;
  /** The sponsor policy lets the signed-in person sponsor. */
  can_sponsor: boolean;
  can_read_all: boolean;
  can_approve: boolean;
}
export interface InviteInput {
  given_name: string;
  family_name: string;
  email: string;
  population: GuestPopulationKey;
  purpose: string;
  /** Omitted: now. */
  starts_at?: string;
  ends_at: string;
  /** Group ids of requestable catalog items. */
  bundle?: number[];
  required_ial?: number;
}
export type BulkRowStatus = "ok" | "needs_approval" | "created" | "refused";
export interface BulkRowResult {
  row: number;
  email: string;
  population: string;
  status: BulkRowStatus;
  /** The stable code of the rule that refused the row. */
  code?: string;
  message?: string;
  needs_approval: boolean;
  policy_version: string;
  sponsorship_id?: string;
}
export interface BulkResult {
  dry_run: boolean;
  batch_id?: string;
  policy_version: string;
  rows: BulkRowResult[];
  created: number;
  would_create: number;
  refused: number;
}
const spPath = (id: string, rest = "") => `/sponsorships/${encodeURIComponent(id)}${rest}`;
export const guests = {
  paths: {
    list: (f: { sponsor?: "me" | "all"; state?: SponsorshipStatus; population?: GuestPopulationKey } = {}) => {
      const q = new URLSearchParams();
      if (f.sponsor) q.set("sponsor", f.sponsor);
      if (f.state) q.set("state", f.state);
      if (f.population) q.set("population", f.population);
      return `/guests${q.size ? `?${q}` : ""}`;
    },
    one: (id: string) => spPath(id),
    approvals: "/sponsorships/approvals",
  },
  invite: (body: InviteInput) => api<Sponsorship>("/guests/invitations", body),
  /** csv: the file's text. dryRun judges every row against the sponsor policy and writes nothing. */
  bulk: (csv: string, dryRun: boolean) => api<BulkResult>("/guests/invitations/bulk", { csv, dry_run: dryRun }),
  approve: (id: string) => api<Sponsorship>(spPath(id, "/approve"), {}),
  reject: (id: string, reason: string) => api<Sponsorship>(spPath(id, "/reject"), { reason }),
  renew: (id: string, endsAt: string, justification: string) => api<Sponsorship>(spPath(id, "/renew"), { ends_at: endsAt, justification }),
  end: (id: string, reason: string) => api<Sponsorship>(spPath(id, "/end"), { reason }),
  transfer: (id: string, toIdentityId: number, reason: string) => api<Sponsorship>(spPath(id, "/transfer"), { to_identity_id: toIdentityId, reason }),
  acceptTransfer: (id: string) => api<Sponsorship>(spPath(id, "/accept-transfer"), {}),
};
/** Kill switch (issue #106): revoke an identity's sessions, refresh tokens and OAuth grants at the providers. */
export interface ContainmentStep {
  action: "revoke_sessions" | "revoke_grants";
  system: string;
  account: string;
  outcome: "done" | "manual" | "failed";
  revoked: number;
  verified: boolean;
  detail?: string;
  notes?: string[];
  started_at: string;
  finished_at: string;
  duration_ms: number;
}
export interface ContainmentReport {
  identity_id: number;
  identity: string;
  trigger: string;
  ok: boolean;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  providers: { system: string; outcome: string; steps: number; failed: number; manual: number; duration_ms: number }[];
  steps: ContainmentStep[];
  manual_tasks: { system: string; account: string; action: string; instructions: string }[];
}
/** Resolves with the report; a failed run rejects with an ApiError whose body.report holds it. */
export const containIdentity = (identityId: number, reason: string) =>
  api<ContainmentReport>(`/identities/${identityId}/contain`, { reason });

/** Disable / Enable of a person: Disable runs the kill switch's containment, then sets the accounts and the identity to disabled. */
export interface DisableRecord {
  id: string;
  identity_id: number;
  reason: string;
  disabled_by: string;
  disabled_at: string;
  /** done, manual, retrying or none: how the provider-side containment of this Disable ended */
  containment_status: "done" | "manual" | "retrying" | "none";
  /** the accounts Disable set to disabled; Enable sets back these and nothing else */
  accounts: { id: number; system: string; username: string }[];
  enabled_by: string | null;
  enabled_at: string | null;
  enable_reason: string | null;
}
export interface DisableResult {
  identity_id: number;
  status: "disabled";
  disable: DisableRecord;
  containment: ContainmentReport & { status: "done" | "manual" | "retrying"; retry_ids?: string[] };
}
export interface EnableResult {
  identity_id: number;
  status: "active";
  disable: DisableRecord;
  restored: { id: number; system: string; username: string }[];
  skipped: { id: number; system: string; username: string }[];
  not_restored: string;
  pending_containment_retries: number;
}
export const disableIdentity = (identityId: number, reason: string) =>
  api<DisableResult>(`/identities/${identityId}/disable`, { reason });
export const enableIdentity = (identityId: number, reason: string) =>
  api<EnableResult>(`/identities/${identityId}/enable`, { reason });
export const identityDisables = (identityId: number) =>
  api<{ identity_id: number; disables: DisableRecord[] }>(`/identities/${identityId}/disables`);

/** A containment step that failed and is queued for retry (or was given up on). */
export interface ContainmentRetry {
  id: string;
  identity_id: number;
  system: string;
  account: string;
  action: "revoke_sessions" | "revoke_grants";
  trigger: string;
  status: "pending" | "succeeded" | "gave_up";
  attempts: number;
  next_attempt_at: string | null;
  last_error: string;
  created_at: string;
  updated_at: string;
  manual_action?: string;
}
export const retryContainmentNow = (retryId: string) =>
  api<{ retry: ContainmentRetry }>(`/containment-retries/${encodeURIComponent(retryId)}/retry-now`, {});

// ---------------------------------------------------------------- attribute policies (issue #162)

/** A condition: all/any/not over attribute tests, evaluated deterministically; a missing attribute denies. */
export type AbacOp = "eq" | "ne" | "in" | "prefix" | "exists" | "gt" | "gte" | "lt" | "lte";
export type AbacCondition =
  | { all: AbacCondition[] }
  | { any: AbacCondition[] }
  | { not: AbacCondition }
  | { attr: string; op: AbacOp; value?: string | number | boolean | (string | number | boolean)[] };
export interface AbacAttribute { name: string; type: "string" | "number" | "boolean" | "time"; note: string }
export interface AbacVersion { version: number; snapshot: { name?: string; description?: string; condition?: AbacCondition; status?: string }; note: string | null; actor: string; changed_at: string }
export interface AbacPolicy {
  id: string;
  name: string;
  description: string;
  condition: AbacCondition;
  status: "active" | "retired";
  version: number;
  created_at: string;
  updated_by: { id: string; display_name: string } | null;
  updated_at: string;
  /** Birthright rules (role names) and catalog entitlements (system:name) that use it. */
  used_by: { roles: string[]; catalog_items: string[] };
  /** Only on GET /abac/policies/{id} and after a change. */
  versions?: AbacVersion[];
}
export interface AbacList { can_manage: boolean; attributes: AbacAttribute[]; policies: AbacPolicy[] }
export interface AbacPolicySpec { name: string; description: string; condition: AbacCondition; note?: string }
export interface AbacSimPerson { id: number; name: string; type: IdentityType; status: string; department: string; title: string }
export interface AbacSimulation {
  evaluated: number;
  matching: number;
  before: number;
  unchanged: number;
  /** Identities for which the draft tests an attribute they lack (they are denied). */
  missing_attributes: number;
  /** The saved version compared against; 0: a new policy. */
  current_version: number;
  gain_count: number;
  lose_count: number;
  gains: AbacSimPerson[];
  loses: AbacSimPerson[];
  lists_truncated: boolean;
}
export interface AbacBinding { kind: "catalog_item"; target_id: string; target: string; policy_id: string }
const abacPath = (id: string, rest = "") => `/abac/policies/${encodeURIComponent(id)}${rest}`;
export const abac = {
  create: (spec: AbacPolicySpec) => api<AbacPolicy>("/abac/policies", spec),
  update: (id: string, version: number, spec: AbacPolicySpec) => api<AbacPolicy>(abacPath(id), { version, ...spec }, "PUT"),
  retire: (id: string, reason: string) => api<AbacPolicy>(abacPath(id, "/retire"), { reason }),
  /** Who gains and loses if the draft replaces the saved version (policyId omitted: a new policy). Changes nothing. */
  simulate: (condition: AbacCondition, policyId?: string, extra?: { resource?: Record<string, string | number | boolean>; context?: Record<string, string | number | boolean> }) =>
    api<AbacSimulation>("/abac/simulate", { condition, ...(policyId ? { policy_id: policyId } : {}), ...extra }),
  /** Bind (or, with null, unbind) the policy that further restricts who may request a catalog entitlement. */
  bindCatalog: (groupId: number, policyId: string | null) => api<{ catalog_item_id: string; policy_id: string | null }>(`/catalog/items/${groupId}/policy`, { policy_id: policyId }, "PUT"),
};
export const abacPaths = { list: "/abac/policies", one: (id: string) => abacPath(id), bindings: "/abac/bindings" };

// ---------------------------------------------------------------- SoD functions, risks, rulesets (issue #298)

export type SodPriority = "critical" | "high" | "medium" | "low";
export type SodAttribute = "environment" | "tag" | "resource" | "privileged";
/** Picks entitlements: a system plus a permission id or an action name pattern (`*` wildcard), optionally narrowed by a resource attribute. */
export interface SodSelector { system?: string; entitlement_id?: number; name_pattern?: string; attribute?: SodAttribute; value?: string }
export interface SodSubjects { identity_types?: IdentityType[]; statuses?: string[]; condition?: AbacCondition }
export interface SodPerson { id: number; name: string; type: IdentityType; status: string }
export interface SodVersion { version: number; snapshot: Record<string, unknown>; note: string | null; actor: string; changed_at: string }
export interface SodRef { id: string; key: string; name: string }
export interface SodFunction {
  id: string; key: string; name: string; description: string; owner: SodPerson | null; selectors: SodSelector[];
  status: "active" | "retired"; version: number; created_at: string; updated_by: { id: string; display_name: string } | null; updated_at: string;
  used_by: SodRef[];
  /** Only on GET /sod/functions/{id} and after a change. */
  versions?: SodVersion[];
}
export interface SodRisk {
  id: string; key: string; name: string; description: string; priority: SodPriority; business_process: string; owner: SodPerson | null;
  ruleset: SodRef; functions: SodRef[]; subjects: SodSubjects; status: "active" | "retired"; version: number; created_at: string;
  updated_by: { id: string; display_name: string } | null; updated_at: string; violations?: number; versions?: SodVersion[];
}
export interface SodRuleset {
  id: string; key: string; name: string; description: string; enabled: boolean; status: "active" | "retired"; version: number;
  created_at: string; updated_by: { id: string; display_name: string } | null; updated_at: string; risks: number; violations?: number;
  versions?: SodVersion[];
}
export interface SodFunctionList { can_manage: boolean; attributes: SodAttribute[]; functions: SodFunction[] }
export interface SodRiskList { can_manage: boolean; priorities: SodPriority[]; risks: SodRisk[] }
export interface SodRulesetList { can_manage: boolean; /** No stored ruleset yet: the policy files are checked. */ legacy: boolean; rulesets: SodRuleset[] }
export interface SodFunctionSpec { key?: string; name: string; description: string; owner_id: number | null; selectors: SodSelector[]; note?: string }
export interface SodRiskSpec {
  key?: string; name: string; description: string; priority: SodPriority; business_process: string; owner_id: number | null;
  ruleset_id: string; function_ids: string[]; subjects: SodSubjects; note?: string;
}
export interface SodRulesetSpec { key?: string; name: string; description: string; enabled: boolean; note?: string }
export interface SodGrant { perm_key: string; action: string; resource: string; system: string; privileged: boolean; paths: string[] }
export interface SodViolation {
  key: string; risk_id: string; risk_key: string; risk_name: string; priority: SodPriority; ruleset: SodRef; business_process: string;
  identity_id: number; identity_name: string; function1: SodRef; function2: SodRef; entitlement: string; systems: string[];
  sides: [{ function: SodRef; grants: SodGrant[] }, { function: SodRef; grants: SodGrant[] }];
  /** open; mitigation statuses arrive with mitigating controls. */
  status: string; message: string; evidence: string[]; edges: [string, string][];
}
export interface SodViolationFilter { risk?: string; priority?: SodPriority; ruleset?: string; system?: string; business_process?: string; identity?: string }
export interface SodImportResult { dry_run: boolean; ruleset: string; created: string[]; updated: string[]; unchanged: string[]; retired: string[] }
export interface SodTrigger {
  risk_id: string; risk_key: string; risk_name: string; priority: SodPriority; business_process: string; ruleset: SodRef;
  identity_id: number; identity_name: string; function1: SodRef; function2: SodRef; entitlement: string; message: string;
}
export interface SodSimulation { checked: number; skipped: { beneficiary_id: number; catalog_item_id: string; reason: string }[]; would_trigger: SodTrigger[]; highest_priority: SodPriority | "" }

const sodPath = (kind: "functions" | "risks" | "rulesets", id: string, rest = "") => `/sod/${kind}/${encodeURIComponent(id)}${rest}`;
/** Query string of the SoD violations filters (empty values are left out). */
export function sodViolationQuery(f: SodViolationFilter): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) if (v) q.set(k, v);
  const s = q.toString();
  return s ? `?${s}` : "";
}
export const sod = {
  createFunction: (spec: SodFunctionSpec) => api<SodFunction>("/sod/functions", spec),
  updateFunction: (id: string, version: number, spec: SodFunctionSpec) => api<SodFunction>(sodPath("functions", id), { version, ...spec }, "PUT"),
  retireFunction: (id: string, reason: string) => api<SodFunction>(sodPath("functions", id, "/retire"), { reason }),
  createRisk: (spec: SodRiskSpec) => api<SodRisk>("/sod/risks", spec),
  updateRisk: (id: string, version: number, spec: SodRiskSpec) => api<SodRisk>(sodPath("risks", id), { version, ...spec }, "PUT"),
  retireRisk: (id: string, reason: string) => api<SodRisk>(sodPath("risks", id, "/retire"), { reason }),
  createRuleset: (spec: SodRulesetSpec) => api<SodRuleset>("/sod/rulesets", spec),
  updateRuleset: (id: string, version: number, spec: SodRulesetSpec) => api<SodRuleset>(sodPath("rulesets", id), { version, ...spec }, "PUT"),
  retireRuleset: (id: string, reason: string) => api<SodRuleset>(sodPath("rulesets", id, "/retire"), { reason }),
  /** The ruleset as a YAML file (access as code). */
  exportRuleset: (id: string) => api<{ filename: string; version: number; yaml: string }>(sodPath("rulesets", id, "/export")),
  importRuleset: (yaml: string, opts: { prune?: boolean; dry_run?: boolean } = {}) => api<SodImportResult>("/sod/rulesets/import", { yaml, ...opts }),
  /** One-time import of the separation_of_duties policy files as a ruleset. */
  importLegacy: (dryRun = false) => api<SodImportResult>("/sod/import-legacy", { dry_run: dryRun }),
  /** Which risks would these requested items trigger? Changes nothing; used before an access request is submitted. */
  simulate: (beneficiaryIds: number[], catalogItemIds: string[], durationHours?: number) =>
    api<SodSimulation>("/sod/simulate", { beneficiary_ids: beneficiaryIds, catalog_item_ids: catalogItemIds, ...(durationHours ? { duration_hours: durationHours } : {}) }),
};
export const sodPaths = {
  functions: "/sod/functions", risks: "/sod/risks", rulesets: "/sod/rulesets",
  function: (id: string) => sodPath("functions", id), risk: (id: string) => sodPath("risks", id), ruleset: (id: string) => sodPath("rulesets", id),
  violations: (f: SodViolationFilter = {}) => `/sod/violations${sodViolationQuery(f)}`,
};

export const simulate = (body: { remove_edge_ids?: number[]; add_edges?: { src: string; dst: string; duration_hours?: number }[]; disable_account_ids?: number[] }) =>
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
  host?: string; port?: number; bind_dn?: string; ca_bundle?: string; base_dns?: string[]; user_filter?: string; group_filter?: string; service_account_ous?: string[];
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
  setCredential: (id: string, body: { secret?: string; reference?: string }) => apiNoResume<RevisionView["credential"]>(`/connections/${id}/credential`, body, "PUT"),
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

// ------------------------------------------------------------- ownership (#167)

export type OwnedKind = "app" | "group" | "resource" | "identity";

export interface NamedRef {
  id: number;
  name: string;
}

export interface OwnedObject {
  kind: OwnedKind;
  key: string;
  label: string;
  primary_owner: NamedRef | null;
  backup_owner: NamedRef | null;
  owner_group: NamedRef | null;
  purpose: string;
  /** "tessera" when set here, "connector" when only the connector names an owner. */
  source: "tessera" | "connector" | null;
  updated_at: string | null;
}

export interface OwnershipList {
  kind: OwnedKind;
  counts: Record<OwnedKind, { total: number; unowned: number }>;
  items: OwnedObject[];
}

export interface OwnershipInput {
  primary_owner_id: number | null;
  backup_owner_id: number | null;
  owner_group_id: number | null;
  purpose: string;
}

export const ownershipPath = (kind: OwnedKind) => `/ownership?kind=${kind}`;

export const setOwnership = (kind: OwnedKind, key: string, body: OwnershipInput) =>
  api<OwnedObject>(`/ownership/${kind}/${encodeURIComponent(key)}`, body, "PUT");

export const bulkSetOwnership = (objects: { kind: OwnedKind; key: string }[], body: Omit<OwnershipInput, "purpose">) =>
  api<{ updated: number }>("/ownership/bulk", { objects, ...body });

/** The one object's row out of a kind's listing, or null. */
export function ownedObject(list: OwnershipList | null, key: string | number): OwnedObject | null {
  return list?.items.find((o) => o.key === String(key)) ?? null;
}

// ----------------------------------------------------- provisioning (#103)

export type ProvStatus = "queued" | "sent" | "pending_verification" | "verified" | "mismatch" | "failed" | "cancelled";
export type ProvKind = "create_account" | "update_account" | "disable_account" | "delete_account" | "add_entitlement" | "remove_entitlement";

export interface ProvOp {
  id: string; connection_id: string; connection_name: string; system: string; kind: ProvKind; target: string;
  source: "jml" | "review" | "jit" | "leastpriv" | "api"; status: ProvStatus; attempts: number; verify_attempts: number;
  next_attempt_at: string; last_error: string | null; observed: string | null; requested_by: string; idempotency_key: string;
  completion: string | null; created_at: string; updated_at: string; completed_at: string | null; can_retry: boolean; can_cancel: boolean;
}

export interface ProvFinding {
  id: string; op_id: string; connection_id: string; code: string; severity: "high" | "medium" | "low"; title: string;
  expected: string; observed: string; status: "open" | "resolved"; created_at: string; resolved_at: string | null;
}

export interface ProvOpDetail extends ProvOp { payload: { account?: Record<string, unknown>; group?: Record<string, unknown> }; findings: ProvFinding[] }

export interface ProvTarget {
  connection_id: string; connection_name: string; system: string; kind: "scim" | "okta" | "fake"; base_url: string;
  dialect?: "standard" | "entra"; fault?: string; write_back: boolean; has_credential: boolean; credential_version: string | null; updated_at: string;
}

/** token is write-only: omit it to keep the stored credential. */
export interface ProvTargetInput { kind: ProvTarget["kind"]; base_url: string; dialect?: string; fault?: string; token?: string; write_back: boolean }

export const provisioning = {
  targets: () => api<ProvTarget[]>("/provisioning/targets"),
  putTarget: (connectionId: string, body: ProvTargetInput) => apiNoResume<ProvTarget>(`/provisioning/targets/${connectionId}`, body, "PUT"),
  deleteTarget: (connectionId: string) => api<{ removed: boolean }>(`/provisioning/targets/${connectionId}`, undefined, "DELETE"),
  get: (id: string) => api<ProvOpDetail>(`/provisioning/ops/${encodeURIComponent(id)}`),
  retry: (id: string) => api<ProvOpDetail>(`/provisioning/ops/${encodeURIComponent(id)}/retry`, {}),
  cancel: (id: string) => api<ProvOpDetail>(`/provisioning/ops/${encodeURIComponent(id)}/cancel`, {}),
  /** Takes the due operations now instead of at the worker's next tick (every 5 seconds). */
  run: () => api<{ processed: number; verified: number; mismatch: number; failed: number; retrying: number }>("/provisioning/run", {}),
};

// ----------------------------------------------------- job runs (#172)

export interface JobRun {
  id: string; kind: string; trigger: "manual" | "schedule" | "retry"; status: "running" | "succeeded" | "failed";
  connection_id: string | null; method: string | null; path: string | null; retryable: boolean; retry_of: string | null;
  actor: string; started_at: string; finished_at: string | null; duration_ms: number | null; result: unknown; error: string | null;
}

export const jobs = {
  list: (q = "") => api<JobRun[]>(`/jobs${q}`),
  get: (id: string) => api<JobRun>(`/jobs/${encodeURIComponent(id)}`),
  /** Replays the run's API call as you; its own permission and step-up apply. */
  retry: (id: string) => api<unknown>(`/jobs/${encodeURIComponent(id)}/retry`, {}),
};

// ------------------------------------------------- config transport (#170)

export interface SigningKey { kid: string; public_key: string; tenant: string; created_at: string | null }
export interface TrustedSigner { kid: string; public_key: string; label: string; added_by: string | null; added_at: string }
export interface ExportedBundle { hash: string; kid: string; file_name: string; excluded: { section: string; name: string; reason: string }[] | null; bundle: unknown }
export type ImportAction = "add" | "change" | "remove" | "unchanged" | "manual";
export interface PlanItem { section: "connections" | "overlays" | "identity_providers"; name: string; action: ImportAction; fields?: string[]; notes?: string[] }
export interface ImportPlan {
  hash: string; digest: string; digest_prune: string; signer: string; signer_kid: string; exported_at: string; items: PlanItem[]; refusals: string[];
  source: { tenant_id: string; tenant: string; env: string; instance?: string; exported_by: string };
  counts: Record<ImportAction, number>;
}
export interface ConfigImport { id: string; bundle_hash: string; signer_kid: string; source: string; exported_at: string; summary: Record<ImportAction, number>; applied_by: string | null; applied_at: string }

export const configTransport = {
  signingKey: () => api<{ key: SigningKey | null }>("/config/signing-key"),
  export: () => api<ExportedBundle>("/config/export", {}),
  signers: () => api<TrustedSigner[]>("/config/trusted-signers"),
  trust: (body: { kid: string; public_key: string; label: string }) => api<TrustedSigner>("/config/trusted-signers", body),
  untrust: (kid: string) => api<{ removed: string }>(`/config/trusted-signers/${encodeURIComponent(kid)}`, undefined, "DELETE"),
  /** bundle is the parsed exported file: the server verifies its signature, not its bytes. */
  plan: (bundle: unknown) => api<ImportPlan>("/config/import/plan", bundle),
  /** The apply is bound to the reviewed plan: plan.digest, or plan.digest_prune with prune. */
  apply: (bundle: unknown, plan: ImportPlan, prune: boolean) =>
    api<{ import_id: string; plan: ImportPlan }>(
      `/config/import/apply?hash=${encodeURIComponent(plan.hash)}&digest=${encodeURIComponent(prune ? plan.digest_prune : plan.digest)}${prune ? "&prune=true" : ""}`, bundle),
  imports: () => api<ConfigImport[]>("/config/imports"),
};

// ------------------------------------------------------------ admin changes (design §15, §16.1)

export type ChangeStatus = "pending_approval" | "cooling_off" | "applied" | "rejected" | "cancelled" | "expired" | "failed";

/** The change types of design §15.2 that the API accepts. */
export type ChangeType =
  | "role.grant" | "role.revoke" | "idp_connection.create" | "idp_connection.update_trust" | "idp_connection.update_cosmetic"
  | "idp_connection.disable" | "tenant.settings.update" | "tenant.security_contacts.update";

interface AdminPersonRef { id: string; display_name: string }

export interface AdminChange {
  id: string; type: ChangeType; summary: string; status: ChangeStatus; target_id: string | null; two_person: boolean;
  cooling_off_seconds: number; requested_by: AdminPersonRef; requested_at: string; expires_at: string; approved_by: AdminPersonRef | null;
  approved_at: string | null; effective_at: string | null; decided_by: AdminPersonRef | null; decided_at: string | null;
  applied_at: string | null; failure: string | null; test_login_at: string | null; payload_hash: string;
  payload: Record<string, unknown> | null;
  notifications?: AdminNotification[];
}

export interface AdminNotification {
  id: string; kind: string; recipient_type: "admin" | "contact" | "operator"; recipient: string; subject: string;
  change_request_id: string | null; recovery_id: string | null; created_at: string; delivered_at: string | null;
}

export interface AdminUser {
  id: string; email: string | null; display_name: string; status: "active" | "disabled"; is_break_glass: boolean;
  roles: { role: string; source: string; expires_at: string | null; change_request_id: string | null }[];
  created_at: string; last_login_at: string | null; disabled_at: string | null; disabled_reason: string | null;
}

export interface AdminIdpConnection {
  id: string; name: string; protocol: string; profile: string; status: "pending" | "active" | "disabled"; is_default: boolean;
  verified_domains: string[]; issuer: string | null; assume_phishing_resistant: boolean; jit_provisioning: boolean;
  default_role: string; created_at: string; updated_at: string; last_change_request_id: string | null;
  activation: { change_request_id: string; requested_by: string; test_login_at: string | null; ready: boolean } | null;
}

export interface AdminRecovery {
  id: string; status: "pending" | "cancelled" | "completed"; ticket: string; operator: string; co_operator: string;
  not_before: string; created_at: string; cancelled_at: string | null; completed_at: string | null;
}

/** GET /api/admin/platform-health: process-wide operational signals (no tenant data, no secrets). */
export interface PlatformHealth {
  generated_at: string; status: "ok" | "degraded"; max_loop_lag_seconds: number;
  checks: { name: string; ok: boolean }[];
  loops: { name: string; interval_seconds: number; gated: boolean; last_run_at: string | null; last_success_at: string | null; lag_seconds: number; runs: number; failures: number; healthy: boolean }[];
  http: { requests: number; server_errors: number; p95_seconds: number | null };
  audit: { writes: number; write_failures: number };
  database: { open_connections: number; in_use: number; idle: number; pool_waits: number; busy_errors: number; tx_p95_seconds: number | null; lock_wait_p95_seconds: number | null };
  logins: { method: string; success: number; failure: number }[];
  connectors: { connector: string; op: string; calls: number; errors: number }[];
}

export interface AdminApiClients { available: boolean; clients: { id: string; name: string }[]; detail: string }

/** Admin-change workflow calls. Approving needs the hash of the payload the admin reviewed. */
export const adminChanges = {
  submit: (type: ChangeType, payload: Record<string, unknown>, client_secret?: string) =>
    client_secret
      ? apiNoResume<AdminChange>("/admin/change-requests", { type, payload, client_secret })
      : api<AdminChange>("/admin/change-requests", { type, payload }),
  approve: (id: string, payload_hash: string) => api<AdminChange>(`/admin/change-requests/${id}/approve`, { payload_hash }),
  reject: (id: string) => api<AdminChange>(`/admin/change-requests/${id}/reject`, {}),
  cancel: (id: string) => api<AdminChange>(`/admin/change-requests/${id}/cancel`, {}),
  apply: (id: string) => api<AdminChange>(`/admin/change-requests/${id}/apply`, {}),
  activateConnection: (id: string) => api<{ id: string; status: string }>(`/admin/idp-connections/${id}/activate`, {}),
  disableUser: (id: string, reason: string) => api<{ id: string; status: string }>(`/admin/users/${id}/disable`, { reason }),
  cancelRecovery: (id: string) => api<AdminRecovery>(`/admin/recovery/${id}/cancel`, {}),
};

/** Seconds as "24 h", "5 min" for the cooling-off column. */
export function fmtSpan(seconds: number): string {
  if (seconds <= 0) return "none";
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}
