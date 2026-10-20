/**
 * The single client for Tessera's backend API (`/api`, proxied by Vite in dev).
 *
 * GET responses are kept in a small in-memory cache so navigating between pages shows the
 * last data instantly while it refreshes. Any successful write broadcasts a change event and
 * every mounted `useApi` refetches, so counts (Inbox badge, KPIs) stay consistent.
 */
import { useCallback, useEffect, useRef, useState } from "react";

const cache = new Map<string, unknown>();
export const CHANGED = "tessera:api-changed";

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
    case "conditional_access_denied":
      return "Your organization's conditional access policy does not allow this action from here. Ask an administrator, or try from an allowed network or device.";
    case "audit_unavailable":
      return "The audit log is unavailable, so Tessera refused the request. Try again shortly.";
    case "lookup_locked": {
      const mins = Math.max(1, Math.ceil((Number(j.retry_after) || 600) / 60));
      return `Too many wrong codes. Command-line approvals are paused for this session; try again in ${mins} minute${mins === 1 ? "" : "s"}.`;
    }
    case "activation_blocked":
    case "transition_blocked":
      return `${j.blocking?.length ?? 0} item(s) block this step`;
  }
  if (typeof j?.detail === "string") return j.detail;
  if (Array.isArray(j?.detail) || status === 422) return "That request wasn't valid. Check the values and try again.";
  return j ? JSON.stringify(j.detail ?? j) : `${status}`;
}

/** For the one kind of request that is not JSON: a file sent as it is (flat-file upload). */
export interface RawBody {
  data: Blob | string;
  contentType: string;
  /** Statuses that carry a result rather than an error (a rejected upload is 422 with its report). */
  resultStatuses?: number[];
}

/**
 * Call the API. A write refused for step-up is kept so it can resume after re-authentication (a raw file
 * upload is not: its body cannot be replayed from storage).
 */
/** idempotencyKey is sent as the Idempotency-Key header: a retried write replays its first answer (the groups API). */
export function api<T = any>(path: string, body?: unknown, method?: string, raw?: RawBody, idempotencyKey?: string): Promise<T> {
  const m = method ?? (body !== undefined || raw ? "POST" : "GET");
  return send<T>(path, body, m, raw ? clearPendingAction : () => savePendingAction({ method: m, path, body, label: actionLabel(m, path), at: Date.now() }), raw, idempotencyKey);
}

/**
 * Call the API with a body that carries a secret. It is never kept for resuming after a step-up: the body
 * never reaches browser storage, and an earlier pending action is dropped so the resume never offers it.
 */
export function apiNoResume<T = any>(path: string, body: unknown, method = "POST"): Promise<T> {
  return send<T>(path, body, method, clearPendingAction);
}

async function send<T>(path: string, body: unknown, m: string, onStepUp: () => void, raw?: RawBody, idempotencyKey?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (idempotencyKey) headers["idempotency-key"] = idempotencyKey;
  if (raw) headers["content-type"] = raw.contentType;
  else if (body !== undefined) headers["content-type"] = "application/json";
  if (m !== "GET" && m !== "HEAD" && csrfToken) headers["x-tessera-csrf"] = csrfToken;
  const epoch = sessionEpoch;
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method: m,
      headers,
      credentials: "same-origin",
      body: raw ? raw.data : body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("Tessera can't reach its API right now.", 0, null);
  }
  if (!res.ok && !raw?.resultStatuses?.includes(res.status)) {
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
export interface PendingAction { method: string; path: string; body?: unknown; label: string; at: number; needsBody?: boolean }

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

const PATH_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/-_.~%:,+@=&?!";
const METHODS = ["POST", "PUT", "PATCH", "DELETE"];

/** Copy s one character at a time out of PATH_ALPHABET: "" when s holds any other character. */
function fromAlphabet(s: string): string {
  let out = "";
  for (const ch of s) {
    const i = PATH_ALPHABET.indexOf(ch);
    if (i < 0) return "";
    out += PATH_ALPHABET[i];
  }
  return out;
}

/** Request bodies kept in memory for a resume without a page reload; never written to browser storage. */
const pendingBodies = new Map<string, unknown>();

function savePendingAction(a: PendingAction): void {
  // Browser storage holds only values rebuilt from constants: an allow-listed method, the path copied
  // from a fixed alphabet, the label recomputed from that path, and a timestamp. The body stays in
  // memory (pendingBodies), so a full page reload across the identity provider drops it and the user
  // submits again; an action with an empty body ({}) needs none and resumes. An earlier pending
  // action is dropped, so the resume prompt never offers a different action than the one just refused.
  clearPendingAction();
  const method = METHODS.find((m) => m === a.method);
  const path = fromAlphabet(a.path);
  if (!method || !path.startsWith("/") || carriesSecret(a.body)) return;
  const needsBody = !(a.body === undefined || (typeof a.body === "object" && a.body !== null && Object.keys(a.body).length === 0));
  if (needsBody) pendingBodies.set(PENDING, a.body);
  const kept: PendingAction = { method, path, label: actionLabel(method, path), at: Date.now() };
  if (needsBody) kept.needsBody = true;
  try {
    sessionStorage.setItem(PENDING, JSON.stringify(kept));
  } catch {
    /* storage unavailable: the user retries by hand after the step-up */
  }
}

/** Forget the pending action (the user declined to resume it, or it ran). */
export function clearPendingAction(): void {
  pendingBodies.delete(PENDING);
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
  const body = pendingBodies.get(PENDING);
  clearPendingAction();
  if (a && a.needsBody && body !== undefined) a.body = body;
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
  [/^\/agents\/([^/]+)\/revoke$/, (m) => `Revoke Directory Agent ${m[1]}`],
  [/^\/flatfile\/apps\/([^/]+)\/mapping$/, (m) => `Save the column mapping of ${m[1]}`],
  [/^\/flatfile\/tasks\/([^/]+)\/close$/, () => "Close the manual task"],
  [/^\/access\/(policies|networks|device-signals)(\/[^/]+)?$/, (m) => `Change conditional access (${m[1].replace("-", " ")})`],
  [/^\/auth\/device\/approve$/, () => "Approve the command-line sign-in"],
  [/^\/helpdesk\/cases\/([^/]+)\/execute$/, () => "Run the verified reset"],
  [/^\/helpdesk\/cases\/([^/]+)\/(manager|second)-approval$/, (m) => `Give the ${m[2]} approval on the reset case`],
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
export const runPendingAction = (a: PendingAction) => {
  if (a.needsBody && a.body === undefined) {
    return Promise.reject(new Error("The page reloaded during the sign-in, so the form was not kept. Fill it in and submit again."));
  }
  return api(a.path, a.body ?? (a.method === "DELETE" ? undefined : {}), a.method);
};

/** Tell mounted views that data changed outside `api()` (e.g. the mock layer). */
export const notifyChanged = () => window.dispatchEvent(new Event(CHANGED));

/** True for a 403: the session lacks the permission, so asking again changes nothing. */
export const isDenied = (e: unknown): boolean => e instanceof ApiError && e.status === 403;

export function useApi<T = any>(path: string | null) {
  const denied = useRef(false);
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
        denied.current = false;
        setData(d);
        setError(null);
      })
      .catch((e) => {
        if (!alive) return;
        denied.current = isDenied(e);
        setError(e instanceof ApiError ? e : new ApiError(String(e?.message ?? e), 0, null));
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [path]);
  useEffect(() => {
    denied.current = false;
    setData(path ? (cached<T>(path) ?? null) : null);
    return load();
  }, [load, path]);
  useEffect(() => {
    const on = () => {
      if (!denied.current) load(); // a 403 does not fix itself: no refetch storm
    };
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
    /** Role membership items: the grants the role made sit under the membership (issue #214). */
    membership?: { role_id: string; role: string; source: RoleMemberSource; assigned_at: string; grants: string[] };
  };
  reviewer: IdentityBrief | null;
  decision: "keep" | "revoke" | null;
  comment: string | null;
  decided_at: string | null;
  /** "membership": the item certifies a business-role membership; absent for a grant. */
  kind?: "membership";
  role?: { id: string; name: string };
  member_source?: RoleMemberSource;
  /** How a revoked membership was resolved. */
  resolution?: "unassign" | "exclude" | "flag" | null;
}
export type RoleMemberSource = "rule" | "request" | "manual";
export type RuleAction = "exclude" | "flag";

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
  secrets: SecretRow[];
}

/** Who is responsible for an agent or a finding (the API's nhi.Owner). */
export interface PersonBrief { id: number; name: string; status: string; department: string | null }

/** An AI agent in the inventory: where it was discovered, who created and sponsors it (issue #116). */
export interface AgentRow {
  id: number;
  name: string;
  status: string;
  description: string | null;
  /** The system the agent was discovered in (entra, okta, aws-agentcore ...). */
  source: string;
  /** What it is there: entra_agent_identity, okta_service_app, bedrock_agentcore_runtime. */
  source_kind: string | null;
  creator: string | null;
  sponsor: PersonBrief | null;
  /** The sponsor as the source spells it, kept when it did not resolve to a person. */
  sponsor_ref: string | null;
  /** active, inactive (the sponsor left or is disabled) or none. */
  sponsor_status: "active" | "inactive" | "none";
  systems: string[];
  credentials: number;
  oldest_secret_days: number | null;
  effective_permissions: number;
  privileged_permissions: number;
  flags: string[];
  risk: number;
  /** Ids of the policies the agent violates. */
  violations: string[];
  first_seen_at: string | null;
  last_seen_at: string | null;
}

/** An MCP server or an agent credential found in source code. Never a secret value. */
export interface McpFinding {
  id: number;
  source: string;
  kind: "mcp_server" | "agent_credential";
  org: string;
  repo: string;
  path: string;
  location: string;
  server: string | null;
  transport: string | null;
  target: string | null;
  /** The type of secret (github_token, anthropic_api_key ...). */
  secret_type: string | null;
  /** First 16 hex digits of a hash of the secret: identifies it without revealing it. */
  fingerprint: string | null;
  owner: { source: "codeowners" | "committer" | "none"; ref: string | null; identity: PersonBrief | null };
  commit_sha: string | null;
  first_seen_at: string;
  last_seen_at: string;
}

export const useAIAgents = () => useApi<AgentRow[]>("/ai-agents");
export const useMcpFindings = () => useApi<McpFinding[]>("/ai-agents/mcp-findings");

export interface Policy { id: string; name: string; type: string; severity: string; description: string; enabled: boolean; source: string; violations: number }

// -------------------------------------------------------------- actions
/** The decider is the signed-in user (the API records it from the session). */
export const jitDecide = (id: number, action: "approve" | "deny" | "revoke") =>
  api<JitRequest>(`/jit/requests/${id}/${action}`, {});

export const jitCreate = (body: { identity_id: number; group_id: number; duration_hours: number; justification: string }) =>
  api<JitRequest>("/jit/requests", body);

/** ruleAction: revoking a rule membership needs exclude (from the rule) or flag (to the role owner). */
export const reviewDecide = (itemId: number, decision: "keep" | "revoke", comment?: string, ruleAction?: RuleAction) =>
  api<{ id: number; decision: string; resolution?: string }>(`/reviews/items/${itemId}/decision`,
    { decision, comment: comment || null, ...(ruleAction ? { rule_action: ruleAction } : {}) });

// ------------------------------------------------ frozen review populations (issue #110)
export interface QAItem {
  id: number;
  identity: string;
  grant: string;
  system: string;
  rule: { id: string; version: number; inputs: Record<string, any> };
  qa_reviewer: string | null;
  qa_decision: "keep" | "revoke" | null;
  overturned: boolean;
}

export interface CampaignPopulation {
  campaign_id: number;
  population_hash: string;
  recomputed_hash: string;
  hash_match: boolean;
  hash_algorithm: string;
  frozen_at: string;
  item_count: number;
  system_counts: Record<string, number>;
  source_syncs: Record<string, string | null>;
  rules_version: string;
  qa_sample_pct: number;
  qa: { auto_certified: number; sampled: number; decided: number; overturned: number };
  qa_queue: QAItem[];
}

export const qaDecide = (qaId: number, decision: "keep" | "revoke", comment?: string) =>
  api<{ id: number; qa_decision: string; overturned: boolean }>(`/reviews/qa/${qaId}/decision`, { decision, comment: comment || null });

/** Downloads the auditor export (population, hash, decisions) of a campaign as CSV or JSON. */
export async function downloadPopulationExport(campaignId: number, format: "csv" | "json"): Promise<void> {
  const res = await fetch(`/api/reviews/campaigns/${campaignId}/export?format=${format}`, { credentials: "same-origin" });
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
    throw new ApiError(j ? errorMessage(res.status, j) : `${res.status} ${res.statusText}`, res.status, j);
  }
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = `tessera-review-population-${campaignId}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// -------------------------------------------------------------- session
export interface SessionInfo {
  /** identity_id: the directory person the server linked this sign-in to; null when unlinked. */
  user: { id: string; email: string | null; display_name: string; identity_id: number | null };
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

// ---------------------------------------------------------------- command-line sign-in (design §9.3)

/** What a device code asks for: shown to the person who must decide. */
export interface DeviceRequest {
  client: string;
  client_id: string;
  scope: string[];
  requested_at: string;
  request_ip: string;
  expires_at: string;
  /** The sign-in the approval needs (a fresh phishing-resistant one, 300 s or less old). */
  requires: { acr: string; max_age: number };
}

/** Look up a user code the command line printed (wrong codes are counted: five lock the session out for ten minutes). */
export const deviceLookup = (userCode: string) => api<DeviceRequest>("/auth/device/lookup", { user_code: userCode });

/**
 * Approve or deny the device. Approval needs a sign-in within five minutes: without one the API
 * answers step_up_required, which opens the step-up dialog and resumes this call afterwards.
 */
export const deviceDecide = (userCode: string, decision: "approve" | "deny") =>
  api<{ status: "approved" | "denied" }>("/auth/device/approve", { user_code: userCode, decision });

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
  /** Business roles whose memberships it reviews (none: grants). */
  role_ids: string[];
}
export interface ReviewScheduleInput {
  name: string; system: string | null; privileged_only: boolean; unused_days: number; duration_days: number; reminder_days: number;
  close_out: "revoke" | "escalate"; escalation_identity_id: number | null; escalation_days: number; recurrence: Recurrence;
  first_run_at?: string; enabled: boolean;
  /** Omitted: kept on update. */
  role_ids?: string[];
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
/** One row a merge re-pointed: numeric ids in `id`; the guest tables, whose ids are text, in `key`. */
export interface MergeMove { table: string; id: number; key?: string; column: string }
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
/** A row created after the merge that now belongs to the survivor; an unmerge leaves it there. */
export interface CreatedAfter { table: string; id: string; at: string }
export interface UnmergeResult { merge: IdentityMerge; restored: MergeMove[]; kept: MergeMove[]; created_after?: CreatedAfter[] }

export const linkAccount = (accountId: number, identityId: number, reason: string) =>
  api<{ account: CorrAccount; decision: LinkDecision }>(`/accounts/${accountId}/link`, { identity_id: identityId, reason });
export const markNotPerson = (accountId: number, reason: string) =>
  api<{ account: CorrAccount; decision: LinkDecision }>(`/accounts/${accountId}/not-person`, { reason });
export const releaseAccount = (accountId: number) =>
  api<{ account: CorrAccount; decision: LinkDecision }>(`/accounts/${accountId}/link`, undefined, "DELETE");
/**
 * Ask for a merge. Where either person holds privileged access, has IAL 2 or more or is an
 * employee, the API answers 202 with a request that a second reviewer approves; the merge has not happened.
 */
export const mergeIdentity = (mergedId: number, survivorId: number, reason: string) =>
  api<IdentityMerge | PendingMerge>(`/identities/${mergedId}/merge`, { into: survivorId, reason });
export const isPendingMerge = (r: IdentityMerge | PendingMerge): r is PendingMerge => (r as PendingMerge).status === "pending_approval";
export const unmergeIdentity = (mergeId: string, reason: string) =>
  api<UnmergeResult>(`/identity-merges/${encodeURIComponent(mergeId)}/unmerge`, { reason });

// ---------------------------------------------------------------- identity matching (issue #68)

/** Why a second reviewer is needed. */
export type MergeRisk = "privileged_access" | "ial2" | "employee";
export interface MergeRequest {
  id: string;
  kind: "merge" | "match_link";
  status: "pending" | "approved" | "rejected" | "cancelled";
  survivor: PersonRef;
  merged: PersonRef;
  match_id: string | null;
  reason: string;
  risk: MergeRisk[];
  requested_by: UserRef;
  requested_at: string;
  decided_by: UserRef | null;
  decided_at: string | null;
  decision_reason: string | null;
  merge_id: string | null;
}
export interface PendingMerge { status: "pending_approval"; request: MergeRequest }

/** A rule that fired, with the (masked) attributes it compared. */
export interface MatchRule { rule: string; tier: "A" | "B" | "C"; score: number; why: string; compared: Record<string, string> }
export interface MatchAffiliation { type: string; status: string; source: string }
export interface IdentityMatchCandidate {
  match_id: string;
  candidate_id: number;
  name: string;
  email: string | null;
  type: string;
  tier: "A" | "B" | "C";
  score: number;
  outcome: string;
  status: "review" | "reverification" | "linked" | "new_person" | "rejected" | "superseded";
  decision: string | null;
  rules: MatchRule[];
  affiliations: MatchAffiliation[];
  privileged_access: boolean;
  ial: number;
  employee: boolean;
  second_reviewer_because: MergeRisk[];
  reverification_required: boolean;
  decided_by: UserRef | null;
  second_reviewer: UserRef | null;
  reason: string | null;
  decided_at: string | null;
  pending_request: MergeRequest | null;
  merge_id: string | null;
}
export interface IdentityMatchItem {
  /** The best candidate's match id; a decision may name any candidate's. */
  id: string;
  intake_id: string;
  channel: string;
  mode: string;
  status: string;
  received_at: string;
  /** What the claimant said at "do you already have an account?". It never links anyone. */
  claimant_says_has_account: "yes" | "no" | null;
  subject: { identity_id: number | null; name: string; email: string | null; population: string | null; purpose: string | null; sponsor: PersonRef | null; sponsorship_id: string | null };
  candidates: IdentityMatchCandidate[];
}
export interface IdentityMatchList { items: IdentityMatchItem[]; count: number }
export type MatchDecision = "link" | "new_person" | "reject";
export interface MatchDecided {
  result: "linked" | "new_person" | "rejected" | "pending_approval" | "reverification_required" | "reverification" | "review";
  item?: IdentityMatchItem;
  request?: MergeRequest;
  merge?: IdentityMerge;
}
export const decideIdentityMatch = (matchId: string, decision: MatchDecision, reason: string) =>
  api<MatchDecided>(`/identity-matches/${encodeURIComponent(matchId)}/decide`, { decision, reason });
export const approveMergeRequest = (id: string) =>
  api<{ request: MergeRequest; result: "merged" | "reverification_required"; merge?: IdentityMerge }>(`/identity-merge-requests/${encodeURIComponent(id)}/approve`, {});
export const rejectMergeRequest = (id: string, reason: string) =>
  api<{ request: MergeRequest }>(`/identity-merge-requests/${encodeURIComponent(id)}/reject`, { reason });

export interface MatchingSettings {
  auto_link_tier_b: boolean;
  require_review_tier_a: boolean;
  unmerge_window_days: number;
  updated_by: UserRef | null;
  updated_at: string | null;
}
export const putMatchingSettings = (s: Pick<MatchingSettings, "auto_link_tier_b" | "require_review_tier_a" | "unmerge_window_days">) =>
  api<MatchingSettings>("/admin/matching", s, "PUT");

// ------------------------------------------------ guest lifecycle (issue #74)

export type GuestLifecycleBucket =
  | "expiring_30" | "expiring_14" | "expiring_3" | "renewal_requests" | "stepup_required" | "pending_transfer"
  | "auto_ended" | "suspended" | "dual_status" | "in_grace" | "deprovisioned" | "purged";
export interface GuestLifecycleSettings {
  sponsor_reminder_days: number[];
  guest_reminder_days: number;
  transfer_deadline_days: number;
  on_sponsor_departure: "end" | "suspend";
  conversion_dual_status: "end" | "sponsor_confirms";
  grace_days: Record<"visitor" | "contractor" | "volunteer" | "partner", number>;
  retention_days: number;
  retention_days_visitor: number;
  keep_rematch_hashes: boolean;
  updated_at: string | null;
}
export interface GuestLifecycleOverview {
  buckets: GuestLifecycleBucket[];
  counts: Record<GuestLifecycleBucket, number>;
  settings: GuestLifecycleSettings;
}
export interface GuestLifecycleItem {
  sponsorship_id?: string;
  task_id?: string;
  task_kind?: "sponsor_transfer" | "renewal_request" | "dual_status";
  guest: { id: number; name: string };
  sponsor?: { id: number; name: string };
  population?: string;
  /** Sponsorship status, or the deprovisioning stage. */
  status?: string;
  ends_at?: string;
  days_left?: number;
  deadline?: string;
  outcome?: string;
  trigger?: string;
  grace_until?: string;
  retention_until?: string;
  held_access?: boolean;
  required_ial?: number;
  can_act: boolean;
}
export type GuestTaskAction = "accept" | "decline" | "keep" | "confirm" | "dismiss";
export const guestLifecycle = {
  resolveTask: (taskId: string, action: GuestTaskAction) =>
    api<{ id: string; kind: string; sponsorship_id: string; status: string; outcome: string | null }>(
      `/guest-lifecycle/tasks/${encodeURIComponent(taskId)}/resolve`, { action }),
  putSettings: (s: Omit<GuestLifecycleSettings, "updated_at">) => api<GuestLifecycleSettings>("/admin/guest-lifecycle", s, "PUT"),
};

/**
 * The guest's "request renewal" link (/renew#t=...): public, no session. The answer is the same
 * whether or not the token was good, so the page says only that the request was received.
 */
export async function requestRenewal(slug: string, token: string): Promise<void> {
  const res = await fetch(`/public/t/${encodeURIComponent(slug)}/guest/renewal-request`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    cache: "no-store",
    referrerPolicy: "no-referrer",
    body: JSON.stringify({ token }),
  });
  if (res.status === 429) throw new Error("Too many tries. Wait a while and try again.");
  if (!res.ok && res.status !== 202) throw new Error("Something went wrong. Try again.");
}

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
/** One row of the People list's affiliation and lifecycle filters: effective affiliation types, no identifiers. */
export interface AffiliationSummaryRow { identity_id: number; lifecycle_state: PersonState; types: AffiliationType[] }
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
  /** Guest populations the item is open to (a guest may request only items naming theirs). */
  populations?: GuestPopulationKey[];
  /** null: until removed. */
  default_hours: number | null;
  /** null: no limit. */
  max_hours: number | null;
  updated_at: string | null;
  /** Approval stages, in order (issue #165), and hours before a stage escalates to deciders. */
  approval: { stages: StageKind[]; escalate_after_hours: number };
}
export type StageKind = "manager" | "owner" | "decider" | "sponsor";
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
    // not resumable after a step-up: the body names a person, and a pending action is kept in browser storage
    apiNoResume<RoleRequest>("/role-requests", { role_id: roleId, beneficiary_id: beneficiaryId, justification }),
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
export type SponsorshipStatus = "requested" | "pending_approval" | "active" | "transfer_pending" | "suspended" | "ended" | "revoked" | "rejected";
/** The status, with a running sponsorship told apart as upcoming, active or ending (within 14 days). */
export type SponsorshipState = SponsorshipStatus | "upcoming" | "ending";
export interface BundleItem { group_id: number; system: string; name: string; risk: Risk; privileged: boolean }
/** Where a bundle item stands (issue #75): waiting for the claim or the target, in place, failed, going or gone. */
export type BundleState = "pending" | "granted" | "failed" | "removing" | "removed";
/** A sponsorship's bundle item with its state; the access expires with the sponsorship. */
export interface BundleItemState extends BundleItem {
  state: BundleState;
  detail?: string;
  /** The provisioning operation doing it (Admin, Provisioning). */
  op_id: string | null;
  op_status: string | null;
  expires_at: string | null;
  granted_at: string | null;
}
/** One item of a person's bundles, from /identities/{id}/access-bundle. */
export interface IdentityBundleItem {
  id: string; sponsorship_id: string; group_id: number; system: string; name: string; state: BundleState; detail?: string;
  op_id: string | null; op_status: string | null; expires_at: string; granted_at: string | null; removed_at: string | null;
}
export interface IdentityBundle { identity_id: number; ial: number; aal: number; items: IdentityBundleItem[] }
export interface SponsorshipEvent {
  event: string;
  from_status: SponsorshipStatus | null;
  to_status: SponsorshipStatus;
  note: string | null;
  policy_version: string;
  actor: string;
  at: string;
}
export type InvitationState = "ready" | "sent" | "claiming" | "expired" | "claimed" | "revoked";
/** A renewal held until the guest's identity assurance reaches `required_ial` (issue #74). */
export interface SponsorshipStepup { required_ial: number; requested_ends_at: string; justification: string; requested_at: string }
export interface Sponsorship {
  id: string;
  /** Set while a renewal waits for a step-up: the access does not extend meanwhile. */
  stepup?: SponsorshipStepup;
  status: SponsorshipStatus;
  state: SponsorshipState;
  guest: PersonRef & { email: string | null };
  sponsor: PersonRef;
  population: GuestPopulationKey;
  purpose: string;
  bundle: BundleItemState[];
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
  /**
   * The guest's invitation: "ready" (not sent: the claim is not set up), "sent" (the link is out),
   * "claiming" (they opened it and are part way), "expired" (it ran out unused), "claimed" or "revoked".
   */
  invitation: InvitationState;
  /** When the newest link stops working (sent invitations only). */
  invitation_expires_at: string | null;
  can_resend_invitation: boolean;
  can_revoke_invitation: boolean;
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
  /** A new claim link by email; the earlier ones stop working. */
  resendInvitation: (guestId: number) => api<Sponsorship>(`/guests/${guestId}/resend-invitation`, {}),
  /** Cancel the invitation: its links and open claim sessions stop working. */
  revokeInvitation: (guestId: number) => api<Sponsorship>(`/guests/${guestId}/revoke-invitation`, {}),
  /** Start recovery for a guest who lost their sign-in: a link goes to the guest, who proves who they are again (issue #73). */
  recover: (guestId: number, reason: string) => api<GuestRecovery>(`/guests/${guestId}/recovery`, { reason }),
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

// ------------------------------------------------ shared signals receiver (issue #114)
export type SsfStatus = "enabled" | "paused" | "disabled";
export type SsfEventStatus = "received" | "matched" | "actioned" | "no_action" | "unmatched" | "ignored" | "failed";

/** A transmitter (an SSF stream). It never carries a secret: `secret_set` says one is stored. */
export interface SsfTransmitter {
  id: string;
  name: string;
  issuer: string;
  audience: string;
  jwks_url: string;
  inline_jwks: boolean;
  delivery: "push" | "poll";
  poll_url: string;
  verification_url: string;
  subject_system: string;
  connection_id: string | null;
  status: SsfStatus;
  secret_set: boolean;
  api_token_set: boolean;
  /** Push streams: the path the transmitter delivers to (on this server's origin). */
  receiver_path?: string;
  last_event_at: string | null;
  last_error: string;
  last_error_at: string | null;
  last_polled_at: string | null;
  verification_pending: boolean;
  verified_at: string | null;
  pending_acks: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

/** One received event and what became of it. Latencies are in milliseconds. */
export interface SsfEvent {
  id: string;
  transmitter_id: string;
  jti: string;
  via: "push" | "poll";
  event_type: string;
  /** Short name: session-revoked, credential-change, account-disabled, verification or unknown. */
  event: string;
  subject_format: string;
  subject: string;
  identity_id: number | null;
  status: SsfEventStatus;
  outcome: string;
  steps: number;
  steps_failed: number;
  received_at: string;
  iat_at: string;
  actioned_at: string | null;
  /** Receipt to the last action done. */
  latency_ms: number | null;
  /** The SET's iat to the last action done. */
  iat_latency_ms: number | null;
}

export interface SsfInput {
  name: string;
  issuer: string;
  audience: string;
  delivery: "push" | "poll";
  subject_system: string;
  status?: SsfStatus;
  jwks_url?: string;
  /** Inline public keys: a JWKS document as a string. */
  jwks?: unknown;
  poll_url?: string;
  verification_url?: string;
  /** Push: the secret the transmitter presents (blank: generate). Poll: the token Tessera presents. */
  secret?: string;
  rotate_secret?: boolean;
  api_token?: string;
  discover?: boolean;
}
/** `receiver_secret` is present once, when Tessera generated the secret of a push stream. */
export interface SsfSaved { transmitter: SsfTransmitter; receiver_secret?: string }

export const createSsfTransmitter = (input: SsfInput) => api<SsfSaved>("/ssf/transmitters", input);
export const updateSsfTransmitter = (id: string, input: SsfInput) => api<SsfSaved>(`/ssf/transmitters/${encodeURIComponent(id)}`, input, "PUT");
export const deleteSsfTransmitter = (id: string) => api<{ deleted: boolean }>(`/ssf/transmitters/${encodeURIComponent(id)}`, undefined, "DELETE");
export const verifySsfTransmitter = (id: string) => api<{ requested: boolean }>(`/ssf/transmitters/${encodeURIComponent(id)}/verify`, {});
// ------------------------------------------------------------ flat-file import (issue #105)

/** Which CSV column holds which field of an accounts file ("" or absent: not mapped). */
export interface FlatAccountCols { account_id: string; username: string; email?: string; identity_id?: string; status?: string }
/** The same for an account-entitlement file: one row per account and entitlement. */
export interface FlatEntitlementCols { account_id: string; entitlement: string; name?: string; privileged?: string }
export interface FlatMapping {
  system: string;
  name: string;
  owner: string;
  accounts: FlatAccountCols;
  entitlements: FlatEntitlementCols | null;
  updated_by: string;
  updated_at: string;
}
export type FlatKind = "accounts" | "entitlements";
export interface FlatUpload {
  id: string;
  system: string;
  kind: FlatKind;
  source: "api" | "sftp";
  filename: string;
  sha256: string;
  size_bytes: number;
  status: "applied" | "rejected";
  rows_total: number;
  rows_rejected: number;
  added: number;
  removed: number;
  changed: number;
  unchanged: number;
  tasks_confirmed: number;
  uploaded_by: string;
  uploaded_at: string;
}
/** A rejected row; row 0 is the file as a whole. */
export interface FlatRowError { row: number; column: string; code: string; message: string }
export interface FlatChange { kind: FlatKind; change: "added" | "removed" | "changed"; label: string; detail?: string }
export interface FlatUploadDetail extends FlatUpload { errors: FlatRowError[]; errors_truncated: boolean; changes: FlatChange[] }
export interface FlatTask {
  id: string;
  system: string;
  kind: "disable_account" | "remove_entitlement";
  account: string;
  account_label: string;
  entitlement: string;
  identity_id: number | null;
  trigger: string;
  status: "open" | "confirmed" | "closed";
  instruction: string;
  created_by: string;
  created_at: string;
  closed_by: string | null;
  closed_at: string | null;
  close_reason: string;
  closed_upload_id: string | null;
}

/** Save an app's column mapping (flatfile.manage, fresh sign-in). */
export const saveFlatMapping = (system: string, body: { name: string; owner: string; accounts: FlatAccountCols; entitlements: FlatEntitlementCols | null }) =>
  api<FlatMapping>(`/flatfile/apps/${encodeURIComponent(system)}/mapping`, body, "PUT");

/**
 * Upload a CSV for an app. Resolves with the upload either way: a file with an invalid row is
 * rejected whole (status "rejected", every bad row listed) and nothing else changes.
 */
export const uploadFlatFile = (system: string, kind: FlatKind, file: File) =>
  api<{ upload: FlatUploadDetail; confirmed_tasks: FlatTask[] }>(
    `/flatfile/apps/${encodeURIComponent(system)}/uploads?${new URLSearchParams({ kind, filename: file.name })}`,
    undefined,
    "POST",
    { data: file, contentType: "text/csv", resultStatuses: [422] },
  );

/** Close a manual task by hand, with a reason (flatfile.close_tasks, fresh sign-in). */
export const closeFlatTask = (taskId: string, reason: string) =>
  api<{ task: FlatTask }>(`/flatfile/tasks/${encodeURIComponent(taskId)}/close`, { reason });
/** Verified help-desk resets (issue #108). */
export type HelpdeskMethod = "push" | "callback" | "manager_approval" | "idv";
export interface HelpdeskPolicy {
  satisfied: boolean;
  required_verifications: number;
  counted_methods: HelpdeskMethod[];
  needs_second_approver: boolean;
  second_approved: boolean;
  allowed_methods: HelpdeskMethod[];
  missing: string[];
}
export interface HelpdeskVerification {
  id: string;
  method: HelpdeskMethod;
  outcome: "passed" | "failed";
  phishing_resistant: boolean;
  verified_by: string;
  evidence: string;
  provider: string;
  created_at: string;
}
export interface HelpdeskFinding {
  id: string;
  case_id: string;
  identity_id: number;
  rule: string;
  detail: { device?: string; location?: string; reset_at?: string; device_added_at?: string; sign_in_at?: string; known_locations?: string[] };
  created_at: string;
}
export interface HelpdeskCase {
  id: string;
  identity_id: number;
  identity: string;
  kind: "password" | "mfa";
  system: "okta" | "entra" | "simulated";
  reason: string;
  status: "open" | "executing" | "executed" | "failed" | "cancelled";
  privileged: boolean;
  requested_by: string;
  second_approver: string | null;
  second_approved_at: string | null;
  executed_by: string | null;
  executed_at: string | null;
  result: string[];
  error: string;
  created_at: string;
  updated_at: string;
  policy: HelpdeskPolicy;
  verifications: HelpdeskVerification[];
  findings: HelpdeskFinding[];
}
const hd = (id: string) => `/helpdesk/cases/${encodeURIComponent(id)}`;
export const startHelpdeskCase = (b: { identity_id: number; kind: "password" | "mfa"; system: string; reason: string }) =>
  api<HelpdeskCase>("/helpdesk/cases", b);
export const verifyHelpdeskCase = (id: string, b: { method: HelpdeskMethod; evidence?: string; number_source?: "hr"; session_ref?: string }) =>
  api<HelpdeskCase>(`${hd(id)}/verifications`, b);
export const managerApproveHelpdeskCase = (id: string, evidence?: string) => api<HelpdeskCase>(`${hd(id)}/manager-approval`, { evidence });
export const secondApproveHelpdeskCase = (id: string) => api<HelpdeskCase>(`${hd(id)}/second-approval`, {});
export const cancelHelpdeskCase = (id: string) => api<HelpdeskCase>(`${hd(id)}/cancel`, {});
/** The temporary access pass (Entra) is in the answer once; it is never stored or shown again. */
export const executeHelpdeskCase = (id: string) => api<{ case: HelpdeskCase; temporary_access_pass?: string }>(`${hd(id)}/execute`, {});

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
  /** The remediation options the risk offers. */
  remediation: SodRemediation[];
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
  ruleset_id: string; function_ids: string[]; subjects: SodSubjects; remediation?: SodRemediation[]; note?: string;
}
export interface SodRulesetSpec { key?: string; name: string; description: string; enabled: boolean; note?: string }
export interface SodGrant { perm_key: string; action: string; resource: string; system: string; privileged: boolean; paths: string[] }
export interface SodViolation {
  key: string; risk_id: string; risk_key: string; risk_name: string; priority: SodPriority; ruleset: SodRef; business_process: string;
  identity_id: number; identity_name: string; function1: SodRef; function2: SodRef; entitlement: string; systems: string[];
  sides: [{ function: SodRef; grants: SodGrant[] }, { function: SodRef; grants: SodGrant[] }];
  /** open, mitigated, accepted or mitigation_pending (a request waits for its second person; still open). */
  status: SodViolationStatus; message: string; evidence: string[]; edges: [string, string][];
  /** The remediation options the risk offers on this violation. */
  remediation: SodRemediation[];
  mitigation?: SodCover;
}
export type SodViolationStatus = "open" | "mitigated" | "accepted" | "mitigation_pending";
export type SodRemediation = "revoke" | "mitigate" | "accept" | "escalate";
/** What covers a violation now ("Mitigated until 2026-11-20"). */
export interface SodCover { mitigation_id: string; kind: "control" | "accept"; status: SodViolationStatus; control?: string; ends_at: string; label: string }
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
    apiNoResume<SodSimulation>("/sod/simulate", { beneficiary_ids: beneficiaryIds, catalog_item_ids: catalogItemIds, ...(durationHours ? { duration_hours: durationHours } : {}) }),
};
// ------------------------------------------------------------ SoD mitigating controls (issue #298)

export type SodControlType = "preventive" | "detective" | "corrective";
export type SodFrequency = "continuous" | "daily" | "weekly" | "monthly" | "quarterly" | "annually";
export interface SodControl {
  id: string; name: string; description: string; owner: SodPerson | null; type: SodControlType; frequency: SodFrequency;
  evidence_requirement: string; status: "active" | "retired"; version: number; updated_by: { id: string; display_name: string } | null;
  updated_at: string; active_mitigations: number;
}
export interface SodControlList { can_manage: boolean; types: SodControlType[]; frequencies: SodFrequency[]; controls: SodControl[] }
export interface SodControlSpec { name: string; description: string; owner_id: number | null; type: SodControlType; frequency: SodFrequency; evidence_requirement: string }
export type SodMitigationStatus = "pending" | "active" | "rejected" | "cancelled" | "expired" | "revoked";
export interface SodMitigation {
  id: string; risk: { id: string; key: string; name: string; priority: SodPriority }; identity: SodPerson; kind: "control" | "accept";
  control: { id: string; name: string } | null; justification: string; evidence: string[]; status: SodMitigationStatus;
  starts_at: string | null; ends_at: string; days_left: number | null; requested_by: { id: string; display_name: string }; requested_at: string;
  decided_by: { id: string; display_name: string } | null; decided_at: string | null; decision_note: string | null;
  revoked_by: { id: string; display_name: string } | null; revoke_reason: string | null; requested_by_me: boolean;
}
export interface SodMitigationList { can_request: boolean; can_approve: boolean; max_days: number; warn_days: number; mitigations: SodMitigation[] }
export interface SodMitigationRequest { risk_id: string; identity_id: number; kind: "control" | "accept"; control_id?: string; justification: string; ends_at: string; evidence?: string[] }
export interface SodReviewContext {
  can_request: boolean;
  items: { item_id: number; violations: { risk_id: string; risk_key: string; risk_name: string; priority: SodPriority; status: SodViolationStatus; mitigation?: SodCover; identity_id: number; remediation: SodRemediation[] }[] }[];
}
export const sodControls = {
  create: (spec: SodControlSpec) => api<SodControl>("/sod/controls", spec),
  update: (id: string, version: number, spec: SodControlSpec) => api<SodControl>(`/sod/controls/${encodeURIComponent(id)}`, { version, ...spec }, "PUT"),
  retire: (id: string, reason: string) => api<SodControl>(`/sod/controls/${encodeURIComponent(id)}/retire`, { reason }),
};
const mitPath = (id: string, rest: string) => `/sod/mitigations/${encodeURIComponent(id)}/${rest}`;
export const sodMitigations = {
  request: (req: SodMitigationRequest) => api<SodMitigation>("/sod/mitigations", req),
  approve: (id: string, note = "") => api<SodMitigation>(mitPath(id, "approve"), { note }),
  reject: (id: string, note: string) => api<SodMitigation>(mitPath(id, "reject"), { note }),
  cancel: (id: string) => api<SodMitigation>(mitPath(id, "cancel"), {}),
  /** End an active mitigation early (the risk owner or an approver): the violation is open again. */
  revoke: (id: string, reason: string) => api<SodMitigation>(mitPath(id, "revoke"), { reason }),
};
/** Remediation of a violation: send it to the risk owner, or remove a grant behind it (the risk must offer it). */
export const sodRemediate = {
  escalate: (riskId: string, identityId: number, note: string) => api<{ id: string }>("/sod/violations/escalate", { risk_id: riskId, identity_id: identityId, note }),
  revoke: (riskId: string, identityId: number, edgeId: number, dryRun: boolean) =>
    api<SimResult>("/sod/violations/revoke", { risk_id: riskId, identity_id: identityId, edge_id: edgeId, dry_run: dryRun }),
};
export const sodControlPaths = {
  controls: "/sod/controls",
  mitigations: (f: { status?: SodMitigationStatus; expiring_within_days?: number } = {}) => {
    const q = new URLSearchParams();
    if (f.status) q.set("status", f.status);
    if (f.expiring_within_days !== undefined) q.set("expiring_within_days", String(f.expiring_within_days));
    const s = q.toString();
    return `/sod/mitigations${s ? `?${s}` : ""}`;
  },
  reviewContext: (campaignId: number) => `/sod/review-context?campaign_id=${campaignId}`,
};

export const sodPaths = {
  functions: "/sod/functions", risks: "/sod/risks", rulesets: "/sod/rulesets",
  function: (id: string) => sodPath("functions", id), risk: (id: string) => sodPath("risks", id), ruleset: (id: string) => sodPath("rulesets", id),
  violations: (f: SodViolationFilter = {}) => `/sod/violations${sodViolationQuery(f)}`,
};
/** A recovery case: the guest re-proves identity at their original assurance level before a new sign-in is set up. */
export interface GuestRecovery {
  id: string;
  identity_id: number;
  status: string;
  via: string;
  reason: string;
  required_ial: number;
  privileged: boolean;
  cooling_until: string | null;
  created_at: string;
  completed_at: string | null;
  expires_at?: string;
}
export const guestRecoveries = {
  list: () => api<{ recoveries: GuestRecovery[] }>("/guest-recoveries"),
  cancel: (id: string, reason: string) => api<GuestRecovery>(`/guest-recoveries/${encodeURIComponent(id)}/cancel`, { reason }),
};

/** What the person page shows besides affiliations: where the person came from and what they accepted. No values, no hashes. */
export interface GuestProfile {
  identity_id: number;
  source_records: { id: string; system: string; system_id: string; status: string; received_at: string; attributes: string[] }[];
  terms_acceptances: { key: string; version: number; context: string; accepted_at: string }[];
}

// ---------------------------------------------------------------- guest claim (issue #69)

/**
 * The public claim API (/public/t/{slug}/claim): a guest with no Tessera session finishing an
 * invitation. It has none of the admin session's assumptions: no CSRF token, no session cache and
 * no sign-out handling. Instead every request carries the claim session's cookie (HttpOnly, set by
 * the API) and a proof signed with the key this page generated (see public/claim/proof.ts), so a
 * stolen cookie alone is useless. The claim link's token travels in the URL fragment and in the
 * POST body of `start`, never in a path or query.
 */
export type ClaimStep = "verify_contact" | "verify_identity" | "existing_account" | "credential" | "complete";
export interface ClaimStatus {
  step: ClaimStep;
  steps: ClaimStep[];
  first_name: string;
  tenant: string;
  sponsor: string;
  population: GuestPopulationKey;
  ends_at: string;
  /**
   * Why the claim waits: "" (it does not), terms or the attribute-release consent still to answer
   * (step 5, before the credential), the organization's own set-up, or identity verification.
   */
  pending: "" | "terms" | "consent" | "organization" | "identity_verification";
  complete: boolean;
  /** Only "recovery": the claim page is recovering an existing account, not setting up a new one. */
  purpose?: "recovery";
}

/** A terms document the claimant has to read and accept (step 5): the text and its hash, which the acceptance echoes. */
export interface ClaimTermsDoc {
  id: string;
  key: string;
  version: number;
  title: string;
  body: string;
  sha256: string;
  state: "accepted" | "grace" | "blocked";
  due_by: string | null;
  previously_accepted: boolean;
}
export interface ClaimAttribute {
  name: string;
  why: string;
  required: boolean;
}
export interface ClaimTerms {
  step: ClaimStep;
  terms: ClaimTermsDoc[];
  /** The attribute-release screen of a federated sign-in; `applies` is false for every other claim. */
  consent: { applies: boolean; given: boolean; authority?: string; attributes: ClaimAttribute[] };
}
export interface ClaimStart {
  /** "check_link" for every link that does not work, whatever the reason; otherwise the first step. */
  next: "check_link" | ClaimStep;
  nonce?: string;
  status?: ClaimStatus;
}
export interface ClaimSigner {
  /** The X-Claim-Proof header value for a request: a signature by the key bound at start over the request and its body ("" for none). */
  sign(method: string, path: string, nonce: string, body: string): Promise<string>;
}
export class ClaimError extends ApiError {
  constructor(message: string, status: number, code: string) {
    super(message, status, { error: code, message });
  }
}

export const claimPath = (slug: string, rest: string) => `/public/t/${encodeURIComponent(slug)}/claim/${rest}`;

async function claimFetch<T>(slug: string, method: "GET" | "POST", rest: string, body: unknown, signer: ClaimSigner, nonce: string): Promise<T> {
  const path = claimPath(slug, rest);
  // serialize once: the proof signs exactly the bytes that are sent
  const payload = body !== undefined ? JSON.stringify(body) : undefined;
  const headers: Record<string, string> = { "x-claim-proof": await signer.sign(method, path, nonce, payload ?? "") };
  if (payload !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    cache: "no-store",
    referrerPolicy: "no-referrer",
    body: payload,
  });
  let j: any = null;
  try {
    j = await res.json();
  } catch {
    /* no body */
  }
  if (!res.ok) throw new ClaimError(claimMessage(res.status, j), res.status, j?.error ?? "error");
  return j as T;
}

function claimMessage(status: number, j: any): string {
  switch (j?.error) {
    case "session_required":
      return "Your sign-up session ended. Open the link in your invitation email again, or ask for a new one.";
    case "rate_limited":
      return "Too many tries. Wait a few minutes and try again.";
    case "code_invalid":
      return j.message ?? "That code did not work.";
    case "authority_unavailable":
      return j.message ?? "We could not reach the sign-in service. Try again in a moment.";
    case "wrong_step":
      return "That step is not open yet.";
    case "terms_required":
      return "Read and accept the terms first.";
    case "consent_required":
      return "Choose what to share first.";
    case "terms_changed":
      return "The terms changed while you were reading them. The page has reloaded the current text.";
  }
  return j?.message ?? `Something went wrong (${status}).`;
}

/** The claim client. `nonce` is the session's, from `start`; the signer holds the key. */
export const claimApi = {
  /** Exchange the link's token for a session (sets the cookie). `publicKey` is the page's public JWK. */
  start: (slug: string, token: string, publicKey: JsonWebKey, signer: ClaimSigner) =>
    claimFetch<ClaimStart>(slug, "POST", "start", { token, key: publicKey }, signer, ""),
  status: (slug: string, signer: ClaimSigner, nonce: string) => claimFetch<ClaimStatus>(slug, "GET", "status", undefined, signer, nonce),
  sendCode: (slug: string, signer: ClaimSigner, nonce: string) =>
    claimFetch<{ status: string; message: string }>(slug, "POST", "verify/send", undefined, signer, nonce),
  checkCode: (slug: string, signer: ClaimSigner, nonce: string, code: string) =>
    claimFetch<{ ok: boolean; step: ClaimStep }>(slug, "POST", "verify/check", { code }, signer, nonce),
  existingAccount: (slug: string, signer: ClaimSigner, nonce: string, answer: "yes" | "no") =>
    claimFetch<{ ok: boolean; step: ClaimStep; message?: string; status?: "redirect"; redirect?: string }>(slug, "POST", "existing-account", { answer }, signer, nonce),
  // "yes" answers {status: "redirect", redirect}: a sign-in as the existing account, which links this
  // invitation to it when it is the account the organization had in mind (and otherwise changes nothing).
  /** Step 5: the terms still to accept and the consent screen. */
  terms: (slug: string, signer: ClaimSigner, nonce: string) => claimFetch<ClaimTerms>(slug, "GET", "terms", undefined, signer, nonce),
  /** Accept the documents as shown ({id, sha256} of each); the credential stays closed until all are accepted. */
  acceptTerms: (slug: string, signer: ClaimSigner, nonce: string, documents: { id: string; sha256: string }[]) =>
    claimFetch<{ ok: boolean; remaining: number }>(slug, "POST", "terms/accept", { documents }, signer, nonce),
  /** The attributes the claimant agrees to release at a federated sign-in (the required ones are always included). */
  consent: (slug: string, signer: ClaimSigner, nonce: string, attributes: string[]) =>
    claimFetch<{ ok: boolean }>(slug, "POST", "consent", { attributes }, signer, nonce),
  /** Set up the sign-in: a redirect to the credential authority, or "pending" when the organization has not set one up. */
  credential: (slug: string, signer: ClaimSigner, nonce: string) =>
    claimFetch<{ status: "redirect" | "pending"; redirect?: string; pending?: string; message?: string }>(slug, "POST", "credential", undefined, signer, nonce),
};

// ---------------------------------------------------------------- guest terms and recovery (issue #73)

/** One version of a terms document (admin list). */
export interface TermsVersion {
  id: string;
  version: number;
  sha256: string;
  grace_days: number;
  created_at: string;
  created_by: string;
}
/** A terms document at its latest version, with where it applies. */
export interface TermsDocument {
  key: string;
  title: string;
  latest_version: number;
  body: string;
  sha256: string;
  grace_days: number;
  versions: TermsVersion[];
  populations: GuestPopulationKey[];
  bundles: { group_id: number; system: string; name: string }[];
}
export const termsAdmin = {
  /** Publish a new version of a document (the first one when the key is new). */
  publish: (d: { key: string; title: string; body: string; grace_days?: number }) => api<TermsVersion>("/admin/terms", d),
  assign: (key: string, a: { populations: GuestPopulationKey[]; bundles: number[] }) =>
    api<TermsDocument>(`/admin/terms/${encodeURIComponent(key)}/assignments`, a, "PUT"),
};
/** A signed-in person's own documents: accepted, in their grace period, or blocking until accepted. */
export interface MyTerms {
  documents: ClaimTermsDoc[];
  blocked: boolean;
}
export const myTerms = {
  accept: (documents: { id: string; sha256: string }[]) => api<MyTerms>("/me/terms/accept", { documents }),
};

/** "Send me a new link": the answer is the same whether or not an invitation exists. No session, so no proof. */
export async function claimResend(slug: string, email: string): Promise<string> {
  const res = await fetch(claimPath(slug, "resend"), {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    cache: "no-store",
    referrerPolicy: "no-referrer",
    body: JSON.stringify({ email }),
  });
  if (res.status === 429) throw new ClaimError("Too many tries. Wait a while and try again.", 429, "rate_limited");
  let j: any = null;
  try {
    j = await res.json();
  } catch {
    /* no body */
  }
  return j?.message ?? "If an invitation exists for this address, we have sent a new link.";
}

// ------------------------------------------------ guest self-registration (issue #66)

/** A sponsor as the public search shows one: a name and an opaque handle, nothing else. */
export interface SponsorChoice {
  name: string;
  handle: string;
}

/** What the visitor typed. `sponsor` is a handle from the search; `code` is a code the sponsor shared (it wins). */
export interface RegistrationForm {
  given_name: string;
  family_name: string;
  email: string;
  purpose: string;
  starts_at?: string;
  ends_at: string;
  sponsor?: string;
  code?: string;
  /** The bot challenge's token (Turnstile or equivalent); empty where none is configured (dev). */
  challenge_token?: string;
}

const publicJSON = (slug: string, rest: string, init: RequestInit = {}) =>
  fetch(`/public/t/${encodeURIComponent(slug)}/${rest}`, {
    credentials: "same-origin",
    cache: "no-store",
    referrerPolicy: "no-referrer",
    ...init,
    headers: init.body ? { "content-type": "application/json" } : undefined,
  });

/** Public sponsor search: names only. Fewer than two letters lists nobody. */
export async function searchSponsors(slug: string, q: string): Promise<SponsorChoice[]> {
  if (q.trim().length < 2) return [];
  const res = await publicJSON(slug, `register/sponsors?q=${encodeURIComponent(q.trim())}`);
  if (res.status === 429) throw new Error("Too many searches. Wait a moment and try again.");
  if (!res.ok) throw new Error("Search is unavailable. Try again.");
  return ((await res.json()) as { sponsors: SponsorChoice[] }).sponsors;
}

/**
 * Ask a sponsor to register you. The answer is the same whatever happened to the request (it does
 * not say whether the address or the sponsor is known); only a form that is not valid, a failed
 * bot challenge and the rate limit are told apart, and none of them depends on anyone else.
 */
export async function submitRegistration(slug: string, form: RegistrationForm): Promise<string> {
  const res = await publicJSON(slug, "register", { method: "POST", body: JSON.stringify(form) });
  if (res.status === 429) throw new Error("Too many tries from this network. Wait a while and try again.");
  if (res.status === 403) throw new Error("We could not confirm you are not a robot. Try again.");
  if (res.status === 400) throw new Error("Check the form: every field is needed, and the end date must be after today.");
  if (res.status === 503) throw new Error("Registration is not available right now.");
  if (!res.ok && res.status !== 202) throw new Error("Something went wrong. Try again.");
  let j: any = null;
  try {
    j = await res.json();
  } catch {
    /* no body */
  }
  return j?.message ?? "Check your email.";
}

/** A request waiting for the signed-in sponsor. */
export interface RegistrationRequest {
  id: string;
  given_name: string | null;
  family_name: string | null;
  email: string | null;
  purpose: string | null;
  via: "search" | "code";
  starts_at: string;
  ends_at: string;
  expires_at: string;
  created_at: string;
}

export const registrationRequests = {
  list: () => api<{ registrations: RegistrationRequest[] }>("/guest-registrations"),
  /** Approve: the guest is created and invited through the ordinary sponsor path. */
  approve: (id: string, terms: { population?: string; ends_at?: string } = {}) =>
    api<{ id: string; status: "approved"; guest_identity_id: number; sponsorship_id: string }>(`/guest-registrations/${encodeURIComponent(id)}/approve`, terms),
  /** Deny: the visitor gets a neutral email; the reason is for the audit log only. */
  deny: (id: string, reason = "") => api<{ id: string; status: "denied" }>(`/guest-registrations/${encodeURIComponent(id)}/deny`, { reason }),
  /** A code to share instead of being searched for; shown once. */
  newCode: () => api<{ code: string; expires_at: string }>("/guest-registrations/code", {}),
};

export const simulate = (body: { remove_edge_ids?: number[]; add_edges?: { src: string; dst: string; duration_hours?: number }[]; disable_account_ids?: number[] }) =>
  api<SimResult>("/simulate", { remove_edge_ids: [], add_edges: [], disable_account_ids: [], ...body });

// ------------------------------------------------------------ evidence packs and point-in-time access (issue #111)
export interface EvidenceControl { id: string; title: string; files: string[] }
export interface EvidenceFramework { id: string; name: string; controls: EvidenceControl[] }
export interface EvidenceFile { name: string; sha256: string; bytes: number; rows: number }
export interface EvidenceManifest {
  schema: string;
  pack_id: string;
  framework: string;
  framework_name: string;
  controls: EvidenceControl[];
  period_from: string;
  period_to: string;
  generated_at: string;
  generated_by: string;
  files: EvidenceFile[];
  user_rows_by_source: Record<string, number>;
  notes: string[];
}
export interface EvidencePack {
  id: string;
  framework: string;
  framework_name: string;
  period_from: string;
  period_to: string;
  generated_at: string;
  generated_by: string;
  manifest_sha256: string;
  size_bytes: number;
  files: number;
  manifest?: EvidenceManifest;
}
export interface EvidencePackList { packs: EvidencePack[]; frameworks: EvidenceFramework[] }

/** Generate a pack. `from` and `to` are dates (YYYY-MM-DD); `to` includes that day. */
export const createEvidencePack = (body: { framework: string; from: string; to: string }) => api<EvidencePack>("/evidence/packs", body);

/** The pack's ZIP, for saving. A server error comes back as an ApiError like any other call. */
export async function downloadEvidencePack(id: string): Promise<Blob> {
  const res = await fetch(`/api/evidence/packs/${encodeURIComponent(id)}/download`, { credentials: "same-origin" });
  if (!res.ok) {
    let j: any = null;
    try {
      j = await res.json();
    } catch {
      /* ignore */
    }
    throw new ApiError(j ? errorMessage(res.status, j) : `${res.status} ${res.statusText}`, res.status, j);
  }
  return res.blob();
}

export interface AsOfPath { text: string; steps: { key: string; kind: string; label: string; system: string | null }[] }
export interface AsOfPermission { permission_id: number; action: string; privileged: boolean; standing: boolean; paths: AsOfPath[] }
export interface AsOfAccess { identity: IdentityBrief; permissions: AsOfPermission[] }
export interface AsOfResult {
  resource: { id: number; system: string; name: string; kind: string; environment: string | null };
  date: string;
  as_of: string;
  identities: AsOfAccess[];
  count: number;
}
/** Path for useApi: who could reach the resource on `date` (YYYY-MM-DD, end of that day, or an ISO instant). */
export const asOfPath = (resourceId: number | string, date: string) =>
  `/access/as-of?resource=${encodeURIComponent(String(resourceId))}&date=${encodeURIComponent(date)}`;

// ------------------------------------------------------------ formatting
const asUtc =(s: string) => new Date(s + (s.endsWith("Z") ? "" : "Z"));
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

export interface Verify { kind: "attestation" | "live" | "data"; check?: string; params?: Record<string, unknown>; on_unsupported?: "attestation" }
export interface Part { kind: Verify["kind"]; check?: string; status: ItemStatus; reason?: string; simulated?: boolean; run_id?: string; observed?: Record<string, unknown>; message?: string; unsupported?: boolean }

export interface ChecklistItem {
  id: string; title: string; category: string; level: Level; template_level?: Level; why: string; verify: Verify[];
  remediation: { hint: string; link?: string }; depends_on?: string[]; config_fields?: string[]; source?: string;
  applicable: boolean; status: ItemStatus; reason?: string; blocked_by?: string[]; live_blocked_by?: string[]; parts: Part[];
  attestation: { actor: string; note: string; at: string; stale: boolean } | null;
  /** An attestation standing in for a live check the system reported unsupported. */
  live_attestation: { attester: string; actor: string; reason: string; evidence: string; at: string; stale: boolean } | null;
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

export interface DriftEvent { kind: string; severity: "high" | "medium" | "low"; subject: string; sentence: string; was?: number; now?: number }
export interface TemplateUpgrade { pin: string; available: string; major: boolean; new_required: string[]; new_other: number; first_seen_at?: string; grace_ends_at?: string; overdue: boolean }
export interface DriftView {
  connection_id: string; connection_name: string; revision_id: string; state: RevisionState;
  baseline: { captured_at: string; score: number; config_hash: string; findings: number; accounts: number; groups: number };
  score: number; accounts: number; groups: number; findings: number; events: DriftEvent[]; template_upgrade: TemplateUpgrade | null;
  fail_streak: number; degraded_reason?: string; degraded_at?: string; last_scheduled_run_at?: string; score_series: { at: string; score: number }[];
}
/** An Inbox task from deployment readiness (source "connection"): a degraded connection. */
export interface ReadinessTask {
  id: string; kind: "connection"; connection_id: string; connection_name: string; owner: string | null; severity: string; title: string;
  reason: string; since: string; href: string;
}

export interface ConnectionHealthRow {
  id: string; name: string; connector_type: string; state: RevisionState; health: string; simulated: boolean; score: number; band: Band;
  counted: boolean; accounts: number; blocking: number; last_validated: string | null; last_dry_run: string | null;
  drift: { events: number; high: number; template_update: boolean } | null;
}

export interface SkippedRow { connection_id: string; connection_name: string; item_id: string; item_title: string; level: string; actor: string; reason: string; skipped_at: string; review_by: string; expired: boolean }

export interface DeploymentHealth {
  generated_at: string;
  tenant: { score: number | null; band: Band | ""; capped: boolean; cap_reason?: string; hr_source: string; connections_counted: number; formula: string };
  kpis: { accounts_correlated_pct?: number; orphans: number; dormant: number; privileged_accounts: number; open_critical_high: number; connections_in_setup: number; degraded: number };
  connections: ConnectionHealthRow[]; needs_attention: AttentionEntry[]; skipped: SkippedRow[]; drift: DriftView[]; tasks: ReadinessTask[];
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
  attestInstead: (id: string, item: string, body: { attester: string; reason: string; evidence: string }) =>
    api<Checklist>(`/connections/${id}/checklist/${item}/attest-instead`, body),
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

// ------------------------------------------------------------ agent authorization (issue #115)
// The MCP authorization server's admin API: registered clients (client ID metadata documents),
// resource servers, issued tokens and the decision log. Tokens themselves are never returned.

export interface McpIdentityRef { id: number; name: string }
export type McpClientStatus = "pending" | "active" | "disabled";
export interface McpClient {
  id: string; client_id: string; name: string; redirect_uris: string[]; loopback_redirect: boolean; has_keys: boolean;
  agent: McpIdentityRef | null; status: McpClientStatus; fetched_at: string; expires_at: string; doc_sha256: string;
}
export interface McpResource {
  id: string; resource: string; name: string; status: "active" | "disabled"; created_by: string; created_at: string;
  metadata_path: string;
  /** Shown once, when the resource is created. */
  secret?: string;
}
export interface McpActor { sub: string; client_id?: string; act?: McpActor }
export interface McpToken {
  jti: string; client_id: string; subject: McpIdentityRef; agent: McpIdentityRef; audience: string; scope: string[];
  act: McpActor | null; grant: "authorization_code" | "token_exchange"; policy_version: string; issued_at: string;
  expires_at: string; revoked_at: string | null; revoked_reason: string; state: "active" | "expired" | "revoked";
}
export interface McpDecision {
  id: number; at: string; kind: "issue" | "exchange" | "tool_call" | "revoke"; allow: boolean; reason: string; jti: string;
  client_id: string; subject: McpIdentityRef | null; agent: McpIdentityRef | null; resource: string; tool: string;
  requested_scope: string[]; granted_scope: string[]; policy_version: string;
}
export interface McpConsent {
  id: string; status: "pending" | "approved" | "denied" | "redeemed";
  client: { client_id: string; name: string; redirect_uris: string[]; loopback_redirect: boolean };
  agent: McpIdentityRef; resource: string; requested_scope: string[]; granted_scope: string[]; expires_at: string; policy_version: string;
}

/** Where the browser may be sent after consent: the client's https redirect, or an http one on the user's own machine. */
export function safeRedirect(u: string): boolean {
  try {
    const x = new URL(u);
    if (x.protocol === "https:") return true;
    return x.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(x.hostname);
  } catch {
    return false;
  }
}

export const mcpAuthz = {
  registerClient: (clientId: string) => api<McpClient>("/mcp/clients", { client_id: clientId }),
  updateClient: (id: string, body: { agent_identity_id: number | null; status: McpClientStatus }) =>
    api<McpClient>(`/mcp/clients/${encodeURIComponent(id)}`, body, "PUT"),
  createResource: (resource: string, name: string) => api<McpResource>("/mcp/resources", { resource, name }),
  updateResource: (id: string, status: "active" | "disabled") =>
    api<McpResource>(`/mcp/resources/${encodeURIComponent(id)}`, { status }, "PUT"),
  revokeToken: (jti: string) => api<{ revoked: boolean; jti: string }>(`/mcp/tokens/${encodeURIComponent(jti)}/revoke`, {}),
  consent: (id: string) => api<McpConsent>(`/mcp/authorizations/${encodeURIComponent(id)}`),
  /** The browser is sent to `redirect_to` (the client's redirect URI with the code, or the error). */
  decide: (id: string, approve: boolean) =>
    api<{ approved: boolean; redirect_to: string }>(`/mcp/authorizations/${encodeURIComponent(id)}/decision`, { approve }),
};

// ------------------------------------------------------ Directory Agents (DR-11)
export type AgentStatus = "pending" | "active" | "revoked";

/** One Directory Agent. It carries no secret and no key pin. */
export interface DirectoryAgent {
  id: string; name: string; status: AgentStatus;
  /** Polled Tessera recently (an active agent that is not online cannot answer checks). */
  online: boolean;
  /** Older than the version Tessera treats as current. */
  outdated: boolean;
  hostname?: string; os?: string; version?: string;
  /** SHA-256 of the agent's local allowlist: changes when its allowed_targets change. */
  allowlist_hash?: string;
  last_seen_at?: string; enrolled_at?: string;
  created_by: string; created_at: string;
  revoked_at?: string; revoked_by?: string;
  /** Prefix of a credential reference for a secret stored on this agent: agent:<id>/ */
  credential_ref_prefix: string;
}

/** Issuing an enrolment code: the code is in this response only. */
export interface AgentEnrolment { agent: DirectoryAgent; code: string; expires_at: string }

export const agents = {
  // the answer holds a code shown once, so a step-up must not replay this call in the background
  enrol: (name: string) => apiNoResume<AgentEnrolment>("/agents", { name }),
  revoke: (id: string) => api<DirectoryAgent>(`/agents/${id}/revoke`, {}),
};

// ---------------------------------------------------------------- AWS evaluator (/api/aws, design §11.2)

export interface AwsReason { code: string; outcome_sensitive: boolean; detail?: string }
export interface AwsCell { outcome: string; deny_kind?: string; fidelity: string; fidelity_reasons: AwsReason[]; residual: string | null }
export interface AwsGap { kind: string; source_arn: string; policy_kind: string; code: string; detail: string; scope: string }
export interface AwsCan {
  decision: { outcome: string; fidelity: string; steps: unknown[] };
  explanation_id: string;
  summary: string;
  narrative: string;
  snapshot: { id: string; taken_at: string };
  profile: string;
  collection_gaps: AwsGap[];
}
export interface AwsPolicyChange { op: string; target_arn: string; document?: string | null; policy_arn?: string | null }
export interface AwsDiffChange {
  principals: string[]; actions: string[]; resources: string[];
  action_count: number; resource_count: number;
  kind: "gained" | "lost" | "conditional_changed" | "fidelity_changed";
  before: AwsCell | null; after: AwsCell | null; trace: string[]; used_days_ago: number | null; gap: boolean;
}
export interface AwsSimulation {
  base_snapshot: string; head_snapshot: string; profile: string; catalog_version: string; engine_version: string;
  summary: { gained: number; lost: number; conditional_changed: number; fidelity_changed: number; principals_affected: number };
  changes: AwsDiffChange[]; omitted_changes: number; comment: string; collection_gaps: AwsGap[];
  pr_comment: { status: string; url?: string; error?: string };
}

export const awsCan = (principal: string, action: string, resource: string, profile = "default") =>
  api<AwsCan>(`/aws/can?${new URLSearchParams({ principal, action, resource, profile })}`);

export const awsSimulate = (changes: AwsPolicyChange[], head?: string, pullNumber?: number) =>
  api<AwsSimulation>("/aws/simulate-policy-change", {
    changes,
    ...(head ? { head } : {}),
    ...(pullNumber ? { comment: { pull_number: pullNumber } } : {}),
  });
// ------------------------------------------------------------------ conditional access (issue #163)

export type AccessScope = "signin" | "privileged";
export type AccessMode = "disabled" | "report_only" | "enforce";
export type AccessOutcome = "allow" | "step_up" | "deny";
export type NetworkOp = "any" | "in" | "not_in";
export type DeviceCondition = "any" | "unmanaged" | "not_compliant";
export type StepUpAcr = "urn:tessera:acr:aal2" | "urn:tessera:acr:phr" | "urn:tessera:acr:phrh";

export interface AccessPolicy {
  id: string; name: string; description: string; scope: AccessScope; mode: AccessMode; outcome: AccessOutcome;
  step_up_acr: StepUpAcr | null; step_up_max_age: number; network_op: NetworkOp; network_range_ids: string[];
  device: DeviceCondition; priority: number; created_at: string; updated_at: string;
}
export type AccessPolicyInput = Omit<AccessPolicy, "id" | "created_at" | "updated_at">;

export interface NetworkRange { id: string; name: string; description: string; cidrs: string[]; used_by: string[]; created_at: string; updated_at: string }
export interface NetworkRangeInput { name: string; description: string; cidrs: string[] }

export interface DeviceSignal {
  user_id: string; user: string; status: "compliant" | "not_compliant"; source: "manual" | "caep"; reason: string;
  set_at: string; expires_at: string | null; active: boolean;
}
export interface AccessUser { id: string; name: string; email: string }

/** The answer of a what-if evaluation: what the current policies would decide. */
export interface AccessDecision {
  scope: AccessScope; outcome: AccessOutcome; policies_evaluated: number;
  decided_by?: { policy_id: string; name: string; mode: AccessMode; outcome: AccessOutcome; step_up_acr?: StepUpAcr; step_up_max_age?: number };
  report_only?: { policy_id: string; name: string; outcome: AccessOutcome }[];
  inputs: { client_ip: string; device_managed: string; device_compliance: string };
}
export interface AccessEvaluateInput { scope: AccessScope; client_ip?: string; device_managed?: boolean | null; device_compliance?: "compliant" | "not_compliant" | "unknown" }

/** Conditional access: network ranges, policies and the device-compliance signal (needs conditional_access.read / .manage). */
export const conditionalAccess = {
  policies: () => api<AccessPolicy[]>("/access/policies"),
  createPolicy: (b: AccessPolicyInput) => api<AccessPolicy>("/access/policies", b),
  updatePolicy: (id: string, b: AccessPolicyInput) => api<AccessPolicy>(`/access/policies/${encodeURIComponent(id)}`, b, "PUT"),
  deletePolicy: (id: string) => api<{ deleted: string }>(`/access/policies/${encodeURIComponent(id)}`, undefined, "DELETE"),
  networks: () => api<NetworkRange[]>("/access/networks"),
  createNetwork: (b: NetworkRangeInput) => api<NetworkRange>("/access/networks", b),
  updateNetwork: (id: string, b: NetworkRangeInput) => api<NetworkRange>(`/access/networks/${encodeURIComponent(id)}`, b, "PUT"),
  deleteNetwork: (id: string) => api<{ deleted: string }>(`/access/networks/${encodeURIComponent(id)}`, undefined, "DELETE"),
  signals: () => api<DeviceSignal[]>("/access/device-signals"),
  setSignal: (userId: string, b: { status: DeviceSignal["status"]; reason: string; expires_in_hours?: number }) =>
    api<DeviceSignal>(`/access/device-signals/${encodeURIComponent(userId)}`, b, "PUT"),
  clearSignal: (userId: string) => api<{ cleared: string }>(`/access/device-signals/${encodeURIComponent(userId)}`, undefined, "DELETE"),
  evaluate: (b: AccessEvaluateInput) => api<AccessDecision>("/access/evaluate", b),
};

/** One line describing when a policy applies, for lists. */
export function describeConditions(p: Pick<AccessPolicy, "network_op" | "network_range_ids" | "device">, ranges: Pick<NetworkRange, "id" | "name">[]): string {
  const name = (id: string) => ranges.find((r) => r.id === id)?.name ?? "a deleted range";
  const parts: string[] = [];
  if (p.network_op !== "any") parts.push(`network ${p.network_op === "in" ? "is in" : "is not in"} ${p.network_range_ids.map(name).join(", ")}`);
  if (p.device === "unmanaged") parts.push("device is not managed");
  if (p.device === "not_compliant") parts.push("device is not known to be compliant");
  return parts.length ? parts.join(" and ") : "always";
}

// ------------------------------------------------------------ SIEM sinks (#169)

export type SiemKind = "syslog" | "webhook";
export type SiemFormat = "json" | "ocsf";
export type SiemFlavor = "hec" | "json" | "";

export interface SiemSink {
  id: string;
  name: string;
  kind: SiemKind;
  format: SiemFormat;
  /** host:port, or the webhook URL without its query string. */
  target: string;
  flavor: SiemFlavor;
  has_ca: boolean;
  has_token: boolean;
  include_http: boolean;
  enabled: boolean;
  cursor_seq: number;
  head_seq: number;
  health: { status: "healthy" | "catching_up" | "degraded" | "failing" | "paused"; lag: number };
  attempts: number;
  next_attempt_at: string | null;
  last_error: string | null;
  last_success_at: string | null;
  delivered_count: number;
  dead_letter_count: number;
  created_at: string;
  updated_at: string;
}

export interface SiemSinkInput {
  name: string;
  kind?: SiemKind;
  format: SiemFormat;
  /** Omit on update to keep the current target. */
  target?: string;
  flavor?: SiemFlavor;
  /** Omit on update to keep; "" removes it. */
  ca_pem?: string;
  /** Omit to keep the stored token; "" removes it. */
  token?: string;
  include_http: boolean;
  enabled: boolean;
  /** Creation only. */
  start?: "now" | "beginning";
}

export interface SiemDeadLetter {
  id: string;
  from_seq: number;
  to_seq: number;
  events: number;
  error: string;
  created_at: string;
}

export const siemApi = {
  create: (body: SiemSinkInput) => api<SiemSink>("/siem/sinks", body),
  update: (id: string, body: SiemSinkInput) => api<SiemSink>(`/siem/sinks/${encodeURIComponent(id)}`, body, "PUT"),
  rewind: (id: string, seq: number) => api<SiemSink>(`/siem/sinks/${encodeURIComponent(id)}/rewind`, { seq }),
  test: (id: string) => api<{ ok: boolean; error?: string }>(`/siem/sinks/${encodeURIComponent(id)}/test`, {}),
};

/** Health → badge tone and label. */
export const SIEM_HEALTH: Record<SiemSink["health"]["status"], { tone: "ok" | "info" | "warning" | "critical" | "outline"; label: string }> = {
  healthy: { tone: "ok", label: "Healthy" },
  catching_up: { tone: "info", label: "Catching up" },
  degraded: { tone: "warning", label: "Retrying" },
  failing: { tone: "critical", label: "Failing" },
  paused: { tone: "outline", label: "Paused" },
};
// ---------------------------------------------------------------- alerts (#168)

export type AlertSeverity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "acknowledged" | "resolved";

export interface UserRef {
  id: string;
  name: string;
}

export interface AlertDeliveryRow {
  id: string;
  channel: string;
  channel_kind: "email" | "webhook";
  status: "pending" | "sent" | "failed";
  attempts: number;
  next_attempt_at: string | null;
  last_error: string | null;
  sent_at: string | null;
}

export interface AlertRow {
  id: string;
  rule: string;
  rule_name: string;
  key: string;
  severity: AlertSeverity;
  title: string;
  detail: Record<string, unknown>;
  status: AlertStatus;
  count: number;
  first_seen_at: string;
  last_seen_at: string;
  assignee: UserRef | null;
  acknowledged_by: UserRef | null;
  acknowledged_at: string | null;
  resolved_by: UserRef | null;
  resolved_at: string | null;
  resolution: string | null;
  deliveries?: AlertDeliveryRow[];
}

export interface AlertSummary {
  open: number;
  acknowledged: number;
  by_severity: Partial<Record<AlertSeverity, number>>;
}

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  kind: "event" | "detection";
  enabled: boolean;
  severity: AlertSeverity;
  threshold: number;
  window_minutes: number;
  customized: boolean;
  updated_at: string | null;
  live: number;
}

export interface AlertChannel {
  id: string;
  name: string;
  kind: "email" | "webhook";
  /** Webhook URLs come back redacted (scheme, host and the last characters). */
  target: string;
  min_severity: AlertSeverity;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  /** Only in the response that created the channel or rotated its secret. */
  secret?: string;
}

export interface AlertChannelInput {
  name: string;
  kind?: "email" | "webhook";
  /** Omit on update to keep the current target. */
  target?: string;
  min_severity: AlertSeverity;
  enabled: boolean;
  rotate_secret?: boolean;
}

export const ALERT_SEVERITIES: AlertSeverity[] = ["low", "medium", "high", "critical"];

export const alertsApi = {
  acknowledge: (id: string) => api<AlertRow>(`/alerts/${encodeURIComponent(id)}/acknowledge`, {}),
  resolve: (id: string, note: string) => api<AlertRow>(`/alerts/${encodeURIComponent(id)}/resolve`, { note }),
  assign: (id: string, assignee_user_id: string | null) => api<AlertRow>(`/alerts/${encodeURIComponent(id)}/assign`, { assignee_user_id }),
  setRule: (id: string, body: { enabled: boolean; severity: AlertSeverity; threshold: number; window_minutes: number }) =>
    api<AlertRule[]>(`/alerts/rules/${encodeURIComponent(id)}`, body, "PUT"),
  createChannel: (body: AlertChannelInput) => api<AlertChannel>("/alerts/channels", body),
  updateChannel: (id: string, body: AlertChannelInput) => api<AlertChannel>(`/alerts/channels/${encodeURIComponent(id)}`, body, "PUT"),
  testChannel: (id: string) => api<{ ok: boolean; error?: string }>(`/alerts/channels/${encodeURIComponent(id)}/test`, {}),
};

/** Severity → badge tone. */
export const severityTone = (s: AlertSeverity) => (s === "critical" ? "critical" : s === "high" ? "warning" : s === "medium" ? "info" : "neutral");
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
  dialect?: "standard" | "entra"; fault?: string; on_deprovision?: "delete"; write_back: boolean; has_credential: boolean; credential_version: string | null; updated_at: string;
}

/** token is write-only: omit it to keep the stored credential. A change of kind or origin (scheme, host, port) needs a new token (422 credential_required). */
export interface ProvTargetInput { kind: ProvTarget["kind"]; base_url: string; dialect?: string; fault?: string; token?: string; write_back: boolean; on_deprovision?: "disable" | "delete" }

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

// ----------------------------------------------------- access drift (#301)

export type DriftClass = "missing" | "rogue" | "orphan" | "stale";
export type DriftStatus = "open" | "remediating" | "resolved" | "accepted";
export type DriftAction = "auto_provision" | "auto_revoke" | "owner_task" | "report_only";

export interface DriftItem {
  id: string; class: DriftClass; status: DriftStatus; system: string; entitlement: string; entitlement_name: string;
  account_ref: string; account: string; identity: { id: number | null; name: string } | null; owner: { id: number | null; name: string } | null;
  intended_id: string | null; observed_id: number | null; action: DriftAction | "none"; remediation_ref: string | null;
  remediation_note: string | null; remediation_at: string | null; detected_at: string; updated_at: string; resolved_at: string | null;
  accepted_by: string | null; accepted_reason: string | null; can_remediate: boolean; can_accept: boolean;
}

export interface DriftList { items: DriftItem[]; counts: { by_class: Partial<Record<DriftClass, number>>; by_status: Partial<Record<DriftStatus, number>> } }

export interface RemediationPolicy { id: string; system: string; entitlement_ref: string; drift_class: DriftClass; action: DriftAction; created_by: string; updated_at: string }
export interface RemediationPolicyInput { system: string; entitlement_ref: string; drift_class: DriftClass; action: DriftAction }

export const drift = {
  run: () => api<{ opened: number; reopened: number; updated: number; resolved: number; actions: number }>("/access-drift/run", {}),
  accept: (id: string, reason: string) => api<DriftItem>(`/access-drift/${encodeURIComponent(id)}/accept`, { reason }),
  remediate: (id: string, action: DriftAction) => api<DriftItem>(`/access-drift/${encodeURIComponent(id)}/remediate`, { action }),
  putPolicy: (body: RemediationPolicyInput) => api<RemediationPolicy>("/remediation-policies", body, "PUT"),
  deletePolicy: (id: string) => api<{ removed: boolean }>(`/remediation-policies/${encodeURIComponent(id)}`, undefined, "DELETE"),
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

// ------------------------------------------------ durable job queue (#300)

export type QueueStatus = "queued" | "running" | "succeeded" | "failed" | "dead";
export interface QueueJob {
  id: string; kind: string; status: QueueStatus; run_at: string; attempts: number; max_attempts: number; last_error: string;
  lease_owner: string | null; lease_expires_at: string | null; schedule_id: string | null; created_at: string; updated_at: string;
  finished_at: string | null;
}
export interface QueueSchedule {
  name: string; kind: string; spec: string; enabled: boolean; max_attempts: number; next_run_at: string; last_enqueued_at: string | null;
}

export const queue = {
  /** Puts a dead job back in the queue with a fresh attempt budget (step-up, audited). */
  retry: (id: string) => api<QueueJob>(`/queue/jobs/${encodeURIComponent(id)}/retry`, {}),
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
  | "idp_connection.disable" | "tenant.settings.update" | "tenant.security_contacts.update" | "breakglass.register" | "breakglass.revoke";

export interface AdminPersonRef { id: string; display_name: string }

export interface AdminChange {
  id: string; type: ChangeType; summary: string; status: ChangeStatus; target_id: string | null; two_person: boolean;
  cooling_off_seconds: number; requested_by: AdminPersonRef; requested_at: string; expires_at: string; approved_by: AdminPersonRef | null;
  approved_at: string | null; effective_at: string | null; decided_by: AdminPersonRef | null; decided_at: string | null;
  applied_at: string | null; failure: string | null; test_login_at: string | null; payload_hash: string;
  payload: Record<string, unknown> | null;
  notifications?: AdminNotification[];
}

export interface AdminNotification {
  id: string; kind: string; severity: "info" | "critical"; recipient_type: "admin" | "contact" | "operator"; recipient: string; subject: string;
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

// ------------------------------------------------------------ break-glass (design §9.6, §15.4)

/** A WebAuthn options document as the API sends it (go-webauthn JSON: binary values are base64url). */
export type WebAuthnOptionsJSON = { publicKey: Record<string, any> };

export interface BreakGlassKey {
  id: string; user_id: string; user: string; label: string; custodian: string; aaguid: string; attestation_format: string;
  attestation_trust: "basic" | "attca" | "mds_verified"; transports: string[]; change_request_id: string; created_at: string;
  last_used_at: string | null; revoked_at: string | null;
}

/** An applied breakglass.register request whose key has not been registered yet (24 h window). */
export interface BreakGlassEnrolment {
  change_request_id: string; user_id: string; label: string; custodian: string; requested_by: AdminPersonRef; window_closes_at: string;
}

/** One break-glass sign-in, open until an admin says why it happened. */
export interface BreakGlassUse {
  id: string; session_id: string; credential_id: string; key: string; used_at: string; ip: string | null; answered: boolean;
  answered_at: string | null; answered_by: AdminPersonRef | null; reason: string | null;
}

/** What a break-glass session may do (§15.4). */
export type BreakGlassAction = "idp_connection.disable" | "idp_connection.update_trust" | "role.grant" | "sessions.revoke_all";

export interface BreakGlassOverview {
  available: boolean; keys: BreakGlassKey[]; open_enrolments: BreakGlassEnrolment[]; uses: BreakGlassUse[]; unanswered_uses: number;
  aaguid_allowlist: string[]; actions: BreakGlassAction[];
}

/** Break-glass calls. Registration is an admin's (step-up); the actions are the break-glass session's alone. */
export const breakGlass = {
  registrationOptions: (changeRequestId: string) =>
    api<WebAuthnOptionsJSON>("/admin/break-glass/registration/options", { change_request_id: changeRequestId }),
  registrationVerify: (changeRequestId: string, credential: unknown) =>
    api<BreakGlassKey>("/admin/break-glass/registration/verify", { change_request_id: changeRequestId, credential }),
  action: (action: BreakGlassAction, payload: Record<string, unknown> = {}) =>
    api<{ action: BreakGlassAction; revoked_sessions: number; change_request?: AdminChange }>(`/admin/break-glass/actions/${action}`, payload),
  attest: (useId: string, reason: string) => api<BreakGlassUse>(`/admin/break-glass/uses/${useId}/attest`, { reason }),
  /** The sign-in page's two calls (no session yet): options for the tenant's keys, then the signed assertion. */
  signInOptions: (tenant: string) => api<WebAuthnOptionsJSON>("/auth/break-glass/options", { tenant }),
  signIn: (tenant: string, credential: unknown) =>
    api<{ ok: boolean; redirect: string; expires_at: string; idle_timeout_s: number }>("/auth/break-glass/verify", { tenant, credential }),
};

/** Seconds as "24 h", "5 min" for the cooling-off column. */
export function fmtSpan(seconds: number): string {
  if (seconds <= 0) return "none";
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}
// ---- MFA posture (GET /api/mfa/posture)

/** Method class, strongest first; "none" is covered-but-nothing-registered, "unknown" is not covered by any IdP read. */
export type MfaClass = "phishing_resistant" | "push_number_match" | "push" | "otp" | "sms_voice" | "none" | "unknown";
export interface MfaMethod { system: string; account: string; kind: string; strength: MfaClass; label: string; enrolled_at: string | null }
export interface MfaIdentity {
  id: number; name: string; department: string; title: string;
  privileged: boolean; privileged_groups: string[]; privileged_via: string[];
  best: MfaClass; passkey: boolean; methods: MfaMethod[]; systems: string[];
}
export interface MfaCounts {
  total: number; phishing_resistant: number; push_number_match: number; push: number; otp: number; sms_voice: number;
  no_mfa: number; unknown: number; passkey_enrolled: number;
}
export interface MfaGroup extends MfaCounts { key: string }
export interface MfaSource { system: string; status: "ok" | "unavailable"; detail: string; updated_at: string }
export interface MfaAppFinding {
  account_id: number; system: string; username: string; identity_id: number | null; identity_name: string;
  privileged: boolean; issues: ("local_password" | "no_mfa" | "sso_not_enforced")[];
}
export interface MfaAppSystem { system: string; accounts: number; with_signals: number; flagged: number }
export interface MfaPosture {
  as_of: string;
  departments: string[];
  sources: MfaSource[];
  summary: { totals: MfaCounts; by_department: MfaGroup[]; by_privileged_group: MfaGroup[]; privileged_totals: MfaCounts };
  trend: (MfaCounts & { date: string })[];
  identities: MfaIdentity[];
  app_findings: MfaAppFinding[];
  app_systems: MfaAppSystem[];
  classes: { key: MfaClass; label: string }[];
}

/** The posture path with its filters; `privileged` is "" (all), "true" or "false". */
export const mfaPosturePath = (department: string, privileged: "" | "true" | "false") => {
  const q = new URLSearchParams();
  if (department) q.set("department", department);
  if (privileged) q.set("privileged", privileged);
  const s = q.toString();
  return `/mfa/posture${s ? `?${s}` : ""}`;
};

// -------------------------------------------------------------- secret rotation
export type RotationState = "pending" | "created" | "handed_over" | "old_disabled" | "verified" | "old_deleted" | "failed" | "cancelled";
export type RotationAction = "rotate" | "manual" | "blocked" | "in_flight";
export type RotationOrigin = "manual" | "policy" | "vendor_compromise" | "jml";
export type RotationAdapterType = "aws_iam" | "aws_secretsmanager" | "vault" | "github" | "fake";

export interface RotationOwner { id: number; name: string; email: string | null; status: string }

/** What a rotation of one secret would do. Computed from the database: nothing is called or written. */
export interface RotationPlanItem {
  secret_id: number;
  name: string;
  system: string;
  kind: string;
  account: string;
  owner: RotationOwner | null;
  age_days: number;
  max_age_days: number | null;
  overdue: boolean;
  action: RotationAction;
  reason?: string;
  adapter: string | null;
  adapter_type?: RotationAdapterType;
  destination: string | null;
  dest_path?: string;
  grace_hours: number;
  steps: string[];
  warnings: string[];
  job_id?: string;
}

export interface RotationJobLite { id: string; state: RotationState; origin: RotationOrigin; at: string; completed_at: string | null; last_error: string | null }

export interface RotationSecretStatus {
  secret_id: number;
  name: string;
  system: string;
  kind: string;
  account: string;
  owner: RotationOwner | null;
  age_days: number;
  max_age_days: number | null;
  overdue: boolean;
  mode: "automatic" | "scheduled" | "manual" | "none";
  action: RotationAction;
  reason?: string;
  adapter: string | null;
  active_job: RotationJobLite | null;
  last_job: RotationJobLite | null;
}

/** The recorded re-read of the old credential: a job is verified only with this. */
export interface RotationVerification {
  checked_at: string;
  verdict: "ok" | "still_active" | "used_after_disable" | "missing_evidence";
  evidence: "age_and_last_use" | "age_only" | "old_credential_absent";
  old_exists: boolean;
  old_active: boolean;
  old_created_at: string | null;
  old_age_days: number | null;
  old_last_used_at: string | null;
  last_used_known: boolean;
  disabled_at: string | null;
  detail?: string;
}

export interface RotationJobStep { state: Exclude<RotationState, "pending" | "failed" | "cancelled">; status: "done" | "current" | "pending" | "failed" | "skipped"; at: string | null }

export interface RotationJob {
  id: string;
  secret_id: number;
  secret: string;
  system: string;
  kind: string;
  account: string;
  origin: RotationOrigin;
  bulk_id: string | null;
  adapter: string;
  adapter_type: RotationAdapterType;
  destination: string | null;
  dest_path: string;
  state: RotationState;
  failed_state: RotationState | null;
  old_ref: string;
  new_ref: string | null;
  grace_hours: number;
  attempts: number;
  last_error: string | null;
  next_step_at: string | null;
  handed_over_at: string | null;
  disabled_at: string | null;
  verified_at: string | null;
  completed_at: string | null;
  verification: RotationVerification | null;
  steps: RotationJobStep[];
  requested_by: string;
  created_at: string;
  updated_at: string;
}

/** An adapter as the API shows it: the credential is never returned, only whether one is set. */
export interface RotationAdapter { id: string; name: string; type: RotationAdapterType; config: Record<string, string>; credential_set: boolean; created_by: string; created_at: string; updated_at: string }
export interface RotationAdapterList { adapters: RotationAdapter[]; types: RotationAdapterType[] }

export interface RotationPolicy {
  id: string;
  kind: string;
  system: string;
  max_age_days: number;
  grace_hours: number;
  adapter: string | null;
  destination: string | null;
  dest_path: string;
  auto_rotate: boolean;
  mode: "automatic" | "scheduled" | "manual";
  created_by: string;
  updated_at: string;
}

export interface RotationPolicyInput { kind: string; system: string; max_age_days: number; grace_hours: number; adapter: string | null; destination: string | null; dest_path: string; auto_rotate: boolean }
export interface RotationAdapterInput { type: RotationAdapterType; config: Record<string, string>; credential?: Record<string, string> }

export interface RotationBulkCounts { total: number; rotate: number; manual: number; blocked: number; in_flight: number }
export interface RotationBulkPlan { system: string; plan_hash: string; counts: RotationBulkCounts; items: RotationPlanItem[] }
export interface RotationBulkItem { secret_id: number; name: string; kind: string; action: RotationAction; reason?: string; adapter: string | null; owner: string | null }
export interface RotationBulk {
  id: string;
  system: string;
  reason: string;
  plan_hash: string;
  requested_by: string;
  created_at: string;
  counts: RotationBulkCounts;
  items: RotationBulkItem[];
  jobs: RotationJob[];
  progress: Partial<Record<RotationState, number>>;
}

/** The rotation endpoints. Reads use `useApi` with these paths; every change needs a fresh phishing-resistant sign-in. */
export const rotation = {
  paths: {
    overview: "/rotation/overview",
    adapters: "/rotation/adapters",
    policies: "/rotation/policies",
    jobs: (q = "") => `/rotation/jobs${q}`,
    job: (id: string) => `/rotation/jobs/${id}`,
    bulks: "/rotation/bulk",
    bulk: (id: string) => `/rotation/bulk/${id}`,
  },
  plan: (secretIds: number[]) => api<RotationPlanItem[]>("/rotation/plan", { secret_ids: secretIds }),
  start: (secretId: number) => api<RotationJob>("/rotation/jobs", { secret_id: secretId }),
  retry: (id: string) => api<RotationJob>(`/rotation/jobs/${id}/retry`, {}),
  cancel: (id: string) => api<RotationJob>(`/rotation/jobs/${id}/cancel`, {}),
  putPolicy: (p: RotationPolicyInput) => api<RotationPolicy>("/rotation/policies", p, "PUT"),
  deletePolicy: (id: string) => api<{ deleted: string }>(`/rotation/policies/${id}`, undefined, "DELETE"),
  putAdapter: (name: string, a: RotationAdapterInput) => api<RotationAdapter>(`/rotation/adapters/${encodeURIComponent(name)}`, a, "PUT"),
  deleteAdapter: (name: string) => api<{ deleted: string }>(`/rotation/adapters/${encodeURIComponent(name)}`, undefined, "DELETE"),
  bulkPlan: (system: string) => api<RotationBulkPlan>("/rotation/bulk/plan", { system }),
  bulkExecute: (system: string, reason: string, planHash: string) => api<RotationBulk>("/rotation/bulk", { system, reason, plan_hash: planHash }),
};

// ------------------------------------------------------------ native groups (Directory → Groups, GR-1 to GR-7)
// Design docs/design/groups-grouper-parity.md §10.11. `GET /api/groups` is the connected-system groups;
// the native (managed) groups are under /api/groups/native, /api/groups/folders and /api/groups/{id}.

export interface GrpFolder {
  id: string; parent_id: string | null; extension: string; display_extension: string; name: string; display_name: string;
  description: string; data_owner: string | null; managed_by: string; created_at: string; version: number;
}
export type GrpDefinition = "basic" | "composite" | "policy";
export type CompositeOp = "union" | "intersection" | "complement";
export interface GrpGroup {
  id: string; folder_id: string; extension: string; display_extension: string; name: string; display_name: string;
  description: string; type: "group" | "role"; definition: GrpDefinition; composite_op: CompositeOp | null; factors?: string[];
  managed_by: string; data_owner: string | null; member_description: string | null; status: string;
  enabled_from: string | null; disabled_at: string | null; requestable: boolean; effective_count: number;
  /** clean, pending (a queued recompute is running: the members are stale) or failed */
  recompute_state: string; created_at: string; version: number;
}
export interface GrpList<T> { items: T[]; limit: number; offset: number }
export interface GrpDirectMember {
  id: string; type: "identity" | "group"; identity_id: number | null; group_id: string | null; name: string;
  enabled_from: string | null; disabled_at: string | null; active: boolean; source: string; reason: string | null; created_at: string;
}
export interface GrpEffectiveMember { identity_id: number; name: string; support: number; since: string }
export interface GrpMembers<T> { items: T[]; limit: number; offset: number; total: number; filter: string; stale: boolean }
export type MemberFilter = "direct" | "indirect" | "effective" | "composite";
export interface TraceStep { group_id: string; name: string; via: string; op?: string; role?: string }
export interface MemberTrace { group_id: string; identity_id: number; member: boolean; stale: boolean; paths?: { steps: TraceStep[] }[]; truncated?: boolean }
export interface MemberAnswer { member?: GrpDirectMember; effective: "applied" | "pending"; op: number | null }
export interface BatchAdd { identity?: number; group?: string; enabled_from?: string; disabled_at?: string; reason?: string }
export interface BatchBody { add?: BatchAdd[]; remove?: string[]; enabled_from?: string; disabled_at?: string; reason?: string; atomic?: boolean }
export interface BatchResult { results?: { index: number; op: string; member_type: string; member: string; status: string; error: unknown }[]; effective?: string; op?: number | null }
export interface SimChange { kind: string; group: string; identity?: number; member_group?: string; member?: string; enabled_from?: string; disabled_at?: string; reason?: string; op?: string; factors?: string[]; discard_members?: boolean }
export interface SimMemberRef { identity_id: number; name: string }
export interface SimGroupResult { group_id: string; name: string; targeted: boolean; before: number; after: number; added: number; removed: number; added_sample: SimMemberRef[]; removed_sample: SimMemberRef[] }
export interface SimulationResult {
  simulated: boolean; changes: { index: number; kind: string; group_id: string; name: string; status: string }[];
  groups: SimGroupResult[]; added: number; removed: number; truncated: boolean;
}
export interface PitMember { identity_id?: number; group_id?: string; name: string; type?: string; source?: string; enabled_from?: string; disabled_at?: string; start_at: string; end_at: string | null }
export interface PitMembers { group_id: string; as_of?: string; from?: string; to?: string; filter: string; group: { name?: string; status?: string } | null; items: PitMember[]; limit: number; offset: number; total: number }
export interface PrivRow {
  id: string; object_type: string; object_id: string; object_name: string; privilege: string; holder_type: string; holder_id: string | null;
  holder_name: string; applies_to: string; scope: string; source: string; created_by: string | null; granted_by?: string; created_at: string;
}
export interface PrivPath { kind: string; role?: string; row?: PrivRow; via?: string; over_folder?: string; holder?: string; text: string }
export interface PrivExplanation { privilege: string; allowed: boolean; paths: PrivPath[] }
export interface GrpPrivGrant { privilege: string; holder_type: "identity" | "group" | "everyone"; identity?: number; group?: string; applies_to?: string; scope?: string }
export interface AttrDef { id: string; folder_id: string; name: string; attr_type: string; value_type: string; multi_assign: boolean; multi_valued: boolean; assign_to: string[]; system: boolean; description: string }
export interface AttrName { id: string; def_id: string; name: string; description: string; implies: string[]; implies_all: string[] }
export interface AttrAssignment {
  id: string; def_id: string; def: string; name_id: string; name: string; action_id: string; action: string; owner_type: string; owner: string;
  disallowed: boolean; enabled_from: string | null; disabled_at: string | null; active: boolean; values: (string | number)[]; created_at: string; version: number;
}
export interface LintFinding { rule: string; severity: string; message: string }
export interface ObjectTypes { object_type: string; object_id: string; types: string[]; vocabulary: string[]; lint: LintFinding[] }

const qs = (o: Record<string, string | number | boolean | undefined | null>) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
};
const gid = encodeURIComponent;

/** The native groups API. Every call is audited and privilege-checked on the server; nothing here decides access. */
export const groups = {
  // folders
  listFolders: (o: { parent?: string; scope?: "one" | "sub"; q?: string; limit?: number; offset?: number } = {}) =>
    api<GrpList<GrpFolder>>(`/groups/folders${qs({ limit: 500, ...o })}`),
  folder: (id: string) => api<GrpFolder>(`/groups/folders/${gid(id)}`),
  createFolder: (b: { parent?: string; extension: string; display_extension?: string; description?: string; data_owner?: string }) => api<GrpFolder>("/groups/folders", b),
  updateFolder: (id: string, b: { extension?: string; display_extension?: string; description?: string; data_owner?: string; version?: number }) =>
    api<GrpFolder>(`/groups/folders/${gid(id)}`, b, "PATCH"),
  deleteFolder: (id: string) => api<{ id: string; deleted: boolean }>(`/groups/folders/${gid(id)}`, undefined, "DELETE"),
  // groups
  listGroups: (o: { folder?: string; scope?: "one" | "sub"; q?: string; type?: string; deleted?: boolean; limit?: number; offset?: number } = {}) =>
    api<GrpList<GrpGroup>>(`/groups/native${qs({ limit: 500, ...o })}`),
  group: (id: string) => api<GrpGroup>(`/groups/${gid(id)}`),
  createGroup: (b: { folder: string; extension: string; display_extension?: string; description?: string; type?: string; data_owner?: string; member_description?: string; requestable?: boolean; definition?: string; composite_op?: string; factors?: string[] }) =>
    api<GrpGroup>("/groups", b),
  updateGroup: (id: string, b: Record<string, unknown>) => api<GrpGroup>(`/groups/${gid(id)}`, b, "PATCH"),
  deleteGroup: (id: string) => api<{ id: string; deleted: boolean }>(`/groups/${gid(id)}`, undefined, "DELETE"),
  restoreGroup: (id: string) => api<GrpGroup>(`/groups/${gid(id)}/restore`, {}),
  // members
  members: <T = GrpDirectMember | GrpEffectiveMember>(id: string, o: { filter?: MemberFilter; q?: string; sort?: string; enabled?: boolean; page?: number; limit?: number } = {}) =>
    api<GrpMembers<T>>(`/groups/${gid(id)}/members${qs(o)}`),
  addMember: (id: string, b: BatchAdd, key?: string) => api<MemberAnswer>(`/groups/${gid(id)}/members`, b, "POST", undefined, key),
  removeMember: (id: string, member: string) => api<MemberAnswer>(`/groups/${gid(id)}/members/${gid(member)}`, undefined, "DELETE"),
  trace: (id: string, identity: number) => api<MemberTrace>(`/groups/${gid(id)}/members/${identity}?trace=true`),
  batch: (id: string, b: BatchBody, key?: string) => api<BatchResult>(`/groups/${gid(id)}/members:batch`, b, "POST", undefined, key),
  simulate: (changes: SimChange[]) => api<SimulationResult>("/groups:simulate", { changes }),
  setComposite: (id: string, b: { op: string; factors: string[] }) => api<GrpGroup>(`/groups/${gid(id)}/composite`, b, "PUT"),
  convertToComposite: (id: string, b: { op: string; factors: string[]; discard_members?: boolean }) => api<GrpGroup>(`/groups/${gid(id)}/convert-to-composite`, b),
  // history (point in time)
  asOf: (id: string, at: string, filter: "effective" | "direct" = "effective") =>
    api<PitMembers>(`/groups/${gid(id)}/members${qs({ as_of: at, filter, limit: 500 })}`),
  between: (id: string, from: string, to: string) => api<PitMembers>(`/groups/${gid(id)}/members${qs({ between: `${from},${to}`, limit: 500 })}`),
  // privileges
  privileges: (kind: "group" | "folder", id: string) => api<{ object_type: string; object_id: string; items: PrivRow[] }>(`/groups/${kind === "folder" ? "folders/" : ""}${gid(id)}/privileges`),
  grant: (kind: "group" | "folder", id: string, b: GrpPrivGrant) => api<PrivRow>(`/groups/${kind === "folder" ? "folders/" : ""}${gid(id)}/privileges`, b),
  revoke: (kind: "group" | "folder", id: string, privilegeId: string) =>
    api<{ id: string; revoked: boolean }>(`/groups/${kind === "folder" ? "folders/" : ""}${gid(id)}/privileges/${gid(privilegeId)}`, undefined, "DELETE"),
  effectivePrivileges: (kind: "group" | "folder", id: string, identity?: number) =>
    api<{ object_type: string; object_id: string; identity_id: number | null; privileges: PrivExplanation[] }>(`/groups/${kind === "folder" ? "folders/" : ""}${gid(id)}/privileges/effective${qs({ identity })}`),
  // attributes and object types
  attrNames: () => api<GrpList<AttrName>>(`/groups/attr-names${qs({ limit: 500 })}`),
  attrDefs: () => api<GrpList<AttrDef>>(`/groups/attr-defs${qs({ limit: 500 })}`),
  assignments: (ownerType: string, owner: string) => api<GrpList<AttrAssignment>>(`/groups/attr-assignments${qs({ owner_type: ownerType, owner, limit: 500 })}`),
  assign: (b: { name: string; action: string; owner_type: string; owner: string; values?: (string | number)[]; enabled_from?: string; disabled_at?: string }) => api<AttrAssignment>("/groups/attr-assignments", b),
  unassign: (id: string) => api<{ id: string; deleted: boolean }>(`/groups/attr-assignments/${gid(id)}`, undefined, "DELETE"),
  objectTypes: (kind: "group" | "folder", id: string) => api<ObjectTypes>(`/groups/${kind === "folder" ? "folders/" : ""}${gid(id)}/object-types`),
  setObjectTypes: (kind: "group" | "folder", id: string, types: string[]) => api<ObjectTypes>(`/groups/${kind === "folder" ? "folders/" : ""}${gid(id)}/object-types`, { types }, "PUT"),
};
