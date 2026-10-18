/**
 * Preview mock layer. Typed stand-ins for backend capabilities that do not exist yet:
 * organizations, workflows, non-JIT access requests, delegations,
 * disable / reset-password actions and admin settings.
 *
 * State lives in this browser only (localStorage) so the demo feels real across reloads.
 * Nothing here calls the API, and nothing here invents API routes.
 */
import { useSyncExternalStore } from "react";
import { store } from "../app/storage";
import { ADMIN_SECTIONS, DELEGATIONS, ORGS, WORKFLOWS } from "./data";
import type { AccessRequestDraft, DelegationItem } from "./types";

export * from "./types";
export { ADMIN_SECTIONS, ORGS, WORKFLOWS };

const delay = <T,>(v: T, ms = 350) => new Promise<T>((r) => setTimeout(() => r(v), ms));

// --------------------------------------------------------- local store
interface MockState {
  requests: AccessRequestDraft[];
  delegations: DelegationItem[];
  log: { at: string; actor: string; action: string; target: string }[];
}

const KEY = "mock.v1";
const EMPTY: MockState = { requests: [], delegations: DELEGATIONS, log: [] };
let state: MockState = { ...EMPTY, ...store.get<Partial<MockState>>(KEY, {}) };
const subs = new Set<() => void>();
function commit(next: MockState) {
  state = next;
  store.set(KEY, state);
  subs.forEach((f) => f());
}
const subscribe = (f: () => void) => {
  subs.add(f);
  return () => subs.delete(f);
};

export function useMockState() {
  return useSyncExternalStore(subscribe, () => state);
}

function log(actor: string, action: string, target: string) {
  return [{ at: new Date().toISOString(), actor, action, target }, ...state.log].slice(0, 200);
}

const newId = (p: string) => `${p}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;

// ------------------------------------------------------------ requests
export const mockRequests = {
  saveDraft(d: Omit<AccessRequestDraft, "id" | "createdAt" | "status"> & { id?: string }) {
    const id = d.id ?? newId("draft");
    const rec: AccessRequestDraft = { ...d, id, createdAt: new Date().toISOString(), status: "draft" };
    commit({ ...state, requests: [rec, ...state.requests.filter((r) => r.id !== id)] });
    return rec;
  },
  async submit(d: Omit<AccessRequestDraft, "id" | "createdAt" | "status"> & { id?: string }) {
    const rec: AccessRequestDraft = { ...d, id: d.id ?? newId("req"), createdAt: new Date().toISOString(), status: "submitted" };
    commit({ ...state, requests: [rec, ...state.requests.filter((r) => r.id !== rec.id)], log: log(d.requester, d.kind === "removal" ? "request.removal" : "request.submit", rec.items.map((i) => i.name).join(", ")) });
    return delay(rec);
  },
  async decide(id: string, decision: "approved" | "denied", actor: string) {
    commit({ ...state, requests: state.requests.map((r) => (r.id === id ? { ...r, status: decision } : r)), log: log(actor, `request.${decision}`, id) });
    return delay(true, 200);
  },
  remove(id: string) {
    commit({ ...state, requests: state.requests.filter((r) => r.id !== id) });
  },
};

export const mockDelegations = {
  async decide(id: string, status: "accepted" | "declined", actor: string) {
    commit({ ...state, delegations: state.delegations.map((d) => (d.id === id ? { ...d, status } : d)), log: log(actor, `delegation.${status}`, id) });
    return delay(true, 200);
  },
};

// -------------------------------------------------------- identity ops
export const mockIdentityOps = {
  /** Would trigger a reset through the identity provider; Tessera never sees the password. */
  async resetPassword(name: string, actor: string) {
    commit({ ...state, log: log(actor, "identity.reset_password", name) });
    return delay({ channel: "IdP reset email" });
  },
  async importRows(kind: string, rows: number, actor: string) {
    commit({ ...state, log: log(actor, `import.${kind}`, `${rows} rows`) });
    return delay({ accepted: rows });
  },
};

/** Create / edit / import for objects that have no write endpoint yet (accounts, orgs, machine identities...). */
export const mockObjects = {
  async save(kind: string, name: string, actor: string, verb: "create" | "update" = "create") {
    commit({ ...state, log: log(actor, `${kind}.${verb}`, name) });
    return delay(true);
  },
};

export function resetMockState() {
  commit(EMPTY);
}

export const ADMIN_BY_ID = Object.fromEntries(ADMIN_SECTIONS.map((s) => [s.id, s]));
