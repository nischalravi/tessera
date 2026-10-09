/**
 * Preview mock layer. Typed stand-ins for backend capabilities that do not exist yet:
 * business roles, organizations, workflows, non-JIT access requests, delegations,
 * disable / reset-password actions and admin settings.
 *
 * State lives in this browser only (localStorage) so the demo feels real across reloads.
 * Nothing here calls the API, and nothing here invents API routes.
 */
import { useMemo, useSyncExternalStore } from "react";
import { store } from "../app/storage";
import { ADMIN_SECTIONS, DELEGATIONS, ORGS, ROLES, WORKFLOWS } from "./data";
import type { AccessRequestDraft, BusinessRole, DelegationItem } from "./types";

export * from "./types";
export { ADMIN_SECTIONS, ORGS, ROLES, WORKFLOWS };

const delay = <T,>(v: T, ms = 350) => new Promise<T>((r) => setTimeout(() => r(v), ms));

// --------------------------------------------------------- local store
interface MockState {
  requests: AccessRequestDraft[];
  delegations: DelegationItem[];
  /** identity id -> state set by preview actions */
  disabled: Record<number, string>;
  /** Roles created in the Preview "New role" form. */
  roles: BusinessRole[];
  log: { at: string; actor: string; action: string; target: string }[];
}

const KEY = "mock.v1";
const EMPTY: MockState = { requests: [], delegations: DELEGATIONS, disabled: {}, roles: [], log: [] };
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
  /** Would disable every account in connected systems and revoke sessions. */
  async disable(id: number, name: string, actor: string) {
    commit({ ...state, disabled: { ...state.disabled, [id]: new Date().toISOString() }, log: log(actor, "identity.disable", name) });
    return delay({ accounts: "all", sessionsRevoked: true });
  },
  async enable(id: number, name: string, actor: string) {
    const disabled = { ...state.disabled };
    delete disabled[id];
    commit({ ...state, disabled, log: log(actor, "identity.enable", name) });
    return delay(true);
  },
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

export const mockRoles = {
  async create(r: Omit<BusinessRole, "id" | "updated" | "members">, actor: string) {
    const role: BusinessRole = { ...r, id: newId("role"), members: 0, updated: new Date().toISOString().slice(0, 10) };
    commit({ ...state, roles: [role, ...state.roles], log: log(actor, "role.create", role.name) });
    return delay(role);
  },
};

/** Create / edit / import for objects that have no write endpoint yet (accounts, orgs, machine identities...). */
export const mockObjects = {
  async save(kind: string, name: string, actor: string, verb: "create" | "update" = "create") {
    commit({ ...state, log: log(actor, `${kind}.${verb}`, name) });
    return delay(true);
  },
};

/** Seeded roles plus any created in this browser. */
export function useRoles(): BusinessRole[] {
  const created = useMockState().roles;
  return useMemo(() => [...created, ...ROLES], [created]);
}

export function resetMockState() {
  commit(EMPTY);
}

export const ADMIN_BY_ID = Object.fromEntries(ADMIN_SECTIONS.map((s) => [s.id, s]));
