/**
 * Preview mock layer. Typed stand-ins for backend capabilities that do not exist yet:
 * workflows, reset-password and import actions, generic object create/edit and admin settings.
 *
 * State lives in this browser only (localStorage) so the demo feels real across reloads.
 * Nothing here calls the API, and nothing here invents API routes.
 */
import { useSyncExternalStore } from "react";
import { store } from "../app/storage";
import { ADMIN_SECTIONS, WORKFLOWS } from "./data";

export * from "./types";
export { ADMIN_SECTIONS, WORKFLOWS };

const delay = <T,>(v: T, ms = 350) => new Promise<T>((r) => setTimeout(() => r(v), ms));

// --------------------------------------------------------- local store
interface MockState {
  log: { at: string; actor: string; action: string; target: string }[];
}

const KEY = "mock.v1";
const EMPTY: MockState = { log: [] };
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
