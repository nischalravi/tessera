/**
 * View logic for service-account requests (issue #298): the request form's checks and the words
 * for a request's state. The server validates everything (internal/svcaccounts: owners are
 * mandatory, active people and different people; no second open request about an account);
 * these mirror it so people see a problem before they submit. Pure functions; `npm test` covers them.
 */
import type { ServiceAccountInput, ServiceAccountRequest, ServiceAccountRequestKind, ServiceAccountRequestStatus, ServiceAccountRow } from "../../api";

export const KINDS: { id: ServiceAccountRequestKind; label: string; hint: string }[] = [
  { id: "create", label: "Create", hint: "A new service account with its owners" },
  { id: "change", label: "Change", hint: "Its purpose or backup owner" },
  { id: "transfer", label: "Transfer", hint: "A new primary owner; the old and the new owner both approve" },
];

export const KIND_LABEL: Record<ServiceAccountRequestKind, string> = { create: "Create", change: "Change", transfer: "Transfer" };

export const LIMITS = { name: 100, username: 100, purpose: 500, description: 500, justification: 1000 };

export interface SaForm {
  kind: ServiceAccountRequestKind;
  identityId: number | null;
  name: string;
  system: string;
  username: string;
  purpose: string;
  description: string;
  primary: number | null;
  backup: number | null;
  justification: string;
}

export const blankForm = (kind: ServiceAccountRequestKind = "create"): SaForm => ({
  kind, identityId: null, name: "", system: "", username: "", purpose: "", description: "", primary: null, backup: null, justification: "",
});

const USERNAME = /^[A-Za-z0-9][A-Za-z0-9._@-]*$/;

/** The first problem with a form, or null. `account` is the chosen service account (change, transfer). */
export function formProblem(f: SaForm, account?: ServiceAccountRow | null): string | null {
  const need = f.kind === "create" ? null : account;
  if (f.kind !== "create" && !f.identityId) return "Choose the service account";
  if (need && need.open_request) return "There is already an open request about this account";
  if (f.kind === "create") {
    if (!f.name.trim() || f.name.trim().length > LIMITS.name) return `A name of 1 to ${LIMITS.name} characters is required`;
    if (!f.system) return "Choose the application the account lives in";
    const u = f.username.trim();
    if (!u || u.length > LIMITS.username || !USERNAME.test(u)) return "The account name is letters, digits, . _ @ or -";
    if (!f.primary) return "A service account needs a primary owner";
    if (!f.backup) return "A service account needs a backup owner";
  }
  if (f.kind === "transfer") {
    if (!f.primary) return "Choose the new primary owner";
    if (account?.primary_owner && account.primary_owner.id === f.primary) return "That person already owns the account";
    const backup = f.backup ?? account?.backup_owner?.id ?? null;
    if (!backup) return "A service account needs a backup owner";
    if (backup === f.primary) return "The backup owner must be someone else";
  }
  if (f.kind === "change") {
    if (!account?.primary_owner) return "The account has no owner; transfer it instead";
    const purpose = f.purpose.trim() || account.purpose;
    const backup = f.backup ?? account.backup_owner?.id ?? null;
    if (purpose === account.purpose && backup === (account.backup_owner?.id ?? null)) return "Change the purpose or the backup owner";
    if (!backup) return "A service account needs a backup owner";
    if (backup === account.primary_owner.id) return "The backup owner must be someone else";
  }
  if (f.purpose.trim().length > LIMITS.purpose) return `The purpose is at most ${LIMITS.purpose} characters`;
  if (!f.justification.trim()) return "Say why you need it";
  if (f.justification.trim().length > LIMITS.justification) return `The justification is at most ${LIMITS.justification} characters`;
  return null;
}

/** The request body for a form. */
export function toInput(f: SaForm): ServiceAccountInput {
  const out: ServiceAccountInput = { kind: f.kind, justification: f.justification.trim() };
  if (f.kind === "create") {
    out.name = f.name.trim();
    out.system = f.system;
    out.username = f.username.trim();
    if (f.description.trim()) out.description = f.description.trim();
  } else {
    out.identity_id = f.identityId!;
  }
  if (f.purpose.trim()) out.purpose = f.purpose.trim();
  if (f.kind !== "change" && f.primary) out.primary_owner_id = f.primary;
  if (f.backup) out.backup_owner_id = f.backup;
  return out;
}

export const STATUS_LABEL: Record<ServiceAccountRequestStatus, string> = {
  pending: "Pending", approved: "Approved, provisioning", fulfilled: "Done", denied: "Denied", cancelled: "Cancelled",
};
export const statusTone = (s: ServiceAccountRequestStatus): "ok" | "warning" | "critical" | "neutral" | "info" =>
  s === "fulfilled" ? "ok" : s === "pending" ? "warning" : s === "denied" ? "critical" : s === "approved" ? "info" : "neutral";

/** "Bob to Alice" for a transfer, the owners for the rest. */
export function ownerSummary(r: ServiceAccountRequest): string {
  const owners = `${r.primary_owner.name}${r.backup_owner ? ` (backup ${r.backup_owner.name})` : ""}`;
  return r.kind === "transfer" && r.previous_primary_owner ? `${r.previous_primary_owner.name} to ${owners}` : owners;
}

/** What a pending request waits for, in words. */
export function waitingFor(r: ServiceAccountRequest): string | null {
  if (r.status !== "pending") return null;
  const st = r.stages.find((s) => s.status === "waiting");
  if (!st) return null;
  const who = st.assignee ? st.assignee.name : st.kind === "decider" ? "an access approver" : "an approver";
  return `${st.label ?? st.kind}: waiting for ${who}`;
}
