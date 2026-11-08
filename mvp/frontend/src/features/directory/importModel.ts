/**
 * The rules of the Directory CSV import and of the create / edit forms (issue #915), kept out of the React
 * components so they are tested on their own. The server decides everything; this only shapes input and
 * words the answers.
 */
import type { ImportPlan, ImportResult, ImportTarget, ManualLookup, ManualSource } from "../../api";

/** The file limit of the server; components/csv.ts holds the same number for the list's own check (a test keeps them equal). */
export const IMPORT_MAX_BYTES = 5 * 1024 * 1024;
export const IMPORT_MAX_ROWS = 10000;

export interface FieldDef {
  id: string;
  label: string;
  required?: boolean;
  options?: string[];
  placeholder?: string;
  hint?: string;
  textarea?: boolean;
}

/** A source name an admin types ("HR spreadsheet") as the system slug the API takes ("hr-spreadsheet"); "" when nothing usable is left. */
export function slugifySource(name: string): string {
  const s = name.normalize("NFKD").toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^[^a-z0-9]+/, "").replace(/-+$/, "").slice(0, 63).replace(/[^a-z0-9]+$/, "");
  return s;
}

/** Why a file can not be imported, found before it is sent; null when it may be tried. The server checks again. */
export function checkImportFile(f: { name: string; size: number; type?: string }): string | null {
  if (!/\.csv$/i.test(f.name) && f.type !== "text/csv") return `${f.name} is not a CSV file. Save the sheet as CSV (UTF-8).`;
  if (f.size === 0) return `${f.name} is empty. The first line must be a header row.`;
  if (f.size > IMPORT_MAX_BYTES) return `${f.name} is larger than ${IMPORT_MAX_BYTES / 1024 / 1024} MiB. Split it into smaller files.`;
  return null;
}

/** The columns a file for this target carries: the canonical ones, or an existing source's own for accounts. */
export function expectedColumns(cols: { all: string[]; required: string[] } | undefined, target: ImportTarget, source?: ManualSource | null): { all: string[]; required: string[] } {
  if (target === "accounts" && source && source.account_columns.length) {
    // the first two of an account mapping are the required ones: account id and username
    return { all: source.account_columns, required: source.account_columns.slice(0, 2) };
  }
  return cols ?? { all: [], required: [] };
}

/** One line on what a plan would do. */
export function planHeadline(p: ImportPlan): string {
  if (p.error_count > 0) return `${p.error_count} problem${p.error_count === 1 ? "" : "s"} in the file. Nothing can be imported until they are fixed.`;
  const parts = [`${p.added} to add`, `${p.changed} to change`, `${p.removed} to remove`];
  if (p.added + p.changed + p.removed === 0) return `Nothing to do: all ${p.unchanged} rows are already in the directory.`;
  return parts.join(", ") + ".";
}

/** What the deletion guard will do with a plan's removals, in words; null when there is nothing to say. */
export function guardNote(p: ImportPlan): string | null {
  const g = p.guard;
  if (!g || g.removals === 0) return null;
  if (g.would_hold) {
    const why = g.reasons?.length ? ` (${g.reasons.join("; ")})` : g.limit != null ? ` (limit ${g.limit} in the window)` : "";
    return `The deletion guard will probably hold ${g.removals} removal${g.removals === 1 ? "" : "s"} for a second admin to approve${why}. Nothing is removed until then.`;
  }
  return `${g.removals} removal${g.removals === 1 ? "" : "s"} within the deletion guard's limit${g.limit != null ? ` of ${g.limit}` : ""}; the guard decides when you apply.`;
}

/** The toast after an apply or a form save. */
export function resultMessage(r: ImportResult, what: string): string {
  const p = r.plan;
  if (r.status === "held") return `${what}: ${p.added} added, ${p.changed} changed. All ${r.held} removals are held for approval.`;
  if (r.status === "partially_applied") return `${what}: ${r.message ?? "some removals are held for approval"}`;
  const bits = [p.added && `${p.added} added`, p.changed && `${p.changed} changed`, p.removed && `${p.removed} removed`].filter(Boolean);
  return `${what}: ${bits.length ? bits.join(", ") : "no changes"}`;
}

// ------------------------------------------------------------------ forms

/** The fields of each target's form. Key fields (email, account id, external id) are fixed once the object exists. */
export const FORM_FIELDS: Record<ImportTarget, FieldDef[]> = {
  people: [
    { id: "name", label: "Display name", required: true },
    { id: "email", label: "Email", required: true, hint: "Correlates the person's accounts. Fixed once created." },
    { id: "department", label: "Department" },
    { id: "title", label: "Job title" },
    { id: "manager_email", label: "Manager's email" },
    { id: "status", label: "Status", options: ["active", "terminated"] },
  ],
  accounts: [
    { id: "username", label: "Username", required: true },
    { id: "account_id", label: "Account id", hint: "The source's own id for the account. Defaults to the username. Fixed once created." },
    { id: "email", label: "Belongs to (email)", hint: "Matches the account to a person, as for a connector." },
    { id: "identity_id", label: "Belongs to (external id)" },
    { id: "status", label: "Status", options: ["active", "disabled"] },
  ],
  entitlements: [
    { id: "name", label: "Name", required: true },
    { id: "external_id", label: "External id", hint: "Defaults to the name. Fixed once created." },
    { id: "kind", label: "Kind", options: ["group", "role", "team", "security_group"] },
    { id: "privileged", label: "Privileged", options: ["no", "yes"] },
    { id: "description", label: "Description", textarea: true },
  ],
};

/** The field that names the object across edits. */
export const KEY_FIELD: Record<ImportTarget, string> = { people: "email", accounts: "account_id", entitlements: "external_id" };

/** What the API takes: trimmed values, empty ones left out, and the defaults the form promises. */
export function toRecordFields(target: ImportTarget, v: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of FORM_FIELDS[target]) {
    const x = (v[f.id] ?? "").trim();
    if (x) out[f.id] = x;
  }
  const key = KEY_FIELD[target];
  if (!out[key]) {
    const from = target === "accounts" ? out.username : target === "entitlements" ? out.name : undefined;
    if (from) out[key] = from;
  }
  if (target === "people" && out.email) out.email = out.email.toLowerCase();
  return out;
}

/** The form values of an existing object: the manual source's fields, or what the caller already knows. */
export function initialValues(target: ImportTarget, lookup: ManualLookup | null | undefined, known?: Record<string, string>): Record<string, string> {
  const src = lookup?.managed && lookup.fields ? lookup.fields : known ?? {};
  const out: Record<string, string> = {};
  for (const f of FORM_FIELDS[target]) {
    let x = src[f.id] ?? "";
    if (target === "entitlements" && f.id === "privileged" && (x === "true" || x === "false")) x = x === "true" ? "yes" : "no";
    out[f.id] = x;
  }
  return out;
}

export type FormMode = "create" | "edit" | "readonly" | "loading";

/**
 * Tessera creates and edits only objects a manual source owns. A new object is a create. An existing one is an
 * edit if a manual source owns it, else read-only: its source-owned fields are shown with "Managed by <system>".
 */
export function formMode(existing: boolean, lookup: ManualLookup | null | undefined): FormMode {
  if (!existing) return "create";
  if (!lookup) return "loading";
  return lookup.managed ? "edit" : "readonly";
}

/** "Managed by <system>" for a read-only object; the caller's fallback names the source when the server does not. */
export function managedBy(lookup: ManualLookup | null | undefined, fallback?: string): string {
  return lookup?.system || fallback || "its source system";
}

/** The kind of owner Tessera keeps for a read-only object, or null when it keeps none (people have a manager, not an owner). */
export function ownerKindFor(target: ImportTarget, human?: boolean): "group" | "identity" | null {
  if (target === "entitlements") return "group";
  if (target === "people" && human === false) return "identity";
  return null;
}
