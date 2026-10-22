/**
 * Pure helpers of the Directory → Groups screens (no React, no fetch), so `npm test` can check them:
 * the folder tree, dates, the change preview text, the history diff, the application template.
 * Types come from `src/api.ts`; nothing here decides access (the server does, per request).
 */
import type { GrpFolder, GrpGroup, GrpPrivGrant, PitMember, SimChange, SimulationResult, BatchAdd } from "../../../api";

// ------------------------------------------------------------ names

/** A name segment: 1 to 255 characters from [A-Za-z0-9_.-] and not "." or ".." (server: internal/groups/naming). */
export function extensionProblem(ext: string): string | null {
  if (!ext) return "Enter a name.";
  if (ext.length > 255) return "At most 255 characters.";
  if (ext === "." || ext === "..") return `A name cannot be "${ext}".`;
  const bad = [...ext].find((c) => !/[A-Za-z0-9_.-]/.test(c));
  return bad ? `"${bad}" is not allowed: use letters, digits, "_", "-" and ".".` : null;
}

// ------------------------------------------------------------ folder tree

export interface FolderIndex {
  byId: Map<string, GrpFolder>;
  /** Children by parent id; folders whose parent the caller cannot see (or the root's children) are under "". */
  children: Map<string, GrpFolder[]>;
  /** The folders to start from: the root's children when the caller sees the root, else every folder it sees with no visible parent. */
  tops: GrpFolder[];
  /** The tenant root folder (empty name), when visible. */
  root: GrpFolder | null;
}

const byName = (a: GrpFolder, b: GrpFolder) => a.name.localeCompare(b.name);

/** Index the folders the caller may view. A folder whose parent is hidden is treated as a top-level one. */
export function indexFolders(folders: GrpFolder[]): FolderIndex {
  const byId = new Map(folders.map((f) => [f.id, f]));
  const children = new Map<string, GrpFolder[]>();
  let root: GrpFolder | null = null;
  for (const f of folders) {
    if (f.parent_id === null && f.name === "") {
      root = f;
      continue;
    }
    const key = f.parent_id && byId.has(f.parent_id) ? f.parent_id : "";
    children.set(key, [...(children.get(key) ?? []), f]);
  }
  for (const list of children.values()) list.sort(byName);
  const tops = root ? (children.get(root.id) ?? []) : (children.get("") ?? []);
  return { byId, children, tops, root };
}

/** The folders to list under `id` (the top level when `id` is null). */
export function childFolders(ix: FolderIndex, id: string | null): GrpFolder[] {
  if (id === null || id === ix.root?.id) return ix.tops;
  return ix.children.get(id) ?? [];
}

/** The path from the top to `id`, root excluded: the breadcrumb. */
export function folderTrail(ix: FolderIndex, id: string | null): GrpFolder[] {
  const out: GrpFolder[] = [];
  const seen = new Set<string>();
  let cur = id ? ix.byId.get(id) : undefined;
  while (cur && !seen.has(cur.id) && cur.id !== ix.root?.id) {
    seen.add(cur.id);
    out.unshift(cur);
    cur = cur.parent_id ? ix.byId.get(cur.parent_id) : undefined;
  }
  return out;
}

/** What a folder shows as its name: the display name, else the last segment. */
export const folderLabel = (f: Pick<GrpFolder, "display_extension" | "extension">) => f.display_extension || f.extension;

/** The identity id in what a person typed or picked: "Alice Chen (#12)", "#12" or "12". */
export function parseIdentityRef(text: string): number | null {
  const m = /(?:#|^)(\d+)\)?\s*$/.exec(text.trim());
  const id = m ? Number(m[1]) : NaN;
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

// ------------------------------------------------------------ dates

/** A `datetime-local` value ("2026-10-16T09:30") as an RFC 3339 instant, or undefined when empty or unreadable. */
export function toInstant(local: string): string | undefined {
  if (!local) return undefined;
  const t = new Date(local);
  return Number.isNaN(t.getTime()) ? undefined : t.toISOString();
}

/** A complaint about the pair of dates of a membership, or null. */
export function datesProblem(from: string, to: string): string | null {
  if (from && toInstant(from) === undefined) return "The start date is not a date.";
  if (to && toInstant(to) === undefined) return "The end date is not a date.";
  const a = toInstant(from);
  const b = toInstant(to);
  if (a && b && Date.parse(b) <= Date.parse(a)) return "The end date must be after the start date.";
  return null;
}

/** An instant in the future is refused by the history API, so the picker clamps to now. */
export const isFuture = (local: string, now = Date.now()) => {
  const i = toInstant(local);
  return !!i && Date.parse(i) > now;
};

// ------------------------------------------------------------ change preview

export interface SimSummary {
  /** "+1,204 / −13 identities in 4 groups" */
  headline: string;
  added: number;
  removed: number;
  /** Groups whose effective membership changes, the ones the change names first. */
  groups: { id: string; name: string; targeted: boolean; before: number; after: number; added: number; removed: number; delta: string }[];
  /** True when nothing changes: the save has no effect on who is a member. */
  noEffect: boolean;
  truncated: boolean;
}

const n = (x: number) => x.toLocaleString("en-US");
export const signed = (x: number) => (x > 0 ? `+${n(x)}` : x < 0 ? `−${n(-x)}` : "0");

/** Turn a simulation answer into what the preview dialog shows. */
export function summarizeSimulation(r: SimulationResult): SimSummary {
  const changed = r.groups.filter((g) => g.added > 0 || g.removed > 0 || g.targeted);
  changed.sort((a, b) => Number(b.targeted) - Number(a.targeted) || a.name.localeCompare(b.name));
  const affected = r.groups.filter((g) => g.added > 0 || g.removed > 0).length;
  const noun = affected === 1 ? "group" : "groups";
  const lower = r.truncated ? "at least " : "";
  return {
    headline: `${lower}+${n(r.added)} / −${n(r.removed)} identities in ${affected} ${noun}`,
    added: r.added,
    removed: r.removed,
    groups: changed.map((g) => ({ id: g.group_id, name: g.name, targeted: g.targeted, before: g.before, after: g.after, added: g.added, removed: g.removed, delta: signed(g.after - g.before) })),
    noEffect: r.added === 0 && r.removed === 0,
    truncated: r.truncated,
  };
}

/** The simulation request for adding members to one group (the preview of an add). */
export function addChanges(group: string, adds: BatchAdd[]): SimChange[] {
  return adds.map((a) => ({
    kind: "add_member", group, identity: a.identity, member_group: a.group,
    enabled_from: a.enabled_from, disabled_at: a.disabled_at, reason: a.reason,
  }));
}

/** The simulation request for removing members from one group. `member` is an identity id or a group id. */
export const removeChanges = (group: string, members: string[]): SimChange[] => members.map((m) => ({ kind: "remove_member", group, member: m }));

/** The simulation request for a composite definition. */
export const compositeChange = (group: string, op: string, factors: string[], convert: boolean, discard = false): SimChange =>
  convert ? { kind: "convert_to_composite", group, op, factors, discard_members: discard } : { kind: "set_composite", group, op, factors };

// ------------------------------------------------------------ trace

/** One path of a member trace as a line: "app:foo:policy:user › app:foo:allow". */
export function traceLine(steps: { name: string; via: string; op?: string }[]): string {
  return steps.map((s, i) => (i === 0 ? s.name : `${s.name}${s.via === "factor" ? ` (${s.op ?? "factor"})` : ""}`)).join(" › ");
}

export const VIA_LABEL: Record<string, string> = { start: "this group", nested: "nested group", factor: "composite factor" };

// ------------------------------------------------------------ history

export interface MemberDiff { added: PitMember[]; removed: PitMember[]; kept: number }

const memberKey = (m: PitMember) => (m.identity_id !== undefined ? `i${m.identity_id}` : `g${m.group_id}`);

/** Who joined and who left between two points in time (`before`, `after`: the as-of answers). */
export function diffMembers(before: PitMember[], after: PitMember[]): MemberDiff {
  const a = new Set(before.map(memberKey));
  const b = new Set(after.map(memberKey));
  return {
    added: after.filter((m) => !a.has(memberKey(m))),
    removed: before.filter((m) => !b.has(memberKey(m))),
    kept: after.filter((m) => a.has(memberKey(m))).length,
  };
}

// ------------------------------------------------------------ composites

/** A complaint about a composite definition before it is sent: union and intersection take two or more distinct factors, complement exactly two. */
export function compositeProblem(op: string, factors: string[], self: string): string | null {
  const ids = factors.filter(Boolean);
  if (ids.length !== factors.length) return "Choose a group for every factor.";
  if (ids.includes(self)) return "A group cannot be a factor of itself.";
  if (new Set(ids).size !== ids.length) return "Each factor can appear once.";
  if (op === "complement") return ids.length === 2 ? null : "A complement is the first group minus one other group.";
  if (op === "union" || op === "intersection") return ids.length >= 2 ? null : "Choose at least two groups.";
  return "Choose how the groups combine.";
}

/** The set expression of a composite as text: "A ∪ B", "A ∩ B", "A − B". */
export function compositeExpression(op: string | null, names: string[]): string {
  const sym = op === "union" ? " ∪ " : op === "intersection" ? " ∩ " : " − ";
  return names.join(sym);
}

// ------------------------------------------------------------ privileges

export const GROUP_PRIVS = ["admin", "update", "read", "view", "optin", "optout", "group_attr_read", "group_attr_update"];
export const FOLDER_PRIVS = ["stem_admin", "create", "stem_attr_read", "stem_attr_update", "stem_view"];
export const ATTR_DEF_PRIVS = ["attr_admin", "attr_update", "attr_read", "attr_view", "attr_optin", "attr_optout", "attr_def_attr_read", "attr_def_attr_update"];

/** The privileges one can grant on a group or folder, or inherited by what a folder contains (`appliesTo`). */
export function privilegesFor(kind: "group" | "folder", appliesTo: string): string[] {
  if (kind === "group") return GROUP_PRIVS;
  switch (appliesTo) {
    case "groups": return GROUP_PRIVS;
    case "folders": return FOLDER_PRIVS;
    case "attr_defs": return ATTR_DEF_PRIVS;
    default: return FOLDER_PRIVS;
  }
}

/** The grant body from the form, with the server's rules checked early so the form can say what is wrong. */
export function grantBody(kind: "group" | "folder", f: { privilege: string; holder: "identity" | "group" | "everyone"; identity: string; group: string; appliesTo: string; scope: string }): { body?: GrpPrivGrant; problem?: string } {
  if (!f.privilege) return { problem: "Choose a privilege." };
  if (kind === "group" && f.appliesTo !== "self") return { problem: "Only a folder's privileges are inherited." };
  const body: GrpPrivGrant = { privilege: f.privilege, holder_type: f.holder };
  if (f.holder === "identity") {
    const id = Number(f.identity);
    if (!Number.isInteger(id) || id < 1) return { problem: "Choose a person." };
    body.identity = id;
  } else if (f.holder === "group") {
    if (!f.group) return { problem: "Choose a group." };
    body.group = f.group;
  }
  if (f.appliesTo !== "self") {
    body.applies_to = f.appliesTo;
    body.scope = f.scope === "one" ? "one" : "sub";
  }
  return { body };
}

// ------------------------------------------------------------ attributes

/** A typed attribute value from text: integers are integers, floats stay decimal strings (the server's rule), timestamps RFC 3339. */
export function parseAttrValue(valueType: string, raw: string): { value?: string | number; problem?: string } {
  const v = raw.trim();
  switch (valueType) {
    case "integer":
      return /^-?\d+$/.test(v) && Number.isSafeInteger(Number(v)) ? { value: Number(v) } : { problem: "Enter a whole number." };
    case "floating":
      return /^-?\d+(\.\d+)?$/.test(v) ? { value: v } : { problem: "Enter a decimal number such as 12.5." };
    case "timestamp": {
      const t = Date.parse(v);
      return Number.isNaN(t) ? { problem: "Enter a date and time." } : { value: new Date(t).toISOString() };
    }
    case "member_id":
      return /^\d+$/.test(v) && Number(v) > 0 ? { value: Number(v) } : { problem: "Enter an identity id." };
    default:
      return v ? { value: v } : { problem: "Enter a value." };
  }
}

// ------------------------------------------------------------ bulk import

export interface ParsedMembers { adds: BatchAdd[]; problems: string[] }

/** Rows of a CSV with the columns `identity` (an identity id) or `group` (a group id), and optionally `enabled_from`, `disabled_at`, `reason`. */
export function parseMemberRows(rows: Record<string, string>[]): ParsedMembers {
  const adds: BatchAdd[] = [];
  const problems: string[] = [];
  rows.forEach((r, i) => {
    const line = i + 2; // the header is line 1
    const id = (r.identity ?? "").trim();
    const g = (r.group ?? "").trim();
    if ((id === "") === (g === "")) return void problems.push(`Line ${line}: give either identity or group.`);
    const a: BatchAdd = {};
    if (id) {
      const num = Number(id);
      if (!Number.isInteger(num) || num < 1) return void problems.push(`Line ${line}: identity must be an identity id.`);
      a.identity = num;
    } else a.group = g;
    const dp = datesProblem(r.enabled_from ?? "", r.disabled_at ?? "");
    if (dp) return void problems.push(`Line ${line}: ${dp}`);
    const from = toInstant(r.enabled_from ?? "");
    const to = toInstant(r.disabled_at ?? "");
    if (from) a.enabled_from = from;
    if (to) a.disabled_at = to;
    if (r.reason?.trim()) a.reason = r.reason.trim();
    adds.push(a);
  });
  if (adds.length > 1000) problems.push("A batch has at most 1,000 members: split the file.");
  return { adds, problems };
}

// ------------------------------------------------------------ new application template (G-06)

export interface TemplateStep {
  /** folder or group */
  kind: "folder" | "group";
  /** Full name, `:` separated, under the parent folder the user chose. */
  path: string;
  /** Object types to set on it (best effort: the vocabulary of GET /api/groups/object-types). */
  types?: string[];
  description?: string;
  /** Composite groups name their operator and the full names of their factors (created earlier in the plan). */
  composite?: { op: "union" | "complement"; factors: string[] };
}

/**
 * The Deployment Guide's standard layout for an application (design §3.15, G-06): the folder, a security
 * folder with the admin group, and a service folder with a reference group, the allow, allow-manual and
 * deny groups, and the policy group `allow − deny`. Every step comes after the ones it depends on.
 */
export function applicationTemplate(app: string): TemplateStep[] {
  const a = app;
  return [
    { kind: "folder", path: a, types: ["app"], description: `The ${a} application` },
    { kind: "folder", path: `${a}:security`, types: ["security"] },
    { kind: "group", path: `${a}:security:${a}Admin`, description: `Administrators of ${a}` },
    { kind: "folder", path: `${a}:service`, types: ["service"] },
    { kind: "folder", path: `${a}:service:ref` },
    { kind: "group", path: `${a}:service:ref:${a}_ref_allowed`, types: ["ref"], description: `Cohorts allowed to use ${a}` },
    { kind: "folder", path: `${a}:service:policy` },
    { kind: "group", path: `${a}:service:policy:${a}_user_allow_manual`, types: ["manual"], description: "Exceptions: people allowed by hand" },
    { kind: "group", path: `${a}:service:policy:${a}_user_deny`, types: ["policy"], description: "People refused access" },
    {
      kind: "group", path: `${a}:service:policy:${a}_user_allow`, types: ["intermediate"], description: "Allowed by cohort or by exception",
      composite: { op: "union", factors: [`${a}:service:ref:${a}_ref_allowed`, `${a}:service:policy:${a}_user_allow_manual`] },
    },
    {
      kind: "group", path: `${a}:service:policy:${a}_user`, types: ["policy"], description: `Access policy for ${a}: allow minus deny`,
      composite: { op: "complement", factors: [`${a}:service:policy:${a}_user_allow`, `${a}:service:policy:${a}_user_deny`] },
    },
  ];
}

/** The parent path and last segment of a full name. */
export function splitPath(path: string): { parent: string; extension: string } {
  const i = path.lastIndexOf(":");
  return i < 0 ? { parent: "", extension: path } : { parent: path.slice(0, i), extension: path.slice(i + 1) };
}

/** Join a base folder name and a relative path ("" is the root). */
export const joinPath = (base: string, rel: string) => (base ? `${base}:${rel}` : rel);

/** A random idempotency key (1 to 255 of A-Za-z0-9._~:+=-): a retried batch replays instead of applying twice. */
export function idempotencyKey(): string {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (c?.randomUUID) return c.randomUUID();
  return `k${Date.now().toString(36)}${Math.random().toString(36).slice(2, 12)}`;
}

// ------------------------------------------------------------ deleting from the list

export interface DeletePlan {
  /** Soft-deleted first (restorable). */
  groups: GrpGroup[];
  /** Deepest first, so a child goes before its parent when both are picked. */
  folders: GrpFolder[];
  /** Picked but not managed from the UI (or a group that is already deleted): left alone. */
  skipped: string[];
}

/** Sort a selection into what can be deleted here and in which order. */
export function planDelete(picked: ({ kind: "folder"; f: GrpFolder } | { kind: "group"; g: GrpGroup })[]): DeletePlan {
  const plan: DeletePlan = { groups: [], folders: [], skipped: [] };
  for (const r of picked) {
    if (r.kind === "folder") {
      if (r.f.managed_by === "ui" && r.f.name !== "") plan.folders.push(r.f);
      else plan.skipped.push(r.f.name);
    }
    else if (r.g.managed_by === "ui" && r.g.status !== "deleted") plan.groups.push(r.g);
    else plan.skipped.push(r.g.name);
  }
  const depth = (f: GrpFolder) => f.name.split(":").length;
  plan.folders.sort((a, b) => depth(b) - depth(a) || a.name.localeCompare(b.name));
  return plan;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "Delete 1 folder and 2 groups?" */
export function deleteTitle(p: Pick<DeletePlan, "groups" | "folders">): string {
  const parts = [p.folders.length && plural(p.folders.length, "folder"), p.groups.length && plural(p.groups.length, "group")].filter(Boolean);
  return `Delete ${parts.join(" and ")}?`;
}

/** The rules shown in the confirm dialog, for what is being deleted. */
export function deleteBody(p: Pick<DeletePlan, "groups" | "folders" | "skipped">): string {
  const rules = [
    p.folders.length ? "Only an empty folder can be deleted; a folder that still holds something is left in place." : "",
    p.groups.length ? "A deleted group stops counting its members and can be restored afterwards." : "",
    p.skipped.length ? `${plural(p.skipped.length, "item")} managed elsewhere will be skipped.` : "",
  ];
  return rules.filter(Boolean).join(" ");
}

/** One toast line for the failures, e.g. "TEST: folder is not empty; G: not found". */
export function failureSummary(failed: { name: string; message: string }[]): string {
  return failed.map((f) => `${f.name}: ${f.message}`).join("; ");
}
