// The deletion threshold guard, as the UI needs it: the words for a threshold, the form turned into the
// deletion_guard.update payload, and the notice shown after a delete the guard held part of. Pure functions,
// so `npm test` covers them. The server decides everything (limits, who may release); these only keep
// the form honest and the messages plain.
import type { DeletionCategory, DeletionHold, DeletionMode, DeletionPolicy, DeletionPolicyInput, HeldAnswer, HoldStatus } from "../../api";

export const CATEGORY_LABEL: Record<DeletionCategory, string> = {
  groups: "Groups",
  folders: "Folders",
  group_members: "Group memberships",
  accounts: "Accounts",
  identities: "Identities",
};

export const CATEGORY_HELP: Record<DeletionCategory, string> = {
  groups: "Deleting and permanently deleting groups, one by one, in bulk or with a folder tree.",
  folders: "Folders removed, including the folders of a tree delete.",
  group_members: "Members removed from groups by anyone: the UI, bulk actions, loaders, rules and reviews.",
  accounts: "Accounts a connector sync removes or disables, and provisioning remove and disable operations.",
  identities: "Identities disabled or ended as leavers.",
};

export const MODE_LABEL: Record<DeletionMode, string> = {
  hold_excess: "Apply up to the threshold, hold the rest",
  hold_all: "Hold the whole batch",
  off: "Off (no protection)",
};

export const HOLD_LABEL: Record<HoldStatus, string> = {
  held: "Waiting for approval",
  released: "Released",
  partially_released: "Partly released",
  discarded: "Discarded",
  expired: "Expired",
};

export const HOLD_TONE: Record<HoldStatus, "warning" | "ok" | "info" | "neutral"> = {
  held: "warning", released: "ok", partially_released: "info", discarded: "neutral", expired: "neutral",
};

export const SOURCE_LABEL: Record<string, string> = {
  user: "A person", loader: "A group loader", rule: "A group rule", connector: "A connector sync", provisioner: "A provisioner",
  lifecycle: "Lifecycle", system: "The system",
};

/** "per hour", "per 30 minutes", "per day". */
export function windowText(minutes: number): string {
  if (minutes === 60) return "per hour";
  if (minutes === 1440) return "per day";
  if (minutes % 1440 === 0) return `per ${minutes / 1440} days`;
  if (minutes % 60 === 0) return `per ${minutes / 60} hours`;
  return `per ${minutes} minutes`;
}

/** "25 per hour", "10% or 500 per hour (5 now)", "none". */
export function thresholdText(p: Pick<DeletionPolicy, "max_count" | "max_percent" | "window_minutes" | "mode" | "limit">): string {
  if (p.mode === "off") return "No limit";
  const parts: string[] = [];
  if (p.max_percent !== null) parts.push(`${p.max_percent}%`);
  if (p.max_count !== null) parts.push(`${p.max_count}`);
  const base = `${parts.join(" or ")} ${windowText(p.window_minutes)}`;
  return p.max_percent !== null && p.limit !== null ? `${base} (${p.limit} now)` : base;
}

/** How full the window is, 0 to 1 (1 when nothing is left). No limit is 0. */
export function usageRatio(p: Pick<DeletionPolicy, "used" | "limit">): number {
  if (p.limit === null) return 0;
  if (p.limit <= 0) return 1;
  return Math.min(1, p.used / p.limit);
}

export interface PolicyEdit { max_count: string; max_percent: string; window_minutes: string; mode: DeletionMode }

export const editOf = (p: DeletionPolicy): PolicyEdit => ({
  max_count: p.max_count === null ? "" : String(p.max_count),
  max_percent: p.max_percent === null ? "" : String(p.max_percent),
  window_minutes: String(p.window_minutes),
  mode: p.mode,
});

/** What is wrong with an edit, or null. */
export function checkEdit(e: PolicyEdit): string | null {
  const count = e.max_count.trim(), pct = e.max_percent.trim(), win = e.window_minutes.trim();
  if (!/^\d{1,5}$/.test(win) || Number(win) < 1 || Number(win) > 10080) return "The window is 1 to 10080 minutes (7 days).";
  if (e.mode === "off") return null;
  if (count === "" && pct === "") return "Set a count, a percent, or turn the category off.";
  if (count !== "" && (!/^\d{1,7}$/.test(count) || Number(count) > 10_000_000)) return "The count is a whole number, 0 or more.";
  if (pct !== "" && (!/^\d{1,3}(\.\d{1,2})?$/.test(pct) || Number(pct) > 100)) return "The percent is 0 to 100.";
  return null;
}

/** The payload entry of an edit; null when it equals the current policy or is not valid. */
export function inputOf(p: DeletionPolicy, e: PolicyEdit): DeletionPolicyInput | null {
  if (checkEdit(e)) return null;
  const off = e.mode === "off";
  const out: DeletionPolicyInput = {
    category: p.category,
    max_count: off || e.max_count.trim() === "" ? null : Number(e.max_count),
    max_percent: off || e.max_percent.trim() === "" ? null : Number(e.max_percent),
    window_minutes: Number(e.window_minutes),
    mode: e.mode,
  };
  // an off category keeps what it had, so turning it on again restores it
  if (off) { out.max_count = p.max_count; out.max_percent = p.max_percent; }
  const same = out.max_count === p.max_count && out.max_percent === p.max_percent && out.window_minutes === p.window_minutes && out.mode === p.mode;
  return same ? null : out;
}

const MODE_RANK: Record<DeletionMode, number> = { hold_all: 0, hold_excess: 1, off: 2 };

/**
 * Whether a change weakens the safety setting, as far as the form can tell: a weaker mode, or a higher limit
 * per minute of window. The server decides (it also knows the tenant's size); this only warns that a
 * second admin will probably be asked.
 */
export function looksLooser(p: DeletionPolicy, i: DeletionPolicyInput): boolean {
  if (MODE_RANK[i.mode] > MODE_RANK[p.mode]) return true;
  if (i.mode === "off") return false;
  const rate = (n: number | null, w: number) => (n === null ? Infinity : n / w);
  return rate(i.max_count, i.window_minutes) > rate(p.max_count, p.window_minutes) || rate(i.max_percent, i.window_minutes) > rate(p.max_percent, p.window_minutes);
}

/** "Deleted 25 of 40: 15 held for approval (threshold 25 per hour)" from the 202 body. */
export const heldMessage = (h: Pick<HeldAnswer, "message">) => h.message;

/** True for the answer of a delete the guard held part of. */
export const isHeld = (r: unknown): r is HeldAnswer => !!r && typeof r === "object" && typeof (r as HeldAnswer).hold_id === "string" && (r as HeldAnswer).held > 0;

/** The notice after a bulk action: how many were applied and held across its calls, and the hold to open. */
export function bulkHeldNotice(answers: unknown[], attempted: number): { text: string; holdId: string } | null {
  const held = answers.filter(isHeld);
  if (held.length === 0) return null;
  const heldN = held.reduce((n, h) => n + h.held, 0);
  const last = held[held.length - 1];
  return { holdId: last.hold_id, text: `Deleted ${attempted - heldN} of ${attempted}: ${heldN} held for approval (threshold ${last.threshold})` };
}

/** One line for the list: what was held and from where. */
export function holdTitle(h: Pick<DeletionHold, "category" | "item_count" | "source" | "source_id">): string {
  const what = `${h.item_count} ${CATEGORY_LABEL[h.category].toLowerCase()}`;
  const from = SOURCE_LABEL[h.source] ?? h.source;
  return h.source_id ? `${what} from ${from.toLowerCase()} ${h.source_id}` : `${what} from ${from.toLowerCase()}`;
}
