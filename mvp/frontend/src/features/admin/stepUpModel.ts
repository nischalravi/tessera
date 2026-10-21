// Step-up per action (issue #298): the page's model. The server decides; these keep the form honest.
import type { StepUpAction, StepUpPolicyView, StepUpRequirement } from "../../api";

/** The assurance levels weakest first, as the server names them (suffix of the ACR URN). */
const RANK = ["aal1", "aal2", "phr", "phrh"];
const LABEL: Record<string, string> = {
  aal2: "Multi-factor sign-in",
  phr: "Phishing-resistant sign-in",
  phrh: "Device-bound security key",
};

const level = (acr: string) => acr.split(":").pop() ?? acr;
export const rank = (acr: string) => RANK.indexOf(level(acr));
export const acrLabel = (acr: string) => LABEL[level(acr)] ?? acr;

export function ageText(seconds: number): string {
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}

export function requirementText(r: StepUpRequirement | null): string {
  return r ? `${acrLabel(r.acr)}, within ${ageText(r.max_age_s)}` : "None";
}

/** One row of the editor: an empty level means no entry. */
export interface Draft { acr: string; minutes: string }
export type Drafts = Record<string, Draft>;

export function draftsOf(v: StepUpPolicyView): Drafts {
  const out: Drafts = {};
  for (const a of v.actions) out[a.action] = a.policy ? { acr: a.policy.acr, minutes: String(a.policy.max_age_s / 60) } : { acr: "", minutes: "" };
  return out;
}

/** The entries the drafts describe, or the first problem. */
export function entriesOf(v: StepUpPolicyView, d: Drafts): { entries: Record<string, StepUpRequirement>; problem: string | null } {
  const entries: Record<string, StepUpRequirement> = {};
  for (const a of v.actions) {
    const row = d[a.action];
    if (!row || !row.acr) continue;
    const minutes = Number(row.minutes);
    const seconds = Math.round(minutes * 60);
    if (!row.minutes.trim() || !Number.isFinite(minutes) || seconds < v.min_max_age_s || seconds > v.max_max_age_s) {
      return { entries, problem: `${a.action}: the sign-in may be ${v.min_max_age_s / 60} to ${v.max_max_age_s / 60} minutes old` };
    }
    const entry = { acr: row.acr, max_age_s: seconds };
    const weak = weakerThanFloor(a, entry);
    if (weak && !v.allow_weaker) return { entries, problem: `${a.action} already requires ${requirementText(a.floor)}; a setting can add step-up or tighten it, not weaken it` };
    entries[a.action] = entry;
  }
  return { entries, problem: null };
}

/** True when an entry is below what the code requires of an action (an action with an unguarded route may add below it). */
export function weakerThanFloor(a: StepUpAction, e: StepUpRequirement): boolean {
  if (!a.floor || a.unguarded) return false;
  return rank(e.acr) < rank(a.floor.acr) || e.max_age_s > a.floor.max_age_s;
}

export function sameEntries(a: Record<string, StepUpRequirement>, b: Record<string, StepUpRequirement>): boolean {
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && a[k].acr === b[k].acr && a[k].max_age_s === b[k].max_age_s);
}

export function savedEntries(v: StepUpPolicyView): Record<string, StepUpRequirement> {
  const out: Record<string, StepUpRequirement> = {};
  for (const a of v.actions) if (a.policy) out[a.action] = a.policy;
  return out;
}
