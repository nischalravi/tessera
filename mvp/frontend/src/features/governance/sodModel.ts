/**
 * View logic for SoD functions, risks and rulesets (issue #298): wording of selectors,
 * editor validation, ordering and the warning shown before an access request is submitted.
 * Pure functions; `npm test` covers them.
 */
import type { SodAttribute, SodMitigation, SodPriority, SodRemediation, SodSelector, SodSimulation, SodSubjects, SodViolation } from "../../api";

export const PRIORITIES: SodPriority[] = ["critical", "high", "medium", "low"];
export const priorityRank = (p: string) => PRIORITIES.length - PRIORITIES.indexOf(p as SodPriority);
export const ATTRIBUTES: { value: SodAttribute; label: string; hint: string }[] = [
  { value: "environment", label: "Environment", hint: "prod, staging, dev" },
  { value: "tag", label: "Resource tag", hint: "pii, payments" },
  { value: "resource", label: "Resource name", hint: "a name or pattern" },
  { value: "privileged", label: "Privileged", hint: "true or false" },
];

/** A selector in words: `workday: payments:approve where environment = prod`. */
export function describeSelector(s: SodSelector): string {
  const what = s.entitlement_id !== undefined ? `entitlement #${s.entitlement_id}` : s.name_pattern ?? "";
  const where = s.attribute ? ` where ${s.attribute} = ${s.value}` : "";
  return `${s.system || "any system"}: ${what}${where}`;
}

/** Why a selector cannot be saved, or null. Mirrors the server's checks. */
export function selectorError(s: SodSelector): string | null {
  if ((s.entitlement_id === undefined) === !s.name_pattern) return "Give an action name pattern or an entitlement id, not both";
  if (s.entitlement_id !== undefined && !s.system) return "An entitlement id needs its system";
  if (!!s.attribute !== !!s.value) return "An attribute needs a value, and a value needs an attribute";
  if (s.attribute === "privileged" && s.value !== "true" && s.value !== "false") return "Privileged is true or false";
  return null;
}

/** Drops empty fields so the request body matches what the server stores. */
export function cleanSelector(s: SodSelector): SodSelector {
  const out: SodSelector = {};
  if (s.system?.trim()) out.system = s.system.trim();
  if (s.entitlement_id !== undefined && Number.isFinite(s.entitlement_id)) out.entitlement_id = s.entitlement_id;
  if (s.name_pattern?.trim()) out.name_pattern = s.name_pattern.trim();
  if (s.attribute && s.value?.trim()) {
    out.attribute = s.attribute;
    out.value = s.value.trim();
  }
  return out;
}

/** The first problem with a risk draft, or null. */
export function riskError(d: { name: string; ruleset_id: string; function_ids: string[] }): string | null {
  if (!d.name.trim()) return "Name the risk";
  if (!d.ruleset_id) return "Choose a ruleset";
  if (d.function_ids.length < 2) return "A risk needs at least two conflicting functions";
  if (new Set(d.function_ids).size !== d.function_ids.length) return "A function cannot conflict with itself";
  return null;
}

/** Who a risk checks, in words. */
export function describeSubjects(s: SodSubjects | null | undefined): string {
  const types = s?.identity_types?.length ? s.identity_types.join(", ") : "every identity type";
  const status = s?.statuses?.length ? s.statuses.join(", ") : "active";
  return `${types} (${status})${s?.condition ? ", narrowed by a condition" : ""}`;
}

/** Most severe first, then by risk and person: the order of the conflicts list. */
export function sortViolations(vs: SodViolation[]): SodViolation[] {
  return [...vs].sort((a, b) => priorityRank(b.priority) - priorityRank(a.priority) || a.risk_name.localeCompare(b.risk_name) || a.identity_name.localeCompare(b.identity_name));
}

/** Distinct sorted option values for a filter chip. */
export function distinct<T>(rows: T[], get: (r: T) => string | string[]): string[] {
  const out = new Set<string>();
  for (const r of rows) for (const v of [get(r)].flat()) if (v) out.add(v);
  return [...out].sort((a, b) => a.localeCompare(b));
}

export const statusLabel = (s: string) => (s === "open" ? "Open" : s === "mitigation_pending" ? "Mitigation requested" : s.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()));

/** The warning for the access request form: null when nothing conflicts. */
export function sodWarning(sim: SodSimulation | null): { tone: "bad" | "warn"; title: string; lines: string[] } | null {
  if (!sim || sim.would_trigger.length === 0) return null;
  const n = sim.would_trigger.length;
  const risks = new Set(sim.would_trigger.map((t) => t.risk_key)).size;
  const top = sim.highest_priority;
  return {
    tone: top === "critical" || top === "high" ? "bad" : "warn",
    title: `This request would create ${n} separation-of-duties conflict${n === 1 ? "" : "s"} (${risks} risk${risks === 1 ? "" : "s"}${top ? `, highest ${top}` : ""})`,
    lines: sim.would_trigger.map((t) => `${t.identity_name}: ${t.risk_name} (${t.priority}). ${t.function1.name} and ${t.function2.name}`),
  };
}

// ------------------------------------------------------------ mitigations and remediation (issue #298)


export const REMEDIATION: { id: SodRemediation; label: string; hint: string }[] = [
  { id: "revoke", label: "Revoke access", hint: "Remove a grant behind the violation, through the revoke path" },
  { id: "mitigate", label: "Mitigate with a control", hint: "Cover it with a control from the library until an end date" },
  { id: "accept", label: "Accept until a date", hint: "Accept the risk until an end date" },
  { id: "escalate", label: "Escalate to the risk owner", hint: "Ask the owner of the risk to decide" },
];

/** True when the violation's risk offers the option (the server enforces the same). */
export const offers = (v: { remediation?: SodRemediation[] }, option: SodRemediation) => !v.remediation || v.remediation.includes(option);

/** Covered violations leave the open counts but stay in reports. */
export const isOpen = (status: string) => status !== "mitigated" && status !== "accepted";
export const openCount = (vs: { status: string }[]) => vs.filter((v) => isOpen(v.status)).length;

const DAY = 24 * 60 * 60 * 1000;
const day = (d: Date) => d.toISOString().slice(0, 10);

/** The latest end day a request may name (the server's limit, counted from now). */
export const latestEndDay = (now: Date, maxDays: number) => day(new Date(now.getTime() + maxDays * DAY));
/** A sensible default end day: 90 days, or the limit if that is sooner. */
export const defaultEndDay = (now: Date, maxDays: number) => day(new Date(now.getTime() + Math.min(90, maxDays) * DAY));

/** Why an end day cannot be used, or null. The end date is mandatory. */
export function endDayError(value: string, now: Date, maxDays: number): string | null {
  if (!value) return "An end date is required";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || Number.isNaN(Date.parse(value))) return "Use a date such as 2026-12-31";
  if (value <= day(now)) return "The end date must be in the future";
  if (value > latestEndDay(now, maxDays)) return `A mitigation can last at most ${maxDays} days (until ${latestEndDay(now, maxDays)})`;
  return null;
}

export function daysLeftLabel(days: number | null): string {
  if (days === null) return "";
  if (days < 0) return "ended";
  if (days === 0) return "ends today";
  return days === 1 ? "1 day left" : `${days} days left`;
}

/** An active mitigation inside the warning window. */
export const expiringSoon = (m: Pick<SodMitigation, "status" | "days_left">, warnDays: number) =>
  m.status === "active" && m.days_left !== null && m.days_left <= warnDays;

/** The second person decides; never the requester (the server refuses it too). */
export const canDecide = (m: Pick<SodMitigation, "status" | "requested_by_me">, canApprove: boolean) => canApprove && m.status === "pending" && !m.requested_by_me;

export const mitigationStatusLabel = (m: Pick<SodMitigation, "status" | "kind">) =>
  m.status === "active" ? (m.kind === "accept" ? "Accepted" : "Mitigated") : m.status === "pending" ? "Awaiting approval" : m.status[0].toUpperCase() + m.status.slice(1);

/** Evidence references typed one per line. */
export const parseEvidence = (text: string) => text.split("\n").map((l) => l.trim()).filter(Boolean);
