// Organization settings (issue #298): the policy form's model. The server validates; these keep the form honest.
import type { OrgPolicies } from "../../api";

export const STAGES: { id: "manager" | "owner" | "decider"; label: string }[] = [
  { id: "manager", label: "The beneficiary's manager" },
  { id: "owner", label: "The item's owner" },
  { id: "decider", label: "A decider (anyone who can decide requests)" },
];

export interface PolicyDraft {
  stages: ("manager" | "owner" | "decider")[];
  escalate: string;
  requireJustification: boolean;
  minLength: string;
  defaultHours: string;
  maxHours: string;
}

const text = (n: number | null) => (n === null ? "" : String(n));

export function draftPolicies(p: OrgPolicies): PolicyDraft {
  return {
    stages: p.default_stages ?? [], escalate: text(p.default_escalate_hours), requireJustification: p.justification_required === true,
    minLength: text(p.justification_min_length), defaultHours: text(p.default_hours), maxHours: text(p.max_hours),
  };
}

const num = (s: string): number | null | "invalid" => {
  if (!s.trim()) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : "invalid";
};

/** The policies a draft describes, or the first problem. */
export function policiesOf(d: PolicyDraft): { policies: OrgPolicies; problem: string | null } {
  const esc = num(d.escalate);
  const min = num(d.minLength);
  const def = num(d.defaultHours);
  const max = num(d.maxHours);
  const policies: OrgPolicies = {
    default_stages: d.stages.length ? d.stages : null,
    default_escalate_hours: d.stages.length && typeof esc === "number" ? esc : null,
    justification_required: d.requireJustification ? true : null,
    justification_min_length: typeof min === "number" ? min : null,
    default_hours: typeof def === "number" ? def : null,
    max_hours: typeof max === "number" ? max : null,
  };
  return { policies, problem: orgPoliciesProblem({ esc, min, def, max }) };
}

function orgPoliciesProblem(v: { esc: number | null | "invalid"; min: number | null | "invalid"; def: number | null | "invalid"; max: number | null | "invalid" }): string | null {
  if (v.esc === "invalid" || (typeof v.esc === "number" && !(v.esc > 0 && v.esc <= 720))) return "Escalation is after 0 to 720 hours.";
  if (v.min === "invalid" || (typeof v.min === "number" && !(Number.isInteger(v.min) && v.min >= 1 && v.min <= 1000))) return "The minimum justification is 1 to 1000 characters.";
  for (const [label, h] of [["default", v.def], ["maximum", v.max]] as const) {
    if (h === "invalid" || (typeof h === "number" && !(h > 0 && h <= 8760))) return `The ${label} duration is between 0 and 8760 hours.`;
  }
  if (typeof v.def === "number" && typeof v.max === "number" && v.def > v.max) return "The default duration cannot exceed the maximum.";
  return null;
}

export function samePolicies(a: OrgPolicies, b: OrgPolicies): boolean {
  return JSON.stringify([a.default_stages, a.default_escalate_hours, a.justification_required, a.justification_min_length, a.default_hours, a.max_hours]) ===
    JSON.stringify([b.default_stages, b.default_escalate_hours, b.justification_required, b.justification_min_length, b.default_hours, b.max_hours]);
}
