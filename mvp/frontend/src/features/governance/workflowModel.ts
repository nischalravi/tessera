/**
 * View logic for the workflow designer (issue #298): blank steps, canonical steps, editing the
 * ordered list, and the cheap checks that spare a round trip. The server validates every
 * definition (internal/workflow: ids, references, cycles, reachability, four eyes), so these only
 * mirror what a form can know on its own. Pure functions; `npm test` covers them.
 */
import type { WorkflowScope, WorkflowStep, WorkflowStepType, WorkflowTarget } from "../../api";

export const END = "end";

export const STEP_TYPES: { id: WorkflowStepType; label: string; hint: string }[] = [
  { id: "approval", label: "Approval", hint: "Someone approves before the request moves on" },
  { id: "questionnaire", label: "Questionnaire", hint: "The requester answers a questionnaire when filing" },
  { id: "notify", label: "Notify", hint: "Tell the requester, the beneficiary, the owner or a group" },
  { id: "wait", label: "Wait", hint: "Hold the next approval for some hours before it opens" },
  { id: "condition", label: "Condition", hint: "Branch on the request's risk, item, requester's organization…" },
  { id: "provisioning", label: "Provisioning", hint: "Push the grant to the target system once approved" },
];

export const stepTypeLabel = (t: string): string => STEP_TYPES.find((x) => x.id === t)?.label ?? t;

export const APPROVER_LABEL: Record<string, string> = {
  manager: "Manager", owner: "Owner of the item", group: "A named group", decider: "Access approver (requests.decide)",
  old_owner: "Current owner of the account", new_owner: "New owner of the account",
};
export const NOTIFY_LABEL: Record<string, string> = { requester: "The requester", beneficiary: "The beneficiary (the new owner)", owner: "The owner", group: "A named group" };
export const ATTRIBUTE_LABEL: Record<string, string> = {
  risk: "Risk of the item", item: "Catalog item", privileged: "Privileged item", system: "Application", requester_org: "Requester's organization",
  beneficiary_org: "Beneficiary's organization", kind: "Kind of request", owner_org: "New owner's organization",
};
export const OP_LABEL: Record<string, string> = { eq: "is", ne: "is not", in: "is one of", not_in: "is none of" };
export const REQUEST_TYPE_LABEL: Record<string, string> = {
  access: "Every access request (items without their own workflow)", service_account_create: "Create a service account",
  service_account_change: "Change a service account", service_account_transfer: "Transfer a service account",
};
/** The values a condition on these attributes may take; others are free text. */
export const ATTRIBUTE_VALUES: Record<string, string[]> = { risk: ["low", "medium", "high"], privileged: ["true", "false"], kind: ["create", "change", "transfer"] };

export const LIMITS = { steps: 20, name: 80, description: 500, message: 500, hours: 720 };

/** A step id nothing else uses ("s1", "s2"…). */
export function nextId(steps: WorkflowStep[]): string {
  let n = steps.length + 1;
  while (steps.some((s) => s.id === `s${n}`)) n++;
  return `s${n}`;
}

/** A new step of a type, with sensible defaults for the scope. */
export function blankStep(type: WorkflowStepType, steps: WorkflowStep[], approvers: string[], attributes: string[]): WorkflowStep {
  const id = nextId(steps);
  switch (type) {
    case "approval": return { id, type, approver: approvers.includes("decider") ? "decider" : approvers[0] };
    case "questionnaire": return { id, type, questionnaire_id: "" };
    case "notify": return { id, type, notify: "requester" };
    case "wait": return { id, type, hours: 4 };
    case "condition": return { id, type, when: { attribute: attributes[0], op: "eq", values: [""] }, then: "", else: "" };
    default: return { id, type };
  }
}

/** Changing a step's type keeps its id and name and drops what no longer applies. */
export function retypeStep(s: WorkflowStep, type: WorkflowStepType, steps: WorkflowStep[], approvers: string[], attributes: string[]): WorkflowStep {
  const b = blankStep(type, steps.filter((x) => x.id !== s.id), approvers, attributes);
  return { ...b, id: s.id, ...(s.name ? { name: s.name } : {}), ...(type !== "condition" && s.next ? { next: s.next } : {}) };
}

/** Removes a step; whatever named it as the next step or a branch must be chosen again. */
export function removeStep(steps: WorkflowStep[], id: string): WorkflowStep[] {
  return steps.filter((s) => s.id !== id).map((s) => {
    const out = { ...s };
    if (out.next === id) delete out.next;
    if (out.then === id) out.then = "";
    if (out.else === id) out.else = "";
    return out;
  });
}

/** Moves a step one place; the list order is the default flow. */
export function moveStep(steps: WorkflowStep[], i: number, by: -1 | 1): WorkflowStep[] {
  const j = i + by;
  if (j < 0 || j >= steps.length) return steps;
  const out = steps.slice();
  [out[i], out[j]] = [out[j], out[i]];
  return out;
}

/** The canonical form the server stores: only the fields of the step's type, trimmed, nothing empty. */
export function cleanSteps(steps: WorkflowStep[]): WorkflowStep[] {
  return steps.map((s) => {
    const out: WorkflowStep = { id: s.id.trim(), type: s.type };
    if (s.name?.trim()) out.name = s.name.trim();
    switch (s.type) {
      case "approval":
        out.approver = s.approver;
        if (s.approver === "group" && s.group_id) out.group_id = s.group_id;
        if (s.escalate_after_hours && s.escalate_after_hours > 0) out.escalate_after_hours = s.escalate_after_hours;
        break;
      case "questionnaire":
        out.questionnaire_id = s.questionnaire_id;
        break;
      case "notify":
        out.notify = s.notify;
        if (s.notify === "group" && s.group_id) out.group_id = s.group_id;
        if (s.message?.trim()) out.message = s.message.trim();
        break;
      case "wait":
        out.hours = s.hours;
        break;
      case "condition":
        out.when = s.when && { attribute: s.when.attribute, op: s.when.op, values: s.when.values.map((v) => v.trim()).filter(Boolean) };
        out.then = s.then;
        out.else = s.else;
        break;
    }
    if (s.type !== "condition" && s.next) out.next = s.next;
    return out;
  });
}

export const sameSteps = (a: WorkflowStep[], b: WorkflowStep[]): boolean => JSON.stringify(cleanSteps(a)) === JSON.stringify(cleanSteps(b));

export interface StepProblem { step: string; message: string }

/** What a form can check without the server: required fields. The server checks the rest (cycles, reachability, four eyes). */
export function localProblems(steps: WorkflowStep[]): StepProblem[] {
  const out: StepProblem[] = [];
  const add = (step: string, message: string) => out.push({ step, message });
  if (steps.length === 0) return [{ step: "", message: "Add at least one step" }];
  if (steps.length > LIMITS.steps) add("", `At most ${LIMITS.steps} steps`);
  const ids = new Set<string>();
  for (const s of steps) {
    if (ids.has(s.id)) add(s.id, "The id is used twice");
    ids.add(s.id);
  }
  const known = (id: string | undefined) => !!id && (id === END || ids.has(id));
  for (const s of steps) {
    switch (s.type) {
      case "approval":
        if (!s.approver) add(s.id, "Choose who approves");
        if (s.approver === "group" && !s.group_id) add(s.id, "Choose the group");
        break;
      case "questionnaire":
        if (!s.questionnaire_id) add(s.id, "Choose the questionnaire");
        break;
      case "notify":
        if (!s.notify) add(s.id, "Choose who is told");
        if (s.notify === "group" && !s.group_id) add(s.id, "Choose the group");
        break;
      case "wait":
        if (!(s.hours && s.hours > 0 && s.hours <= LIMITS.hours)) add(s.id, `Wait between 1 and ${LIMITS.hours} hours`);
        break;
      case "condition":
        if (!s.when || s.when.values.map((v) => v.trim()).filter(Boolean).length === 0) add(s.id, "Enter the value to test");
        if (!known(s.then) || !known(s.else)) add(s.id, "Choose where to go when it holds and when it does not");
        else if (s.then === s.else) add(s.id, "Both branches go to the same step");
        break;
    }
    if (s.type !== "condition" && s.next && !known(s.next)) add(s.id, "The next step does not exist");
  }
  return out;
}

/** The first line a person reads for a step in the list. */
export function describeStep(s: WorkflowStep, names: { group?: (id: string) => string; questionnaire?: (id: string) => string } = {}): string {
  switch (s.type) {
    case "approval":
      return `${s.approver === "group" ? `Group ${names.group?.(s.group_id ?? "") ?? s.group_id ?? ""}` : APPROVER_LABEL[s.approver ?? ""] ?? s.approver ?? "?"} approves` +
        (s.escalate_after_hours ? `, escalates after ${s.escalate_after_hours} h` : "");
    case "questionnaire": return `Ask ${names.questionnaire?.(s.questionnaire_id ?? "") ?? s.questionnaire_id ?? "?"}`;
    case "notify": return `Tell ${(s.notify === "group" ? `group ${names.group?.(s.group_id ?? "") ?? ""}` : NOTIFY_LABEL[s.notify ?? ""] ?? "?").toLowerCase()}`;
    case "wait": return `Wait ${s.hours ?? "?"} h before the next approval`;
    case "condition": return s.when ? `If ${ATTRIBUTE_LABEL[s.when.attribute] ?? s.when.attribute} ${OP_LABEL[s.when.op] ?? s.when.op} ${s.when.values.filter(Boolean).join(", ") || "…"}` : "If …";
    case "provisioning": return "Provision in the target system";
  }
}

/** Where a step goes when it is done, as words (for the flow summary). */
export function flowLabel(steps: WorkflowStep[], i: number): string {
  const s = steps[i];
  if (s.type === "condition") return `yes: ${s.then || "?"}, no: ${s.else || "?"}`;
  return s.next ? (s.next === END ? "end" : s.next) : i + 1 < steps.length ? steps[i + 1].id : "end";
}

/** What a workflow applies to, in words. */
export function appliesTo(targets: WorkflowTarget[], itemName: (id: string) => string = (id) => id): string {
  if (targets.length === 0) return "Nothing yet";
  const types = targets.filter((t) => t.kind === "request_type").map((t) => REQUEST_TYPE_LABEL[t.target_id] ?? t.target_id);
  const items = targets.filter((t) => t.kind === "catalog_item");
  return [...types, ...(items.length ? [items.length === 1 ? itemName(items[0].target_id) : `${items.length} catalog items`] : [])].join("; ");
}

export const scopeLabel = (s: WorkflowScope): string => (s === "service_account" ? "Service accounts" : "Access requests");
