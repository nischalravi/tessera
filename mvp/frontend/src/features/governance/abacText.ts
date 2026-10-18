import type { AbacCondition } from "../../api";

const OPS: Record<string, string> = { eq: "=", ne: "≠", gt: ">", gte: "≥", lt: "<", lte: "≤" };
const short = (a: string) => a.replace(/^(identity|resource|context)\./, (_, ns) => (ns === "identity" ? "" : `${ns} `)).replace(/_/g, " ");

/** A condition in words: "department = Finance and (type = human or title starts with Lead)". */
export function describeCondition(c: AbacCondition, top = true): string {
  if ("all" in c || "any" in c) {
    const parts = ("all" in c ? c.all : c.any).map((p) => describeCondition(p, false));
    const text = parts.join("all" in c ? " and " : " or ");
    return top || parts.length < 2 ? text : `(${text})`;
  }
  if ("not" in c) return `not ${describeCondition(c.not, false)}`;
  const a = short(c.attr);
  switch (c.op) {
    case "exists": return `${a} is set`;
    case "in": return `${a} is one of ${(Array.isArray(c.value) ? c.value : []).join(", ")}`;
    case "prefix": return `${a} starts with ${String(c.value)}`;
    default: return `${a} ${OPS[c.op] ?? c.op} ${String(c.value)}`;
  }
}

/** Parses the editor's JSON; the server validates the language itself (operators, limits, attributes). */
export function parseConditionText(text: string): { condition: AbacCondition | null; error: string | null } {
  if (!text.trim()) return { condition: null, error: "Write a condition." };
  try {
    const v = JSON.parse(text);
    if (typeof v !== "object" || v === null || Array.isArray(v)) return { condition: null, error: "A condition is a JSON object." };
    return { condition: v as AbacCondition, error: null };
  } catch (e) {
    return { condition: null, error: `Not valid JSON: ${(e as Error).message}` };
  }
}

export const EXAMPLE_CONDITION: AbacCondition = {
  all: [
    { attr: "identity.department", op: "eq", value: "Finance" },
    { attr: "identity.type", op: "eq", value: "human" },
  ],
};
