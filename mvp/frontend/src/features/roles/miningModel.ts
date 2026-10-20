import type { MiningRule } from "../../api";

/** Confidence bands: 80 and up is strong, 60 and up fair, below that weak. */
export function confidenceTone(n: number): "ok" | "info" | "warning" {
  return n >= 80 ? "ok" : n >= 60 ? "info" : "warning";
}

/** "department: Engineering", or null without a rule. */
export function ruleLabel(r: MiningRule | null): string | null {
  if (!r || !r.values.length) return null;
  return `${r.attribute}: ${r.values.join(" or ")}`;
}
