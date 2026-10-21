// SoD page configuration (issue #298): what the conflicts page shows. The default, with no configuration
// loaded (or one that could not be), is everything, as before the page was configurable.
import type { SodViewKey, SodViewSettings } from "../../api";

export const SOD_VIEW_KEYS: SodViewKey[] = ["risk", "function", "entitlement", "ruleset", "mitigating_control", "business_process"];
export const SOD_VIEW_LABEL: Record<SodViewKey, string> = {
  risk: "Risk",
  function: "Function",
  entitlement: "Entitlement",
  ruleset: "Ruleset",
  mitigating_control: "Mitigating control",
  business_process: "Business process",
};
export const ALL_VISIBLE: SodViewSettings = { columns: SOD_VIEW_KEYS, filters: SOD_VIEW_KEYS };

export function sodViewProblem(columns: SodViewKey[]): string | null {
  return columns.length === 0 ? "Show at least one column." : null;
}

export const sameKeys = (a: SodViewKey[], b: SodViewKey[]) => a.length === b.length && a.every((k, i) => k === b[i]);

/** Keeps the entries of a table's columns or filters whose key the tenant shows; an entry with no key is always shown. */
export function visible<T extends { key?: SodViewKey }>(items: T[], shown: SodViewKey[]): T[] {
  return items.filter((i) => !i.key || shown.includes(i.key));
}
