// The field errors of a connection config save (PATCH /connections/{id}/config answers 200 with `fields`:
// the draft is stored, but those fields are not valid yet). Pure, so `npm test` covers it (issue #622).

export interface FieldIssue { field: string; msg: string }

/**
 * The form key of a server field name: the wizard's inputs use the config key itself (`base_url`, `host`,
 * `settings.port`), except the SQL object, whose inputs are `sql_<key>`.
 */
export const formKeyOf = (field: string) => (field.startsWith("sql.") ? `sql_${field.slice(4)}` : field);

/** The messages of each rejected field, joined, by form key (one field can fail more than one rule). */
export function fieldErrorsByKey(fields: FieldIssue[] | null | undefined): Record<string, string> {
  const out: Record<string, string[]> = {};
  for (const f of fields ?? []) {
    if (!f?.field || !f.msg) continue;
    const k = formKeyOf(f.field);
    const list = (out[k] ??= []);
    if (!list.includes(f.msg)) list.push(f.msg);
  }
  return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, v.join("; ")]));
}

/** The toast after a save the server flagged: how many fields, and which. */
export function fieldErrorsSummary(fields: FieldIssue[] | null | undefined): string {
  const keys = [...new Set((fields ?? []).filter((f) => f?.field && f.msg).map((f) => f.field))];
  if (!keys.length) return "";
  return `Saved as a draft, but ${keys.length === 1 ? "1 field is" : `${keys.length} fields are`} not valid yet: ${keys.join(", ")}. Fix the marked field${keys.length === 1 ? "" : "s"} and save again.`;
}
