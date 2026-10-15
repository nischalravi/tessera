// The pure parts of the flat-file import screen (issue #105): the mapping form, the checks made
// before a file is sent, and plain-language text for the API's row error codes. No React here, so
// `npm test` runs them directly.
import type { FlatAccountCols, FlatEntitlementCols, FlatMapping } from "../../api";

/** The server's own limits (internal/flatfile), checked first so a big file is not sent for nothing. */
export const MAX_UPLOAD_BYTES = 512 * 1024;

export const SYSTEM_RE = /^[a-z0-9][a-z0-9_.-]{0,62}$/;

export interface MappingForm {
  system: string;
  name: string;
  owner: string;
  account_id: string;
  username: string;
  email: string;
  identity_id: string;
  status: string;
  hasEntitlements: boolean;
  e_account_id: string;
  entitlement: string;
  e_name: string;
  privileged: string;
}

export const emptyForm = (): MappingForm => ({
  system: "", name: "", owner: "", account_id: "", username: "", email: "", identity_id: "", status: "",
  hasEntitlements: false, e_account_id: "", entitlement: "", e_name: "", privileged: "",
});

export function formFromMapping(m: FlatMapping): MappingForm {
  const e = m.entitlements;
  return {
    system: m.system, name: m.name, owner: m.owner,
    account_id: m.accounts.account_id, username: m.accounts.username, email: m.accounts.email ?? "",
    identity_id: m.accounts.identity_id ?? "", status: m.accounts.status ?? "",
    hasEntitlements: !!e, e_account_id: e?.account_id ?? "", entitlement: e?.entitlement ?? "", e_name: e?.name ?? "", privileged: e?.privileged ?? "",
  };
}

const clean = (s: string) => s.trim();

/** Field -> what is wrong, empty when the form can be saved. The server checks again. */
export function formProblems(f: MappingForm, isNew: boolean): Record<string, string> {
  const p: Record<string, string> = {};
  if (isNew && !SYSTEM_RE.test(f.system)) p.system = "Use lower-case letters, digits, '.', '_' or '-', starting with a letter or digit.";
  if (!clean(f.name)) p.name = "Give the app a name.";
  if (!clean(f.account_id)) p.account_id = "Name the column that holds the account id.";
  if (!clean(f.username)) p.username = "Name the column that holds the username.";
  const own = [f.account_id, f.username, f.email, f.identity_id, f.status].map((c) => clean(c).toLowerCase()).filter(Boolean);
  if (new Set(own).size !== own.length) p.accounts = "One column cannot serve two account fields.";
  if (f.hasEntitlements) {
    if (!clean(f.e_account_id)) p.e_account_id = "Name the column that holds the account id.";
    if (!clean(f.entitlement)) p.entitlement = "Name the column that holds the entitlement.";
    const ents = [f.e_account_id, f.entitlement, f.e_name, f.privileged].map((c) => clean(c).toLowerCase()).filter(Boolean);
    if (new Set(ents).size !== ents.length) p.entitlements = "One column cannot serve two entitlement fields.";
  }
  return p;
}

/** The body of PUT /flatfile/apps/{system}/mapping: unmapped optional fields are left out. */
export function toBody(f: MappingForm): { name: string; owner: string; accounts: FlatAccountCols; entitlements: FlatEntitlementCols | null } {
  const opt = <K extends string>(k: K, v: string) => (clean(v) ? { [k]: clean(v) } : {}) as Partial<Record<K, string>>;
  return {
    name: clean(f.name),
    owner: clean(f.owner),
    accounts: { account_id: clean(f.account_id), username: clean(f.username), ...opt("email", f.email), ...opt("identity_id", f.identity_id), ...opt("status", f.status) },
    entitlements: f.hasEntitlements
      ? { account_id: clean(f.e_account_id), entitlement: clean(f.entitlement), ...opt("name", f.e_name), ...opt("privileged", f.privileged) }
      : null,
  };
}

/** The column names in the first line of a CSV file (quotes honoured), to suggest in the mapping form. */
export function headerOf(text: string): string[] {
  const line = text.replace(/^﻿/, "").split(/\r\n|\n|\r/, 1)[0] ?? "";
  const out: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { out.push(cell.trim()); cell = ""; }
    else cell += c;
  }
  out.push(cell.trim());
  return out.filter(Boolean);
}

/** Why a file is not sent, or null when it can be. */
export function checkFile(f: { name: string; size: number }): string | null {
  if (f.size === 0) return "The file is empty.";
  if (f.size > MAX_UPLOAD_BYTES) return `The file is larger than ${MAX_UPLOAD_BYTES / 1024} KiB. Split it, or send only what changed.`;
  if (!/\.csv$/i.test(f.name)) return "Choose a .csv file (save the sheet as CSV UTF-8).";
  return null;
}

/** What each error code of a rejected row means, in the words of the person fixing the file. */
export const ROW_ERROR_HELP: Record<string, string> = {
  file_too_large: "The file is too large.",
  too_many_rows: "The file has too many rows.",
  too_many_columns: "The file has too many columns.",
  not_utf8: "The file is not UTF-8 text. Save it as CSV UTF-8.",
  no_header: "The first row must be the column names.",
  bad_csv: "The file is not valid CSV.",
  duplicate_column: "A column name appears twice in the header.",
  missing_column: "A column the mapping needs is not in the file.",
  column_count: "The row has a different number of columns from the header.",
  required: "A required value is empty.",
  too_long: "A value is too long.",
  control_character: "A value has a line break or other control character.",
  formula_prefix: "An identifier starts with = + - or @, which a spreadsheet would run as a formula.",
  invalid_email: "Not an email address.",
  invalid_status: "Unknown status.",
  invalid_value: "Not a yes or no.",
  duplicate_key: "This account or entitlement is already in the file.",
  unknown_account: "The account is not in the accounts file last uploaded. Upload accounts first.",
};

export const errorHelp = (code: string) => ROW_ERROR_HELP[code] ?? code;

/** "row 3" or "the file", for the error list. */
export const rowLabel = (row: number) => (row === 0 ? "File" : `Row ${row}`);
