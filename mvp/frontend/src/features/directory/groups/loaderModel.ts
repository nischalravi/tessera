/**
 * Pure helpers of the group loader screens (no React, no fetch), so `npm test` can check them: what each
 * loader type needs, how the wizard's form becomes the API's LoaderSpec, the checks that mirror the server's
 * (the server decides: internal/groups/loaders/config.go), and the words for runs and failsafe trips.
 */
import type { GrpLoader, LoaderFailsafe, LoaderRun, LoaderSpec, LoaderTrip, LoaderType, OnMissingGroup } from "../../../api";
import { extensionProblem } from "./model.ts";

export interface LoaderTypeInfo {
  id: LoaderType;
  label: string;
  blurb: string;
  /** Runs a query a person wrote: creating or changing it needs a second admin (GRP-6311). */
  sql?: boolean;
  needsConnection?: boolean;
}

/** The loader types that can be configured today (the others are designed but refused by the server). */
export const LOADER_TYPES: LoaderTypeInfo[] = [
  { id: "sql_simple", label: "SQL query: one group", sql: true, blurb: "A query on a database file returns the people; they all become members of one group." },
  { id: "sql_group_list", label: "SQL query: many groups", sql: true, blurb: "A query returns group name and person pairs; one group is kept per name." },
  { id: "csv", label: "CSV file or URL", blurb: "A file under the loader data directory, or an https URL, with a header row." },
  { id: "connector_groups", label: "A connected system's groups", needsConnection: true, blurb: "Every group a connection has becomes a native group here." },
  { id: "attribute", label: "Identity attribute rule", blurb: "One group per value of an identity attribute, such as department." },
  { id: "recent_memberships", label: "Recent members of a group", blurb: "People who were in a group in the last N days, optionally with its current members." },
];
export const typeInfo = (t: string) => LOADER_TYPES.find((x) => x.id === t);
export const typeLabel = (t: string) => typeInfo(t)?.label ?? t;
export const isSqlType = (t: string) => !!typeInfo(t)?.sql;

/** Where the people named by a source are matched. The server matches exactly; nothing is guessed. */
export const SUBJECT_SOURCES: { id: string; label: string; hint: string }[] = [
  { id: "identity", label: "Identity external id", hint: "The id the identity carries from its source (employee or student id)." },
  { id: "email", label: "Email address", hint: "Matched without regard to case; an address two people share matches nobody." },
  { id: "tessera_id", label: "Tessera identity id", hint: "The number Tessera gave the identity." },
  { id: "account", label: "A connected system's account", hint: "The account's external id in that system (type the system name)." },
];

export const ATTRIBUTES = ["department", "title", "type", "status", "source"];
export const ON_MISSING: { id: OnMissingGroup; label: string; hint: string }[] = [
  { id: "empty", label: "Empty it", hint: "Remove the loader's members; keep the group." },
  { id: "disable", label: "Disable it", hint: "Disable the group, so it counts as empty." },
  { id: "delete", label: "Delete it", hint: "Delete the group (it can be restored)." },
  { id: "keep", label: "Leave it alone", hint: "Keep the members as they are." },
];
export const SCHEDULES: { id: string; label: string }[] = [
  { id: "@hourly", label: "Every hour" }, { id: "@daily", label: "Every day (midnight UTC)" }, { id: "@weekly", label: "Every week (Sunday, UTC)" }, { id: "custom", label: "Custom (cron, UTC)" },
];

export interface LoaderForm {
  type: LoaderType | null;
  name: string;
  targetFolder: string;
  // sql
  database: string; query: string; group: string; groupsQuery: string; incrementalQuery: string; incrementalSecs: string;
  // csv
  csvFrom: "path" | "url"; csvPath: string; csvUrl: string; csvSecret: string; csvGroupBy: "one" | "column"; groupColumn: string; displayColumn: string;
  subjectColumn: string; subjectSource: string; accountSystem: string; sourceColumn: string; delimiter: string;
  // connector_groups
  connectionId: string; namePrefix: string;
  // attribute
  attribute: string; prefix: string; onlyActive: boolean;
  // recent_memberships
  sourceGroup: string; days: string; includeCurrent: boolean;
  // common
  nameTemplate: string; onMissing: OnMissingGroup; andGroup: string; schedule: string; cron: string; startEnabled: boolean;
  failsafe: { maxRemovedPercent: string; maxRemoved: string; minGroupSize: string; maxEmptiedPercent: string; maxUnresolvedPercent: string };
}

export function emptyForm(targetFolder = ""): LoaderForm {
  return {
    type: null, name: "", targetFolder,
    database: "", query: "", group: "", groupsQuery: "", incrementalQuery: "", incrementalSecs: "",
    csvFrom: "path", csvPath: "", csvUrl: "", csvSecret: "", csvGroupBy: "one", groupColumn: "", displayColumn: "",
    subjectColumn: "", subjectSource: "identity", accountSystem: "", sourceColumn: "", delimiter: "",
    connectionId: "", namePrefix: "",
    attribute: "department", prefix: "", onlyActive: true,
    sourceGroup: "", days: "30", includeCurrent: false,
    nameTemplate: "{{.Name}}", onMissing: "empty", andGroup: "", schedule: "@daily", cron: "", startEnabled: false,
    failsafe: { maxRemovedPercent: "20", maxRemoved: "500", minGroupSize: "", maxEmptiedPercent: "5", maxUnresolvedPercent: "2" },
  };
}

const trim = (s: string) => s.trim();
const opt = <T>(o: Record<string, unknown>, k: string, v: T | "" | undefined | false) => { if (v !== "" && v !== undefined && v !== false) o[k] = v; };

/** The `config` of the type's form fields, in the shape the server's strict decoder accepts. */
export function buildConfig(f: LoaderForm): Record<string, unknown> {
  const c: Record<string, unknown> = {};
  switch (f.type) {
    case "sql_simple":
    case "sql_group_list":
      c.database = trim(f.database);
      c.query = trim(f.query);
      if (f.type === "sql_simple") c.group = trim(f.group);
      else opt(c, "groups_query", trim(f.groupsQuery));
      opt(c, "incremental_query", trim(f.incrementalQuery));
      break;
    case "csv":
      if (f.csvFrom === "path") c.path = trim(f.csvPath);
      else c.url = trim(f.csvUrl);
      if (f.csvGroupBy === "one") c.group = trim(f.group);
      else {
        c.group_column = trim(f.groupColumn);
        opt(c, "display_column", trim(f.displayColumn));
      }
      c.subject_column = trim(f.subjectColumn);
      if (f.sourceColumn.trim()) c.source_column = trim(f.sourceColumn);
      else if (f.subjectSource === "account") opt(c, "subject_source", trim(f.accountSystem));
      else opt(c, "subject_source", f.subjectSource === "identity" ? "" : f.subjectSource);
      opt(c, "delimiter", f.delimiter);
      break;
    case "connector_groups":
      opt(c, "name_prefix", trim(f.namePrefix));
      break;
    case "attribute":
      c.attribute = f.attribute;
      opt(c, "prefix", trim(f.prefix));
      if (!f.onlyActive) c.only_active = false;
      break;
    case "recent_memberships":
      c.source_group = trim(f.sourceGroup);
      c.days = Number(f.days);
      if (f.includeCurrent) c.include_current = true;
      c.group = trim(f.group);
      break;
  }
  return c;
}

const num = (s: string) => (s.trim() === "" ? undefined : Number(s));

/** The failsafe fields that were filled in; the server fills the rest with its defaults. */
export function buildFailsafe(f: LoaderForm["failsafe"]): LoaderFailsafe {
  const o: LoaderFailsafe = {};
  const a = num(f.maxRemovedPercent), b = num(f.maxRemoved), c = num(f.minGroupSize), d = num(f.maxEmptiedPercent), e = num(f.maxUnresolvedPercent);
  if (a !== undefined) o.max_removed_percent = a;
  if (b !== undefined) o.max_removed = b;
  if (c !== undefined) o.min_group_size = c;
  if (d !== undefined) o.max_groups_emptied_percent = d;
  if (e !== undefined) o.max_unresolved_percent = e;
  return o;
}

export function buildSpec(f: LoaderForm): LoaderSpec {
  const spec: LoaderSpec = { name: trim(f.name), type: f.type as LoaderType, config: buildConfig(f), target_folder: f.targetFolder };
  if (f.connectionId) spec.connection_id = f.connectionId;
  if (f.nameTemplate && f.nameTemplate !== "{{.Name}}") spec.name_template = f.nameTemplate;
  spec.on_missing_group = f.onMissing;
  if (f.andGroup.trim()) spec.and_group = trim(f.andGroup);
  spec.schedule = f.schedule === "custom" ? trim(f.cron) : f.schedule;
  const inc = num(f.incrementalSecs);
  if (inc !== undefined && isSqlType(f.type ?? "") && f.incrementalQuery.trim()) spec.incremental_secs = inc;
  spec.failsafe = buildFailsafe(f.failsafe);
  spec.status = f.startEnabled ? "enabled" : "disabled";
  if (f.type === "csv" && f.csvFrom === "url" && f.csvSecret) spec.secret = f.csvSecret;
  return spec;
}

// ------------------------------------------------------------ checks (the server repeats them)

const columnRE = /^[A-Za-z0-9_ .-]{1,64}$/;
const fileRE = /^[A-Za-z0-9_][A-Za-z0-9_.-]*(\/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$/;
const sourceRE = /^[A-Za-z0-9_.:-]{1,64}$/;

/** The first keyword of a SQL statement must be SELECT or WITH: the first line of defence (the server also runs it read-only). */
export function sqlProblem(q: string): string | null {
  const t = q.trim().replace(/^(--[^\n]*\n|\/\*[\s\S]*?\*\/|\s)+/, "");
  if (!t) return "Enter a query.";
  if (!/^(select|with)\b/i.test(t)) return "A query must be a single SELECT or WITH statement.";
  if (/;\s*\S/.test(t)) return "Only one statement is allowed.";
  return null;
}

/** Fields of the step that are wrong or missing, as sentences; empty means the step is complete. */
export function stepProblems(step: "type" | "source" | "people" | "schedule", f: LoaderForm): string[] {
  const p: string[] = [];
  const add = (s: string | null | false | undefined) => { if (s) p.push(s); };
  switch (step) {
    case "type":
      add(!f.type && "Choose where the members come from.");
      break;
    case "source":
      add(!f.name.trim() && "Name the loader.");
      add(!f.targetFolder && "Choose the folder its groups go in.");
      switch (f.type) {
        case "sql_simple":
        case "sql_group_list":
          add(!fileRE.test(f.database) || f.database.includes("..") ? "The database is a file name under the loader data directory." : null);
          add(sqlProblem(f.query));
          if (f.type === "sql_simple") add(extensionProblem(f.group.trim()) && `Group: ${extensionProblem(f.group.trim())}`);
          if (f.groupsQuery.trim()) add(sqlProblem(f.groupsQuery) && `Groups query: ${sqlProblem(f.groupsQuery)}`);
          if (f.incrementalQuery.trim()) {
            add(sqlProblem(f.incrementalQuery) && `Incremental query: ${sqlProblem(f.incrementalQuery)}`);
            add(!f.incrementalQuery.includes("@cursor") && "The incremental query must use @cursor.");
            const n = num(f.incrementalSecs);
            add(n === undefined || !(n >= 30 && n <= 86400) ? "Incremental interval is 30 to 86400 seconds." : null);
          }
          break;
        case "csv":
          if (f.csvFrom === "path") add(!fileRE.test(f.csvPath) || f.csvPath.includes("..") ? "The file is a name under the loader data directory." : null);
          else add(!/^https?:\/\/[^/@\s]+/i.test(f.csvUrl) ? "The URL starts with https:// and has no credentials in it." : null);
          if (f.csvGroupBy === "one") add(extensionProblem(f.group.trim()) && `Group: ${extensionProblem(f.group.trim())}`);
          else add(!columnRE.test(f.groupColumn) && "Name the column of the groups.");
          add(!columnRE.test(f.subjectColumn) && "Name the column of the people.");
          break;
        case "connector_groups":
          add(!f.connectionId && "Choose the connection.");
          break;
        case "attribute":
          add(!ATTRIBUTES.includes(f.attribute) && "Choose an attribute.");
          break;
        case "recent_memberships": {
          add(!f.sourceGroup.trim() && "Name the group to look back on.");
          const d = num(f.days);
          add(d === undefined || !Number.isInteger(d) || d < 1 || d > 366 ? "Days is 1 to 366." : null);
          add(extensionProblem(f.group.trim()) && `Group: ${extensionProblem(f.group.trim())}`);
          break;
        }
      }
      break;
    case "people":
      if (f.type === "csv") {
        add(f.sourceColumn.trim() && !columnRE.test(f.sourceColumn) && "The source column is not a valid column name.");
        add(!f.sourceColumn.trim() && f.subjectSource === "account" && !sourceRE.test(f.accountSystem) && "Type the system's name.");
      }
      add(f.nameTemplate.split("{{.Name}}").length !== 2 && "The name template has exactly one {{.Name}}.");
      break;
    case "schedule": {
      add(f.schedule === "custom" && f.cron.trim().split(/\s+/).length !== 5 && "A cron schedule has five fields.");
      for (const [k, v, max] of [["Removed percent", f.failsafe.maxRemovedPercent, 100], ["Emptied percent", f.failsafe.maxEmptiedPercent, 100], ["Unresolved percent", f.failsafe.maxUnresolvedPercent, 100]] as const) {
        const n = num(v);
        add(n !== undefined && !(n >= 0 && n <= max) && `${k} is 0 to ${max}.`);
      }
      for (const [k, v] of [["Largest removal", f.failsafe.maxRemoved], ["Smallest group", f.failsafe.minGroupSize]] as const) {
        const n = num(v);
        add(n !== undefined && !(Number.isInteger(n) && n >= 0) && `${k} is a whole number, 0 or more.`);
      }
      break;
    }
  }
  return p;
}

// ------------------------------------------------------------ words

export const RUN_STATUS_LABEL: Record<string, string> = {
  running: "Running", applied: "Applied", held: "Held for approval", failed: "Failed", approved: "Approved and applied", rejected: "Rejected", previewed: "Preview",
};
export const RUN_TONE: Record<string, "ok" | "warning" | "critical" | "info" | "neutral"> = {
  applied: "ok", approved: "ok", held: "warning", failed: "critical", rejected: "neutral", running: "info", previewed: "info",
};

/** "3 added, 1 removed" for a run; a failed or running one says so. */
export function runSummary(r: Pick<LoaderRun, "status" | "adds" | "removes" | "unresolved" | "error">): string {
  if (r.status === "failed") return r.error ?? "The run failed.";
  const parts = [`${r.adds ?? 0} added`, `${r.removes ?? 0} removed`];
  if (r.unresolved) parts.push(`${r.unresolved} unresolved`);
  return parts.join(", ");
}

export function tripText(t: LoaderTrip): string { return t.detail || `${t.rule}: ${t.value} (limit ${t.limit})`; }

/** What the schedule says in words. */
export function scheduleText(s: string): string {
  const known: Record<string, string> = { "@hourly": "every hour", "@daily": "every day at 00:00 UTC", "@weekly": "every Sunday at 00:00 UTC" };
  return known[s] ?? `cron ${s} (UTC)`;
}

/** The loader's state as one word and a tone for its badge. */
export function loaderState(l: Pick<GrpLoader, "status" | "job">): { label: string; tone: "ok" | "warning" | "critical" | "neutral" } {
  const last = l.job?.last_run;
  if (l.status === "held" || l.job?.state === "held") return { label: "Held", tone: "warning" };
  if (l.status === "disabled") return { label: "Off", tone: "neutral" };
  if (last?.status === "failed") return { label: "Last run failed", tone: "critical" };
  return { label: "On", tone: "ok" };
}

/** The loader that fills a group, from the loader list (the group names it when the API says so). */
export function loaderOfGroup<L extends { id: string }>(loaders: L[], g: { loader_id?: string | null }): L | null {
  return (g.loader_id && loaders.find((l) => l.id === g.loader_id)) || null;
}

/** A person's time zone is the server's business; lag is shown in coarse units. */
export function lagText(sec: number | null | undefined): string {
  if (sec === null || sec === undefined) return "never loaded";
  if (sec < 90) return "just now";
  if (sec < 5400) return `${Math.round(sec / 60)} min ago`;
  if (sec < 172800) return `${Math.round(sec / 3600)} h ago`;
  return `${Math.round(sec / 86400)} d ago`;
}
