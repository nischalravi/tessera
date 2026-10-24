/**
 * Connection setup wizard with the checklist panel (§10.2): choose type → connect → scope →
 * mapping → validate → dry run → review and activate. Every step's gate is enforced by the
 * server; the UI shows the same blockers the server returns.
 */
import { Fragment, FormEvent, KeyboardEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ArrowRightLeft, Bot, Briefcase, CircleCheck, Database, FlaskConical, HardHat, Search, Users, Play, Power, ShieldCheck, Trash2, Wand2 } from "lucide-react";
import {
  Checklist, ChecklistItem, ConnConfig, Connection, DryRunView, RunView, SQLConfig, ScimPreset, readiness, useApi,
} from "../../../api";
import { SourceDeletionGuard } from "../SourceDeletionGuard";
import { VendorLogo, vendorForType } from "../../../components/VendorLogo"; // not in the barrel: keeps the brand marks out of the main chunk
import {
  Badge, Button, Callout, AttestInsteadDialog, ChecklistPanel, EmptyState, Kpi, Loading, Page, ReasonDialog, Step, Stepper, useConfirm, useToast,
} from "../../../components";
import {
  BlockerList, CONNECTOR_TYPES, GateCallout, STATE_LABEL, ScoreCell, SimulatedBadge, StateBadge, observedText, useAction,
} from "./shared";
import { CAPABILITIES, CATEGORIES, Capability, Category, filterGallery, groupGallery, metaOf, nextIndex } from "./gallery";
import { GOVERNED, settingValues, settingsPatch } from "./governed";
import { BASE_URL_FIELDS } from "./baseUrl";

// ---------------------------------------------------------------- step 1
/** The spec as editable text: JSON, since that is what the server stores. */
const restText = (r: Record<string, unknown> | undefined) => (r ? JSON.stringify(r, null, 2) : "");

const REST_EXAMPLE = `base_url: https://api.example.com/v2
auth: { type: bearer }
users:
  path: /users
  items_path: $.data
  pagination: { style: cursor, cursor_param: after, next_path: $.meta.next }
  fields: { id: $.id, username: $.login, email: $.email, status: $.state }`;

export function NewConnection() {
  const nav = useNavigate();
  const toast = useToast();
  const { data: existing } = useApi<{ connector_type?: string; legacy?: boolean }[]>("/connections");
  const [type, setType] = useState("demo-ad");
  const [name, setName] = useState("Active Directory (demo)");
  const [busy, setBusy] = useState(false);
  // A SCIM vendor tile has the id "scim:<preset>" and creates a scim_app connection pre-filled from the preset.
  const presetOf = (id: string) => (id.startsWith("scim:") ? id.slice(5) : undefined);
  const pick = (id: string) => {
    setType(id);
    setName(CONNECTOR_TYPES.find((t) => t.id === id)?.label ?? "");
  };
  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const preset = presetOf(type);
      const c = await readiness.create(preset
        ? { name: name.trim(), connector_type: "scim_app", config: { preset } }
        : { name: name.trim(), connector_type: type });
      toast(`${c.name} created as a draft`);
      nav(`/admin/connections/${c.id}?step=connect`);
    } catch (x) {
      toast((x as Error).message, { kind: "error" });
      setBusy(false);
    }
  };
  const taken = (id: string) => (existing ?? []).some((c) => !c.legacy && c.connector_type === id);
  return (
    <Page title="New connection" crumbs={[["Settings"], ["Connections", "/admin/connections"], ["New connection"]]}
      sub="Choose the system. Its readiness checklist is pinned to the connection and every Required item must pass before it can become active.">
      <div className="wizard-new">
        <Stepper current="type" onSelect={() => {}} steps={WIZARD_STEPS.map((s, i) => ({ ...s, disabled: i > 0, reason: "Create the connection first" }))} />
        <form className="card stack" onSubmit={create}>
          <h2>1. Choose type</h2>
          <TypeGallery type={type} onPick={pick} taken={taken} />
          {!CONNECTOR_TYPES.find((t) => t.id === type)?.demo && (
            <Callout tone="warn">Real connector types can be set up and validated against the simulated scenario, but simulated results never satisfy their gates, and they cannot be activated until tenancy, RBAC and step-up land (Phase 0, DR-10).</Callout>
          )}
          <label className="field" style={{ maxWidth: 420 }}>
            Name
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} />
          </label>
          <div className="row"><Button type="submit" variant="primary" disabled={busy || !name.trim()}>{busy ? "Creating…" : "Create connection"}</Button><Link to="/admin/connections">Cancel</Link></div>
        </form>
      </div>
    </Page>
  );
}

const CAP_ICON = { "Identity source": Users, "Provisioning target": ArrowRightLeft, "HR source": Briefcase, "Access inventory": Database,
  "Contractor source": HardHat, "Agent discovery": Bot } as const;

/** App-gallery picker for the connector type: search, category and capability chips, grouped tiles. */
function TypeGallery({ type, onPick, taken }: { type: string; onPick: (id: string) => void; taken: (id: string) => boolean }) {
  const [q, setQ] = useState("");
  const [category, setCategory] = useState<Category | "">("");
  const [capability, setCapability] = useState<Capability | "">("");
  const refs = useRef<Record<string, HTMLDivElement | null>>({});
  const shown = filterGallery(CONNECTOR_TYPES, { q, category, capability });
  const groups = groupGallery(shown);
  const ids = groups.flatMap((g) => g.items.map((t) => t.id));
  const tabStop = ids.includes(type) ? type : ids[0]; // roving tabindex: the selected tile, else the first
  const onKey = (e: KeyboardEvent, id: string) => {
    if (e.key === " " || e.key === "Enter") { e.preventDefault(); onPick(id); return; }
    if (!e.key.startsWith("Arrow") && e.key !== "Home" && e.key !== "End") return;
    const to = nextIndex(e.key, ids.indexOf(id), ids.length);
    e.preventDefault();
    if (to < 0 || ids[to] === id) return;
    onPick(ids[to]);
    refs.current[ids[to]]?.focus();
  };
  const chip = (label: string, on: boolean, set: () => void) => (
    <button key={label} type="button" className={`fchip ${on ? "on" : ""}`} aria-pressed={on} onClick={set}>{label}</button>
  );
  return (
    <div className="gallery stack">
      <div className="gallery-bar">
        <label className="gallery-search">
          <Search size={14} aria-hidden />
          <input className="input" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search systems" aria-label="Search connector types" />
        </label>
        <div className="chips" role="group" aria-label="Filter by category">
          {chip("All", category === "", () => setCategory(""))}
          {CATEGORIES.map((c) => chip(c, category === c, () => setCategory(category === c ? "" : c)))}
        </div>
        <div className="chips" role="group" aria-label="Filter by capability">
          {chip("Any capability", capability === "", () => setCapability(""))}
          {CAPABILITIES.map((c) => chip(c, capability === c, () => setCapability(capability === c ? "" : c)))}
        </div>
      </div>
      <p className="sr-only" role="status">{shown.length} of {CONNECTOR_TYPES.length} systems shown</p>
      <div role="radiogroup" aria-label="Connector type" className="stack">
        {groups.map((g) => (
          <section key={g.category} aria-labelledby={`gal-${g.category}`}>
            <h3 id={`gal-${g.category}`} className="gallery-h">{g.category}</h3>
            <div className="gallery-grid">
              {g.items.map((t) => {
                const m = metaOf(t.id);
                return (
                  <div key={t.id} ref={(el) => { refs.current[t.id] = el; }} role="radio" aria-checked={type === t.id}
                    tabIndex={tabStop === t.id ? 0 : -1} className={`gallery-tile ${type === t.id ? "on" : ""}`}
                    aria-labelledby={`gal-n-${t.id}`} aria-describedby={`gal-d-${t.id}`}
                    onClick={() => onPick(t.id)} onKeyDown={(e) => onKey(e, t.id)}>
                    <VendorLogo vendor={m.vendor} />
                    <span className="gallery-body">
                      <b id={`gal-n-${t.id}`}>{t.label}</b>
                      <span className="small faint">{m.publisher}</span>
                      <span id={`gal-d-${t.id}`} className="small faint">{t.blurb}</span>
                      <span className="gallery-caps">
                        {m.capabilities.map((c) => {
                          const Icon = CAP_ICON[c];
                          return <span key={c} className="gallery-cap" title={c}><Icon size={16} aria-hidden /><span className="sr-only">{c}</span></span>;
                        })}
                      </span>
                    </span>
                    <span className="gallery-foot row tight">
                      {t.demo ? <Badge tone="info">Simulated</Badge> : <Badge tone="outline">Needs DR-10+</Badge>}
                      {taken(t.id) && <Badge>Exists</Badge>}
                    </span>
                  </div>
                );
              })}
            </div>
          </section>
        ))}
        {groups.length === 0 && (
          <EmptyState icon={<Search size={20} />} title="No systems match"
            action={<Button type="button" onClick={() => { setQ(""); setCategory(""); setCapability(""); }}>Clear search and filters</Button>}>
            Try a different name, or clear the filters.
          </EmptyState>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- detail
type StepId = "type" | "connect" | "scope" | "mapping" | "validate" | "dryrun" | "activate" | "guard";
const WIZARD_STEPS: { id: StepId; label: string; sub: string }[] = [
  { id: "type", label: "Choose type", sub: "Template pinned" },
  { id: "connect", label: "Connect", sub: "Endpoint, credential, owners" },
  { id: "scope", label: "Scope", sub: "Base DNs, filters, expected counts" },
  { id: "mapping", label: "Mapping", sub: "Correlation key, HR id, status" },
  { id: "validate", label: "Validate", sub: "Read-only live checks" },
  { id: "dryrun", label: "Dry run", sub: "Staging snapshot and reconciliation" },
  { id: "guard", label: "Deletion guard", sub: "Limits on what a sync may remove" },
  { id: "activate", label: "Review and activate", sub: "Every gate re-evaluated" },
];
const ORDER: string[] = ["draft", "ready_to_validate", "validated", "dry_run_reconciled", "active"];
const atLeast = (state: string, s: string) => state === "degraded" || ORDER.indexOf(state) >= ORDER.indexOf(s);

function defaultStep(state: string): StepId {
  switch (state) {
    case "draft": return "connect";
    case "ready_to_validate": return "validate";
    case "validated": return "dryrun";
    default: return "activate";
  }
}

const lines = (s: string) => s.split("\n").map((x) => x.trim()).filter(Boolean);
const privToText = (m?: Record<string, string[]>) => Object.entries(m ?? {}).map(([g, ms]) => `${g}: ${ms.join(", ")}`).join("\n");
const textToPriv = (s: string) => Object.fromEntries(lines(s).map((l) => {
  const [g, ...rest] = l.split(":");
  return [g.trim(), rest.join(":").split(",").map((x) => x.trim()).filter(Boolean)];
}).filter(([g]) => g));

function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return <label className="field">{label}{children}{hint && <span className="hint">{hint}</span>}</label>;
}

/** Hint under the SCIM base URL: the vendor's documented URL shape and plan note when the connection came from a preset. */
function scimUrlHint(preset: string | undefined, presets: ScimPreset[] | null | undefined): ReactNode {
  const p = preset ? presets?.find((x) => x.id === preset) : undefined;
  if (!p) return "HTTPS only.";
  return <>HTTPS only.{p.base_url_example ? <> {p.name} URLs look like <code>{p.base_url_example}</code>.</> : <> {p.name}'s URL shape is not confirmed; any HTTPS URL is accepted.</>} {p.hint}</>;
}

/** The config form of one step; saves only the fields that changed. */
function ConfigForm({ conn, step, onSaved }: { conn: Connection; step: "connect" | "scope" | "mapping"; onSaved: () => void }) {
  const rev = conn.pending_revision ?? conn.active_revision!;
  const cfg = rev.config;
  const tid = conn.template.id;
  const gov = GOVERNED[conn.connector_type]; // the connector types the server already had (vaults, ERP, AWS, ...)
  const writes = !gov || tid === "pam" || tid === "erp"; // the others only read
  const { data: presets } = useApi<ScimPreset[]>(cfg.preset ? "/scim/presets" : null);
  const toast = useToast();
  const [v, setV] = useState<Record<string, string>>({});
  useEffect(() => {
    setV({
      host: cfg.host ?? "", port: String(cfg.port ?? ""), bind_dn: cfg.bind_dn ?? "", ca_bundle: cfg.ca_bundle ?? "", org_url: cfg.org_url ?? "", tenant_id: cfg.tenant_id ?? "", cloud: cfg.cloud ?? "",
      customer: cfg.customer ?? "", domain: cfg.domain ?? "", base_url: cfg.base_url ?? "", tenant_host: cfg.tenant_host ?? "",
      interface: cfg.interface ?? "", api_version: cfg.api_version ?? "", hybrid: cfg.hybrid ? "true" : "false", use_dirsync: cfg.use_dirsync ? "true" : "false", time_zone: cfg.time_zone ?? "", technical_owner: cfg.technical_owner ?? "", business_owner: cfg.business_owner ?? "",
      base_dns: (cfg.base_dns ?? []).join("\n"), service_account_ous: (cfg.service_account_ous ?? []).join("\n"), user_filter: cfg.user_filter ?? "",
      group_filter: cfg.group_filter ?? "", exp_users: cfg.expected_counts ? String(cfg.expected_counts.users) : "",
      exp_groups: cfg.expected_counts ? String(cfg.expected_counts.groups) : "", privileged: privToText(cfg.privileged_expected),
      correlation_key: cfg.correlation_key ?? "", hr_id_attribute: cfg.hr_id_attribute ?? "", stale_days: String(cfg.stale_days ?? ""),
      sync_schedule: cfg.sync_schedule ?? "", write_mode: cfg.write_mode ?? "off", write_scope: (cfg.write_scope ?? []).join("\n"),
      sql_engine: cfg.sql?.engine ?? "", sql_host: cfg.sql?.host ?? "", sql_port: String(cfg.sql?.port ?? ""), sql_database: cfg.sql?.database ?? "",
      sql_username: cfg.sql?.username ?? "", sql_ca_bundle: cfg.sql?.ca_bundle ?? "", sql_mode: cfg.sql?.mode ?? "native",
      sql_max_rows: String(cfg.sql?.max_rows ?? ""), sql_accounts_query: cfg.sql?.app?.accounts_query ?? "",
      sql_entitlements_query: cfg.sql?.app?.entitlements_query ?? "",
      rest: restText(cfg.rest),
      ...settingValues(conn.connector_type, cfg.settings),
    });
    // Reset only when the saved config itself changes (not on credential changes),
    // so unsaved edits survive saving the credential.
  }, [rev.id, JSON.stringify(cfg)]); // eslint-disable-line react-hooks/exhaustive-deps
  const [secret, setSecret] = useState("");
  const [ref, setRef] = useState("");
  const { busy, run } = useAction();
  const set = (k: string) => (e: { target: { value: string } }) => setV((x) => ({ ...x, [k]: e.target.value }));
  const input = (k: string, label: string, hint?: ReactNode, props: Record<string, unknown> = {}) => (
    <Field label={label} hint={hint}><input className="input" value={v[k] ?? ""} onChange={set(k)} {...props} /></Field>
  );
  const flag = (k: string, label: string, hint?: ReactNode) => (
    <Field label={label} hint={hint}>
      <select className="input" value={v[k] ?? "false"} onChange={set(k)}><option value="false">No</option><option value="true">Yes</option></select>
    </Field>
  );
  const area = (k: string, label: string, hint?: ReactNode) => (
    <Field label={label} hint={hint}><textarea className="input" value={v[k] ?? ""} onChange={set(k)} rows={3} /></Field>
  );
  const save = async (e: FormEvent) => {
    e.preventDefault();
    const next: ConnConfig = {};
    const str = (k: keyof ConnConfig) => {
      const now = v[k as string] ?? "";
      if (now !== String(cfg[k] ?? "")) (next as Record<string, unknown>)[k] = now === "" ? null : now;
    };
    if (tid === "sql" && (step === "connect" || step === "scope")) {
      // the sql object is replaced as a whole by the server, so start from what is saved
      const prev = cfg.sql;
      const app = { ...(prev?.app ?? {}) };
      const q = (k: "accounts_query" | "entitlements_query", val: string) => { if (val.trim()) app[k] = val; else delete app[k]; };
      q("accounts_query", v.sql_accounts_query ?? "");
      q("entitlements_query", v.sql_entitlements_query ?? "");
      const sql: SQLConfig = { ...prev, engine: v.sql_engine, host: v.sql_host, username: v.sql_username, mode: v.sql_mode || "native" };
      for (const [k, val] of [["database", v.sql_database], ["ca_bundle", v.sql_ca_bundle]] as const) { if (val) sql[k] = val; else delete sql[k]; }
      for (const [k, val] of [["port", v.sql_port], ["max_rows", v.sql_max_rows]] as const) { if (val) sql[k] = Number(val); else delete sql[k]; }
      if (sql.mode === "app") sql.app = app; else delete sql.app;
      if (JSON.stringify(sql) !== JSON.stringify(prev)) next.sql = sql;
    }
    if (step === "connect") {
      (["host", "bind_dn", "ca_bundle", "org_url", "tenant_id", "cloud", "customer", "domain", "base_url", "tenant_host", "api_version", "interface", "time_zone", "technical_owner", "business_owner"] as const).forEach(str);
      if (v.port && Number(v.port) !== cfg.port) next.port = Number(v.port);
      for (const k of (tid === "entra" ? ["hybrid"] : tid === "ad" ? ["use_dirsync"] : []) as ("hybrid" | "use_dirsync")[]) {
        if ((v[k] === "true") !== !!cfg[k]) next[k] = v[k] === "true";
      }
      if (gov) {
        const sp = settingsPatch(conn.connector_type, v, cfg.settings);
        if (sp) next.settings = sp;
      }
      // the spec is sent as the text the admin wrote (JSON or YAML); the server parses and validates it strictly
      if (tid === "rest_generic" && v.rest !== restText(cfg.rest)) (next as Record<string, unknown>).rest = v.rest.trim() === "" ? null : v.rest;
    }
    if (step === "scope") {
      (["user_filter", "group_filter"] as const).forEach(str);
      if (v.base_dns !== (cfg.base_dns ?? []).join("\n")) next.base_dns = lines(v.base_dns);
      if (v.service_account_ous !== (cfg.service_account_ous ?? []).join("\n")) next.service_account_ous = lines(v.service_account_ous);
      const users = Number(v.exp_users || 0), groups = Number(v.exp_groups || 0);
      if (users !== (cfg.expected_counts?.users ?? 0) || groups !== (cfg.expected_counts?.groups ?? 0)) next.expected_counts = { users, groups };
      if (v.privileged !== privToText(cfg.privileged_expected)) next.privileged_expected = textToPriv(v.privileged);
    }
    if (step === "mapping") {
      (["correlation_key", "hr_id_attribute", "sync_schedule"] as const).forEach(str);
      if (Number(v.stale_days || 0) !== (cfg.stale_days ?? 0)) next.stale_days = Number(v.stale_days || 0);
      if (v.write_mode !== (cfg.write_mode ?? "off")) next.write_mode = v.write_mode as ConnConfig["write_mode"];
      if (writes && v.write_scope !== (cfg.write_scope ?? []).join("\n")) next.write_scope = lines(v.write_scope);
    }
    if (Object.keys(next).length === 0) {
      toast("Nothing changed", { kind: "info" });
      return;
    }
    const r = await run("save", () => readiness.patchConfig(conn.id, next));
    if (r) {
      toast(r.new_revision ? "Saved as a new draft revision; the active one keeps syncing" : r.invalidated.length
        ? `Saved. ${r.invalidated.length} item${r.invalidated.length === 1 ? "" : "s"} need new evidence: ${r.invalidated.slice(0, 3).join(", ")}${r.invalidated.length > 3 ? "…" : ""}`
        : "Saved", { kind: r.invalidated.length ? "info" : "ok" });
      onSaved();
    }
  };
  const saveCredential = async () => {
    const body = ref.trim() ? { reference: ref.trim() } : { secret };
    const r = await run("cred", () => readiness.setCredential(conn.id, body), () => "Credential stored. It is write-only and never shown again.");
    if (r) {
      setSecret("");
      setRef("");
      onSaved();
    }
  };
  return (
    <form className="stack" onSubmit={save}>
      {step === "connect" && (
        <>
          <div className="form-grid">
            {(tid === "ad" || tid === "ldap") && <>{input("host", "Domain controller or server", "Host name only; LDAPS on 636 or StartTLS on 389.")}{input("port", "Port", undefined, { inputMode: "numeric" })}{tid === "ad" && flag("use_dirsync", "Use the DirSync control", "Needs the Replicating Directory Changes right, which conflicts with least privilege. Leave off unless required.")}</>}
            {tid === "ldap" && <>
              {input("bind_dn", "Bind DN", "A dedicated read-only account (LLDAP: a member of lldap_strict_readonly), never the root DN. Its password is the credential below.")}
              {area("ca_bundle", "CA certificate (PEM)", "Public certificates only: the CA that signed the server certificate. Empty uses the system roots.")}
            </>}
            {tid === "okta" && input("org_url", "Org URL", "An Okta domain (*.okta.com) or a verified custom domain.")}
            {tid === "entra" && <>{input("tenant_id", "Tenant id", "The directory GUID from the Overview page, not a domain.")}{input("cloud", "Cloud", "global, usgov or china")}{flag("hybrid", "Hybrid tenant", "Yes when users are synced from an on-premises AD (enables the cross-link check to AD).")}</>}
            {tid === "google" && <>{input("customer", "Customer", "my_customer or the customer id")}{input("domain", "Primary domain")}</>}
            {tid === "workday" && <>{input("tenant_host", "Tenant host", "*.workday.com or *.myworkday.com")}{input("api_version", "Web Services version", "For example v44.0. Empty uses the connector default.")}{input("interface", "Interface", "get_workers or raas")}{input("time_zone", "Tenant time zone")}</>}
            {tid === "scim_app" && input("base_url", BASE_URL_FIELDS.scim_app.label, scimUrlHint(cfg.preset, presets))}
            {!gov && tid !== "scim_app" && BASE_URL_FIELDS[tid] && input("base_url", BASE_URL_FIELDS[tid].label, BASE_URL_FIELDS[tid].hint, { "aria-required": true })}
            {gov?.baseUrl && input("base_url", gov.baseUrl.label, gov.baseUrl.hint, { "aria-required": gov.baseUrl.required })}
            {gov?.settings.map((f) => <Fragment key={f.key}>{input(`settings.${f.key}`, f.label, f.hint, { "aria-required": !!f.required })}</Fragment>)}
            {tid === "rest_generic" && (
              <Field label="REST connector spec (JSON or YAML)"
                hint="Base URL (https only), auth type, the resources to read with their pagination and JSONPath mapping, and optional write operations as request templates. No secret goes here: the credential below is sealed. Errors name the field.">
                <textarea className="input mono" value={v.rest ?? ""} onChange={set("rest")} rows={14} spellCheck={false} placeholder={REST_EXAMPLE} />
              </Field>
            )}
            {tid === "sql" && <>
              {input("sql_engine", "Engine", "postgres, mysql, sqlserver or oracle")}
              {input("sql_host", "Host", "Host name or IP only. Production refuses loopback, private and metadata addresses.")}
              {input("sql_port", "Port", "Empty uses the engine's default (5432, 3306, 1433, 1521).", { inputMode: "numeric" })}
              {input("sql_database", "Database", "Oracle: the service name.")}
              {input("sql_username", "Database user", "A dedicated read-only user, never postgres, root, sa or SYS. Its password is the credential below.")}
              {area("sql_ca_bundle", "CA certificate (PEM)", "Public certificates only. TLS is always verified (host name and chain); empty uses the system roots.")}
              {input("sql_mode", "Mode", "native (the database's own users and roles) or app (your SELECT statements, set under Scope)")}
            </>}
            {input("technical_owner", "Technical owner", "Accountable for the connection and its findings (base.owner).")}
            {input("business_owner", "Business owner")}
          </div>
          {gov && gov.credential === null && (
            <Callout tone="info">This connection holds no credential: it reads a recorded snapshot from this tenant&apos;s directory.</Callout>
          )}
          {gov?.credential && (
            <fieldset className="card stack-sm" style={{ background: "var(--surface-2)" }}>
              <legend className="small"><b>{gov.credential.label}</b> {rev.credential.present ? <Badge tone="ok">stored sealed</Badge> : <Badge tone="warning">Missing</Badge>}</legend>
              <Field label="Secret" hint={`${gov.credential.hint} Write-only: sealed under the key, never returned, logged or exported. Tessera must open it to read the system, so a vault reference cannot be used here.`}>
                {gov.credential.area
                  ? <textarea className="input" rows={3} autoComplete="off" spellCheck={false} value={secret} onChange={(e) => setSecret(e.target.value)} />
                  : <input className="input" type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)} />}
              </Field>
              <div><Button size="sm" onClick={saveCredential} disabled={busy === "cred" || !secret}>Save credential</Button></div>
            </fieldset>
          )}
          {!gov && (
            <fieldset className="card stack-sm" style={{ background: "var(--surface-2)" }}>
              <legend className="small"><b>Credential</b> {rev.credential.present ? <Badge tone="ok">{rev.credential.kind} reference set</Badge> : <Badge tone="warning">Missing</Badge>}</legend>
              <div className="form-grid">
                <Field label="Vault or agent reference" hint="vault:<path> or agent:<id>/<name>. Preferred: the secret never reaches Tessera.">
                  <input className="input" value={ref} onChange={(e) => setRef(e.target.value)} placeholder="vault:kv/tessera/ad-corp" />
                </Field>
                <Field label="Or the secret" hint="Write-only. Never returned, logged or exported.">
                  <input className="input" type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)} disabled={!!ref.trim()} />
                </Field>
              </div>
              <div><Button size="sm" onClick={saveCredential} disabled={busy === "cred" || (!ref.trim() && !secret)}>Save credential</Button></div>
            </fieldset>
          )}
        </>
      )}
      {step === "scope" && (
        <div className="form-grid">
          {(tid === "ad" || tid === "ldap") && (
            <>
              {area("base_dns", "Base DNs", "One per line. A typo returns zero objects, not an error.")}
              {area("service_account_ous", "Service-account OUs", "Where service accounts and gMSAs live (ad.scope.service_accounts).")}
              {input("user_filter", "People filter", "AD: (&(objectCategory=person)(objectClass=user)) excludes computers.")}
              {input("group_filter", "Group filter")}
            </>
          )}
          {tid === "sql" && <>
            {input("sql_max_rows", "Row cap", "Empty uses 100000. A read that reaches the cap is partial and the deletion guard holds every removal.", { inputMode: "numeric" })}
            {v.sql_mode === "app" && <>
              {area("sql_accounts_query", "Accounts SELECT", "One SELECT with no placeholders. Columns: id (required), username, email, display_name, status.")}
              {area("sql_entitlements_query", "Entitlements SELECT", "Optional. Columns: account (an id or username above), entitlement, description. Writes (create, disable, grant) are set on the provisioning target.")}
            </>}
          </>}
          {input("exp_users", "Expected users", "From the directory's own console (base.scope.count).", { inputMode: "numeric" })}
          {input("exp_groups", "Expected groups", undefined, { inputMode: "numeric" })}
          {tid !== "workday" && !gov && area("privileged", "Privileged groups and expected members", "One group per line: Group name: member, member. Members not listed become RF-08 findings.")}
        </div>
      )}
      {step === "mapping" && (
        <div className="form-grid">
          {input("correlation_key", "Correlation key", "Immutable: objectGUID, entryUUID, id. Never email or UPN.")}
          {input("hr_id_attribute", "HR id attribute", "Tier-1 correlation to the HR worker id (for AD usually employeeID).")}
          {input("stale_days", "Dormancy threshold (days)", "Default 90 (PCI DSS v4 8.2.6).", { inputMode: "numeric" })}
          {input("sync_schedule", "Sync schedule", "Full sync at least weekly plus incremental.")}
          {writes && (
            <Field label="Write-back" hint="Write-enabled connections need a second approver (DR-10).">
              <select className="input" value={v.write_mode ?? "off"} onChange={set("write_mode")}>
                <option value="off">Off (read only)</option><option value="dry_run">Dry run</option><option value="scoped">Scoped</option>
              </select>
            </Field>
          )}
          {writes && (v.write_mode ?? "off") !== "off" && area("write_scope", "Write scope", gov ? "One per line: the safe ids or roles write-back may change. A vault's write scope is checked against the service user's own rights." : "One per line: the containers or groups write-back may change.")}
        </div>
      )}
      <div className="row"><Button type="submit" variant="primary" disabled={busy === "save"}>{busy === "save" ? "Saving…" : "Save"}</Button><span className="small faint">Editing evidence-bearing fields makes that evidence stale.</span></div>
    </form>
  );
}

function ValidateStep({ conn }: { conn: Connection }) {
  const { data: run } = useApi<RunView>(conn.latest_validation_id ? `/connections/${conn.id}/validations/${conn.latest_validation_id}` : null);
  const { busy, report, run: act } = useAction();
  const toast = useToast();
  const draft = conn.state === "draft";
  const fix = async (check: string) => {
    const cfg = (conn.pending_revision ?? conn.active_revision!).config;
    const r = await act("fix", () => readiness.patchConfig(conn.id, { demo_fixed_checks: [...new Set([...(cfg.demo_fixed_checks ?? []), check])] }));
    if (r) toast(`Simulated fix applied to ${check}. Re-run validation.`, { kind: "info" });
  };
  const failing = run?.results.filter((r) => r.status !== "pass" && r.status !== "warn") ?? [];
  return (
    <div className="stack">
      <p className="muted">Read-only checks against the system: TLS, bind, least privilege read from effective rights, scope, paging, change tracking. Nothing is written to the directory. Live evidence stays fresh for 24 hours.</p>
      {draft && <Callout tone="warn">Finish Connect, Scope and Mapping and move the connection to Ready to validate first.</Callout>}
      <GateCallout report={report} connectionId={conn.id} />
      <div className="row">
        <Button variant="primary" icon={<Play size={14} />} disabled={draft || busy === "validate"} onClick={() => act("validate", () => readiness.validate(conn.id), (r) => `Validation ${r.status}: ${r.summary.passed} passed, ${r.summary.failed + r.summary.errors} failed, ${r.summary.blocked} blocked`)}>
          {busy === "validate" ? "Running checks…" : run ? "Re-run validation" : "Run validation"}
        </Button>
        {run && <Link to={`/admin/connections/${conn.id}/validation/${run.id}`}>Open validation results</Link>}
      </div>
      {run && (
        <>
          <div className="grid g4">
            <Kpi label="Passed" value={run.summary.passed + run.summary.warned} />
            <Kpi label="Failed" value={run.summary.failed + run.summary.errors} tone={run.summary.failed ? "critical" : undefined} />
            <Kpi label="Blocked" value={run.summary.blocked} tone={run.summary.blocked ? "warning" : undefined} />
            <Kpi label="Duration" value={`${run.duration_ms} ms`} sub={run.simulated ? <SimulatedBadge scenario={run.scenario} /> : undefined} />
          </div>
          {run.stale && <Callout tone="warn">{run.stale_reason}</Callout>}
          {failing.length > 0 && (
            <div className="card flush">
              <div className="card-h"><h2>Not passing</h2></div>
              <ul className="result-list">
                {failing.map((r) => (
                  <li key={r.item_id + r.check_id}>
                    <div className="row tight"><Badge tone={r.status === "blocked" ? "neutral" : "critical"}>{r.status}</Badge><b>{r.item_title}</b><code className="xs faint">{r.check_id}</code></div>
                    <div className="small">{r.message}</div>
                    {Object.keys(r.observed).length > 0 && <div className="xs faint">{observedText(r.observed)}</div>}
                    {r.fixable && conn.simulated && (
                      <Button size="sm" icon={<Wand2 size={13} />} disabled={busy === "fix"} onClick={() => fix(r.check_id)}>Apply simulated fix</Button>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function DryRunStep({ conn }: { conn: Connection }) {
  const { data: dr } = useApi<DryRunView>(conn.latest_dry_run_id ? `/connections/${conn.id}/dry-runs/${conn.latest_dry_run_id}` : null);
  const { busy, report, run } = useAction();
  const allowed = conn.state === "validated" || conn.state === "dry_run_reconciled";
  return (
    <div className="stack">
      <p className="muted">Stages a snapshot into staging tables only and reconciles it against the HR source: tier 1 HR id, tier 2 immutable link, tier 3 email (proposals only). Nothing reaches the live graph until activation.</p>
      {!allowed && <Callout tone="warn">The connection must be Validated before a dry run.</Callout>}
      <GateCallout report={report} connectionId={conn.id} />
      <div className="row">
        <Button variant="primary" icon={<FlaskConical size={14} />} disabled={!allowed || busy === "dry"} onClick={() => run("dry", () => readiness.dryRun(conn.id), (r) => `Dry run staged ${r.counts.accounts} accounts: ${r.findings.length} findings`)}>
          {busy === "dry" ? "Reconciling…" : dr ? "Run the dry run again" : "Run dry run"}
        </Button>
        {dr && <Link to={`/admin/connections/${conn.id}/reconciliation/${dr.id}`}>Open reconciliation report</Link>}
      </div>
      {dr && (
        <>
          <div className="grid g4">
            <Kpi label="Accounts staged" value={dr.counts.accounts} sub={`${dr.counts.groups} groups · ${dr.counts.memberships} memberships`} />
            <Kpi label="Correlated" value={`${dr.counts.correlated_pct}%`} sub={`${dr.counts.proposed} email proposals`} />
            <Kpi label="Orphans" value={dr.kpis.orphans} tone={dr.kpis.orphans ? "warning" : undefined} />
            <Kpi label="Open critical / high" value={(dr.open_by_severity.critical ?? 0) + (dr.open_by_severity.high ?? 0)} tone={(dr.open_by_severity.critical ?? 0) ? "critical" : undefined} />
          </div>
          <Callout tone="neutral">{dr.activation_note}</Callout>
        </>
      )}
      {conn.state === "validated" && conn.next && (
        <div className="stack-sm">
          <Button icon={<CircleCheck size={14} />} disabled={busy === "rec" || conn.next.blocking.length > 0} onClick={() => run("rec", () => readiness.transition(conn.id, "dry_run_reconciled"), () => "Dry run reconciled")}>Mark dry run reconciled</Button>
          <BlockerList blocking={conn.next.blocking} connectionId={conn.id} />
        </div>
      )}
    </div>
  );
}

function ActivateStep({ conn }: { conn: Connection }) {
  const { busy, report, run } = useAction();
  const confirm = useConfirm();
  const nav = useNavigate();
  const blocking = report?.blocking ?? (conn.state === "dry_run_reconciled" ? conn.next?.blocking ?? [] : []);
  const ready = conn.state === "dry_run_reconciled" && blocking.length === 0;
  const retire = async () => {
    if ((await confirm({ title: `Retire ${conn.name}?`, body: "The connection stops syncing; data already synced stays read-only for the retention period. Retiring needs step-up once DR-10 lands.", confirmLabel: "Retire", danger: true })) === null) return;
    const r = await run("retire", () => readiness.retire(conn.id), () => `${conn.name} retired`);
    if (r) nav("/admin/connections");
  };
  return (
    <div className="stack">
      {conn.state === "active" || conn.state === "degraded" ? (
        <Callout tone="ok" icon={<ShieldCheck size={16} />}>
          {conn.name} is {STATE_LABEL[conn.state].toLowerCase()} (revision {conn.active_revision?.rev}, activated by {conn.active_revision?.activated_by}).
          {conn.update_in_progress ? " A new draft revision is in progress; the active one keeps syncing until it is activated." : " Editing the configuration opens a new draft revision."}
        </Callout>
      ) : (
        <p className="muted">Activation re-evaluates every gate from stored evidence (not cached), checks that live evidence is fresh, and swaps the revision in atomically. Then the first sync runs.</p>
      )}
      <GateCallout report={report} connectionId={conn.id} />
      {conn.state !== "active" && conn.state !== "degraded" && (
        <div className="stack-sm">
          <div><Button variant="primary" icon={<Power size={14} />} disabled={busy === "activate" || !ready} title={ready ? undefined : "Resolve the blockers listed below; the server enforces the same gate"} onClick={() => run("activate", () => readiness.activate(conn.id), (c) => `${c.name} is active`)}>
            {busy === "activate" ? "Activating…" : "Activate"}
          </Button></div>
          {!ready && (
            <div className="small">
              <b>{conn.state !== "dry_run_reconciled" ? `Activation needs Dry run reconciled; the revision is ${STATE_LABEL[conn.state]}.` : "Blocking activation:"}</b>
              <BlockerList blocking={blocking} connectionId={conn.id} />
            </div>
          )}
        </div>
      )}
      <div className="row" style={{ borderTop: "1px solid var(--border)", paddingTop: 12 }}>
        <Button variant="danger" size="sm" icon={<Trash2 size={13} />} disabled={busy === "retire"} onClick={retire}>Retire connection</Button>
      </div>
    </div>
  );
}

export function ConnectionDetail() {
  const { id = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const { data: conn, error, reload } = useApi<Connection>(`/connections/${id}`);
  const { data: cl, reload: reloadCl } = useApi<Checklist>(`/connections/${id}/checklist`);
  const toast = useToast();
  const [dialog, setDialog] = useState<{ kind: "attest" | "attest_instead" | "skip"; item: ChecklistItem } | null>(null);
  const focus = params.get("item");
  const current = (params.get("step") as StepId | null) ?? (conn ? defaultStep(conn.state) : "connect");
  const setStep = (s: string) => setParams((p) => { const n = new URLSearchParams(p); n.set("step", s); n.delete("item"); return n; }, { replace: true });
  const refresh = () => { reload(); reloadCl(); };
  const steps: Step[] = useMemo(() => {
    if (!conn) return [];
    const st = conn.state;
    const live = st === "active" || st === "degraded";
    return WIZARD_STEPS.map((s) => {
      switch (s.id) {
        case "type": return { ...s, done: true, disabled: true, reason: "The template is pinned when the connection is created" };
        case "validate": return { ...s, done: atLeast(st, "validated"), disabled: st === "draft" && !live, reason: "Move to Ready to validate first" };
        case "dryrun": return { ...s, done: atLeast(st, "dry_run_reconciled"), disabled: !atLeast(st, "validated"), reason: "Validation must pass first" };
        case "activate": return { ...s, done: live, disabled: !atLeast(st, "dry_run_reconciled"), reason: "The dry run must be reconciled first" };
        // the guard can be set at any time, before the first sync included; it is never "done"
        case "guard": return { ...s, done: false, disabled: !!conn.retired_at, reason: "A retired connection has no deletion guard" };
        default: return { ...s, done: atLeast(st, "ready_to_validate") };
      }
    });
  }, [conn]);
  if (!conn) return <Page title="Connection" crumbs={[["Settings"], ["Connections", "/admin/connections"], ["…"]]}><Loading error={error} kind="page" /></Page>;
  const rev = conn.pending_revision ?? conn.active_revision;
  const step = steps.find((s) => s.id === current && !s.disabled) ? current : defaultStep(conn.state);
  const submit = async (text: string, day?: string) => {
    if (!dialog) return;
    if (dialog.kind === "attest") {
      await readiness.attest(conn.id, dialog.item.id, text);
      toast(`Attested: ${dialog.item.title}`);
    } else {
      await readiness.skip(conn.id, dialog.item.id, text, day);
      toast(`Skipped: ${dialog.item.title}. It stays listed as a known gap.`, { kind: "info" });
    }
    setDialog(null);
    refresh();
  };
  return (
    <Page
      title={conn.name}
      crumbs={[["Settings"], ["Connections", "/admin/connections"], [conn.name]]}
      badge={<span className="row tight"><VendorLogo vendor={vendorForType(conn.system, conn.connector_type)} size={32} /><StateBadge state={conn.state} />{conn.simulated && <SimulatedBadge />}</span>}
      sub={<>Template <code>{conn.template.pin}</code> ({conn.template.display_name} {conn.template.version}{conn.template.overlay_version ? `, overlay v${conn.template.overlay_version}` : ""}) · system <code>{conn.system}</code> · role {conn.role.replace("_", " ")}{rev ? ` · revision ${rev.rev}` : ""}</>}
    >
      <div className="wizard">
        <div className="stack">
          <Stepper steps={steps} current={step} onSelect={setStep} />
          {step === "guard" ? (
            <SourceDeletionGuard kind="connection" id={conn.id} heading={`${WIZARD_STEPS.findIndex((s) => s.id === "guard") + 1}. Deletion guard`} />
          ) : (
          <div className="card stack">
            <h2>{WIZARD_STEPS.findIndex((s) => s.id === step) + 1}. {WIZARD_STEPS.find((s) => s.id === step)!.label}</h2>
            {(step === "connect" || step === "scope" || step === "mapping") && (
              conn.retired_at ? <EmptyState title="Retired">A retired connection cannot be edited.</EmptyState> : <ConfigForm conn={conn} step={step} onSaved={refresh} />
            )}
            {step === "validate" && <ValidateStep conn={conn} />}
            {step === "dryrun" && <DryRunStep conn={conn} />}
            {step === "activate" && <ActivateStep conn={conn} />}
            {conn.state === "draft" && conn.next && (step === "connect" || step === "scope" || step === "mapping") && <ReadyToValidate conn={conn} onDone={() => { refresh(); setStep("validate"); }} />}
          </div>
          )}
        </div>
        <div className="wizard-side">
          {cl ? (
            <ChecklistPanel
              data={cl}
              focusItem={focus}
              score={conn.score ? <ScoreCell score={conn.score.score} band={conn.score.band} /> : undefined}
              onAttest={(item) => setDialog({ kind: "attest", item })}
              onAttestInstead={(item) => setDialog({ kind: "attest_instead", item })}
              onSkip={(item) => setDialog({ kind: "skip", item })}
              onUnskip={async (item) => {
                try {
                  await readiness.unskip(conn.id, item.id);
                  toast(`Un-skipped ${item.title}`);
                  refresh();
                } catch (e) {
                  toast((e as Error).message, { kind: "error" });
                }
              }}
            />
          ) : <div className="card"><Loading kind="block" /></div>}
        </div>
      </div>
      {dialog?.kind === "attest" && (
        <ReasonDialog title={`Attest: ${dialog.item.title}`} body={dialog.item.why} label="Note (what you checked, ideally with a change ticket)" minLength={10} confirmLabel="Attest" onCancel={() => setDialog(null)} onSubmit={submit} />
      )}
      {dialog?.kind === "attest_instead" && (
        <AttestInsteadDialog
          item={dialog.item}
          onCancel={() => setDialog(null)}
          onSubmit={async (body) => {
            await readiness.attestInstead(conn.id, dialog.item.id, body);
            toast(`Attested instead of the live check: ${dialog.item.title}`);
            setDialog(null);
            refresh();
          }}
        />
      )}
      {dialog?.kind === "skip" && (
        <ReasonDialog title={`Skip: ${dialog.item.title}`} body="A skipped Recommended item earns no score and stays visible as a known gap until its review date." label="Reason" minLength={20} confirmLabel="Skip with reason" date={{ label: "Review by (optional)", hint: "Defaults to 90 days. The skip expires then and the item needs attention again." }} onCancel={() => setDialog(null)} onSubmit={submit} />
      )}
    </Page>
  );
}

function ReadyToValidate({ conn, onDone }: { conn: Connection; onDone: () => void }) {
  const { busy, report, run } = useAction();
  const blocking = report?.blocking ?? conn.next?.blocking ?? [];
  return (
    <div className="stack-sm" style={{ borderTop: "1px solid var(--border)", paddingTop: 12 }}>
      <div className="row">
        <Button variant="primary" disabled={busy === "rtv"} onClick={async () => { if (await run("rtv", () => readiness.transition(conn.id, "ready_to_validate"), () => "Ready to validate")) onDone(); }}>Mark ready to validate</Button>
        <span className="small faint">Needs a valid config, a credential and every Required attestation.</span>
      </div>
      <BlockerList blocking={blocking} connectionId={conn.id} empty={<span className="small" style={{ color: "var(--ok)" }}>Nothing blocks this step.</span>} />
    </div>
  );
}
