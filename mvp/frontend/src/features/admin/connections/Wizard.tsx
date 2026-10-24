/**
 * Connection setup wizard with the checklist panel (§10.2): choose type → connect → scope →
 * mapping → validate → dry run → review and activate. Every step's gate is enforced by the
 * server; the UI shows the same blockers the server returns.
 */
import { FormEvent, ReactNode, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { CircleCheck, FlaskConical, Play, Power, ShieldCheck, Trash2, Wand2 } from "lucide-react";
import {
  Checklist, ChecklistItem, ConnConfig, Connection, DryRunView, RunView, ScimPreset, readiness, useApi,
} from "../../../api";
import { SourceDeletionGuard } from "../SourceDeletionGuard";
import {
  Badge, Button, Callout, AttestInsteadDialog, ChecklistPanel, EmptyState, Kpi, Loading, Page, ReasonDialog, Step, Stepper, useConfirm, useToast,
} from "../../../components";
import {
  BlockerList, CONNECTOR_TYPES, GateCallout, STATE_LABEL, ScoreCell, SimulatedBadge, StateBadge, observedText, useAction,
} from "./shared";

// ---------------------------------------------------------------- step 1
export function NewConnection() {
  const nav = useNavigate();
  const toast = useToast();
  const { data: existing } = useApi<{ connector_type?: string; legacy?: boolean }[]>("/connections");
  const { data: presets } = useApi<ScimPreset[]>("/scim/presets");
  const [type, setType] = useState("demo-ad");
  const [name, setName] = useState("Active Directory (demo)");
  const [busy, setBusy] = useState(false);
  // A SCIM vendor tile has the id "scim:<preset>" and creates a scim_app connection pre-filled from the preset.
  const presetOf = (id: string) => (id.startsWith("scim:") ? (presets ?? []).find((p) => `scim:${p.id}` === id) : undefined);
  const pick = (id: string) => {
    setType(id);
    setName(presetOf(id)?.name ?? CONNECTOR_TYPES.find((t) => t.id === id)?.label ?? "");
  };
  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const preset = presetOf(type);
      const c = await readiness.create(preset
        ? { name: name.trim(), connector_type: "scim_app", config: { preset: preset.id, correlation_key: preset.mapping.username } }
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
          <div className="type-grid" role="radiogroup" aria-label="Connector type">
            {CONNECTOR_TYPES.map((t) => (
              <label key={t.id} className={`type-card ${type === t.id ? "on" : ""}`}>
                <input type="radio" name="type" value={t.id} checked={type === t.id} onChange={() => pick(t.id)} />
                <span className="stack-sm">
                  <span className="row tight"><b>{t.label}</b>{t.demo ? <Badge tone="info">Simulated</Badge> : <Badge tone="outline">Needs DR-10+</Badge>}{taken(t.id) && <Badge>Exists</Badge>}</span>
                  <span className="small faint">{t.blurb}</span>
                </span>
              </label>
            ))}
          </div>
          {(["Cloud & SaaS", "Identity providers"] as const).map((cat) => {
            const tiles = (presets ?? []).filter((p) => p.category === cat);
            return tiles.length === 0 ? null : (
              <div key={cat} className="stack-sm">
                <h3>{cat} (SCIM 2.0)</h3>
                {/* Logos arrive with the app-gallery picker (PR #551, simple-icons); until then each tile shows a neutral glyph. */}
                <div className="type-grid" role="radiogroup" aria-label={`${cat} SCIM presets`}>
                  {tiles.map((p) => (
                    <label key={p.id} className={`type-card ${type === `scim:${p.id}` ? "on" : ""}`}>
                      <input type="radio" name="type" value={`scim:${p.id}`} checked={type === `scim:${p.id}`} onChange={() => pick(`scim:${p.id}`)} />
                      <span className="stack-sm">
                        <span className="row tight"><span aria-hidden="true">▣</span><b>{p.name}</b><Badge tone="outline">Needs DR-10+</Badge></span>
                        <span className="small faint">{p.publisher}. {p.hint}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            );
          })}
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

// ---------------------------------------------------------------- detail
type StepId = "type" | "connect" | "scope" | "mapping" | "validate" | "dryrun" | "activate";
const WIZARD_STEPS: { id: StepId; label: string; sub: string }[] = [
  { id: "type", label: "Choose type", sub: "Template pinned" },
  { id: "connect", label: "Connect", sub: "Endpoint, credential, owners" },
  { id: "scope", label: "Scope", sub: "Base DNs, filters, expected counts" },
  { id: "mapping", label: "Mapping", sub: "Correlation key, HR id, status" },
  { id: "validate", label: "Validate", sub: "Read-only live checks" },
  { id: "dryrun", label: "Dry run", sub: "Staging snapshot and reconciliation" },
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
  const { data: presets } = useApi<ScimPreset[]>(cfg.preset ? "/scim/presets" : null);
  const toast = useToast();
  const [v, setV] = useState<Record<string, string>>({});
  useEffect(() => {
    setV({
      host: cfg.host ?? "", port: String(cfg.port ?? ""), bind_dn: cfg.bind_dn ?? "", ca_bundle: cfg.ca_bundle ?? "", org_url: cfg.org_url ?? "", tenant_id: cfg.tenant_id ?? "", cloud: cfg.cloud ?? "",
      customer: cfg.customer ?? "", domain: cfg.domain ?? "", base_url: cfg.base_url ?? "", tenant_host: cfg.tenant_host ?? "",
      interface: cfg.interface ?? "", time_zone: cfg.time_zone ?? "", technical_owner: cfg.technical_owner ?? "", business_owner: cfg.business_owner ?? "",
      base_dns: (cfg.base_dns ?? []).join("\n"), service_account_ous: (cfg.service_account_ous ?? []).join("\n"), user_filter: cfg.user_filter ?? "",
      group_filter: cfg.group_filter ?? "", exp_users: cfg.expected_counts ? String(cfg.expected_counts.users) : "",
      exp_groups: cfg.expected_counts ? String(cfg.expected_counts.groups) : "", privileged: privToText(cfg.privileged_expected),
      correlation_key: cfg.correlation_key ?? "", hr_id_attribute: cfg.hr_id_attribute ?? "", stale_days: String(cfg.stale_days ?? ""),
      sync_schedule: cfg.sync_schedule ?? "", write_mode: cfg.write_mode ?? "off",
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
    if (step === "connect") {
      (["host", "bind_dn", "ca_bundle", "org_url", "tenant_id", "cloud", "customer", "domain", "base_url", "tenant_host", "interface", "time_zone", "technical_owner", "business_owner"] as const).forEach(str);
      if (v.port && Number(v.port) !== cfg.port) next.port = Number(v.port);
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
            {(tid === "ad" || tid === "ldap") && <>{input("host", "Domain controller or server", "Host name only; LDAPS on 636 or StartTLS on 389.")}{input("port", "Port", undefined, { inputMode: "numeric" })}</>}
            {tid === "ldap" && <>
              {input("bind_dn", "Bind DN", "A dedicated read-only account (LLDAP: a member of lldap_strict_readonly), never the root DN. Its password is the credential below.")}
              {area("ca_bundle", "CA certificate (PEM)", "Public certificates only: the CA that signed the server certificate. Empty uses the system roots.")}
            </>}
            {tid === "okta" && input("org_url", "Org URL", "An Okta domain (*.okta.com) or a verified custom domain.")}
            {tid === "entra" && <>{input("tenant_id", "Tenant id", "The directory GUID from the Overview page, not a domain.")}{input("cloud", "Cloud", "global, usgov or china")}</>}
            {tid === "google" && <>{input("customer", "Customer", "my_customer or the customer id")}{input("domain", "Primary domain")}</>}
            {tid === "workday" && <>{input("tenant_host", "Tenant host", "*.workday.com or *.myworkday.com")}{input("interface", "Interface", "get_workers or raas")}{input("time_zone", "Tenant time zone")}</>}
            {tid === "scim_app" && input("base_url", "SCIM base URL", scimUrlHint(cfg.preset, presets))}
            {input("technical_owner", "Technical owner", "Accountable for the connection and its findings (base.owner).")}
            {input("business_owner", "Business owner")}
          </div>
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
          {input("exp_users", "Expected users", "From the directory's own console (base.scope.count).", { inputMode: "numeric" })}
          {input("exp_groups", "Expected groups", undefined, { inputMode: "numeric" })}
          {tid !== "workday" && area("privileged", "Privileged groups and expected members", "One group per line: Group name: member, member. Members not listed become RF-08 findings.")}
        </div>
      )}
      {step === "mapping" && (
        <div className="form-grid">
          {input("correlation_key", "Correlation key", "Immutable: objectGUID, entryUUID, id. Never email or UPN.")}
          {input("hr_id_attribute", "HR id attribute", "Tier-1 correlation to the HR worker id (for AD usually employeeID).")}
          {input("stale_days", "Dormancy threshold (days)", "Default 90 (PCI DSS v4 8.2.6).", { inputMode: "numeric" })}
          {input("sync_schedule", "Sync schedule", "Full sync at least weekly plus incremental.")}
          <Field label="Write-back" hint="Write-enabled connections need a second approver (DR-10).">
            <select className="input" value={v.write_mode ?? "off"} onChange={set("write_mode")}>
              <option value="off">Off (read only)</option><option value="dry_run">Dry run</option><option value="scoped">Scoped</option>
            </select>
          </Field>
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
      badge={<span className="row tight"><StateBadge state={conn.state} />{conn.simulated && <SimulatedBadge />}</span>}
      sub={<>Template <code>{conn.template.pin}</code> ({conn.template.display_name} {conn.template.version}{conn.template.overlay_version ? `, overlay v${conn.template.overlay_version}` : ""}) · system <code>{conn.system}</code> · role {conn.role.replace("_", " ")}{rev ? ` · revision ${rev.rev}` : ""}</>}
    >
      <div className="wizard">
        <div className="stack">
          <Stepper steps={steps} current={step} onSelect={setStep} />
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
          {!conn.retired_at && <SourceDeletionGuard kind="connection" id={conn.id} />}
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
