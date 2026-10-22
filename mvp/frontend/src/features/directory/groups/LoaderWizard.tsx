import { ReactNode, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Connection, GrpLoader, LoaderPending, LoaderRun, groupLoaders, groups, loaderPending, useApi } from "../../../api";
import { Badge, Button, Callout, Drawer, Loading, Stepper, useToast } from "../../../components";
import { PlanView } from "./LoaderRuns";
import { errText, useLoad } from "./hooks";
import {
  ATTRIBUTES, LOADER_TYPES, LoaderForm, ON_MISSING, SCHEDULES, SUBJECT_SOURCES, buildSpec, emptyForm, isSqlType, scheduleText, stepProblems, typeInfo, typeLabel,
} from "./loaderModel";

type StepId = "type" | "source" | "people" | "schedule" | "review";
const STEPS: { id: StepId; label: string; sub: string }[] = [
  { id: "type", label: "Kind of source", sub: "Where members come from" },
  { id: "source", label: "Source", sub: "Where to read it" },
  { id: "people", label: "People and groups", sub: "How people are matched" },
  { id: "schedule", label: "Schedule and safety", sub: "When, and what holds a run" },
  { id: "review", label: "Review", sub: "Save and preview" },
];

function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return <label className="field"><span>{label}</span>{children}{hint && <span className="hint">{hint}</span>}</label>;
}

/**
 * Add a membership source: pick the kind, configure it, say how people are matched, set the schedule and the
 * failsafes, then save. A source that is not a SQL query is saved turned off and previewed at once, so the plan
 * it computes is seen before anything changes; a SQL source waits for a second administrator's approval.
 */
export function LoaderWizard({ folder, onClose, onSaved }: { folder?: string; onClose: () => void; onSaved?: (l: GrpLoader | null) => void }) {
  const toast = useToast();
  const [step, setStep] = useState<StepId>("type");
  const [f, setF] = useState<LoaderForm>(() => emptyForm(folder ?? ""));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<{ loader?: GrpLoader; pending?: LoaderPending; preview?: LoaderRun | null; previewError?: string } | null>(null);
  const set = (p: Partial<LoaderForm>) => setF((x) => ({ ...x, ...p }));
  const folders = useLoad(() => groups.listFolders(), "folders");
  const allGroups = useLoad(() => groups.listGroups({ limit: 500 }), "wizard-groups");
  const conns = useApi<Connection[]>(f.type === "connector_groups" ? "/connections" : null);
  const info = typeInfo(f.type ?? "");
  const sql = isSqlType(f.type ?? "");

  const order = STEPS.map((s) => s.id);
  const idx = order.indexOf(step);
  const problems = useMemo(() => (step === "review" ? [] : stepProblems(step, f)), [step, f]);
  const allProblems = useMemo(() => (["type", "source", "people", "schedule"] as const).flatMap((s) => stepProblems(s, f)), [f]);
  const stepDone = (s: StepId) => s !== "review" && order.indexOf(s) < idx && stepProblems(s, f).length === 0;
  const goTo = (s: StepId) => {
    // a step opens only when every step before it is complete
    const ok = order.slice(0, order.indexOf(s)).every((p) => p === "review" || stepProblems(p, f).length === 0);
    if (ok) setStep(s);
  };

  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await groupLoaders.create(buildSpec(f));
      if (loaderPending(r)) {
        setResult({ pending: r });
        onSaved?.(null);
        return;
      }
      let preview: LoaderRun | null = null;
      let previewError: string | undefined;
      try {
        const pr = await groupLoaders.run(r.id, "preview");
        preview = "id" in pr ? await groupLoaders.runDetail(r.id, pr.id) : null;
      } catch (e) {
        previewError = errText(e);
      }
      setResult({ loader: r, preview, previewError });
      onSaved?.(r);
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const turnOn = async () => {
    if (!result?.loader) return;
    setBusy(true);
    try {
      const r = await groupLoaders.update(result.loader.id, { status: "enabled", version: result.loader.version });
      if (!loaderPending(r)) setResult({ ...result, loader: r });
      toast("Source turned on");
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    const l = result.loader;
    return (
      <Drawer title={result.pending ? "Waiting for a second administrator" : "Source saved"} sub={f.name} onClose={onClose} wide
        footer={<>
          {l && l.status === "disabled" && <Button variant="primary" disabled={busy} onClick={turnOn}>Turn on</Button>}
          <Button onClick={onClose}>{l?.status === "disabled" ? "Leave it off" : "Done"}</Button>
        </>}>
        <div className="stack">
          {result.pending && (
            <Callout tone="info">
              A source that runs a SQL query needs a second administrator to approve it before it exists. The request is filed (change request {result.pending.change_request_id.slice(0, 8)}).{" "}
              <Link to="/admin/change-requests">Open the change requests</Link>. Once it is approved, open the group's Source tab, or Loaders, to preview it.
            </Callout>
          )}
          {l && (
            <>
              <Callout tone={l.status === "disabled" ? "info" : "ok"}>
                {l.status === "disabled"
                  ? "The source is saved turned off. Read the preview below; turn it on when the plan looks right. Nothing has changed in any group."
                  : "The source is on. It runs on its schedule; a run that would remove too many people is held for approval."}
              </Callout>
              <h3 style={{ fontSize: "var(--fs-lg)" }}>Preview</h3>
              {result.previewError && <Callout tone="bad">The preview could not run: {result.previewError}</Callout>}
              {result.preview?.plan ? <PlanView plan={result.preview.plan} /> : !result.previewError && <p className="muted">The preview has no plan.</p>}
            </>
          )}
        </div>
      </Drawer>
    );
  }

  const next = () => { if (!problems.length) setStep(order[idx + 1]); };
  const sub = (
    <span>{info ? typeLabel(info.id) : "New source"}{sql && <> <Badge tone="warning">Second admin approves</Badge></>}</span>
  );

  return (
    <Drawer title="Add a membership source" sub={sub} onClose={onClose} wide
      footer={<>
        <Button onClick={onClose}>Cancel</Button>
        {idx > 0 && <Button onClick={() => setStep(order[idx - 1])}>Back</Button>}
        {step !== "review"
          ? <Button variant="primary" onClick={next} disabled={problems.length > 0}>Next</Button>
          : <Button variant="primary" onClick={save} disabled={busy || allProblems.length > 0}>{busy ? "Saving…" : sql ? "Submit for approval" : "Save and preview"}</Button>}
      </>}>
      <div className="stack">
        <Stepper label="Steps of adding a source" current={step} onSelect={(s) => goTo(s as StepId)}
          steps={STEPS.map((s) => ({ ...s, done: stepDone(s.id) }))} />
        {step === "type" && (
          <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
            <legend className="sr-only">Kind of source</legend>
            {LOADER_TYPES.map((t) => (
              <label key={t.id} className="row tight" style={{ alignItems: "flex-start", gap: 10, padding: 8, border: "1px solid var(--border)", borderRadius: "var(--r-md)" }}>
                <input type="radio" name="loader-type" checked={f.type === t.id} onChange={() => set({ type: t.id, startEnabled: !!t.sql })} style={{ marginTop: 4 }} />
                <span>
                  <b>{t.label}</b>{t.sql && <> <Badge tone="warning">Second admin approves</Badge></>}
                  <span className="muted small" style={{ display: "block" }}>{t.blurb}</span>
                </span>
              </label>
            ))}
            <p className="small muted">LDAP, SFTP and HR or student feeds are designed but not available yet.</p>
          </fieldset>
        )}
        {step === "source" && (
          <div className="stack-sm">
            <Field label="Name" hint="Shown in lists and the audit log."><input className="input" value={f.name} onChange={(e) => set({ name: e.target.value })} data-autofocus /></Field>
            <Field label="Put the groups in this folder" hint="The loader owns the groups it makes here; they are read-only for everyone else.">
              <select className="input" value={f.targetFolder} onChange={(e) => set({ targetFolder: e.target.value })}>
                <option value="">Choose a folder…</option>
                {(folders.data?.items ?? []).filter((x) => x.managed_by === "ui").map((x) => <option key={x.id} value={x.id}>{x.name || "(root)"}</option>)}
              </select>
            </Field>
            {(f.type === "sql_simple" || f.type === "sql_group_list") && (
              <>
                <Callout tone="warn">This runs a query you write on a database file. It must be one SELECT or WITH statement, and it runs in a read-only transaction. Creating or changing it needs a second administrator's approval.</Callout>
                <div className="row" role="radiogroup" aria-label="Where the database is">
                  <label className="row tight"><input type="radio" name="sqlengine" checked={f.sqlEngine === "file"} onChange={() => set({ sqlEngine: "file" })} /><span>A database file</span></label>
                  <label className="row tight"><input type="radio" name="sqlengine" checked={f.sqlEngine === "postgres"} onChange={() => set({ sqlEngine: "postgres" })} /><span>A Postgres server</span></label>
                </div>
                {f.sqlEngine === "file"
                  ? <Field label="Database file" hint="A file name under the loader data directory."><input className="input" value={f.database} onChange={(e) => set({ database: e.target.value })} placeholder="hr.db" /></Field>
                  : (
                    <>
                      <Field label="Connection string" hint="postgres://user:password@host/database. Sealed, never shown again. Production needs sslmode=verify-full (the default). Use a read-only login."><input className="input" type="password" autoComplete="off" value={f.dsn} onChange={(e) => set({ dsn: e.target.value })} /></Field>
                      <Field label="CA certificate (optional)" hint="PEM, if the server's certificate is from a private CA."><textarea className="input mono" rows={3} value={f.caPem} onChange={(e) => set({ caPem: e.target.value })} /></Field>
                    </>
                  )}
                {f.type === "sql_simple" && <Field label="Group" hint="Every row's person becomes a member of this group."><input className="input" value={f.group} onChange={(e) => set({ group: e.target.value })} placeholder="staff" /></Field>}
                <Field label="Query" hint={f.type === "sql_simple" ? "Returns a subject_id column, and optionally subject_source." : "Returns group_name and subject_id, and optionally subject_source."}>
                  <textarea className="input mono" rows={5} value={f.query} onChange={(e) => set({ query: e.target.value })} placeholder="SELECT employee_id AS subject_id FROM staff WHERE active = 1" />
                </Field>
                {f.type === "sql_group_list" && <Field label="Groups query (optional)" hint="Returns group_name, display_name and description."><textarea className="input mono" rows={3} value={f.groupsQuery} onChange={(e) => set({ groupsQuery: e.target.value })} /></Field>}
                <Field label="Incremental query (optional)" hint="Returns group_name, subject_id, op (add or remove) and seq for the rows after @cursor.">
                  <textarea className="input mono" rows={3} value={f.incrementalQuery} onChange={(e) => set({ incrementalQuery: e.target.value })} />
                </Field>
                {f.incrementalQuery.trim() && <Field label="Incremental interval (seconds)" hint="30 to 86400."><input className="input" inputMode="numeric" value={f.incrementalSecs} onChange={(e) => set({ incrementalSecs: e.target.value })} /></Field>}
              </>
            )}
            {f.type === "csv" && (
              <>
                <div className="row" role="radiogroup" aria-label="Where the CSV is">
                  <label className="row tight"><input type="radio" name="csvfrom" checked={f.csvFrom === "path"} onChange={() => set({ csvFrom: "path" })} /><span>A file</span></label>
                  <label className="row tight"><input type="radio" name="csvfrom" checked={f.csvFrom === "url"} onChange={() => set({ csvFrom: "url" })} /><span>An https URL</span></label>
                </div>
                {f.csvFrom === "path"
                  ? <Field label="File" hint="A file name under the loader data directory."><input className="input" value={f.csvPath} onChange={(e) => set({ csvPath: e.target.value })} placeholder="staff.csv" /></Field>
                  : (
                    <>
                      <Field label="URL" hint="No credentials in the URL; the server refuses addresses inside the network."><input className="input" type="url" value={f.csvUrl} onChange={(e) => set({ csvUrl: e.target.value })} placeholder="https://example.com/staff.csv" /></Field>
                      <Field label="Bearer token (optional)" hint="Sent with the request, kept sealed, and never shown again."><input className="input" type="password" autoComplete="off" value={f.csvSecret} onChange={(e) => set({ csvSecret: e.target.value })} /></Field>
                    </>
                  )}
                <div className="row" role="radiogroup" aria-label="Groups in the CSV">
                  <label className="row tight"><input type="radio" name="csvgroup" checked={f.csvGroupBy === "one"} onChange={() => set({ csvGroupBy: "one" })} /><span>Every row joins one group</span></label>
                  <label className="row tight"><input type="radio" name="csvgroup" checked={f.csvGroupBy === "column"} onChange={() => set({ csvGroupBy: "column" })} /><span>A column names the group</span></label>
                </div>
                {f.csvGroupBy === "one"
                  ? <Field label="Group"><input className="input" value={f.group} onChange={(e) => set({ group: e.target.value })} /></Field>
                  : (
                    <>
                      <Field label="Group column" hint="The header of the column."><input className="input" value={f.groupColumn} onChange={(e) => set({ groupColumn: e.target.value })} /></Field>
                      <Field label="Display name column (optional)"><input className="input" value={f.displayColumn} onChange={(e) => set({ displayColumn: e.target.value })} /></Field>
                    </>
                  )}
                <Field label="People column" hint="The header of the column that names the person."><input className="input" value={f.subjectColumn} onChange={(e) => set({ subjectColumn: e.target.value })} /></Field>
                <Field label="Delimiter (optional)" hint="One character; a comma if empty."><input className="input" maxLength={1} value={f.delimiter} onChange={(e) => set({ delimiter: e.target.value })} style={{ width: 80 }} /></Field>
              </>
            )}
            {f.type === "scim" && (
              <>
                <Field label="Service URL" hint="The SCIM 2.0 root, such as https://example.com/scim/v2."><input className="input" type="url" value={f.scimUrl} onChange={(e) => set({ scimUrl: e.target.value })} /></Field>
                <div className="row" role="radiogroup" aria-label="How to sign in to the provider">
                  <label className="row tight"><input type="radio" name="scimauth" checked={f.scimAuth === "bearer"} onChange={() => set({ scimAuth: "bearer" })} /><span>Bearer token</span></label>
                  <label className="row tight"><input type="radio" name="scimauth" checked={f.scimAuth === "client_credentials"} onChange={() => set({ scimAuth: "client_credentials" })} /><span>OAuth client credentials</span></label>
                </div>
                {f.scimAuth === "client_credentials" && (
                  <>
                    <Field label="Token URL"><input className="input" type="url" value={f.scimTokenUrl} onChange={(e) => set({ scimTokenUrl: e.target.value })} /></Field>
                    <Field label="Client id"><input className="input" value={f.scimClientId} onChange={(e) => set({ scimClientId: e.target.value })} autoComplete="off" /></Field>
                    <Field label="Scope (optional)"><input className="input" value={f.scimScope} onChange={(e) => set({ scimScope: e.target.value })} /></Field>
                  </>
                )}
                <Field label={f.scimAuth === "bearer" ? "Bearer token" : "Client secret"} hint="Sealed, never shown again."><input className="input" type="password" autoComplete="off" value={f.scimSecret} onChange={(e) => set({ scimSecret: e.target.value })} /></Field>
                <Field label="Group filter (optional)" hint={<>A SCIM filter the provider applies, such as <span className="sys">displayName sw "eng"</span>.</>}><input className="input mono" value={f.scimGroupFilter} onChange={(e) => set({ scimGroupFilter: e.target.value })} /></Field>
                <Field label="User filter (optional)" hint="Limits who can be a member."><input className="input mono" value={f.scimUserFilter} onChange={(e) => set({ scimUserFilter: e.target.value })} /></Field>
                <Field label="Name prefix (optional)"><input className="input" value={f.namePrefix} onChange={(e) => set({ namePrefix: e.target.value })} /></Field>
                <label className="row tight"><input type="checkbox" checked={f.scimOnlyActive} onChange={(e) => set({ scimOnlyActive: e.target.checked })} /><span>Leave out users the provider marks inactive</span></label>
              </>
            )}
            {(f.type === "ldap_simple" || f.type === "ldap_group_list") && (
              <>
                <Callout tone="info">The connection always uses TLS (LDAPS on 636, or StartTLS on 389). From a hosted server a directory on a private address is not reachable.</Callout>
                <Field label="Directory URL" hint="ldaps://host, or ldap://host for StartTLS."><input className="input" value={f.ldapUrl} onChange={(e) => set({ ldapUrl: e.target.value })} placeholder="ldaps://ldap.example.com" /></Field>
                <Field label="Bind DN" hint="A read-only account."><input className="input" value={f.ldapBindDn} onChange={(e) => set({ ldapBindDn: e.target.value })} autoComplete="off" /></Field>
                <Field label="Bind password" hint="Sealed, never shown again."><input className="input" type="password" autoComplete="off" value={f.ldapSecret} onChange={(e) => set({ ldapSecret: e.target.value })} /></Field>
                <Field label="CA certificate (optional)" hint="PEM, for a private CA."><textarea className="input mono" rows={3} value={f.caPem} onChange={(e) => set({ caPem: e.target.value })} /></Field>
                <Field label="Base DN"><input className="input" value={f.ldapBaseDn} onChange={(e) => set({ ldapBaseDn: e.target.value })} placeholder="ou=people,dc=example,dc=com" /></Field>
                <Field label="Filter" hint={f.type === "ldap_simple" ? "Selects the people." : "Selects the group entries."}><input className="input mono" value={f.ldapFilter} onChange={(e) => set({ ldapFilter: e.target.value })} /></Field>
                <Field label="Search"><select className="input" value={f.ldapScope} onChange={(e) => set({ ldapScope: e.target.value as "sub" | "one" })}><option value="sub">The whole subtree</option><option value="one">One level</option></select></Field>
                {f.type === "ldap_simple" ? (
                  <>
                    <Field label="Attribute that names the person" hint="uid, mail, employeeNumber…"><input className="input" value={f.ldapSubjectAttr} onChange={(e) => set({ ldapSubjectAttr: e.target.value })} /></Field>
                    <Field label="Group"><input className="input" value={f.group} onChange={(e) => set({ group: e.target.value })} /></Field>
                  </>
                ) : (
                  <>
                    <Field label="Group name attribute (optional)" hint="cn if empty."><input className="input" value={f.ldapGroupNameAttr} onChange={(e) => set({ ldapGroupNameAttr: e.target.value })} /></Field>
                    <Field label="Member attribute (optional)" hint="member if empty; memberUid for POSIX groups."><input className="input" value={f.ldapMemberAttr} onChange={(e) => set({ ldapMemberAttr: e.target.value })} /></Field>
                    <Field label="RDN that names the person (optional)" hint="When members are DNs: uid takes uid=alice,… as alice. Leave empty when the value is the id itself."><input className="input" value={f.ldapMemberRdn} onChange={(e) => set({ ldapMemberRdn: e.target.value })} /></Field>
                  </>
                )}
                <Field label="Name prefix (optional)"><input className="input" value={f.namePrefix} onChange={(e) => set({ namePrefix: e.target.value })} /></Field>
              </>
            )}
            {f.type === "connector_groups" && (
              <>
                <Field label="Connection" hint="Every group of this connection becomes a native group.">
                  {conns.data
                    ? (
                      <select className="input" value={f.connectionId} onChange={(e) => set({ connectionId: e.target.value })}>
                        <option value="">Choose a connection…</option>
                        {conns.data.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.system})</option>)}
                      </select>
                    )
                    : conns.error ? <input className="input" value={f.connectionId} onChange={(e) => set({ connectionId: e.target.value })} placeholder="Connection id" /> : <Loading kind="block" />}
                </Field>
                <Field label="Name prefix (optional)" hint="Put in front of each group's name."><input className="input" value={f.namePrefix} onChange={(e) => set({ namePrefix: e.target.value })} /></Field>
              </>
            )}
            {f.type === "attribute" && (
              <>
                <Field label="Attribute" hint="One group per value.">
                  <select className="input" value={f.attribute} onChange={(e) => set({ attribute: e.target.value })}>{ATTRIBUTES.map((a) => <option key={a} value={a}>{a}</option>)}</select>
                </Field>
                <Field label="Name prefix (optional)"><input className="input" value={f.prefix} onChange={(e) => set({ prefix: e.target.value })} placeholder="dept_" /></Field>
                <label className="row tight"><input type="checkbox" checked={f.onlyActive} onChange={(e) => set({ onlyActive: e.target.checked })} /><span>Only identities that are active</span></label>
              </>
            )}
            {f.type === "recent_memberships" && (
              <>
                <Field label="Group to look back on" hint="The name of the group, such as app:staff."><input className="input" value={f.sourceGroup} onChange={(e) => set({ sourceGroup: e.target.value })} /></Field>
                <Field label="Days" hint="1 to 366."><input className="input" inputMode="numeric" value={f.days} onChange={(e) => set({ days: e.target.value })} style={{ width: 100 }} /></Field>
                <label className="row tight"><input type="checkbox" checked={f.includeCurrent} onChange={(e) => set({ includeCurrent: e.target.checked })} /><span>Include the people who are members now</span></label>
                <Field label="Group to fill"><input className="input" value={f.group} onChange={(e) => set({ group: e.target.value })} /></Field>
              </>
            )}
          </div>
        )}
        {step === "people" && (
          <div className="stack-sm">
            {f.type === "csv" && (
              <>
                <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
                  <legend style={{ fontWeight: 600 }}>The people column holds</legend>
                  {SUBJECT_SOURCES.map((s) => (
                    <label key={s.id} className="row tight" style={{ alignItems: "flex-start" }}>
                      <input type="radio" name="subject-source" checked={f.subjectSource === s.id} onChange={() => set({ subjectSource: s.id })} style={{ marginTop: 4 }} />
                      <span>{s.label}<span className="muted small" style={{ display: "block" }}>{s.hint}</span></span>
                    </label>
                  ))}
                </fieldset>
                {f.subjectSource === "account" && <Field label="System"><input className="input" value={f.accountSystem} onChange={(e) => set({ accountSystem: e.target.value })} /></Field>}
                <Field label="Or a column that says it, row by row (optional)" hint="Overrides the choice above."><input className="input" value={f.sourceColumn} onChange={(e) => set({ sourceColumn: e.target.value })} /></Field>
              </>
            )}
            {f.type === "scim" && (
              <>
                <Field label="Identify each member by" hint="Members come with the provider's own ids, so the users are read to find this.">
                  <select className="input" value={f.scimSubject} onChange={(e) => set({ scimSubject: e.target.value as LoaderForm["scimSubject"] })}>
                    <option value="userName">User name</option><option value="email">Email address</option><option value="externalId">External id</option><option value="id">The provider's own id (a connected account)</option>
                  </select>
                </Field>
                <Field label="Match that against" hint="Blank: email addresses for email, identity external ids otherwise. Type a system's name to match its accounts.">
                  <input className="input" value={f.scimSubjectSource} onChange={(e) => set({ scimSubjectSource: e.target.value })} placeholder={f.scimSubject === "email" ? "email" : "identity"} />
                </Field>
              </>
            )}
            {(f.type === "ldap_simple" || f.type === "ldap_group_list") && (
              <Field label="Match the values against" hint="Blank: email for mail, identity external ids otherwise. Or email, tessera_id, or a system's name for its accounts.">
                <input className="input" value={f.scimSubjectSource} onChange={(e) => set({ scimSubjectSource: e.target.value })} />
              </Field>
            )}
            {sql && <Callout tone="neutral">Matching is by the <span className="sys">subject_source</span> column of the query: <span className="sys">identity</span> (external id, also the default), <span className="sys">email</span>, <span className="sys">tessera_id</span>, or the name of a connected system for its account ids.</Callout>}
            {!sql && !["csv", "scim", "ldap_simple", "ldap_group_list"].includes(f.type ?? "") && <Callout tone="neutral">This source names people by their Tessera identity, so no matching is needed.</Callout>}
            <p className="small muted">Matching is exact. A person who matches nobody is never dropped silently: they are listed as unresolved and tried again on every run.</p>
            <Field label="Group name template" hint={<>Turns the source's group name into the group's name. Exactly one <span className="sys">{"{{.Name}}"}</span>.</>}>
              <input className="input mono" value={f.nameTemplate} onChange={(e) => set({ nameTemplate: e.target.value })} />
            </Field>
            <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
              <legend style={{ fontWeight: 600 }}>When the source stops returning a group</legend>
              {ON_MISSING.map((o) => (
                <label key={o.id} className="row tight" style={{ alignItems: "flex-start" }}>
                  <input type="radio" name="on-missing" checked={f.onMissing === o.id} onChange={() => set({ onMissing: o.id })} style={{ marginTop: 4 }} />
                  <span>{o.label}<span className="muted small" style={{ display: "block" }}>{o.hint}</span></span>
                </label>
              ))}
            </fieldset>
            <Field label="Only keep people who are also in (optional)" hint="Everyone the source names who is not in this group is left out.">
              <select className="input" value={f.andGroup} onChange={(e) => set({ andGroup: e.target.value })}>
                <option value="">No extra condition</option>
                {(allGroups.data?.items ?? []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
              </select>
            </Field>
          </div>
        )}
        {step === "schedule" && (
          <div className="stack-sm">
            <Field label="Run">
              <select className="input" value={f.schedule} onChange={(e) => set({ schedule: e.target.value })}>{SCHEDULES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}</select>
            </Field>
            {f.schedule === "custom" && <Field label="Cron (five fields, UTC)" hint="Minute, hour, day of month, month, day of week."><input className="input mono" value={f.cron} onChange={(e) => set({ cron: e.target.value })} placeholder="15 2 * * 1-5" /></Field>}
            <h3 style={{ fontSize: "var(--fs-lg)", marginTop: 8 }}>Failsafes</h3>
            <p className="small muted">A run that breaks one of these limits is held: nothing is applied, the plan is kept, and the owners of the folder get a task to approve or reject it.</p>
            <div className="row" style={{ alignItems: "flex-end" }}>
              <Field label="Most removed from a group (%)"><input className="input" inputMode="decimal" value={f.failsafe.maxRemovedPercent} onChange={(e) => set({ failsafe: { ...f.failsafe, maxRemovedPercent: e.target.value } })} style={{ width: 120 }} /></Field>
              <Field label="Most removed from a group (people)"><input className="input" inputMode="numeric" value={f.failsafe.maxRemoved} onChange={(e) => set({ failsafe: { ...f.failsafe, maxRemoved: e.target.value } })} style={{ width: 120 }} /></Field>
              <Field label="Smallest group the source may return"><input className="input" inputMode="numeric" value={f.failsafe.minGroupSize} onChange={(e) => set({ failsafe: { ...f.failsafe, minGroupSize: e.target.value } })} style={{ width: 120 }} placeholder="none" /></Field>
              <Field label="Most groups emptied in a run (%)"><input className="input" inputMode="decimal" value={f.failsafe.maxEmptiedPercent} onChange={(e) => set({ failsafe: { ...f.failsafe, maxEmptiedPercent: e.target.value } })} style={{ width: 120 }} /></Field>
              <Field label="Most people left unresolved (%)"><input className="input" inputMode="decimal" value={f.failsafe.maxUnresolvedPercent} onChange={(e) => set({ failsafe: { ...f.failsafe, maxUnresolvedPercent: e.target.value } })} style={{ width: 120 }} /></Field>
            </div>
          </div>
        )}
        {step === "review" && (
          <div className="stack-sm">
            <dl className="kv">
              <dt>Name</dt><dd>{f.name}</dd>
              <dt>Kind</dt><dd>{typeLabel(f.type ?? "")}</dd>
              <dt>Folder</dt><dd>{(folders.data?.items ?? []).find((x) => x.id === f.targetFolder)?.name ?? f.targetFolder}</dd>
              <dt>Runs</dt><dd>{scheduleText(f.schedule === "custom" ? f.cron : f.schedule)}</dd>
              <dt>If a group goes missing</dt><dd>{ON_MISSING.find((o) => o.id === f.onMissing)?.label}</dd>
            </dl>
            {sql
              ? (
                <>
                  <Callout tone="warn">A second administrator must approve this before it exists. The query is part of the request, so they approve exactly what will run. After it is approved you can preview it from the group's Source tab.</Callout>
                  <label className="row tight"><input type="checkbox" checked={f.startEnabled} onChange={(e) => set({ startEnabled: e.target.checked })} /><span>Start turned on (turning it on later needs another approval)</span></label>
                </>
              )
              : <Callout tone="info">It is saved turned off, and a preview of the first run is computed right away. Nothing changes in any group until you turn it on.</Callout>}
            {allProblems.length > 0 && <Callout tone="bad">{allProblems.join(" ")}</Callout>}
            {err && <Callout tone="bad">{err}</Callout>}
          </div>
        )}
        {problems.length > 0 && step !== "type" && <p className="small muted" role="status">{problems[0]}</p>}
      </div>
    </Drawer>
  );
}
