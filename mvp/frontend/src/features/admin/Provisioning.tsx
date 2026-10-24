import { FormEvent, useEffect, useState } from "react";
import { FlaskConical, Play, RotateCcw, Settings2, XCircle } from "lucide-react";
import {
  Connection, ProvDryRun, ProvKind, ProvOp, ProvOpDetail, ProvStatus, ProvTarget, ProvTargetInput, fmtDate, provisioning, relTime, useApi,
} from "../../api";
import { Badge, Button, Callout, DataTable, SidePanel, useToast } from "../../components";

const KIND: Record<ProvKind, string> = {
  create_account: "Create account", update_account: "Update account", disable_account: "Disable account", delete_account: "Delete account",
  add_entitlement: "Add to group", remove_entitlement: "Remove from group",
};
const STATUS: Record<ProvStatus, { label: string; tone: "ok" | "critical" | "warning" | "info" | "neutral"; help: string }> = {
  queued: { label: "Queued", tone: "neutral", help: "Waiting to be sent to the target." },
  sent: { label: "Sent", tone: "info", help: "Being sent to the target." },
  pending_verification: { label: "Pending verification", tone: "warning", help: "The target accepted the change. Tessera has not yet read it back, so its own records still show the old state." },
  verified: { label: "Verified", tone: "ok", help: "A re-read of the target shows the change. Tessera's records were updated in the same step." },
  mismatch: { label: "Mismatch", tone: "critical", help: "The target accepted the change but a re-read does not show it. A finding was raised and Tessera's records were left alone." },
  failed: { label: "Failed", tone: "critical", help: "The target refused the change or could not be reached after the retries. Tessera's records were left alone, so the item it was for is still open." },
  cancelled: { label: "Cancelled", tone: "neutral", help: "Withdrawn by an operator. Nothing was changed in Tessera." },
};
const SOURCE: Record<string, string> = { jml: "Joiner / mover / leaver", review: "Access review", jit: "JIT access", leastpriv: "Least privilege", api: "API" };
const ORDER: ProvStatus[] = ["queued", "sent", "pending_verification", "verified", "mismatch", "failed", "cancelled"];
const INFLIGHT = new Set<ProvStatus>(["queued", "sent", "pending_verification"]);

interface OpList { items: ProvOp[]; counts: Partial<Record<ProvStatus, number>> }

/** Admin → Provisioning: the changes sent to target systems and whether a re-read confirmed them (issue #103). */
const VAULT: Record<string, string> = { cyberark: "CyberArk safes", delinea: "Delinea folders", beyondtrust: "BeyondTrust smart rules", sap: "SAP roles", oracle: "Oracle Fusion roles" };
const JSON_KINDS: Record<string, string> = { servicenow: "ServiceNow", atlassian: "Atlassian Cloud" }; // targets whose credential is JSON

export function Provisioning() {
  const { data, error, reload } = useApi<OpList>("/provisioning/ops?limit=500");
  const [open, setOpen] = useState<string | null>(null);
  const live = data?.items.some((o) => INFLIGHT.has(o.status));
  useEffect(() => {
    if (!live) return;
    const t = window.setInterval(reload, 5000);
    return () => window.clearInterval(t);
  }, [live, reload]);
  return (
    <div className="stack">
      <Targets />
      <div className="card stack-sm">
        <div className="row wrap" style={{ gap: 8, justifyContent: "space-between" }}>
          <h2 style={{ margin: 0 }}>Operations</h2>
          <RunNow />
        </div>
        <div className="row wrap" style={{ gap: 6 }} aria-label="Operations by status">
          {ORDER.filter((s) => (data?.counts[s] ?? 0) > 0).map((s) => (
            <Badge key={s} tone={STATUS[s].tone} title={STATUS[s].help}>{STATUS[s].label} {data?.counts[s]}</Badge>
          ))}
          {data && Object.keys(data.counts).length === 0 && <span className="small faint">No operation yet.</span>}
        </div>
      </div>
      <DataTable
        id="provisioning-ops"
        rows={data?.items ?? null}
        error={error}
        rowKey={(r) => r.id}
        initialSort={["created", -1]}
        onRowClick={(r) => setOpen(r.id)}
        activeKey={open}
        onRefresh={reload}
        rowLabel={(r) => `${KIND[r.kind]} ${r.target} ${STATUS[r.status].label}`}
        columns={[
          { id: "created", header: "Queued", sort: (r) => r.created_at, cell: (r) => <span className="small nowrap" title={fmtDate(r.created_at)}>{relTime(r.created_at.replace("Z", ""))}</span> },
          { id: "kind", header: "Change", sort: (r) => r.kind, cell: (r) => <span className="small"><b>{KIND[r.kind]}</b></span> },
          { id: "target", header: "Account / group", sort: (r) => r.target, cell: (r) => <span className="small">{r.target}</span> },
          { id: "system", header: "Target", sort: (r) => r.connection_name, cell: (r) => <span className="small">{r.connection_name}</span>, hideNarrow: true },
          { id: "status", header: "Status", sort: (r) => ORDER.indexOf(r.status), cell: (r) => <Badge tone={STATUS[r.status].tone}>{STATUS[r.status].label}</Badge> },
          { id: "attempts", header: "Tries", num: true, sort: (r) => r.attempts, cell: (r) => <span className="small tnum">{r.attempts}</span>, hideNarrow: true },
          { id: "source", header: "From", sort: (r) => r.source, cell: (r) => <span className="small">{SOURCE[r.source] ?? r.source}</span>, hideNarrow: true },
          { id: "error", header: "Detail", csv: (r) => r.last_error ?? "", cell: (r) => r.last_error ? <span className="xs truncate" style={{ display: "block", maxWidth: 320 }}>{r.last_error}</span> : <span className="faint xs">—</span>, hideNarrow: true },
        ]}
        searchText={(r) => `${KIND[r.kind]} ${r.kind} ${r.target} ${r.connection_name} ${r.status} ${r.source} ${r.requested_by} ${r.last_error ?? ""}`}
        searchPlaceholder="Search account, group, connection or error…"
        chips={3}
        filters={[
          { id: "status", label: "Status", options: ORDER.map((s) => ({ value: s, label: STATUS[s].label })), get: (r) => r.status },
          { id: "kind", label: "Change", options: (Object.keys(KIND) as ProvKind[]).map((k) => ({ value: k, label: KIND[k] })), get: (r) => r.kind },
          { id: "source", label: "From", options: Object.entries(SOURCE).map(([value, label]) => ({ value, label })), get: (r) => r.source },
        ]}
        empty="No change has been sent to a target yet. Turn write-back on for a connection above, then run a leaver, a review revoke or a JIT expiry in that system."
      />
      {open && <OpPanel id={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

function RunNow() {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      const s = await provisioning.run();
      toast(`${s.processed} operation${s.processed === 1 ? "" : "s"} processed: ${s.verified} verified, ${s.mismatch} mismatched, ${s.failed} failed, ${s.retrying} to retry`);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return <Button size="sm" icon={<Play size={13} />} disabled={busy} onClick={run}>Run now</Button>;
}

// ---------------------------------------------------------------- targets

function Targets() {
  const { data, reload } = useApi<ProvTarget[]>("/provisioning/targets");
  const [edit, setEdit] = useState<ProvTarget | "new" | null>(null);
  const [dry, setDry] = useState<ProvTarget | null>(null);
  return (
    <div className="card stack-sm">
      <div className="row wrap" style={{ gap: 8, justifyContent: "space-between" }}>
        <h2 style={{ margin: 0 }}>Target systems</h2>
        <Button size="sm" icon={<Settings2 size={13} />} onClick={() => setEdit("new")}>Configure a target</Button>
      </div>
      <p className="small muted" style={{ margin: 0 }}>
        With <b>write-back</b> on, a change in that system goes to the target first and Tessera's own records change only after a re-read confirms it.
        With it off (the default) Tessera changes its own records at once and nothing reaches the target.
      </p>
      {data && data.length === 0 && <p className="small faint" style={{ margin: 0 }}>No target is configured.</p>}
      {data && data.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Connection</th><th>Type</th><th>Address</th><th>Write-back</th><th>Agent resource</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {data.map((t) => (
                <tr key={t.connection_id}>
                  <td className="small"><b>{t.connection_name}</b> <span className="faint">· {t.system}</span></td>
                  <td className="small">{t.kind === "scim" ? `SCIM 2.0${t.dialect === "entra" ? " (Entra)" : ""}` : t.kind === "okta" ? "Okta API" : VAULT[t.kind] ?? JSON_KINDS[t.kind] ?? "Dev fake"}{t.fault ? <span className="faint"> · {t.fault.replace("_", " ")}</span> : null}</td>
                  <td className="small"><code className="xs">{t.base_url}</code></td>
                  <td><Badge tone={t.write_back ? "ok" : "neutral"}>{t.write_back ? "On" : "Off"}</Badge></td>
                  <td className="small">{t.kind === "scim" && !t.agent_id ? <DiscoveryCell target={t} onDone={reload} /> : <span className="faint">n/a</span>}</td>
                  <td>
                    <Button size="sm" onClick={() => setEdit(t)}>Edit</Button>{" "}
                    {["scim", "okta", "fake"].includes(t.kind) && !t.agent_id && <Button size="sm" variant="ghost" icon={<FlaskConical size={13} />} onClick={() => setDry(t)}>Dry run</Button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {edit && <TargetPanel target={edit === "new" ? null : edit} onClose={() => setEdit(null)} />}
      {dry && <DryRunPanel target={dry} onClose={() => setDry(null)} />}
    </div>
  );
}

/** Whether the SCIM service advertises the Agent resource (issue #542). Read-only: Tessera does not provision /Agents yet. */
function DiscoveryCell({ target, onDone }: { target: ProvTarget; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const d = target.discovery;
  const check = async () => {
    setBusy(true);
    setErr(null);
    try {
      await provisioning.discover(target.connection_id);
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack-sm">
      {!d ? <span className="faint">Not checked</span> : d.error && !d.agent_advertised
        ? <Badge tone="warning">Check failed</Badge>
        : <Badge tone={d.agent_advertised ? "info" : "neutral"}>{d.agent_advertised ? "Advertised" : "Not advertised"}</Badge>}
      {d && <div className="xs faint">{relTime(d.checked_at)}{d.error ? ` · ${d.error}` : ""}</div>}
      {err && <div className="xs" role="alert">{err}</div>}
      <Button size="sm" variant="ghost" disabled={busy} onClick={() => void check()}>{busy ? "Checking…" : d ? "Check again" : "Check"}</Button>
    </div>
  );
}

/** Shows what a change would send to the target, before write-back is on: reads happen, writes are only listed. */
function DryRunPanel({ target, onClose }: { target: ProvTarget; onClose: () => void }) {
  const [kind, setKind] = useState<ProvKind>("add_entitlement");
  const [username, setUsername] = useState("");
  const [group, setGroup] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<ProvDryRun | null>(null);
  const entitlement = kind === "add_entitlement" || kind === "remove_entitlement";
  const run = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setRes(null);
    try {
      setRes(await provisioning.dryRun(target.connection_id, { kind, username: username.trim(), ...(entitlement ? { group_name: group.trim() } : {}) }));
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <SidePanel title={`Dry run: ${target.connection_name}`} onClose={onClose}>
      <form className="stack-sm" onSubmit={run}>
        <p className="small muted" style={{ margin: 0 }}>
          Pick a change and see the requests Tessera would make to this target. The target is read; nothing is changed. Write-back is <b>{target.write_back ? "on" : "off"}</b> for this connection.
        </p>
        {err && <Callout tone="bad">{err}</Callout>}
        <label className="field">Change
          <select className="input" value={kind} onChange={(e) => setKind(e.target.value as ProvKind)}>
            {Object.entries(KIND).map(([k, label]) => <option key={k} value={k}>{label}</option>)}
          </select>
        </label>
        <label className="field">Account (user name in the target)<input className="input" required maxLength={200} value={username} onChange={(e) => setUsername(e.target.value)} /></label>
        {entitlement && <label className="field">Group name<input className="input" required maxLength={200} value={group} onChange={(e) => setGroup(e.target.value)} /></label>}
        <div className="row"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Reading the target…" : "Show what would be sent"}</Button></div>
      </form>
      {res && (
        <div className="stack-sm" aria-live="polite">
          <h3 style={{ margin: "8px 0 0" }}>{res.writes === 0 ? "Nothing would be changed" : `${res.writes} change${res.writes === 1 ? "" : "s"} would be sent`}</h3>
          {res.error && <Callout tone="warn">The change stopped before its last step: {res.error}</Callout>}
          <ol className="small stack-sm" style={{ margin: 0, paddingLeft: 18 }}>
            {res.steps.map((s, i) => (
              <li key={i}>
                <Badge tone={s.sent ? "neutral" : "warning"}>{s.sent ? `Read ${s.status}` : "Held back"}</Badge> <code className="xs">{s.method} {s.url}</code>
                {s.body && <pre className="xs" style={{ margin: "4px 0 0", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{s.body}</pre>}
              </li>
            ))}
          </ol>
          <p className="xs faint" style={{ margin: 0 }}>A held-back request is answered with an empty success, so a change that needs the answer to its first write (a new account's id) may show only that first write.</p>
        </div>
      )}
    </SidePanel>
  );
}

function TargetPanel({ target, onClose }: { target: ProvTarget | null; onClose: () => void }) {
  const toast = useToast();
  const conns = useApi<Connection[]>(target ? null : "/connections");
  const [conn, setConn] = useState(target?.connection_id ?? "");
  const [kind, setKind] = useState<ProvTarget["kind"]>(target?.kind ?? "scim");
  const [url, setUrl] = useState(target?.base_url ?? "");
  const [dialect, setDialect] = useState(target?.dialect ?? "standard");
  const [fault, setFault] = useState(target?.fault ?? "none");
  const [token, setToken] = useState("");
  const [writeBack, setWriteBack] = useState(target?.write_back ?? false);
  const [onDeprovision, setOnDeprovision] = useState<"disable" | "delete">(target?.on_deprovision ?? "disable");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // legacy (pre-readiness) entries have no id and no target to configure
  const usable = (conns.data ?? []).filter((c) => c.id && !c.legacy && !c.retired_at);
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const body: ProvTargetInput = { kind, base_url: url, write_back: writeBack, on_deprovision: onDeprovision };
    if (kind === "scim") body.dialect = dialect;
    if (kind === "fake") body.fault = fault;
    if (token) body.token = token;
    try {
      await provisioning.putTarget(conn, body);
      toast(`Target saved. Write-back is ${writeBack ? "on" : "off"}.`);
      onClose();
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <SidePanel title={target ? `Target of ${target.connection_name}` : "Configure a target"} onClose={onClose}>
      <form className="stack-sm" onSubmit={save}>
        {err && <Callout tone="bad">{err}</Callout>}
        {!target && (
          <label className="field">Connection
            <select className="input" required value={conn} onChange={(e) => setConn(e.target.value)}>
              <option value="">Choose a connection…</option>
              {usable.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.system})</option>)}
            </select>
          </label>
        )}
        <label className="field">Type
          <select className="input" value={kind} onChange={(e) => setKind(e.target.value as ProvTarget["kind"])}>
            <option value="scim">SCIM 2.0 service</option>
            <option value="okta">Okta API</option>
            <option value="cyberark">CyberArk safe membership</option>
            <option value="delinea">Delinea Secret Server folder membership</option>
            <option value="beyondtrust">BeyondTrust Password Safe smart-rule roles</option>
            <option value="sap">SAP role assignment</option>
            <option value="oracle">Oracle Fusion role assignment</option>
            <option value="servicenow">ServiceNow users, groups and roles, or a ticket per change</option>
            <option value="atlassian">Atlassian Cloud groups and project roles</option>
            <option value="fake">Dev fake target (no real system)</option>
          </select>
        </label>
        {kind !== "fake" && (
          <label className="field">Base URL
            <input className="input" required value={url} onChange={(e) => setUrl(e.target.value)} placeholder={kind === "okta" ? "https://example.okta.com" : kind === "servicenow" ? "https://name.service-now.com" : kind === "atlassian" ? "https://name.atlassian.net" : kind in VAULT ? "https://vault.example.com" : "https://example.com/scim/v2"} />
            <span className="hint">https only. Requests go through Tessera's outbound guard, which refuses private and internal addresses.</span>
          </label>
        )}
        {kind === "scim" && (
          <label className="field">Dialect
            <select className="input" value={dialect} onChange={(e) => setDialect(e.target.value as "standard" | "entra")}>
              <option value="standard">Standard SCIM</option>
              <option value="entra">Microsoft Entra ID (string booleans, capitalised PATCH operations)</option>
            </select>
          </label>
        )}
        {(kind === "sap" || kind === "oracle") && <p className="small muted">Assigns and removes roles, then re-reads the user. Users are not created or disabled here.</p>}
        {kind in VAULT && kind !== "sap" && kind !== "oracle" && <p className="small muted">Adds and removes members of a safe at a profile (list, use, read, manage), then re-reads the safe. {kind === "delinea" ? "Secret Server has no role that means use." : kind === "beyondtrust" ? "Password Safe can express list and use only." : ""} Accounts are not created or disabled here.</p>}
        {kind === "servicenow" && <p className="small muted">Credential: {`{"auth":"basic","username":"…","password":"…"}`} or {`{"auth":"oauth","client_id":"…","client_secret":"…"}`}. Add {`"mode":"ticket"`} (and optionally {`"assignment_group":"<sys_id>"`}) to raise an incident per change for a person to act on: the change counts as done once the incident is resolved or closed. Otherwise users are changed directly (deactivated, never deleted), and groups and roles are added or removed.</p>}
        {kind === "atlassian" && <p className="small muted">Credential: {`{"email":"…","api_token":"…"}`}. Adds and removes group members and project role actors, then re-reads the site; product access is granted by the group that carries it. Accounts are not created or suspended here: use the Atlassian Cloud SCIM target.</p>}
        {kind === "fake" && (
          <label className="field">Simulated fault
            <select className="input" value={fault} onChange={(e) => setFault(e.target.value)}>
              <option value="none">None: the target applies every change</option>
              <option value="fail_writes">Fail writes: every write answers 503</option>
              <option value="drop_writes">Drop writes: accepted but never applied (a mismatch)</option>
            </select>
          </label>
        )}
        {kind !== "fake" && (
          <label className="field">{kind === "okta" ? "API token" : kind in JSON_KINDS ? "Credential (JSON)" : kind in VAULT ? kind === "sap" || kind === "oracle" ? "OAuth client (client_id:client_secret)" : "Service user and secret (user:secret)" : "Bearer token"}
            <input className="input" type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} placeholder={target?.has_credential ? "Stored; leave empty to keep it (same kind and host only)" : ""} />
            <span className="hint">Write-only. Sealed under the platform key and never shown again.</span>
          </label>
        )}
        <label className="row tight small">
          <input type="checkbox" checked={writeBack} onChange={(e) => setWriteBack(e.target.checked)} /> Write-back: send changes to this target and update Tessera only after a re-read confirms them
        </label>
        <label className="field">Accounts of deprovisioned guests
          <select className="input" value={onDeprovision} onChange={(e) => setOnDeprovision(e.target.value as "disable" | "delete")}>
            <option value="disable">Leave disabled after the grace period</option>
            <option value="delete">Delete in this target after the grace period</option>
          </select>
          <span className="hint">Applies when write-back is on: the delete is sent and confirmed by a re-read.</span>
        </label>
        <div className="row" style={{ gap: 8 }}>
          <Button variant="primary" type="submit" disabled={busy || (!target && !conn)}>Save target</Button>
          <Button type="button" onClick={onClose}>Cancel</Button>
        </div>
      </form>
    </SidePanel>
  );
}

// ---------------------------------------------------------------- operation panel

function OpPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const toast = useToast();
  const { data, error, reload } = useApi<ProvOpDetail>(`/provisioning/ops/${id}`);
  const [busy, setBusy] = useState(false);
  const act = async (name: string, fn: () => Promise<ProvOpDetail>) => {
    setBusy(true);
    try {
      const d = await fn();
      toast(`${name}: now ${STATUS[d.status].label.toLowerCase()}`);
      reload();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const op = data;
  return (
    <SidePanel
      title={op ? `${KIND[op.kind]}` : "Operation"}
      sub={op && <span className="row tight"><Badge tone={STATUS[op.status].tone}>{STATUS[op.status].label}</Badge><span className="small faint">{op.target}</span></span>}
      onClose={onClose}
      commands={op && (op.can_retry || op.can_cancel) ? (
        <div className="row" style={{ gap: 8 }}>
          {op.can_retry && <Button size="sm" variant="primary" icon={<RotateCcw size={13} />} disabled={busy} onClick={() => act("Retried", () => provisioning.retry(op.id))}>Retry</Button>}
          {op.can_cancel && <Button size="sm" icon={<XCircle size={13} />} disabled={busy} onClick={() => act("Cancelled", () => provisioning.cancel(op.id))}>Cancel</Button>}
        </div>
      ) : undefined}
    >
      {error && <Callout tone="bad">{error.message}</Callout>}
      {op && (
        <div className="stack-sm">
          <p className="small muted" style={{ margin: 0 }}>{STATUS[op.status].help}</p>
          {op.last_error && <Callout tone={op.status === "verified" ? "neutral" : "bad"}><b>Last error.</b> {op.last_error}</Callout>}
          {op.findings.filter((f) => f.status === "open").map((f) => (
            <Callout key={f.id} tone="bad">
              <b>{f.title}.</b> Expected <i>{f.expected}</i>, the target shows <i>{f.observed}</i>. The change was not applied in Tessera.
            </Callout>
          ))}
          <dl className="kv small">
            <dt>Target</dt><dd>{op.connection_name} <span className="faint">({op.system})</span></dd>
            <dt>From</dt><dd>{SOURCE[op.source] ?? op.source} · requested by {op.requested_by}</dd>
            <dt>Sends</dt><dd>{op.attempts} of 5 · re-reads {op.verify_attempts} of 3</dd>
            {INFLIGHT.has(op.status) && <><dt>Next attempt</dt><dd>{fmtDate(op.next_attempt_at)}</dd></>}
            {op.observed && <><dt>Target shows</dt><dd>{op.observed}</dd></>}
            <dt>When verified</dt><dd>{op.completion ? <code className="xs">{op.completion}</code> : "nothing further"}</dd>
            <dt>Queued</dt><dd>{fmtDate(op.created_at)}</dd>
            {op.completed_at && <><dt>Finished</dt><dd>{fmtDate(op.completed_at)}</dd></>}
            <dt>Idempotency key</dt><dd><code className="xs">{op.idempotency_key}</code></dd>
            <dt>Operation id</dt><dd><code className="xs">{op.id}</code></dd>
          </dl>
          <div>
            <h3 className="small">Request</h3>
            <pre className="xs sys" style={{ whiteSpace: "pre-wrap", margin: 0 }}>{JSON.stringify(op.payload, null, 2)}</pre>
          </div>
        </div>
      )}
    </SidePanel>
  );
}

