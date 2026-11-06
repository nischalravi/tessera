import { FormEvent, Fragment, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { BellRing, Check, CheckCheck, Mail, Pencil, Plus, Send, UserMinus, UserPlus, Webhook } from "lucide-react";
import {
  ALERT_SEVERITIES, AlertChannel, AlertChannelInput, AlertRow, AlertRule, AlertSeverity, alertsApi, fmtDate, relTime, severityTone, useApi,
} from "../../api";
import { useSession } from "../../app/auth";
import { TwoAdminDialog } from "../admin/TwoAdminDialog";
import { alertLoosenPayload, twoAdminType } from "../admin/twoAdmin";
import {
  Badge, Button, Callout, Column, CommandBar, DataTable, Drawer, EmptyState, Loading, Page, SidePanel, Tabs, useConfirm, useToast,
} from "../../components";

/**
 * Alerts (issue #168): what the alert engine raised from audit events and detections, with
 * triage (acknowledge, assign, resolve), the built-in rules and the delivery channels.
 */
type View = "alerts" | "rules" | "channels";

const STATUS_LABEL = { open: "Open", acknowledged: "Acknowledged", resolved: "Resolved" } as const;
const statusTone = (s: AlertRow["status"]) => (s === "open" ? "critical" : s === "acknowledged" ? "warning" : "ok");

export function SeverityBadge({ s }: { s: AlertSeverity }) {
  return <Badge tone={severityTone(s)}>{s[0].toUpperCase() + s.slice(1)}</Badge>;
}

export function Alerts() {
  const [params, setParams] = useSearchParams();
  const { can } = useSession();
  const view = (["alerts", "rules", "channels"].includes(params.get("view") ?? "") ? params.get("view") : "alerts") as View;
  const setView = (v: View) => {
    const next = new URLSearchParams(params);
    next.set("view", v);
    next.delete("selected");
    setParams(next, { replace: true });
  };
  const tabs: { id: View; label: string }[] = [{ id: "alerts", label: "Alerts" }, { id: "rules", label: "Rules" }];
  if (can("alerts.configure")) tabs.push({ id: "channels", label: "Channels" });
  return (
    <Page
      title="Alerts"
      crumbs={[["Protection"], ["Alerts"]]}
      sub="Raised from the audit ledger and from detections. Each alert is live once per rule and subject; repeats add to its count."
      tabs={<Tabs label="Alerts" value={view} onChange={setView} tabs={tabs} />}
    >
      {view === "alerts" ? <AlertList /> : view === "rules" ? <RuleList /> : <ChannelList />}
    </Page>
  );
}

// ------------------------------------------------------------------ alerts

function AlertList() {
  const { data, error, reload } = useApi<AlertRow[]>("/alerts");
  const [params, setParams] = useSearchParams();
  const selected = params.get("selected");
  const select = (id: string | null) => {
    const next = new URLSearchParams(params);
    if (id) next.set("selected", id);
    else next.delete("selected");
    setParams(next, { replace: true });
  };
  const cols: Column<AlertRow>[] = [
    { id: "severity", header: "Severity", sort: (r) => ALERT_SEVERITIES.indexOf(r.severity), csv: (r) => r.severity, cell: (r) => <SeverityBadge s={r.severity} /> },
    { id: "title", header: "Alert", sort: (r) => r.title.toLowerCase(), csv: (r) => r.title, cell: (r) => <div style={{ minWidth: 0 }}><span className="name-link">{r.title}</span><div className="xs faint truncate">{r.rule_name}</div></div> },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Badge tone={statusTone(r.status)}>{STATUS_LABEL[r.status]}</Badge> },
    { id: "count", header: "Count", num: true, sort: (r) => r.count, cell: (r) => r.count, hideNarrow: true },
    { id: "assignee", header: "Assignee", sort: (r) => r.assignee?.name ?? "", csv: (r) => r.assignee?.name ?? "", cell: (r) => <span className="small">{r.assignee?.name ?? <span className="faint">Nobody</span>}</span>, hideNarrow: true },
    { id: "last", header: "Last seen", sort: (r) => r.last_seen_at, csv: (r) => r.last_seen_at, cell: (r) => <span className="small nowrap">{relTime(r.last_seen_at)}</span>, hideNarrow: true },
  ];
  return (
    <>
      <DataTable
        id="alerts"
        rows={data}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        initialSort={["last", -1]}
        initialFilters={{ status: "live" }}
        searchText={(r) => `${r.title} ${r.rule_name} ${r.key} ${r.assignee?.name ?? ""}`}
        searchPlaceholder="Search alerts…"
        filters={[
          { id: "status", label: "Status", options: [{ value: "live", label: "Open or acknowledged" }, { value: "open", label: "Open" }, { value: "acknowledged", label: "Acknowledged" }, { value: "resolved", label: "Resolved" }],
            get: (r) => (r.status === "resolved" ? ["resolved"] : [r.status, "live"]) },
          { id: "severity", label: "Severity", options: ALERT_SEVERITIES.map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) })), get: (r) => r.severity },
          { id: "rule", label: "Rule", options: [...new Map((data ?? []).map((r) => [r.rule, r.rule_name])).entries()].map(([value, label]) => ({ value, label })), get: (r) => r.rule },
        ]}
        onRefresh={reload}
        rowLabel={(r) => r.title}
        onRowClick={(r) => select(r.id)}
        activeKey={selected}
        empty={<EmptyState title="No alerts" icon={<BellRing size={18} />}>Nothing matches. The engine reads new audit events every minute and runs detections every 15 minutes.</EmptyState>}
      />
      {selected && <AlertPanel id={selected} onClose={() => select(null)} onChanged={reload} />}
    </>
  );
}

function AlertPanel({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { data, error, reload } = useApi<AlertRow>(`/alerts/${encodeURIComponent(id)}`);
  const { can, session } = useSession();
  const confirm = useConfirm();
  const toast = useToast();
  const manage = can("alerts.manage");
  if (!data) return <SidePanel title="Alert" onClose={onClose}><Loading error={error} /></SidePanel>;
  const a = data;
  const me = session?.user.id ?? null;
  const run = async (fn: () => Promise<unknown>, done: string) => {
    try {
      await fn();
      toast(done);
      reload();
      onChanged();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    }
  };
  const resolve = async () => {
    const note = await confirm({ title: "Resolve this alert?", body: a.title, confirmLabel: "Resolve", reason: { label: "What happened", placeholder: "e.g. planned break-glass drill" } });
    if (note !== null) await run(() => alertsApi.resolve(a.id, note), "Alert resolved");
  };
  const live = a.status !== "resolved";
  const detail = Object.entries(a.detail ?? {});
  return (
    <SidePanel
      title={a.title}
      sub={<><SeverityBadge s={a.severity} /><Badge tone={statusTone(a.status)}>{STATUS_LABEL[a.status]}</Badge>{a.rule_name}</>}
      onClose={onClose}
      commands={manage && live ? (
        <CommandBar
          label="Alert actions"
          items={[
            a.status === "open" && { label: "Acknowledge", icon: <Check size={16} />, onClick: () => run(() => alertsApi.acknowledge(a.id), "Acknowledged") },
            !!me && a.assignee?.id !== me && { label: "Assign to me", icon: <UserPlus size={16} />, onClick: () => run(() => alertsApi.assign(a.id, me), "Assigned to you") },
            a.assignee && { label: "Unassign", icon: <UserMinus size={16} />, onClick: () => run(() => alertsApi.assign(a.id, null), "Unassigned") },
            { label: "Resolve", icon: <CheckCheck size={16} />, onClick: resolve },
          ]}
        />
      ) : undefined}
    >
      <dl className="kv">
        <dt>Occurrences</dt><dd>{a.count}</dd>
        <dt>First seen</dt><dd>{fmtDate(a.first_seen_at)}</dd>
        <dt>Last seen</dt><dd>{fmtDate(a.last_seen_at)} <span className="faint">({relTime(a.last_seen_at)})</span></dd>
        <dt>Subject</dt><dd className="sys">{a.key}</dd>
        <dt>Assignee</dt><dd>{a.assignee?.name ?? <span className="faint">Nobody</span>}</dd>
        {a.acknowledged_by && <><dt>Acknowledged</dt><dd>{a.acknowledged_by.name}, {a.acknowledged_at && relTime(a.acknowledged_at)}</dd></>}
        {a.resolved_at && <><dt>Resolved</dt><dd>{a.resolved_by?.name ?? "Automatically"}, {relTime(a.resolved_at)}{a.resolution && <div className="small muted">{a.resolution}</div>}</dd></>}
      </dl>
      {detail.length > 0 && (
        <>
          <h3 className="mt">Details</h3>
          <dl className="kv">
            {detail.map(([k, v]) => <Fragment key={k}><dt>{k.replace(/_/g, " ")}</dt><dd className="small">{Array.isArray(v) ? v.join(", ") : String(v)}</dd></Fragment>)}
          </dl>
        </>
      )}
      <h3 className="mt">Deliveries</h3>
      {!a.deliveries?.length ? (
        <p className="small muted">No channel takes {a.severity} alerts.{can("alerts.configure") ? " Add one on the Channels tab." : ""}</p>
      ) : (
        <div className="stack-sm">
          {a.deliveries.map((d) => (
            <div key={d.id} className="small">
              {d.channel_kind === "email" ? <Mail size={14} aria-hidden /> : <Webhook size={14} aria-hidden />} <b>{d.channel}</b>{" "}
              <Badge tone={d.status === "sent" ? "ok" : d.status === "failed" ? "critical" : "warning"}>{d.status}</Badge>{" "}
              <span className="faint">
                {d.status === "sent" && d.sent_at ? relTime(d.sent_at) : `${d.attempts} ${d.attempts === 1 ? "attempt" : "attempts"}`}
                {d.status === "pending" && d.next_attempt_at && `, next ${relTime(d.next_attempt_at)}`}
              </span>
              {d.last_error && d.status !== "sent" && <div className="xs faint">{d.last_error}</div>}
            </div>
          ))}
        </div>
      )}
    </SidePanel>
  );
}

// ------------------------------------------------------------------- rules

function RuleList() {
  const { data, error, reload } = useApi<AlertRule[]>("/alerts/rules");
  const { can } = useSession();
  const [edit, setEdit] = useState<AlertRule | null>(null);
  if (!data) return <div className="card flush"><Loading error={error} /></div>;
  return (
    <div className="card flush">
      <div className="table-scroll">
        <table>
          <thead><tr><th>Rule</th><th>Severity</th><th className="hide-narrow">Fires when</th><th className="hide-narrow">Live</th><th /></tr></thead>
          <tbody>
            {data.map((r) => (
              <tr key={r.id}>
                <td>
                  <b>{r.name}</b> {!r.enabled && <Badge tone="outline">Off</Badge>} {r.customized && <Badge tone="outline">Customized</Badge>}
                  <div className="xs faint">{r.description}</div>
                </td>
                <td><SeverityBadge s={r.severity} /></td>
                <td className="small hide-narrow">{r.kind === "detection" ? (r.threshold > 1 ? `Detected ${r.threshold}+ times` : "Detected (checked every 15 min)") : r.threshold > 1 ? `${r.threshold} events in ${r.window_minutes} min` : "Every matching event"}</td>
                <td className="small hide-narrow">{r.live || <span className="faint">0</span>}</td>
                <td className="actions-cell">{can("alerts.configure") && <Button size="sm" variant="ghost" icon={<Pencil size={14} />} onClick={() => setEdit(r)}>Edit</Button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {edit && <RuleForm rule={edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload(); }} />}
    </div>
  );
}

function RuleForm({ rule, onClose, onSaved }: { rule: AlertRule; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [f, setF] = useState({ enabled: rule.enabled, severity: rule.severity, threshold: String(rule.threshold), window: String(rule.window_minutes) });
  const [error, setError] = useState<string | null>(null);
  const [ask, setAsk] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const spec = { enabled: f.enabled, severity: f.severity, threshold: Number(f.threshold), window_minutes: Number(f.window) };
    try {
      await alertsApi.setRule(rule.id, spec);
      toast(`${rule.name} saved`);
      onSaved();
    } catch (err: any) {
      if (twoAdminType(err) === "alerts.rule.loosen") { setAsk(true); return; }
      setError(String(err.message ?? err));
    }
  };
  return (
    <Drawer title={rule.name} sub={rule.description} onClose={onClose}>
      {ask && (
        <TwoAdminDialog type="alerts.rule.loosen" onClose={() => setAsk(false)}
          payload={alertLoosenPayload(rule.id, { enabled: f.enabled, severity: f.severity, threshold: Number(f.threshold), window_minutes: Number(f.window) })}
          what={`${rule.name} is a security rule: it may be the only control watching what it covers. Switching it off, lowering its severity, raising its threshold or shortening its window must be approved by a second admin.`} />
      )}
      <form className="stack" onSubmit={submit}>
        <label className="row tight small"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Enabled</label>
        <label className="field">Severity
          <select className="input" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value as AlertSeverity })}>
            {ALERT_SEVERITIES.map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </select>
        </label>
        <div className="row">
          <label className="field" style={{ flex: 1 }}>{rule.kind === "detection" ? "Raise at count" : "Events needed"}<input className="input" inputMode="numeric" value={f.threshold} onChange={(e) => setF({ ...f, threshold: e.target.value })} /></label>
          {rule.kind === "event" && <label className="field" style={{ flex: 1 }}>Within (minutes)<input className="input" inputMode="numeric" value={f.window} onChange={(e) => setF({ ...f, window: e.target.value })} /></label>}
        </div>
        {!f.enabled && rule.kind === "detection" && <Callout tone="warn">Switching a detection off resolves its open alerts at the next check.</Callout>}
        {error && <Callout tone="bad">{error}</Callout>}
        <div className="row"><Button type="submit" variant="primary">Save</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
    </Drawer>
  );
}

// ---------------------------------------------------------------- channels

function ChannelList() {
  const { data, error, reload } = useApi<AlertChannel[]>("/alerts/channels");
  const toast = useToast();
  const [edit, setEdit] = useState<AlertChannel | "new" | null>(null);
  const [secret, setSecret] = useState<{ name: string; secret: string } | null>(null);
  if (!data) return <div className="card flush"><Loading error={error} /></div>;
  const test = async (c: AlertChannel) => {
    try {
      const r = await alertsApi.testChannel(c.id);
      toast(r.ok ? `Test sent to ${c.name}` : `Test to ${c.name} failed: ${r.error}`, r.ok ? undefined : { kind: "error" });
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    }
  };
  return (
    <div className="stack">
      <div className="row"><Button variant="primary" icon={<Plus size={15} />} onClick={() => setEdit("new")}>New channel</Button></div>
      {secret && (
        <Callout tone="warn">
          <b>Signing secret for {secret.name}</b>. Copy it now; it is not shown again. Verify each request's <code>X-Tessera-Signature</code> (<code>t=…,v1=</code> HMAC-SHA256 of <code>t.body</code>) with it.
          <div className="row mt"><code className="sys" style={{ wordBreak: "break-all" }}>{secret.secret}</code><Button size="sm" onClick={() => { void navigator.clipboard?.writeText(secret.secret); toast("Copied"); }}>Copy</Button><Button size="sm" variant="ghost" onClick={() => setSecret(null)}>Done</Button></div>
        </Callout>
      )}
      {data.length === 0 ? (
        <div className="card"><EmptyState title="No channels" icon={<Send size={18} />}>Alerts are recorded here either way. Add an email list or a Slack or Teams webhook to be told.</EmptyState></div>
      ) : (
        <div className="card flush">
          <div className="table-scroll">
            <table>
              <thead><tr><th>Channel</th><th className="hide-narrow">Sends</th><th /></tr></thead>
              <tbody>
                {data.map((c) => (
                  <tr key={c.id}>
                    <td>
                      {c.kind === "email" ? <Mail size={14} aria-hidden /> : <Webhook size={14} aria-hidden />} <b>{c.name}</b> {!c.enabled && <Badge tone="outline">Off</Badge>}
                      <div className="xs faint truncate">{c.target}</div>
                    </td>
                    <td className="small hide-narrow">{c.min_severity === "low" ? "Every alert" : `${c.min_severity[0].toUpperCase() + c.min_severity.slice(1)} and above`}</td>
                    <td className="actions-cell">
                      <Button size="sm" icon={<Send size={14} />} onClick={() => test(c)}>Test</Button>{" "}
                      <Button size="sm" variant="ghost" onClick={() => setEdit(c)}>Edit</Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {edit && (
        <ChannelForm
          channel={edit === "new" ? null : edit}
          onClose={() => setEdit(null)}
          onSaved={(c) => { setEdit(null); if (c.secret) setSecret({ name: c.name, secret: c.secret }); reload(); }}
        />
      )}
    </div>
  );
}

function ChannelForm({ channel, onClose, onSaved }: { channel: AlertChannel | null; onClose: () => void; onSaved: (c: AlertChannel) => void }) {
  const toast = useToast();
  const c = channel;
  const [f, setF] = useState({ name: c?.name ?? "", kind: c?.kind ?? ("webhook" as "email" | "webhook"), target: "", min: c?.min_severity ?? ("high" as AlertSeverity), enabled: c?.enabled ?? true, rotate: false });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const body: AlertChannelInput = { name: f.name, min_severity: f.min, enabled: f.enabled };
    if (!c) body.kind = f.kind;
    if (!c || f.target.trim()) body.target = f.target.trim();
    if (c && f.rotate) body.rotate_secret = true;
    try {
      const saved = c ? await alertsApi.updateChannel(c.id, body) : await alertsApi.createChannel(body);
      toast(`${saved.name} saved`);
      onSaved(saved);
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={c ? `Edit ${c.name}` : "New alert channel"} onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Name<input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required maxLength={100} placeholder="e.g. Slack #security" /></label>
        {!c && (
          <fieldset className="stack-sm">
            <legend className="small">Kind</legend>
            <label className="row tight small"><input type="radio" name="kind" checked={f.kind === "webhook"} onChange={() => setF({ ...f, kind: "webhook" })} /> Webhook (Slack, Teams or any HTTPS endpoint)</label>
            <label className="row tight small"><input type="radio" name="kind" checked={f.kind === "email"} onChange={() => setF({ ...f, kind: "email" })} /> Email</label>
          </fieldset>
        )}
        <label className="field">{f.kind === "email" ? "Addresses (comma-separated)" : "Webhook URL (https)"}
          <input className="input" value={f.target} onChange={(e) => setF({ ...f, target: e.target.value })} required={!c} placeholder={c ? `Keep ${c.target}` : f.kind === "email" ? "secops@example.com, oncall@example.com" : "https://hooks.slack.com/services/…"} />
        </label>
        <label className="field">Send
          <select className="input" value={f.min} onChange={(e) => setF({ ...f, min: e.target.value as AlertSeverity })}>
            {ALERT_SEVERITIES.map((s) => <option key={s} value={s}>{s === "low" ? "Every alert" : `${s[0].toUpperCase() + s.slice(1)} and above`}</option>)}
          </select>
        </label>
        <label className="row tight small"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Enabled</label>
        {c?.kind === "webhook" && <label className="row tight small"><input type="checkbox" checked={f.rotate} onChange={(e) => setF({ ...f, rotate: e.target.checked })} /> Issue a new signing secret</label>}
        <p className="small muted">{f.kind === "webhook" ? "Requests are signed with a secret shown once after saving. Private and cloud-metadata addresses are refused." : "Email goes out through the server's TESSERA_NOTIFY setting."} Saving needs a recent strong sign-in.</p>
        {error && <Callout tone="bad">{error}</Callout>}
        <div className="row"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Save"}</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
    </Drawer>
  );
}
