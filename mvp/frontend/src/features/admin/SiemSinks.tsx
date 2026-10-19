import { FormEvent, useState } from "react";
import { History, Plus, Radio, Send } from "lucide-react";
import { SIEM_HEALTH, SiemDeadLetter, SiemFlavor, SiemFormat, SiemKind, SiemSink, SiemSinkInput, relTime, siemApi, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Drawer, EmptyState, Loading, useConfirm, useToast } from "../../components";

/**
 * Log streaming (issue #169): push the tenant's audit ledger to a SIEM, in seq order, at least
 * once, from a durable cursor. Each sink shows its health, lag and dead letters.
 */
const KIND_LABEL: Record<string, string> = { "webhook/hec": "Splunk HEC", "webhook/json": "HTTPS (JSON)", "syslog/": "Syslog over TLS" };

export function SiemSinks() {
  const { data, error, reload } = useApi<SiemSink[]>("/siem/sinks");
  const { can } = useSession();
  const manage = can("siem.configure");
  const toast = useToast();
  const confirm = useConfirm();
  const [edit, setEdit] = useState<SiemSink | "new" | null>(null);
  const [dead, setDead] = useState<SiemSink | null>(null);
  if (!data) return <div className="card flush"><Loading error={error} /></div>;
  const test = async (k: SiemSink) => {
    try {
      const r = await siemApi.test(k.id);
      toast(r.ok ? `Test event sent to ${k.name}` : `Test to ${k.name} failed: ${r.error}`, r.ok ? undefined : { kind: "error" });
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    }
  };
  const replay = async (k: SiemSink) => {
    const ok = await confirm({ title: `Replay the whole ledger to ${k.name}?`, body: `${k.head_seq.toLocaleString()} events will be sent again from the first one. The SIEM sees duplicates of what it already has.`, confirmLabel: "Replay" });
    if (ok === null) return;
    try {
      await siemApi.rewind(k.id, 0);
      toast(`${k.name} will replay from the start`);
      reload();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    }
  };
  return (
    <div className="stack">
      {manage && <div className="row"><Button variant="primary" icon={<Plus size={15} />} onClick={() => setEdit("new")}>New sink</Button></div>}
      {data.length === 0 ? (
        <div className="card"><EmptyState title="No SIEM sinks" icon={<Radio size={18} />}>Stream every audit event to Splunk, Sentinel or a syslog collector. The NDJSON export on the Audit log page stays available either way.</EmptyState></div>
      ) : (
        <div className="card flush">
          <div className="table-scroll">
            <table>
              <thead><tr><th>Sink</th><th>Health</th><th className="hide-narrow">Delivered</th><th className="hide-narrow">Last success</th><th /></tr></thead>
              <tbody>
                {data.map((k) => {
                  const h = SIEM_HEALTH[k.health.status];
                  return (
                    <tr key={k.id}>
                      <td>
                        <b>{k.name}</b> <Badge tone="outline">{k.format === "ocsf" ? "OCSF" : "JSON"}</Badge>
                        <div className="xs faint truncate">{KIND_LABEL[`${k.kind}/${k.flavor}`] ?? k.kind} · {k.target}</div>
                      </td>
                      <td>
                        <Badge tone={h.tone}>{h.label}</Badge>
                        <div className="xs faint">{k.health.lag ? `${k.health.lag.toLocaleString()} behind` : "Up to date"}{k.next_attempt_at && k.attempts > 0 && ` · retry ${relTime(k.next_attempt_at)}`}</div>
                        {k.last_error && k.attempts > 0 && <div className="xs faint truncate" title={k.last_error}>{k.last_error}</div>}
                      </td>
                      <td className="small hide-narrow">
                        {k.delivered_count.toLocaleString()}
                        {k.dead_letter_count > 0 && <> · <Button size="sm" variant="ghost" onClick={() => setDead(k)}>{k.dead_letter_count} dead-lettered</Button></>}
                      </td>
                      <td className="small hide-narrow">{k.last_success_at ? relTime(k.last_success_at) : <span className="faint">Never</span>}</td>
                      <td className="actions-cell">
                        {manage && <><Button size="sm" icon={<Send size={14} />} onClick={() => test(k)}>Test</Button>{" "}<Button size="sm" variant="ghost" icon={<History size={14} />} onClick={() => replay(k)}>Replay</Button>{" "}<Button size="sm" variant="ghost" onClick={() => setEdit(k)}>Edit</Button></>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <p className="small muted">
        Delivery is at least once and in ledger order: a sink resumes from the last event its destination accepted, so restarts and outages leave no gaps.
        JSON events are the export records (each carries <code>hash</code> and <code>prev_hash</code>; recompute them to check the chain). OCSF maps sign-ins to Authentication, role changes to Account Change and the rest to API Activity, with the chain fields under <code>unmapped.tessera</code>.
      </p>
      {edit && <SinkForm sink={edit === "new" ? null : edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload(); }} />}
      {dead && <DeadLetters sink={dead} onClose={() => setDead(null)} />}
    </div>
  );
}

function DeadLetters({ sink, onClose }: { sink: SiemSink; onClose: () => void }) {
  const { data, error } = useApi<SiemDeadLetter[]>(`/siem/sinks/${encodeURIComponent(sink.id)}/dead-letters`);
  return (
    <Drawer title={`Dead letters: ${sink.name}`} sub="Batches the destination rejected outright, after every retry. Replay to send them again." onClose={onClose}>
      {!data ? <Loading error={error} /> : data.length === 0 ? <p className="small muted">None.</p> : (
        <div className="stack-sm">
          {data.map((d) => (
            <div key={d.id} className="small">
              <b>Events {d.from_seq}–{d.to_seq}</b> ({d.events}) <span className="faint">· {relTime(d.created_at)}</span>
              <div className="xs faint">{d.error}</div>
            </div>
          ))}
        </div>
      )}
    </Drawer>
  );
}

type Preset = "hec" | "json" | "syslog";

function SinkForm({ sink, onClose, onSaved }: { sink: SiemSink | null; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const k = sink;
  const [f, setF] = useState({
    name: k?.name ?? "", preset: (k ? (k.kind === "syslog" ? "syslog" : k.flavor) : "hec") as Preset, format: k?.format ?? ("ocsf" as SiemFormat),
    target: "", token: "", ca: "", includeHttp: k?.include_http ?? false, enabled: k?.enabled ?? true, start: "now" as "now" | "beginning",
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const kind: SiemKind = f.preset === "syslog" ? "syslog" : "webhook";
  const flavor: SiemFlavor = f.preset === "syslog" ? "" : f.preset;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const body: SiemSinkInput = { name: f.name, format: f.format, include_http: f.includeHttp, enabled: f.enabled };
    if (!k) {
      body.kind = kind;
      body.start = f.start;
    }
    if (kind === "webhook") body.flavor = flavor;
    if (!k || f.target.trim()) body.target = f.target.trim();
    if (f.token) body.token = f.token;
    if (kind === "syslog" && f.ca.trim()) body.ca_pem = f.ca.trim();
    try {
      const saved = k ? await siemApi.update(k.id, body) : await siemApi.create(body);
      toast(`${saved.name} saved`);
      onSaved();
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  const placeholder = f.preset === "hec" ? "https://splunk.example.com:8088/services/collector/event" : f.preset === "json" ? "https://….ingest.monitor.azure.com/dataCollectionRules/…/streams/…" : "logs.example.com:6514";
  return (
    <Drawer title={k ? `Edit ${k.name}` : "New SIEM sink"} onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Name<input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required maxLength={100} placeholder="e.g. Splunk Cloud" /></label>
        {!k && (
          <fieldset className="stack-sm">
            <legend className="small">Destination</legend>
            <label className="row tight small"><input type="radio" name="preset" checked={f.preset === "hec"} onChange={() => setF({ ...f, preset: "hec" })} /> Splunk HTTP Event Collector</label>
            <label className="row tight small"><input type="radio" name="preset" checked={f.preset === "json"} onChange={() => setF({ ...f, preset: "json" })} /> HTTPS endpoint, JSON array (Microsoft Sentinel, Cribl, Logstash)</label>
            <label className="row tight small"><input type="radio" name="preset" checked={f.preset === "syslog"} onChange={() => setF({ ...f, preset: "syslog" })} /> Syslog over TLS (RFC 5425)</label>
          </fieldset>
        )}
        <label className="field">{kind === "syslog" ? "Collector (host:port)" : "URL (https)"}
          <input className="input" value={f.target} onChange={(e) => setF({ ...f, target: e.target.value })} required={!k} placeholder={k ? `Keep ${k.target}` : placeholder} />
        </label>
        {kind === "webhook" && (
          <label className="field">{f.preset === "hec" ? "HEC token" : "Bearer token (optional)"}
            <input className="input" type="password" autoComplete="off" value={f.token} onChange={(e) => setF({ ...f, token: e.target.value })} required={!k && f.preset === "hec"} placeholder={k?.has_token ? "Keep the stored token" : ""} />
          </label>
        )}
        {kind === "syslog" && (
          <label className="field">CA certificate (PEM, optional, for a private CA)
            <textarea className="input" rows={3} value={f.ca} onChange={(e) => setF({ ...f, ca: e.target.value })} placeholder={k?.has_ca ? "Keep the stored CA" : "-----BEGIN CERTIFICATE-----"} />
          </label>
        )}
        <label className="field">Format
          <select className="input" value={f.format} onChange={(e) => setF({ ...f, format: e.target.value as SiemFormat })}>
            <option value="ocsf">OCSF 1.3 (Authentication, Account Change, API Activity)</option>
            <option value="json">Tessera JSON (hash-chained export records)</option>
          </select>
        </label>
        {!k && (
          <label className="field">Start from
            <select className="input" value={f.start} onChange={(e) => setF({ ...f, start: e.target.value as "now" | "beginning" })}>
              <option value="now">New events only</option>
              <option value="beginning">The whole ledger (backfill)</option>
            </select>
          </label>
        )}
        <label className="row tight small"><input type="checkbox" checked={f.includeHttp} onChange={(e) => setF({ ...f, includeHttp: e.target.checked })} /> Include every HTTP request (high volume)</label>
        <label className="row tight small"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Enabled</label>
        <p className="small muted">Tokens are encrypted at rest and never shown again. Private, loopback and cloud-metadata addresses are refused. Saving needs a recent strong sign-in.</p>
        {error && <Callout tone="bad">{error}</Callout>}
        <div className="row"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Save"}</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
    </Drawer>
  );
}
