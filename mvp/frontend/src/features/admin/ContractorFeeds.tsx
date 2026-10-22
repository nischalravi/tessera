import { SourceDeletionGuard } from "./SourceDeletionGuard";
import { ChangeEvent, FormEvent, useRef, useState } from "react";
import { Plus, RefreshCw, Upload, UserPlus } from "lucide-react";
import { VMS_OUTCOME, VMS_REASON, VmsRecord, VmsReport, VmsSettings, VmsSource, VmsVendor, relTime, useApi, vmsApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Drawer, EmptyState, Loading, useConfirm, useToast } from "../../components";

/**
 * Contractor feeds (issue #304): contractors come from a vendor-management system (Fieldglass, Beeline) or a
 * CSV file. Every contractor needs a sponsor; the end date in the feed drives the leaver plan. A record that
 * names no usable sponsor is held here and creates nobody.
 */
const VENDOR: Record<VmsVendor, string> = { fieldglass: "SAP Fieldglass", beeline: "Beeline", csv: "CSV file" };

function summary(r: VmsReport): string {
  const parts = Object.entries(r.applied ?? {}).map(([k, n]) => `${n} ${(VMS_OUTCOME[k]?.label ?? k).toLowerCase()}`);
  return `${r.records} record${r.records === 1 ? "" : "s"}${parts.length ? `: ${parts.join(", ")}` : ""}${r.failed ? `, ${r.failed} failed` : ""}`;
}

export function ContractorFeeds() {
  const src = useApi<{ sources: VmsSource[] }>(vmsApi.sourcesPath);
  const recs = useApi<{ records: VmsRecord[] }>(vmsApi.recordsPath);
  const { can } = useSession();
  const manage = can("connections.manage");
  const run = can("lifecycle.manage");
  const toast = useToast();
  const confirm = useConfirm();
  const [edit, setEdit] = useState<VmsSource | "new" | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const file = useRef<HTMLInputElement>(null);
  const [uploadFor, setUploadFor] = useState<VmsSource | null>(null);
  if (!src.data) return <div className="card flush"><Loading error={src.error} /></div>;
  const sources = src.data.sources;
  const reload = () => { src.reload(); recs.reload(); };
  const sync = async (s?: VmsSource) => {
    setBusy(s?.id ?? "all");
    try {
      const { reports } = await vmsApi.sync(s?.id);
      const failed = reports.filter((r) => r.status === "failed");
      toast(failed.length ? `${failed[0].name} failed: ${failed[0].error}` : reports.length === 0 ? "No feed to read" : reports.map((r) => `${r.name}: ${r.status === "skipped" ? "skipped" : summary(r)}`).join(" · "), failed.length ? { kind: "error" } : undefined);
      reload();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  const upload = async (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    const s = uploadFor;
    e.target.value = "";
    if (!f || !s) return;
    setBusy(s.id);
    try {
      toast(`${s.name}: ${summary(await vmsApi.importCsv(s.id, f))}`);
      reload();
    } catch (err: any) {
      toast(String(err.message ?? err), { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  const remove = async (s: VmsSource) => {
    const ok = await confirm({ title: `Remove ${s.name}?`, body: "The contractors it brought in stay, with their sponsors and end dates. Only the feed is removed.", confirmLabel: "Remove" });
    if (ok === null) return;
    try {
      await vmsApi.remove(s.id);
      toast(`${s.name} removed`);
      reload();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    }
  };
  return (
    <div className="stack">
      <div className="row">
        {manage && <Button variant="primary" icon={<Plus size={15} />} onClick={() => setEdit("new")}>New feed</Button>}
        {run && sources.length > 0 && <Button icon={<RefreshCw size={14} />} disabled={busy !== null} onClick={() => sync()}>{busy === "all" ? "Reading…" : "Read all now"}</Button>}
      </div>
      <input ref={file} type="file" accept=".csv,text/csv" hidden onChange={upload} aria-label="CSV file of contractors" />
      {sources.length === 0 ? (
        <div className="card"><EmptyState title="No contractor feeds" icon={<UserPlus size={18} />}>Connect Fieldglass or Beeline, or upload a CSV of contractors. Each one needs a sponsor and an end date.</EmptyState></div>
      ) : (
        <div className="card flush">
          <div className="table-scroll">
            <table>
              <thead><tr><th>Feed</th><th>Last read</th><th className="hide-narrow">Last result</th><th /></tr></thead>
              <tbody>
                {sources.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <b>{s.name}</b> <Badge tone="outline">{VENDOR[s.vendor]}</Badge> {s.status === "paused" && <Badge tone="warning">Paused</Badge>}
                      <div className="xs faint truncate">{s.base_url || "Uploaded file"}</div>
                    </td>
                    <td className="small">
                      {s.last_sync_at ? relTime(s.last_sync_at) : <span className="faint">Never</span>}
                      {s.last_result === "failed" && <div><Badge tone="critical">Failed</Badge></div>}
                    </td>
                    <td className="small hide-narrow">
                      {s.last_result === "failed" ? <span className="xs" title={s.last_error ?? ""}>{s.last_error}</span> : Object.keys(s.last_counts).length === 0 ? <span className="faint">—</span> : Object.entries(s.last_counts).map(([k, n]) => `${n} ${(VMS_OUTCOME[k]?.label ?? k).toLowerCase()}`).join(", ")}
                    </td>
                    <td className="actions-cell">
                      {run && s.vendor === "csv" && !s.base_url && <Button size="sm" icon={<Upload size={14} />} disabled={busy !== null} onClick={() => { setUploadFor(s); setTimeout(() => file.current?.click(), 0); }}>Upload CSV</Button>}
                      {run && (s.vendor !== "csv" || s.base_url) && <Button size="sm" icon={<RefreshCw size={14} />} disabled={busy !== null || s.status === "paused"} onClick={() => sync(s)}>{busy === s.id ? "Reading…" : "Read now"}</Button>}{" "}
                      {manage && <><Button size="sm" variant="ghost" onClick={() => setEdit(s)}>Edit</Button>{" "}<Button size="sm" variant="ghost" onClick={() => remove(s)}>Remove</Button></>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <div className="card flush">
        <div className="card-h"><h2>Recent contractor records</h2></div>
        {!recs.data ? <Loading error={recs.error} /> : recs.data.records.length === 0 ? (
          <p className="small muted" style={{ padding: "0 16px 16px" }}>No record has been read yet.</p>
        ) : (
          <div className="table-scroll" style={{ maxHeight: 360 }}>
            <table>
              <thead><tr><th>Received</th><th>Person</th><th>Feed</th><th>Outcome</th></tr></thead>
              <tbody>
                {recs.data.records.map((r) => {
                  const o = VMS_OUTCOME[r.outcome] ?? { tone: "outline" as const, label: r.outcome };
                  return (
                    <tr key={r.id}>
                      <td className="small nowrap">{relTime(r.created_at)}</td>
                      <td className="small">{r.person ?? <span className="faint">Nobody created</span>}</td>
                      <td className="small">{VENDOR[r.source as VmsVendor] ?? r.source} <span className="faint">· {r.record_state}</span></td>
                      <td><Badge tone={o.tone}>{o.label}</Badge>{r.reason && <div className="xs faint">{VMS_REASON[r.reason] ?? r.reason}</div>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <p className="small muted">
        A contractor's sponsor is an active employee the feed names by employee id or e-mail. The end date becomes the contractor's end date: warnings go to the sponsor, and on the day Tessera revokes sessions and runs the leaver plan. A feed that reports an assignment as ended ends it at once.
      </p>
      {edit && <FeedForm source={edit === "new" ? null : edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload(); }} />}
    </div>
  );
}

function FeedForm({ source, onClose, onSaved }: { source: VmsSource | null; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const s = source;
  const [f, setF] = useState({
    vendor: (s?.vendor ?? "fieldglass") as VmsVendor, name: s?.name ?? "", baseUrl: s?.base_url ?? "", credential: "",
    status: s?.status ?? "active", workersPath: s?.settings.workers_path ?? "", csvPath: s?.settings.csv_path ?? "",
    dateFormat: s?.settings.date_format ?? "", mapping: s?.settings.mapping ? JSON.stringify(s.settings.mapping, null, 1) : "",
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const rest = f.vendor !== "csv";
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const settings: VmsSettings = {};
      if (rest && f.workersPath.trim()) settings.workers_path = f.workersPath.trim();
      if (!rest) {
        if (f.csvPath.trim()) settings.csv_path = f.csvPath.trim();
        if (f.dateFormat.trim()) settings.date_format = f.dateFormat.trim();
        if (f.mapping.trim()) {
          try {
            settings.mapping = JSON.parse(f.mapping);
          } catch {
            throw new Error("The column mapping must be a JSON object, for example {\"worker_id\": \"Contractor No\"}.");
          }
        }
      }
      const body = { name: f.name.trim(), base_url: f.baseUrl.trim(), settings, status: f.status, ...(f.credential ? { credential: f.credential } : {}) };
      const saved = s ? await vmsApi.update(s.id, body) : await vmsApi.create({ ...body, vendor: f.vendor });
      toast(`${saved.name} saved`);
      onSaved();
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={s ? `Edit ${s.name}` : "New contractor feed"} onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        {!s && (
          <label className="field">Source
            <select className="input" value={f.vendor} onChange={(e) => setF({ ...f, vendor: e.target.value as VmsVendor })}>
              {(Object.keys(VENDOR) as VmsVendor[]).map((v) => <option key={v} value={v}>{VENDOR[v]}</option>)}
            </select>
          </label>
        )}
        <label className="field">Name<input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required maxLength={100} placeholder="e.g. Fieldglass EU" /></label>
        <label className="field">{rest ? "Base URL (https)" : "Base URL to fetch from (optional)"}
          <input className="input" value={f.baseUrl} onChange={(e) => setF({ ...f, baseUrl: e.target.value })} required={rest} placeholder={rest ? "https://yourcompany.fieldglass.net" : "Leave empty to upload files instead"} />
        </label>
        <label className="field">{rest ? "Client id and secret (client_id:client_secret)" : "Bearer token (optional)"}
          <input className="input" type="password" autoComplete="off" value={f.credential} onChange={(e) => setF({ ...f, credential: e.target.value })} required={rest && !s?.has_credential} placeholder={s?.has_credential ? "Keep the stored credential" : ""} />
        </label>
        {rest ? (
          <label className="field">Listing path (optional)
            <input className="input" value={f.workersPath} onChange={(e) => setF({ ...f, workersPath: e.target.value })} placeholder={f.vendor === "beeline" ? "/api/v2/assignments" : "/api/v1/workers"} />
          </label>
        ) : (
          <>
            <label className="field">File path under the base URL (with a base URL)<input className="input" value={f.csvPath} onChange={(e) => setF({ ...f, csvPath: e.target.value })} placeholder="/feeds/contractors.csv" /></label>
            <label className="field">Date format (optional, Go layout)<input className="input" value={f.dateFormat} onChange={(e) => setF({ ...f, dateFormat: e.target.value })} placeholder="2006-01-02" /></label>
            <label className="field">Column mapping (optional JSON)
              <textarea className="input" rows={4} value={f.mapping} onChange={(e) => setF({ ...f, mapping: e.target.value })} placeholder={'{"worker_id": "Contractor No", "end_date": "Finish"}'} />
            </label>
            <p className="xs faint">Columns: worker_id, name (or first_name and last_name), email, supplier, role, sponsor_email, sponsor_employee_id, status, start_date, end_date, updated_at.</p>
          </>
        )}
        <label className="row tight small"><input type="checkbox" checked={f.status === "active"} onChange={(e) => setF({ ...f, status: e.target.checked ? "active" : "paused" })} /> Active (read on the hourly schedule)</label>
        <p className="small muted">Credentials are encrypted at rest and never shown again. Private and loopback addresses are refused. A change of base URL needs a new credential.</p>
        {error && <Callout tone="bad">{error}</Callout>}
        <div className="row"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Save"}</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
      {s && <SourceDeletionGuard kind="vms_source" id={s.id} />}
    </Drawer>
  );
}
