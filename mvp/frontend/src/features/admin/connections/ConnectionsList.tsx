/** Admin → Connections & integrations: governed connections and legacy demo connectors (§10.1). */
import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Activity, CalendarClock, Plus, RefreshCw, Server } from "lucide-react";
import { Connection, ConnectorSyncStatus, LegacyConnection, api, connectorSchedule, fmtDate, readiness, relTime, useApi } from "../../../api";
import { useSession } from "../../../app/auth";
import { Badge, Button, Callout, Chip, DataTable, Drawer, Page, useToast } from "../../../components";
import { VendorLogo, vendorForType } from "../../../components/VendorLogo";
import { STATE_LABEL, ScoreCell, SimulatedBadge, StateBadge } from "./shared";

type Row = Connection | LegacyConnection;
const key = (r: Row) => (r.legacy ? `legacy:${r.system}` : r.id);
const STATE_ORDER = ["degraded", "draft", "ready_to_validate", "validated", "dry_run_reconciled", "active", "retired", "superseded"];

export function ConnectionsList() {
  const { data, error, reload } = useApi<Row[]>("/connections");
  const { data: sync, reload: reloadSync } = useApi<ConnectorSyncStatus>("/connectors/sync-status");
  const { can } = useSession();
  const [scheduling, setScheduling] = useState(false);
  const nav = useNavigate();
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const conn = (system: string) => sync?.connectors.find((c) => c.system === system);
  const accounts = (system: string) => conn(system)?.accounts;
  const syncLegacy = async () => {
    setBusy("sync");
    try {
      await api("/connectors/sync", {});
      toast("Legacy demo connectors synced");
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  const rerun = async () => {
    setBusy("rerun");
    try {
      const r = await readiness.rerun(false);
      const ran = r.results.filter((x) => x.validation_run_id).length;
      toast(`Deployment health check: ${ran} connection${ran === 1 ? "" : "s"} re-validated`);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  const governed = (data ?? []).filter((r): r is Connection => !r.legacy);
  return (
    <Page
      title="Connections & integrations"
      crumbs={[["Settings"], ["Connections"]]}
      count={data ? `${governed.length} governed · ${(data.length - governed.length)} legacy` : undefined}
      sub="Every customer system is a connection with a readiness checklist. It cannot become active until every Required item passes; the server enforces it. Legacy demo connectors from TESSERA_CONNECTORS keep syncing as before."
    >
      {sync && <SyncSummary s={sync} />}
      {scheduling && sync && can("connections.manage") ? (
        <SchedulePanel s={sync.schedule} onClose={() => setScheduling(false)} onSaved={() => { setScheduling(false); reloadSync(); }} />
      ) : scheduling && sync ? (
        <Drawer title="Sync schedule" onClose={() => setScheduling(false)}><SyncSummary s={sync} /><p className="small muted">Changing the schedule needs the connections.manage permission.</p></Drawer>
      ) : null}
      <DataTable<Row>
        id="connections"
        rows={data}
        error={error}
        rowKey={key}
        onRefresh={reload}
        columns={[
          {
            id: "name", header: "Connection", sort: (r) => r.name,
            cell: (r) => (
              <div className="row tight" style={{ flexWrap: "nowrap" }}>
                <VendorLogo vendor={vendorForType(r.system, r.legacy ? "" : r.connector_type)} size={36} />
                <div>
                  <b className="name-link">{r.name}</b>
                  <div className="xs faint row tight">
                    {r.legacy ? r.type : r.template.display_name}
                    {!r.legacy && r.simulated && <SimulatedBadge />}
                  </div>
                </div>
              </div>
            ),
          },
          { id: "sys", header: "System", sort: (r) => r.system, cell: (r) => <Chip mono>{r.system}</Chip>, hideNarrow: true },
          {
            id: "state", header: "State", sort: (r) => (r.legacy ? 99 : STATE_ORDER.indexOf(r.state)), csv: (r) => (r.legacy ? "legacy" : STATE_LABEL[r.state]),
            cell: (r) => r.legacy ? (
              <span className="row tight"><StateBadge state="legacy" />{r.governed_by && <span className="xs faint">governed below</span>}</span>
            ) : (
              <span className="row tight"><StateBadge state={r.state} />{r.update_in_progress && <span className="xs faint">update in progress</span>}</span>
            ),
          },
          {
            id: "score", header: "Readiness", sort: (r) => (r.legacy ? -1 : r.score?.score ?? -1), csv: (r) => (r.legacy ? "" : r.score?.score ?? ""),
            cell: (r) => (r.legacy ? <span className="faint small">Not governed</span> : <ScoreCell score={r.score?.score} band={r.score?.band} />),
          },
          {
            id: "blocking", header: "Blocking", num: true, sort: (r) => (r.legacy ? 0 : r.blocking),
            cell: (r) => (r.legacy || !r.next ? <span className="faint">–</span> : r.blocking ? <b style={{ color: "var(--critical)" }}>{r.blocking}</b> : 0),
          },
          { id: "accounts", header: "Accounts", num: true, hideNarrow: true, sort: (r) => accounts(r.system) ?? 0, cell: (r) => accounts(r.system) ?? 0 },
          { id: "groups", header: "Groups", num: true, hideNarrow: true, sort: (r) => conn(r.system)?.groups ?? 0, cell: (r) => conn(r.system)?.groups ?? 0 },
          { id: "resources", header: "Resources", num: true, hideNarrow: true, sort: (r) => conn(r.system)?.resources ?? 0, cell: (r) => conn(r.system)?.resources ?? 0 },
          {
            id: "lastsync", header: "Last sync", hideNarrow: true, sort: (r) => conn(r.system)?.last_sync_at ?? "",
            cell: (r) => {
              const c = conn(r.system);
              return c?.last_sync_at
                ? <span className="small" title={c.last_full_sync_at ? `Last full read ${fmtDate(c.last_full_sync_at)}` : undefined}>{relTime(c.last_sync_at)}</span>
                : <span className="faint small" title="This connector keeps no checkpoint, so only the run of the whole sync is recorded">–</span>;
            },
          },
          { id: "updated", header: "Last change", hideNarrow: true, sort: (r) => (r.legacy ? "" : r.updated_at), cell: (r) => (r.legacy ? <span className="faint small">–</span> : <span className="small">{fmtDate(r.updated_at)}</span>) },
        ]}
        searchText={(r) => `${r.name} ${r.system} ${r.legacy ? "legacy" : r.connector_type}`}
        filters={[{ id: "state", label: "State", options: Object.entries(STATE_LABEL).map(([value, label]) => ({ value, label })), get: (r) => (r.legacy ? "legacy" : r.state) }]}
        commands={[
          { label: "New connection", icon: <Plus size={16} />, onClick: () => nav("/admin/connections/new") },
          { label: busy === "rerun" ? "Checking…" : "Run deployment health check", icon: <Activity size={16} />, disabled: !!busy, onClick: rerun },
          { label: "Directory agents", icon: <Server size={16} />, onClick: () => nav("/admin/connections/agents") },
          { label: "Sync schedule", icon: <CalendarClock size={16} />, onClick: () => setScheduling(true) },
          { label: busy === "sync" ? "Syncing…" : "Sync legacy connectors", icon: <RefreshCw size={16} />, disabled: !!busy, onClick: syncLegacy },
        ]}
        onRowClick={(r) => nav(r.legacy ? (r.governed_by ? `/admin/connections/${r.governed_by}` : `/directory/apps?selected=${r.system}`) : `/admin/connections/${r.id}`)}
        initialSort={["state", 1]}
      />
    </Page>
  );
}

/** The tenant's sync schedule and its last run, above the list. */
function SyncSummary({ s }: { s: ConnectorSyncStatus }) {
  const { delta_every_minutes: d, full_every_hours: f } = s.schedule;
  const every = (n: number, unit: string) => (n === 0 ? "off" : `every ${n} ${unit}${n === 1 ? "" : "s"}`);
  return (
    <p className="small muted" style={{ margin: "0 0 8px" }}>
      Delta sync <b>{every(d, "minute")}</b>{s.schedule.next_delta_at && <> (next {relTime(s.schedule.next_delta_at)})</>} · full sync <b>{every(f, "hour")}</b>{s.schedule.next_full_at && <> (next {relTime(s.schedule.next_full_at)})</>}
      {" · "}
      {s.last_run
        ? <>last sync run <Badge tone={s.last_run.status === "succeeded" ? "ok" : s.last_run.status === "failed" ? "critical" : "info"}>{s.last_run.status}</Badge> {relTime(s.last_run.finished_at ?? s.last_run.started_at)} ({s.last_run.trigger})</>
        : "no sync has run yet"}
    </p>
  );
}

function SchedulePanel({ s, onClose, onSaved }: { s: ConnectorSyncStatus["schedule"]; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [delta, setDelta] = useState(String(s.delta_every_minutes));
  const [full, setFull] = useState(String(s.full_every_hours));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await connectorSchedule.put(Number(delta) || 0, Number(full) || 0);
      toast("Sync schedule saved");
      onSaved();
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title="Sync schedule" sub="When Tessera reads your connected systems on its own." onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Delta sync every (minutes, 5 to 1440, 0 is off)
          <input className="input" type="number" min={0} max={1440} value={delta} onChange={(e) => setDelta(e.target.value)} required />
          <span className="hint">Each connector resumes from where its last sync stopped, so only what changed is read.</span>
        </label>
        <label className="field">Full sync every (hours, 1 to 720, 0 is off)
          <input className="input" type="number" min={0} max={720} value={full} onChange={(e) => setFull(e.target.value)} required />
          <span className="hint">Every connector reads everything again and ignores its checkpoint. It catches what a delta sync cannot see, such as deletions.</span>
        </label>
        <p className="small muted">Each run appears under Jobs as a connector sync. Leave a schedule off to sync only when someone runs it.</p>
        {err && <Callout tone="bad">{err}</Callout>}
        <div className="row"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Save"}</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
    </Drawer>
  );
}
