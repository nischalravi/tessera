/** Admin → Connections & integrations: governed connections and legacy demo connectors (§10.1). */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Activity, Plus, RefreshCw, Server } from "lucide-react";
import { Connection, ConnectorRow, LegacyConnection, api, fmtDate, readiness, useApi } from "../../../api";
import { Chip, DataTable, Page, useToast } from "../../../components";
import { STATE_LABEL, ScoreCell, SimulatedBadge, StateBadge } from "./shared";

type Row = Connection | LegacyConnection;
const key = (r: Row) => (r.legacy ? `legacy:${r.system}` : r.id);
const STATE_ORDER = ["degraded", "draft", "ready_to_validate", "validated", "dry_run_reconciled", "active", "retired", "superseded"];

export function ConnectionsList() {
  const { data, error, reload } = useApi<Row[]>("/connections");
  const { data: counts } = useApi<ConnectorRow[]>("/connectors");
  const nav = useNavigate();
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const accounts = (system: string) => counts?.find((c) => c.system === system)?.accounts;
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
              <div>
                <b className="name-link">{r.name}</b>
                <div className="xs faint row tight">
                  {r.legacy ? r.type : r.template.display_name}
                  {!r.legacy && r.simulated && <SimulatedBadge />}
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
          { id: "updated", header: "Last change", hideNarrow: true, sort: (r) => (r.legacy ? "" : r.updated_at), cell: (r) => (r.legacy ? <span className="faint small">–</span> : <span className="small">{fmtDate(r.updated_at)}</span>) },
        ]}
        searchText={(r) => `${r.name} ${r.system} ${r.legacy ? "legacy" : r.connector_type}`}
        filters={[{ id: "state", label: "State", options: Object.entries(STATE_LABEL).map(([value, label]) => ({ value, label })), get: (r) => (r.legacy ? "legacy" : r.state) }]}
        commands={[
          { label: "New connection", icon: <Plus size={16} />, onClick: () => nav("/admin/connections/new") },
          { label: busy === "rerun" ? "Checking…" : "Run deployment health check", icon: <Activity size={16} />, disabled: !!busy, onClick: rerun },
          { label: "Directory agents", icon: <Server size={16} />, onClick: () => nav("/admin/connections/agents") },
          { label: busy === "sync" ? "Syncing…" : "Sync legacy connectors", icon: <RefreshCw size={16} />, disabled: !!busy, onClick: syncLegacy },
        ]}
        onRowClick={(r) => nav(r.legacy ? (r.governed_by ? `/admin/connections/${r.governed_by}` : `/directory/apps?selected=${r.system}`) : `/admin/connections/${r.id}`)}
        initialSort={["state", 1]}
      />
    </Page>
  );
}
