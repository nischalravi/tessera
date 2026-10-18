import { PlatformHealth as Health, useApi } from "../../api";
import { Badge, Callout, DataTable, Page } from "../../components";

const secs = (v: number | null) => (v === null ? "no data" : v < 1 ? `${Math.round(v * 1000)} ms` : `${v.toFixed(2)} s`);
const when = (t: string | null) => (t ? new Date(t).toLocaleString() : "never");
const CHECK_LABEL: Record<string, string> = {
  database: "Database reachable", audit_chain: "Audit chain head readable", kek: "Encryption key loaded", loops: "Background loops fresh",
};

/**
 * Platform health: the signals /metrics exposes, summarised for a person (GET /api/admin/platform-health).
 * Counters are since the process started; alerting and SLOs live in docs/operations/slo.md.
 */
export function PlatformHealth() {
  const { data, error, reload } = useApi<Health>("/admin/platform-health");
  return (
    <Page
      title="Platform health"
      crumbs={[["Settings"], ["Admin", "/admin"], ["Platform health"]]}
      sub="Whether the service itself is healthy. Counts are since the server started and cover every tenant; nothing here is tenant data."
    >
      <div className="stack">
        {error && <Callout tone="bad">Could not load platform health.</Callout>}
        {data && (
          <Callout tone={data.status === "ok" ? "ok" : "warn"}>
            {data.status === "ok" ? "All readiness checks pass." : "One or more readiness checks fail; the load balancer is told not to send traffic."}{" "}
            Updated {when(data.generated_at)}. <button className="btn" onClick={reload}>Refresh</button>
          </Callout>
        )}
        {data && (
          <>
            <h2>Readiness</h2>
            <DataTable
              id="health-checks"
              searchText={(c) => c.name}
              rows={data.checks}
              rowKey={(c) => c.name}
              columns={[
                { id: "check", header: "Check", cell: (c) => CHECK_LABEL[c.name] ?? c.name },
                { id: "state", header: "State", cell: (c) => <Badge tone={c.ok ? "ok" : "critical"}>{c.ok ? "Passing" : "Failing"}</Badge> },
              ]}
              empty="No checks."
            />
            <h2>Background loops</h2>
            <DataTable
              id="health-loops"
              searchText={(l) => l.name}
              rows={data.loops}
              rowKey={(l) => l.name}
              columns={[
                { id: "loop", header: "Loop", cell: (l) => <b>{l.name}</b> },
                { id: "state", header: "State", cell: (l) => <Badge tone={l.healthy ? "ok" : "critical"}>{l.healthy ? "Fresh" : "Lagging"}</Badge> },
                { id: "last", header: "Last success", cell: (l) => when(l.last_success_at) },
                { id: "lag", header: "Lag", cell: (l) => `${Math.round(l.lag_seconds)} s` },
                { id: "runs", header: "Runs / failures", cell: (l) => `${l.runs} / ${l.failures}` },
              ]}
              empty="No loops are running."
            />
            <h2>Service</h2>
            <DataTable
              id="health-service"
              searchText={(r) => r.k}
              rows={[
                { k: "API requests", v: `${data.http.requests} (${data.http.server_errors} server errors)` },
                { k: "API p95 latency", v: secs(data.http.p95_seconds) },
                { k: "Audit writes", v: `${data.audit.writes} (${data.audit.write_failures} failed)` },
                { k: "Database connections", v: `${data.database.in_use} in use, ${data.database.idle} idle, ${data.database.open_connections} open` },
                { k: "Database transaction p95", v: secs(data.database.tx_p95_seconds) },
                { k: "Database lock wait p95", v: secs(data.database.lock_wait_p95_seconds) },
                { k: "Database busy errors", v: String(data.database.busy_errors) },
              ]}
              rowKey={(r) => r.k}
              columns={[{ id: "k", header: "Signal", cell: (r) => r.k }, { id: "v", header: "Value", cell: (r) => r.v }]}
              empty=""
            />
            <h2>Sign-in outcomes</h2>
            <DataTable
              id="health-logins"
              searchText={(l) => l.method}
              rows={data.logins}
              rowKey={(l) => l.method}
              columns={[
                { id: "m", header: "Method", cell: (l) => l.method },
                { id: "s", header: "Succeeded", cell: (l) => l.success },
                { id: "f", header: "Refused", cell: (l) => l.failure },
              ]}
              empty="No sign-ins since the server started."
            />
            <h2>Calls to external systems</h2>
            <DataTable
              id="health-connectors"
              searchText={(c) => `${c.connector} ${c.op}`}
              rows={data.connectors}
              rowKey={(c) => `${c.connector}/${c.op}`}
              columns={[
                { id: "c", header: "System", cell: (c) => `${c.connector} ${c.op}` },
                { id: "n", header: "Calls", cell: (c) => c.calls },
                { id: "e", header: "Errors", cell: (c) => c.errors },
              ]}
              empty="No calls since the server started."
            />
          </>
        )}
      </div>
    </Page>
  );
}
