/**
 * Insights → Deployment health (design §10.5): the tenant readiness score, per-connection
 * scores, the ranked needs-attention list, skipped recommendations and drift. Every number is
 * computed by the server (GET /api/insights/deployment-health) from checklist evidence and
 * dry-run findings; a score breakdown explains every deducted point.
 */
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Activity, Download, Plug, RefreshCw } from "lucide-react";
import {
  AttentionEntry, Band, ConnectionHealthRow, DeploymentHealth as Health, DriftView, ReadinessSummary, ScoreBreakdown, SkippedRow, fmtDate, fmtDay,
  readiness, useApi,
} from "../../api";
import {
  Badge, Button, ButtonLink, Callout, DataTable, EmptyState, InsightsTabs, Kpi, Loading, Page, Segmented, Sev, SidePanel, useSelected, useToast,
} from "../../components";
import { BAND_LABEL, STATE_LABEL, ScoreCell, SimulatedBadge, StateBadge } from "../admin/connections/shared";

const bandText = (b: Band | "") => (b ? BAND_LABEL[b] : "No score yet");
const kpiTone = (score: number | null | undefined): "critical" | "warning" | undefined =>
  score === null || score === undefined ? undefined : score < 50 ? "critical" : score < 70 ? "warning" : undefined;

/** One needs-attention row with its single Fix link. */
function AttentionRow({ e, compact }: { e: AttentionEntry; compact?: boolean }) {
  const tone = e.severity === "critical" ? "crit" : e.severity === "high" || e.severity === "medium" ? "" : "low";
  return (
    <div className="att">
      <span className={`att-bar ${tone}`} aria-hidden />
      <div className="grow">
        <b>{e.sentence}</b>
        <div className="small faint row tight">
          <Sev s={e.severity} />
          <span>{e.connection_name}</span>
          {!compact && <span>· {e.age_days === 0 ? "today" : `${e.age_days} d old`}</span>}
          {e.blocks_activation && <Badge tone="outline">Blocks activation</Badge>}
          {e.privileged && <Badge tone="warning">Privileged</Badge>}
          {e.code && <code className="xs">{e.code}</code>}
        </div>
      </div>
      <ButtonLink size="sm" to={e.fix.href} aria-label={`Fix: ${e.sentence}`}>Fix</ButtonLink>
    </div>
  );
}

export function NeedsAttentionList({ entries, limit, compact }: { entries: AttentionEntry[] | null; limit?: number; compact?: boolean }) {
  if (!entries) return <Loading kind="block" />;
  if (!entries.length) return <EmptyState title="Nothing needs attention">No failing checks, open findings or expiring skips.</EmptyState>;
  return <div>{entries.slice(0, limit).map((e) => <AttentionRow key={e.id} e={e} compact={compact} />)}</div>;
}

/** The Home card KPI: tenant score, band as tone, and what needs attention. */
export function ReadinessKpi({ data, error }: { data: ReadinessSummary | null | undefined; error?: string | null }) {
  if (error) return <Kpi label="Deployment readiness" value="–" sub={<span className="err">Couldn't load readiness</span>} to="/insights/deployment-health" />;
  if (!data) return <Kpi label="Deployment readiness" value="…" sub="Loading" />;
  return (
    <Kpi
      label="Deployment readiness"
      value={data.score === null ? "–" : <>{data.score} <span className="faint" style={{ fontSize: "var(--fs-lg)" }}>/ 100</span></>}
      tone={kpiTone(data.score)}
      sub={<>{bandText(data.band)} · {data.needs_attention} item{data.needs_attention === 1 ? "" : "s"} need attention · {data.draft} connection{data.draft === 1 ? "" : "s"} in setup</>}
      to="/insights/deployment-health"
    />
  );
}

/** Home's "Needs attention" card: the top three deployment entries. */
export function ReadinessAttentionCard({ data, error }: { data: ReadinessSummary | null | undefined; error?: string | null }) {
  return (
    <div className="card">
      <div className="spread" style={{ marginBottom: 4 }}>
        <h2>Needs attention</h2>
        <Link to="/insights/deployment-health" className="small">Deployment health</Link>
      </div>
      {error ? <Callout tone="bad">Couldn't load deployment health: {error}</Callout> : <NeedsAttentionList entries={data ? data.top : null} limit={3} compact />}
    </div>
  );
}

function Breakdown({ id, name }: { id: string; name: string }) {
  const { data, error } = useApi<{ breakdown: ScoreBreakdown; needs_attention: AttentionEntry[] }>(`/connections/${id}/health`);
  if (!data) return <Loading error={error} kind="block" />;
  const b = data.breakdown;
  return (
    <div className="stack">
      <div>
        <ScoreCell score={b.score} band={b.band} />
        <p className="small muted mt-sm">
          Checklist {b.checklist.score} ({b.checklist.earned} of {b.checklist.possible} points) − findings {b.penalty.total}{b.penalty.capped ? " (capped at 40)" : ""} = {b.uncapped}
          {b.capped ? `; ${b.cap_reason}` : ""}{b.band_limited ? `; ${b.recommended_skipped_pct}% of the Recommended weight is skipped, so it cannot be Healthy` : ""}.
        </p>
      </div>
      <section className="stack-sm">
        <h3>Checklist points not earned</h3>
        {b.checklist.missing.length === 0 ? <p className="small faint">Every applicable item passes.</p> : (
          <table>
            <thead><tr><th>Item</th><th>Status</th><th className="num">Points</th></tr></thead>
            <tbody>
              {b.checklist.missing.map((m) => (
                <tr key={m.item}>
                  <td className="small"><Link to={`/admin/connections/${id}?item=${m.item}`}>{m.title}</Link><div className="xs faint">{m.level}{m.reason ? ` · skipped: ${m.reason}` : ""}</div></td>
                  <td className="small">{m.status}</td>
                  <td className="num small">−{m.score_points}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <section className="stack-sm">
        <h3>Finding penalty</h3>
        {b.penalty.findings.length === 0 ? <p className="small faint">No findings.</p> : (
          <table>
            <tbody>
              {b.penalty.findings.map((f, i) => (
                <tr key={i}><td className="small"><code>{f.code}</code> {f.title}</td><td><Sev s={f.severity} /></td><td className="small">{f.status}</td><td className="num small">−{f.points}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <Link to={`/admin/connections/${id}`}>Open {name}</Link>
    </div>
  );
}

/** Per live connection: the activation baseline against now, and what drifted. */
function DriftRows({ drift, days }: { drift: DriftView[]; days: number }) {
  if (drift.length === 0) return <p className="small faint">No live connection has a baseline yet. One is captured when a connection is activated.</p>;
  const since = Date.now() - days * 86_400_000;
  return (
    <div className="stack-sm">
      {drift.map((d) => {
        const start = d.score_series.find((p) => Date.parse(p.at) >= since)?.score ?? d.baseline.score;
        const delta = d.score - start;
        return (
          <div key={d.connection_id} className="stack-sm">
            <div className="spread">
              <b><Link to={`/admin/connections/${d.connection_id}`}>{d.connection_name}</Link> {d.state === "degraded" && <Badge tone="warning">Degraded</Badge>}</b>
              <span className="small">
                Score {d.baseline.score} → {d.score} ({delta === 0 ? "no change" : `${delta > 0 ? "+" : ""}${delta}`} in {days} days) · findings {d.baseline.findings} → {d.findings} · accounts {d.baseline.accounts} → {d.accounts}
              </span>
            </div>
            {d.degraded_reason && <div className="small">Degraded: {d.degraded_reason}</div>}
            {d.events.length === 0 && !d.template_upgrade && <div className="small faint">No drift from the baseline.</div>}
            {d.events.map((e) => (
              <div key={e.kind + e.subject} className="small row tight"><Sev s={e.severity} /><span>{e.sentence}</span></div>
            ))}
            {d.template_upgrade && d.events.every((e) => e.kind !== "template_update") && (
              <div className="small faint">Template update available: {d.template_upgrade.available}{d.template_upgrade.major ? " (a major release needs a new revision)" : ""}.</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function DeploymentHealthBody({ data, compact }: { data: Health; compact?: boolean }) {
  const nav = useNavigate();
  const [selected, setSelected] = useSelected();
  const [driftWindow, setDriftWindow] = useState<"7" | "30" | "90">("30");
  const t = data.tenant;
  const k = data.kpis;
  const sel = data.connections.find((c) => c.id === selected);
  return (
    <div className="stack">
      <div className="grid g4">
        <Kpi label="Tenant readiness" value={t.score === null ? "–" : <>{t.score} <span className="faint" style={{ fontSize: "var(--fs-lg)" }}>/ 100</span></>} tone={kpiTone(t.score)} sub={`${bandText(t.band)} · ${t.connections_counted} connection${t.connections_counted === 1 ? "" : "s"} counted`} />
        <Kpi label="Accounts correlated" value={k.accounts_correlated_pct === undefined ? "–" : `${k.accounts_correlated_pct}%`} sub={`${k.orphans} orphans · ${k.dormant} dormant · ${k.privileged_accounts} privileged`} />
        <Kpi label="Open critical and high" value={k.open_critical_high} tone={k.open_critical_high ? "critical" : undefined} sub="findings from dry runs" />
        <Kpi label="Not yet active" value={k.connections_in_setup} sub={`${k.degraded} degraded`} tone={k.degraded ? "warning" : undefined} to="/admin/connections" />
      </div>
      {(t.capped || !t.hr_source) && <Callout tone="warn">{t.cap_reason ?? "No active authoritative HR source: people with no account cannot be computed."}</Callout>}
      {!compact && t.hr_source && !t.capped && <p className="small faint">HR source: {t.hr_source}. {t.formula}.</p>}
      {compact && (
        <div className="grid g21">
        <div className="card">
          <div className="spread" style={{ marginBottom: 4 }}><h2>Needs attention</h2><span className="small faint">{data.needs_attention.length} ranked by severity, reach and whether they block activation</span></div>
          <NeedsAttentionList entries={data.needs_attention} limit={compact ? 5 : undefined} />
        </div>
        <div className="card flush" style={{ alignSelf: "start" }}>
          <div className="card-h"><h2>Connections</h2><Link to="/admin/connections" className="small">Manage</Link></div>
          {data.connections.length === 0 ? (
            <EmptyState title="No governed connections yet" icon={<Plug size={18} />} action={<ButtonLink to="/admin/connections/new" variant="primary">New connection</ButtonLink>}>Create a connection to see its readiness here.</EmptyState>
          ) : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Connection</th><th>State</th><th>Score</th></tr></thead>
                <tbody>
                  {data.connections.map((c) => (
                    <tr key={c.id} className={`click ${selected === c.id ? "active" : ""}`} tabIndex={0} onClick={() => setSelected(c.id)} onKeyDown={(e) => e.key === "Enter" && setSelected(c.id)}>
                      <td><b className="name-link">{c.name}</b><div className="xs faint">{c.counted ? `${c.accounts} accounts` : "not counted until validated"}{c.simulated && " · simulated"}</div></td>
                      <td><StateBadge state={c.state} /></td>
                      <td><ScoreCell score={c.score} band={c.band} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
      )}
      {!compact && (
        <>
          <DataTable<ConnectionHealthRow>
            id="deployment-connections"
            rows={data.connections}
            rowKey={(r) => r.id}
            activeKey={selected}
            onRowClick={(r) => setSelected(r.id)}
            columns={[
              { id: "name", header: "Connection", sort: (r) => r.name, cell: (r) => <div><b className="name-link">{r.name}</b><div className="xs faint row tight">{r.connector_type}{r.simulated && <SimulatedBadge />}</div></div> },
              { id: "state", header: "State", sort: (r) => r.state, csv: (r) => STATE_LABEL[r.state], cell: (r) => <StateBadge state={r.state} /> },
              { id: "score", header: "Score", sort: (r) => r.score, cell: (r) => <ScoreCell score={r.score} band={r.band} /> },
              { id: "blocking", header: "Blocking", num: true, sort: (r) => r.blocking, cell: (r) => r.blocking },
              { id: "validated", header: "Last validated", sort: (r) => r.last_validated ?? "", cell: (r) => <span className="small">{r.last_validated ? fmtDate(r.last_validated) : "Never"}</span>, hideNarrow: true },
              {
                id: "drift", header: "Drift", sort: (r) => r.drift?.events ?? 0, csv: (r) => String(r.drift?.events ?? 0), hideNarrow: true,
                cell: (r) => r.drift && r.drift.events > 0
                  ? <Badge tone={r.drift.high > 0 ? "critical" : "warning"}>{r.drift.events} since activation</Badge>
                  : <span className="faint small" title={r.drift ? "No drift from the activation baseline" : "Only live connections have a baseline"}>–</span>,
              },
            ]}
            searchText={(r) => `${r.name} ${r.connector_type} ${r.state}`}
            empty={<EmptyState title="No governed connections yet" icon={<Plug size={18} />} action={<ButtonLink to="/admin/connections/new" variant="primary">New connection</ButtonLink>}>Create a connection to see its readiness here.</EmptyState>}
          />
          <div className="card">
            <div className="spread" style={{ marginBottom: 4 }}><h2>Needs attention</h2><span className="small faint">{data.needs_attention.length} ranked by severity, reach and whether they block activation</span></div>
            <NeedsAttentionList entries={data.needs_attention} />
          </div>
          <div className="card flush">
            <div className="card-h"><h2>Skipped recommendations</h2><span className="small faint">Accepted gaps stay listed until un-skipped or their review date passes</span></div>
            {data.skipped.length === 0 ? <EmptyState title="Nothing skipped">Recommended items skipped with a reason show here with who skipped them and when to review.</EmptyState> : (
              <div className="table-scroll">
                <table>
                  <thead><tr><th>Item</th><th>Connection</th><th>Who</th><th>Reason</th><th>Review by</th></tr></thead>
                  <tbody>
                    {data.skipped.map((s: SkippedRow) => (
                      <tr key={s.connection_id + s.item_id} className="click" tabIndex={0} onClick={() => nav(`/admin/connections/${s.connection_id}?item=${s.item_id}`)} onKeyDown={(e) => e.key === "Enter" && nav(`/admin/connections/${s.connection_id}?item=${s.item_id}`)}>
                        <td className="small"><b>{s.item_title}</b><div className="xs faint">{s.item_id}</div></td>
                        <td className="small">{s.connection_name}</td>
                        <td className="small">{s.actor}<div className="xs faint">{fmtDay(s.skipped_at)}</div></td>
                        <td className="small">“{s.reason}”</td>
                        <td className="small nowrap">{fmtDay(s.review_by)}{s.expired && <> <Badge tone="warning">Expired</Badge></>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          <div className="card">
            <div className="spread"><h2>Drift since activation</h2><Segmented label="Drift window" value={driftWindow} onChange={setDriftWindow} options={[["7", "7 days"], ["30", "30 days"], ["90", "90 days"]]} /></div>
            <p className="small muted mt-sm">
              A baseline is captured at activation. Live checks re-run {data.schedule.live_checks} and reconciliation {data.schedule.reconciliation}; each run is compared with the baseline.
              Two failing runs of a Required check, a credential close to expiry or a template grace period that ends move a connection to Degraded: reads continue, write-back stops.
            </p>
            <DriftRows drift={data.drift} days={Number(driftWindow)} />
            {data.tasks.map((t) => (
              <div key={t.id} className="att">
                <span className="att-bar" aria-hidden />
                <div className="grow"><b>{t.title}</b><div className="small faint">Inbox task · {t.reason}{t.owner && <> · owner {t.owner}</>}</div></div>
                <ButtonLink size="sm" to={t.href}>Open</ButtonLink>
              </div>
            ))}
          </div>
        </>
      )}
      {sel && (
        <SidePanel title={sel.name} sub={<><StateBadge state={sel.state} />{sel.simulated && <SimulatedBadge />}</>} onClose={() => setSelected(null)} fullHref={`/admin/connections/${sel.id}`} fullLabel="Open connection">
          <Breakdown id={sel.id} name={sel.name} />
        </SidePanel>
      )}
    </div>
  );
}

export function DeploymentHealth() {
  const { data, error } = useApi<Health>("/insights/deployment-health");
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const rerun = async (reconcile: boolean) => {
    setBusy(true);
    try {
      const r = await readiness.rerun(reconcile);
      const v = r.results.filter((x) => x.validation_run_id).length;
      toast(`Re-ran ${v} connection${v === 1 ? "" : "s"}${reconcile ? " with reconciliation" : ""}`);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Page
      title="Deployment health"
      crumbs={[["Protection"], ["Insights", "/insights"], ["Deployment health"]]}
      tabs={<InsightsTabs />}
      sub="What was missed during deployment: readiness per connection, gaps found by dry-run reconciliation, and what to fix next."
      actions={
        <>
          <Button icon={<RefreshCw size={14} />} disabled={busy} onClick={() => rerun(false)}>{busy ? "Running…" : "Re-run now"}</Button>
          <Button icon={<Activity size={14} />} disabled={busy} onClick={() => rerun(true)}>Re-run with reconciliation</Button>
          <Button icon={<Download size={14} />} disabled title="The evidence export (manifest, checklist, checks, findings, skips) arrives with DR-8">Export evidence</Button>
        </>
      }
    >
      {!data ? <Loading error={error} kind="page" /> : (
        <>
          <p className="small faint" style={{ marginTop: -8, marginBottom: 12 }}>
            Schedule: live checks {data.schedule.live_checks}, reconciliation {data.schedule.reconciliation} ({data.schedule.note}). Demo connectors validate against the simulated “{data.scenario}” scenario.
          </p>
          <DeploymentHealthBody data={data} />
        </>
      )}
    </Page>
  );
}
