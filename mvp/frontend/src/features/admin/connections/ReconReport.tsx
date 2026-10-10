/** Reconciliation report (§10.4): staged counts, correlation tiers and findings. */
import { useState } from "react";
import { useParams } from "react-router-dom";
import { Connection, DryRunView, Finding, fmtDate, useApi } from "../../../api";
import { Bar, Callout, DataTable, FilterChips, Kpi, Loading, Page, Sev } from "../../../components";
import { FindingDrawer, FindingStatus } from "./FindingDrawer";
import { SimulatedBadge } from "./shared";

const code = (f: Finding) => (/^[a-z]$/.test(f.variant) ? f.code + f.variant : f.code);

export function ReconReport() {
  const { id = "", run = "" } = useParams();
  const { data: conn } = useApi<Connection>(`/connections/${id}`);
  const { data: dr, error, reload } = useApi<DryRunView>(`/connections/${id}/dry-runs/${run}`);
  const [sev, setSev] = useState("all");
  const [status, setStatus] = useState("all");
  const [open, setOpen] = useState<Finding | null>(null);
  const crumbs: [string, string?][] = [["Settings"], ["Connections", "/admin/connections"], [conn?.name ?? "Connection", `/admin/connections/${id}?step=dryrun`], ["Reconciliation"]];
  if (!dr) return <Page title="Reconciliation report" crumbs={crumbs}><Loading error={error} kind="page" /></Page>;
  const c = dr.counts;
  const latest = conn?.latest_dry_run_id === dr.id;
  const rows = dr.findings.filter((f) => (sev === "all" || f.severity === sev) && (status === "all" || f.status === status));
  const n = (s: string) => dr.findings.filter((f) => f.severity === s).length;
  return (
    <Page
      title="Reconciliation report"
      crumbs={crumbs}
      badge={dr.simulated ? <SimulatedBadge /> : undefined}
      sub={<>Dry run {dr.id.slice(0, 8)} by {dr.actor} · {fmtDate(dr.started_at)} · staged only: nothing here is in the live graph yet</>}
    >
      <div className="stack">
        <Callout tone={dr.kpis.orphans ? "warn" : "neutral"}>{dr.activation_note}</Callout>
        {dr.stale && <Callout tone="warn">{dr.stale_reason}</Callout>}
        <div className="grid g4">
          <Kpi label="Objects staged" value={c.accounts} sub={`${c.users} user · ${c.service} service accounts · ${c.groups} groups · ${c.memberships} memberships`} />
          <Kpi
            label="Correlated"
            value={`${c.correlated_pct}%`}
            sub={
              <div className="stack-sm">
                <Bar value={c.tier1 + c.tier2} max={Math.max(1, c.users)} tone="ok" />
                <span>tier 1 {c.tier1} · tier 2 {c.tier2} · email proposals {c.proposed} · ambiguous {c.ambiguous} · none {c.uncorrelated}</span>
              </div>
            }
          />
          <Kpi label="Orphans" value={dr.kpis.orphans} tone={dr.kpis.orphans ? "warning" : undefined} sub={`${dr.kpis.people_without_account} people with no account`} />
          <Kpi label="Privileged unexpected" value={dr.kpis.privileged_unexpected} tone={dr.kpis.privileged_unexpected ? "critical" : undefined} sub="memberships in privileged groups" />
        </div>
        <div className="spread" style={{ flexWrap: "wrap" }}>
          <FilterChips label="Severity" value={sev} onChange={setSev} options={[{ id: "all", label: "All", count: dr.findings.length }, ...["critical", "high", "medium", "low"].map((s) => ({ id: s, label: s[0].toUpperCase() + s.slice(1), count: n(s) }))]} />
          <FilterChips label="Status" value={status} onChange={setStatus} options={[{ id: "all", label: "Any status" }, { id: "open", label: "Open" }, { id: "accepted", label: "Accepted" }, { id: "resolved", label: "Resolved" }]} />
        </div>
        <DataTable<Finding>
          id="reconciliation-findings"
          rows={rows}
          rowKey={(f) => f.id}
          activeKey={open?.id}
          onRowClick={setOpen}
          initialSort={["sev", 1]}
          columns={[
            { id: "sev", header: "Severity", sort: (f) => ["critical", "high", "medium", "low", "info"].indexOf(f.severity), csv: (f) => f.severity, cell: (f) => <Sev s={f.severity} /> },
            { id: "code", header: "Finding", sort: (f) => code(f), csv: (f) => `${code(f)} ${f.title}`, cell: (f) => <div><b className="name-link">{f.title}</b><div className="xs faint">{code(f)}</div></div> },
            { id: "count", header: "Count", num: true, sort: (f) => f.count, csv: (f) => f.count, cell: (f) => <span className="tnum">{f.count}<span className="faint xs"> / {f.denominator} ({f.percent}%)</span></span> },
            { id: "impact", header: "Impact", csv: (f) => f.impact.sentence, cell: (f) => <span className="small">{f.impact.sentence}</span>, hideNarrow: true },
            { id: "cause", header: "Probable cause", csv: (f) => f.cause?.sentence ?? "", cell: (f) => <span className="small">{f.cause?.sentence ?? <span className="faint">–</span>}</span>, hideNarrow: true },
            { id: "status", header: "Status", sort: (f) => f.status, csv: (f) => f.status, cell: (f) => <FindingStatus s={f.status} /> },
          ]}
          searchText={(f) => `${f.code} ${f.title} ${f.impact.sentence} ${f.cause?.sentence ?? ""}`}
        />
      </div>
      {open && <FindingDrawer connectionId={id} f={open} latest={latest} onClose={() => setOpen(null)} onChanged={reload} />}
    </Page>
  );
}
