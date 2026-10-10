/** Validation results (§10.3): one row per check, grouped by category. */
import { Link, useParams } from "react-router-dom";
import { ExternalLink, RefreshCw } from "lucide-react";
import { CheckResultView, Connection, RunView, fmtDate, readiness, useApi } from "../../../api";
import { Badge, CATEGORY_LABEL, Callout, DataTable, Kpi, LevelBadge, Loading, Page, Tone } from "../../../components";
import { GateCallout, SimulatedBadge, observedText, useAction } from "./shared";

const RESULT_TONE: Record<string, Tone> = { pass: "ok", warn: "warning", fail: "critical", error: "critical", blocked: "neutral", skipped: "outline" };

export function ResultStatus({ s }: { s: string }) {
  return <Badge tone={RESULT_TONE[s] ?? "neutral"} dot>{s[0].toUpperCase() + s.slice(1)}</Badge>;
}

export function ValidationResults() {
  const { id = "", run = "" } = useParams();
  const { data: conn } = useApi<Connection>(`/connections/${id}`);
  const { data: v, error } = useApi<RunView>(`/connections/${id}/validations/${run}`);
  const { busy, report, run: act } = useAction();
  const crumbs: [string, string?][] = [["Settings"], ["Connections", "/admin/connections"], [conn?.name ?? "Connection", `/admin/connections/${id}?step=validate`], ["Validation"]];
  if (!v) return <Page title="Validation results" crumbs={crumbs}><Loading error={error} kind="page" /></Page>;
  const s = v.summary;
  const rerun = (label: string) => act("rerun", () => readiness.validate(id), (r) => `${label}: ${r.summary.passed} passed, ${r.summary.failed + r.summary.errors} failed`);
  return (
    <Page
      title="Validation results"
      crumbs={crumbs}
      badge={v.simulated ? <SimulatedBadge scenario={v.scenario} /> : undefined}
      sub={<>Run {v.id.slice(0, 8)} by {v.actor} · {fmtDate(v.started_at)} · {v.kind === "scheduled" ? "re-run of the active revision" : "in-progress revision"} · status {v.status}</>}
      actions={
        <>
          <button type="button" className="btn" disabled={busy === "rerun"} onClick={() => rerun("Re-run")}><RefreshCw size={14} aria-hidden /> Re-run</button>
          <button type="button" className="btn" disabled={busy === "rerun" || s.failed + s.errors + s.blocked === 0} title="Checks are short; failed and blocked checks are re-run together with their dependencies" onClick={() => rerun("Re-run of failed checks")}>Re-run failed only</button>
        </>
      }
    >
      <div className="stack">
        {v.stale && <Callout tone="warn">{v.stale_reason}</Callout>}
        {v.simulated && <Callout tone="neutral">These results come from the simulated <b>{v.scenario}</b> scenario, not a live directory. They are labelled Simulated everywhere and can never satisfy a gate for a real connector type.</Callout>}
        <GateCallout report={report} connectionId={id} />
        <div className="grid g4">
          <Kpi label="Passed" value={s.passed + s.warned} sub={s.warned ? `${s.warned} with a warning` : undefined} />
          <Kpi label="Failed" value={s.failed + s.errors} tone={s.failed + s.errors ? "critical" : undefined} sub={s.errors ? `${s.errors} errors` : undefined} />
          <Kpi label="Blocked" value={s.blocked} tone={s.blocked ? "warning" : undefined} sub="dependency not passing; not run" />
          <Kpi label="Duration" value={`${v.duration_ms} ms`} sub={`${v.results.length} checks`} />
        </div>
        <DataTable<CheckResultView>
          id="validation-results"
          rows={v.results}
          rowKey={(r) => `${r.item_id}/${r.check_id}`}
          initialSort={["category", 1]}
          columns={[
            { id: "status", header: "Status", sort: (r) => ["fail", "error", "blocked", "warn", "skipped", "pass"].indexOf(r.status), csv: (r) => r.status, cell: (r) => <ResultStatus s={r.status} /> },
            { id: "category", header: "Category", sort: (r) => r.category, csv: (r) => r.category, cell: (r) => <span className="small">{CATEGORY_LABEL[r.category] ?? r.category}</span>, hideNarrow: true },
            {
              id: "check", header: "Check", sort: (r) => r.item_title, csv: (r) => `${r.item_id} ${r.check_id}`,
              cell: (r) => (
                <div>
                  <Link to={`/admin/connections/${id}?item=${r.item_id}`}><b>{r.item_title}</b></Link>
                  <div className="row tight xs faint"><code>{r.check_id}</code> · <LevelBadge level={r.level} />{r.simulated && <Badge tone="info">Simulated</Badge>}</div>
                </div>
              ),
            },
            { id: "observed", header: "Observed", csv: (r) => observedText(r.observed), cell: (r) => <span className="xs">{observedText(r.observed) || <span className="faint">–</span>}</span>, hideNarrow: true },
            { id: "message", header: "Message", sort: (r) => r.message, cell: (r) => <span className="small">{r.message}</span> },
            { id: "ms", header: "ms", num: true, sort: (r) => r.duration_ms, cell: (r) => r.duration_ms, hideNarrow: true },
            {
              id: "fix", header: "Remediation", csv: (r) => r.remediation.hint,
              cell: (r) => r.status === "pass" ? null : (
                <span className="xs">{r.remediation.hint} {r.remediation.link && <a href={r.remediation.link} target="_blank" rel="noreferrer noopener" aria-label="Documentation"><ExternalLink size={11} /></a>}</span>
              ),
              hideNarrow: true,
            },
          ]}
          searchText={(r) => `${r.item_title} ${r.item_id} ${r.check_id} ${r.message}`}
          filters={[
            { id: "status", label: "Status", options: ["pass", "warn", "fail", "error", "blocked", "skipped"].map((x) => ({ value: x, label: x })), get: (r) => r.status },
            { id: "category", label: "Category", options: Object.entries(CATEGORY_LABEL).map(([value, label]) => ({ value, label })), get: (r) => r.category },
          ]}
        />
      </div>
    </Page>
  );
}
