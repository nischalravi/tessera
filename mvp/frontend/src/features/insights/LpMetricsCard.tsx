/**
 * Insights → Least privilege: how the revocation loop is doing (LP-10, #666). Unused permissions removed, the
 * false-positive rate (restores and JIT re-requests over revocations carried out) and the restore rate per confidence
 * level, the median restore time and auto against staged counts. Every number comes from GET /api/lp/metrics; the
 * per-revocation evidence behind them is GET /api/lp/evidence and the evidence packs.
 */
import { useState } from "react";
import { LpMetrics, useApi } from "../../api";
import { Badge, EmptyState, Loading, Segmented } from "../../components";

const pct = (n: number) => `${n.toFixed(n > 0 && n < 10 ? 1 : 0)}%`;

function duration(s: number | null): string {
  if (s === null) return "none yet";
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

export function LpMetricsCard() {
  const [days, setDays] = useState<"30" | "60" | "90" | "365">("60");
  const { data, error } = useApi<{ metrics: LpMetrics; high_threshold_percent: number }>(`/lp/metrics?days=${days}`);
  if (error) return null; // no permission on this server: nothing to show
  const m = data?.metrics;
  return (
    <section className="card" style={{ marginTop: 16 }} aria-label="Least-privilege loop metrics">
      <div className="spread" style={{ padding: 12 }}>
        <div>
          <b>Loop metrics</b>
          <div className="xs faint">Revocations carried out in the last {days} days. A restore, or a JIT request for the access within the revoke window, counts as a false positive.</div>
        </div>
        <Segmented label="Window" value={days} onChange={setDays} options={[["30", "30 days"], ["60", "60 days"], ["90", "90 days"], ["365", "1 year"]]} />
      </div>
      {!m || !data ? <Loading kind="block" /> : m.executed === 0 ? (
        <EmptyState title="No revocations yet">Nothing has been revoked in this window, so there is no rate to show.</EmptyState>
      ) : (
        <div style={{ padding: "0 12px 12px" }}>
          <div className="stat-row" style={{ marginBottom: 12 }}>
            <div className="s"><b className="tnum">{m.unused_permissions_removed}</b><span>unused permissions removed</span></div>
            <div className="s"><b className="tnum">{m.executed}</b><span>revocations ({m.auto} auto, {m.staged} staged)</span></div>
            <div className="s"><b className="tnum">{pct(m.false_positive_percent)}</b><span>false-positive rate</span></div>
            <div className="s"><b className="tnum">{duration(m.median_restore_seconds)}</b><span>median restore time ({m.restores_within_slo} of {m.restores} within {Math.round(m.restore_slo_seconds / 60)} min)</span></div>
          </div>
          <div className="table-scroll">
            <table>
              <caption className="sr-only">Outcomes by confidence level</caption>
              <thead><tr><th scope="col">Confidence</th><th scope="col" className="num">Revoked</th><th scope="col" className="num">Restored</th><th scope="col" className="num">False positives</th><th scope="col">Status</th></tr></thead>
              <tbody>
                {m.levels.map((l) => (
                  <tr key={l.confidence}>
                    <td>{l.confidence}</td>
                    <td className="num">{l.revoked}</td>
                    <td className="num">{l.restored} ({pct(l.restore_percent)})</td>
                    <td className="num">{l.false_positives} ({pct(l.false_positive_percent)})</td>
                    <td>{l.review ? <Badge tone="critical">Over {data.high_threshold_percent}%: review the rule</Badge> : <Badge tone="ok">Within threshold</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {m.truncated && <div className="xs faint" style={{ marginTop: 8 }}>The window holds more revocations than one read covers; the figures cover the oldest.</div>}
        </div>
      )}
    </section>
  );
}
