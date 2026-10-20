/** "Vendor compromised": plan (dry run) and then rotate every credential of one integration at once. */
import { FormEvent, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { ApiError, RotationBulk, RotationBulkPlan, RotationSecretStatus, fmtDate, rotation, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, EmptyState, Loading, Page, useToast } from "../../components";
import { bulkProgressText } from "./model";
import { PlanTable, RotationTabs } from "./shared";

export function VendorCompromised() {
  const { data: secrets } = useApi<RotationSecretStatus[]>(rotation.paths.overview);
  const { data: runs, reload } = useApi<RotationBulk[]>(rotation.paths.bulks);
  const [params] = useSearchParams();
  const [system, setSystem] = useState(params.get("system") ?? "");
  const [plan, setPlan] = useState<RotationBulkPlan | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();
  const { can } = useSession();
  const allowed = can("secrets.rotate");
  const systems = [...new Set((secrets ?? []).map((s) => s.system))].sort();
  const count = (sys: string) => (secrets ?? []).filter((s) => s.system === sys).length;

  const makePlan = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!system) return;
    setBusy(true);
    setError(null);
    try {
      setPlan(await rotation.bulkPlan(system));
    } catch (err) {
      setPlan(null);
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };
  const execute = async () => {
    if (!plan) return;
    setBusy(true);
    try {
      const run = await rotation.bulkExecute(plan.system, reason.trim(), plan.plan_hash);
      toast(`${run.counts.rotate} credential${run.counts.rotate === 1 ? "" : "s"} of ${run.system} queued for immediate rotation; owners were notified`);
      setPlan(null);
      setReason("");
      reload();
    } catch (err) {
      const stale = err instanceof ApiError && err.body?.error === "plan_changed";
      toast(err instanceof ApiError ? err.message : String(err), { kind: "error" });
      if (stale) await makePlan();
    } finally {
      setBusy(false);
    }
  };
  const reasonOk = reason.trim().length >= 10;
  return (
    <Page
      title="Vendor compromised"
      crumbs={[["Identity"], ["Secret rotation", "/rotation/secrets"], ["Vendor compromised"]]}
      sub="When a vendor or integration is breached, rotate every credential tied to it at once. Tessera plans first (a dry run that calls nothing), then rotates with no grace period: the old credentials are disabled, verified and deleted as soon as the new ones are in your vault."
      tabs={<RotationTabs />}
    >
      <div className="card stack-sm">
        <form className="row" style={{ alignItems: "flex-end" }} onSubmit={makePlan}>
          <label className="field" style={{ minWidth: 240 }}>
            Integration
            <select className="input" value={system} onChange={(e) => { setSystem(e.target.value); setPlan(null); setError(null); }}>
              <option value="">Choose a system…</option>
              {systems.map((s) => <option key={s} value={s}>{s} ({count(s)} credential{count(s) === 1 ? "" : "s"})</option>)}
            </select>
          </label>
          <Button type="submit" disabled={!system || busy}>{busy && !plan ? "Planning…" : "Plan (dry run)"}</Button>
        </form>
        {error && <Callout tone="bad">{error}</Callout>}
      </div>

      {plan && (
        <div className="card stack-sm mt">
          <div className="spread">
            <h2>Plan for {plan.system}</h2>
            <span className="row tight">
              <Badge tone="ok">{plan.counts.rotate} will be rotated</Badge>
              {plan.counts.manual > 0 && <Badge tone="warning">{plan.counts.manual} manual</Badge>}
              {plan.counts.blocked > 0 && <Badge tone="critical">{plan.counts.blocked} blocked</Badge>}
              {plan.counts.in_flight > 0 && <Badge tone="info">{plan.counts.in_flight} already rotating</Badge>}
            </span>
          </div>
          <PlanTable items={plan.items} />
          {plan.counts.manual + plan.counts.blocked > 0 && (
            <Callout tone="warn">Credentials Tessera cannot rotate are not skipped silently: their owners are notified to rotate them by hand, and the run lists them.</Callout>
          )}
          <label className="field">
            Why (recorded in the audit log, at least 10 characters)
            <textarea className="input" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Vendor breach notice of 12 Oct: tokens issued before the 10th may be exposed" />
          </label>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <Button variant="danger-solid" icon={<ShieldAlert size={16} />} disabled={!allowed || busy || !reasonOk || plan.counts.rotate + plan.counts.manual === 0}
              title={!allowed ? "Needs the secrets.rotate permission (policy admin) and a fresh phishing-resistant sign-in" : undefined} onClick={execute}>
              {busy ? "Working…" : `Rotate ${plan.counts.rotate} credential${plan.counts.rotate === 1 ? "" : "s"} now`}
            </Button>
          </div>
        </div>
      )}

      <h2 className="mt">Earlier runs</h2>
      {!runs ? <Loading kind="block" /> : runs.length === 0 ? <EmptyState title="No vendor-compromised runs yet">Plans and runs you start here are listed with their progress.</EmptyState> : (
        <div className="card flush table-scroll">
          <table>
            <thead><tr><th>Integration</th><th>Reason</th><th>Progress</th><th>By</th><th>When</th></tr></thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td><b>{r.system}</b></td>
                  <td className="small">{r.reason}</td>
                  <td className="small"><Link to={`/rotation/jobs?bulk=${r.id}`}>{bulkProgressText(r.progress, r.counts.rotate)}</Link>{r.counts.manual > 0 && <span className="faint"> · {r.counts.manual} manual</span>}</td>
                  <td className="small">{r.requested_by}</td>
                  <td className="small nowrap">{fmtDate(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}
