/**
 * Insights → Deployment health: the production shadow agreement of AWS decisions (EP-6). A tenant
 * that opts in has a few of the evaluator's decisions a day compared with iam:SimulatePrincipalPolicy
 * in the customer account. This card shows the agreement rate, lets an admin opt in or out and set
 * the daily sample size, and lists the disagreements for triage. Every number comes from
 * GET /api/aws/shadow and GET /api/aws/shadow/checks.
 */
import { useState } from "react";
import { AwsShadow, AwsShadowCheck, AwsShadowTriage, awsShadow, fmtDate, refetchAll, useApi } from "../../api";
import { Badge, Button, EmptyState, Loading, useToast } from "../../components";

const TRIAGE: [Exclude<AwsShadowTriage, "none">, string][] = [
  ["open", "Open"], ["investigating", "Investigating"], ["engine_bug", "Engine bug"], ["expected", "Expected difference"], ["resolved", "Resolved"],
];
const TRIAGE_LABEL: Record<string, string> = Object.fromEntries(TRIAGE);

const pct = (r: number | null) => (r === null ? "–" : `${(r * 100).toFixed(r === 1 ? 0 : 1)}%`);

function DisagreementRow({ c, onDone }: { c: AwsShadowCheck; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const set = async (status: Exclude<AwsShadowTriage, "none">) => {
    if (status === c.triage_status) return;
    setBusy(true);
    try {
      await awsShadow.triage(c.id, status, "");
      toast(`Marked ${TRIAGE_LABEL[status].toLowerCase()}`);
      onDone();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <tr>
      <td className="small"><code className="xs" style={{ wordBreak: "break-all" }}>{c.principal_arn}</code></td>
      <td className="small"><code className="xs">{c.action}</code><div className="xs faint" style={{ wordBreak: "break-all" }}>{c.resource_arn}</div></td>
      <td className="small">{c.detail}<div className="xs faint">{fmtDate(c.checked_at)}</div></td>
      <td>
        <select className="input" aria-label={`Triage for ${c.action} on ${c.principal_arn}`} value={c.triage_status} disabled={busy} onChange={(e) => set(e.target.value as Exclude<AwsShadowTriage, "none">)}>
          {TRIAGE.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
      </td>
    </tr>
  );
}

export function AwsShadowCard() {
  const { data, error, reload } = useApi<AwsShadow>("/aws/shadow");
  const list = useApi<{ items: AwsShadowCheck[] }>("/aws/shadow/checks?verdict=disagree&limit=50");
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [k, setK] = useState<string | null>(null);
  if (error) return null; // no permission, or no AWS evaluator on this server: nothing to show
  if (!data) return <Loading kind="block" />;
  const ag = data.agreement;
  const kValue = k ?? String(data.daily_k);
  const save = async (enabled: boolean) => {
    const n = Number(kValue);
    if (!Number.isInteger(n) || n < 1 || n > 200) {
      toast("The daily sample is a whole number from 1 to 200", { kind: "error" });
      return;
    }
    setBusy(true);
    try {
      await awsShadow.set(enabled, n);
      toast(enabled ? "Shadow agreement is on" : "Shadow agreement is off");
      setK(null);
      reload();
      refetchAll();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const done = () => {
    reload();
    list.reload();
    refetchAll();
  };
  const rows = (list.data?.items ?? []).filter((c) => c.triage_status !== "resolved" && c.triage_status !== "expected");
  return (
    <div className="card">
      <div className="spread" style={{ marginBottom: 4 }}>
        <h2>Production agreement for AWS decisions</h2>
        <Badge tone={data.enabled ? "ok" : "neutral"}>{data.enabled ? "On" : "Off"}</Badge>
      </div>
      <p className="small muted">
        Each day Tessera asks AWS (iam:SimulatePrincipalPolicy, in your account) the same question it answered for a sample of principals and compares the two.
        A disagreement is a finding to triage. Decisions that need context keys are counted apart and are not in the rate.
      </p>
      <div className="grid g4 mt-sm">
        <div><div className="xs faint">Agreement, last {ag?.window_days ?? 30} days</div><b style={{ fontSize: "var(--fs-xl)" }}>{pct(ag?.rate ?? null)}</b><div className="xs faint">{ag ? `${ag.agree} of ${ag.compared} compared` : "No decisions compared yet"}</div></div>
        <div><div className="xs faint">Open disagreements</div><b style={{ fontSize: "var(--fs-xl)" }}>{ag?.open_disagreements ?? 0}</b></div>
        <div><div className="xs faint">Inconclusive · errors</div><b style={{ fontSize: "var(--fs-xl)" }}>{ag ? `${ag.inconclusive} · ${ag.errors}` : "0 · 0"}</b></div>
        <div><div className="xs faint">Today</div><b style={{ fontSize: "var(--fs-xl)" }}>{data.today.sampled} / {data.daily_k}</b><div className="xs faint">{ag?.last_checked_at ? `Last check ${fmtDate(ag.last_checked_at)}` : "No checks yet"}</div></div>
      </div>
      <div className="row mt-sm" style={{ alignItems: "end" }}>
        <label className="field" style={{ maxWidth: 200 }}>Decisions a day
          <input className="input" type="number" min={1} max={200} value={kValue} onChange={(e) => setK(e.target.value)} />
        </label>
        {data.enabled
          ? <><Button disabled={busy || kValue === String(data.daily_k)} onClick={() => save(true)}>Save</Button><Button disabled={busy} onClick={() => save(false)}>Turn off</Button></>
          : <Button variant="primary" disabled={busy} onClick={() => save(true)}>Turn on</Button>}
      </div>
      <h3 className="mt-sm">Disagreements to triage</h3>
      {rows.length === 0 ? (
        <EmptyState title="No open disagreements">When the simulator and Tessera differ, the decision is listed here until someone triages it.</EmptyState>
      ) : (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Principal</th><th>Action and resource</th><th>What differed</th><th>Triage</th></tr></thead>
            <tbody>{rows.map((c) => <DisagreementRow key={c.id} c={c} onDone={done} />)}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}
