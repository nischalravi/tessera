/**
 * Insights → Least privilege: staged revocation of unused AWS access (LP-5, #661). The loop's mode and caps, the
 * kill switch (one person pauses; resuming is a two-admin change request) and the revocations by state, with
 * announce, object and restore. Every number comes from GET /api/lp/settings and GET /api/lp/revocations.
 */
import { useState } from "react";
import { LpRevocation, LpSettings, LpState, LpTerraform, fmtDate, lpLoop, lpRecommendations, refetchAll, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Drawer, EmptyState, Loading, useToast } from "../../components";

const TONE: Record<LpState, "info" | "warning" | "critical" | "ok" | "neutral"> = {
  candidate: "neutral", announced: "warning", revoking: "warning", revoked: "info", finalized: "ok", restoring: "warning",
  restored: "ok", exempted: "neutral", failed: "critical", superseded: "neutral",
};

function Row({ r, onDone }: { r: LpRevocation; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = async (what: string, f: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await f();
      toast(what);
      onDone();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const auto = r.eligibility === "auto";
  const [tf, setTf] = useState<LpTerraform | null>(null);
  return (
    <tr>
      <td className="small"><code className="xs" style={{ wordBreak: "break-all" }}>{r.principal}</code><div className="xs faint sys">{r.policy_arn}</div></td>
      <td><Badge tone={TONE[r.state]}>{r.state}</Badge>{r.reason && <div className="xs faint">{r.reason}</div>}</td>
      <td className="small">{r.confidence} confidence, unused {r.unused_days} days<div className="xs faint">{auto ? "Batch approval" : "Approve one by one"}</div></td>
      <td className="small nowrap">
        {r.state === "announced" && r.announce_until ? `Revokes after ${fmtDate(r.announce_until)}` : r.state === "revoked" && r.restore_until ? `Restorable until ${fmtDate(r.restore_until)}` : fmtDate(r.created_at)}
      </td>
      <td className="actions-cell">
        {r.state === "candidate" && <Button size="sm" disabled={busy} onClick={() => run("Announced", () => lpLoop.approve(auto ? [r.id] : [], auto ? [] : [r.id]))}>Announce</Button>}
        {r.state === "announced" && <Button size="sm" disabled={busy} onClick={() => run("Objection recorded", () => lpLoop.object(r.id, "Objected in the console"))}>Object</Button>}
        {(r.state === "revoked" || r.state === "failed") && <Button size="sm" disabled={busy} onClick={() => run("Restore queued", () => lpLoop.restore(r.id))}>Restore</Button>}
        {(r.state === "candidate" || r.state === "announced") && <Button size="sm" disabled={busy} onClick={() => run("Terraform suggestion ready", async () => setTf(await lpRecommendations.terraform(r.id)))}>Terraform</Button>}
        {tf && (
          <Drawer title="Terraform suggestion" sub="Paste over your own resource for this policy, review the plan and apply it yourself. Tessera writes nothing." onClose={() => setTf(null)} wide
            footer={<Button onClick={() => { void navigator.clipboard?.writeText(tf.snippet); }}>Copy</Button>}>
            <pre className="xs" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{tf.snippet}</pre>
          </Drawer>
        )}
      </td>
    </tr>
  );
}

export function AwsRevocationsCard() {
  const s = useApi<LpSettings>("/lp/settings");
  const list = useApi<{ items: LpRevocation[] }>("/lp/revocations?limit=50");
  const toast = useToast();
  const { can } = useSession();
  const [busy, setBusy] = useState(false);
  if (s.error) return null; // no permission, or no AWS write target on this server: nothing to show
  if (!s.data || !list.data) return <Loading kind="block" />;
  const d = s.data;
  const done = () => { s.reload(); list.reload(); refetchAll(); };
  const pause = async () => {
    setBusy(true);
    try {
      await lpLoop.pause("Paused from the console");
      toast("The loop is paused: nothing new is executed");
      done();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="card" style={{ marginTop: 16 }} aria-label="Staged revocation of unused AWS access">
      <div className="spread" style={{ padding: 12 }}>
        <div>
          <b>Staged revocation of unused AWS access</b>{" "}
          <Badge tone={d.active ? "ok" : "warning"}>{d.operator_disabled ? "Disabled by operator" : d.paused ? "Paused" : d.mode}</Badge>
          <div className="xs faint">
            Announced {d.announce_days} days ahead, restorable for {d.finalize_days}. Caps: {d.cap_per_run} per run, {d.cap_per_day} per day ({d.executed_last_24h} used), {d.cap_per_account} per account, {d.cap_per_principal} per principal.
            {d.paused && ` Paused${d.paused_by ? ` by ${d.paused_by}` : ""}: resuming needs a second admin (change request lp.settings.update).`}
          </div>
        </div>
        {can("lp.manage") && <Button disabled={busy || d.paused} onClick={pause}>Pause the loop</Button>}
      </div>
      {list.data.items.length === 0 ? <EmptyState title="No revocations">Candidates appear when a verified right-size is proposed in staged mode.</EmptyState> : (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Principal and policy</th><th>State</th><th>Evidence</th><th>When</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>{list.data.items.map((r) => <Row key={r.id} r={r} onDone={done} />)}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}
