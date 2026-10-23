/**
 * "Breach response" (issue #475): when a vendor or integration is breached, list every credential tied to it
 * (secrets, OAuth grants, GitHub tokens, service accounts), run rotation and revocation as one tracked plan,
 * verify by re-reading, and export the evidence. Nothing is shown as done until a re-read (or, for what no API
 * can do, a person's attestation) says so.
 */
import { FormEvent, useState } from "react";
import { Download, PlayCircle, RefreshCw, ShieldAlert } from "lucide-react";
import { ApiError, BreachCandidate, BreachInventory, BreachItem, BreachItemState, BreachPlan, BreachPlanSummary, breach, fmtDate, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, EmptyState, Loading, Page, SidePanel, Tone, useSelected, useToast } from "../../components";
import { RotationTabs } from "./shared";

const KIND: Record<string, string> = { secret: "Secret", oauth_grant: "OAuth grant", github_token: "GitHub token", service_account: "Service account" };
const ACTION: Record<string, string> = { rotate: "Rotate", revoke: "Revoke", manual: "By hand" };
const STATE: Record<BreachItemState, { label: string; tone: Tone }> = {
  pending: { label: "Pending", tone: "neutral" }, in_progress: { label: "In progress", tone: "info" }, verified: { label: "Verified", tone: "ok" },
  attested: { label: "Attested", tone: "ok" }, failed: { label: "Failed", tone: "critical" },
};
const PLAN_TONE: Record<string, Tone> = { planned: "neutral", running: "info", completed: "ok" };

const msg = (e: unknown) => (e instanceof ApiError ? e.message : String(e));

function Credentials({ rows }: { rows: BreachCandidate[] }) {
  return (
    <div className="card flush table-scroll">
      <table>
        <thead><tr><th>Credential</th><th>Kind</th><th>Plan</th></tr></thead>
        <tbody>
          {rows.map((c) => (
            <tr key={`${c.kind}:${c.ref}`}>
              <td>{c.label}{c.detail && <div className="small muted">{c.detail}</div>}</td>
              <td className="small">{KIND[c.kind]}</td>
              <td><Badge tone={c.action === "manual" ? "warning" : "info"}>{ACTION[c.action]}</Badge></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ItemRow({ planId, item, running, canChange, onChanged }: { planId: string; item: BreachItem; running: boolean; canChange: boolean; onChanged: () => void }) {
  const [note, setNote] = useState("");
  const [open, setOpen] = useState(false);
  const toast = useToast();
  const attest = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await breach.attest(planId, item.id, note.trim());
      toast("Recorded");
      setOpen(false);
      onChanged();
    } catch (err) {
      toast(msg(err), { kind: "error" });
    }
  };
  const s = STATE[item.state];
  return (
    <tr>
      <td>
        {item.label}
        {item.detail && <div className="small muted">{item.detail}</div>}
        {item.attested_by && <div className="small muted">Attested by {item.attested_by}: {item.attested_note}</div>}
        {open && (
          <form className="stack-sm" onSubmit={attest} aria-label={`Attest ${item.label}`}>
            <label className="field">What was done (at least 10 characters)
              <input className="input" value={note} onChange={(e) => setNote(e.target.value)} />
            </label>
            <div className="row tight">
              <Button type="submit" size="sm" variant="primary" disabled={note.trim().length < 10}>Confirm it was done</Button>
              <Button type="button" size="sm" onClick={() => setOpen(false)}>Cancel</Button>
            </div>
          </form>
        )}
      </td>
      <td className="small">{KIND[item.kind]}</td>
      <td><Badge tone={item.action === "manual" ? "warning" : "info"}>{ACTION[item.action]}</Badge></td>
      <td><Badge tone={s.tone} dot>{s.label}</Badge></td>
      <td>
        {item.action === "manual" && item.state !== "verified" && item.state !== "attested" && running && canChange && !open &&
          <Button size="sm" onClick={() => setOpen(true)}>Attest</Button>}
      </td>
    </tr>
  );
}

function PlanPanel({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { data: plan, error, reload } = useApi<BreachPlan>(breach.planPath(id));
  const { can } = useSession();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const canChange = can("secrets.rotate");
  const changed = () => { reload(); onChanged(); };
  const act = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true);
    try {
      await fn();
      toast(done);
      changed();
    } catch (err) {
      toast(msg(err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const run = () => act(async () => {
    const r = await breach.run(id);
    if (r.oauth_revoke === "pending_second_admin") throw new Error("Rotation is queued. Revoking the OAuth grants needs a second admin: ask another admin to run this plan too.");
  }, "Run started: rotation queued, grants revoked where possible, everything re-read");
  const download = async () => {
    try {
      const url = URL.createObjectURL(await breach.evidence(id));
      const a = document.createElement("a");
      a.href = url;
      a.download = `breach-${plan?.vendor ?? "vendor"}-evidence.json`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      toast(msg(err), { kind: "error" });
    }
  };
  const c = plan?.report.counts;
  return (
    <SidePanel
      title={plan ? `Breach response: ${plan.vendor}` : "Breach response"}
      sub={plan && <Badge tone={PLAN_TONE[plan.status]} dot>{plan.status}</Badge>}
      onClose={onClose}
      commands={plan && (
        <>
          {plan.status !== "completed" && <Button variant="danger-solid" icon={<PlayCircle size={16} />} disabled={!canChange || busy} onClick={run}
            title={!canChange ? "Needs the secrets.rotate permission and a fresh phishing-resistant sign-in" : undefined}>{plan.status === "planned" ? "Run plan" : "Run again"}</Button>}
          {plan.status === "running" && <Button icon={<RefreshCw size={16} />} disabled={!canChange || busy} onClick={() => act(() => breach.verify(id), "Re-read done")}>Verify now</Button>}
          <Button icon={<Download size={16} />} onClick={download}>Evidence</Button>
        </>
      )}
    >
      {error && <div className="small" role="alert">{error.message}</div>}
      {!plan && !error && <Loading kind="block" />}
      {plan && c && (
        <>
          <p className="small">{plan.reason}</p>
          <div className="row tight">
            <Badge tone="ok">{c.verified + c.attested} of {c.total} done</Badge>
            {c.failed > 0 && <Badge tone="critical">{c.failed} failed</Badge>}
            {c.in_progress > 0 && <Badge tone="info">{c.in_progress} in progress</Badge>}
            {c.pending > 0 && <Badge tone="neutral">{c.pending} pending</Badge>}
          </div>
          {plan.report.complete
            ? <Callout tone="ok">Every credential was verified by a re-read or attested by a person. Completed {plan.completed_at ? fmtDate(plan.completed_at) : ""}.</Callout>
            : <Callout tone="warn">Not complete: {c.open} credential{c.open === 1 ? "" : "s"} still open. A request is never counted as done until a re-read shows it.</Callout>}
          <div className="table-scroll">
            <table>
              <thead><tr><th>Credential</th><th>Kind</th><th>Plan</th><th>State</th><th><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {plan.items.map((it) => <ItemRow key={it.id} planId={id} item={it} running={plan.status === "running"} canChange={canChange} onChanged={changed} />)}
              </tbody>
            </table>
          </div>
        </>
      )}
    </SidePanel>
  );
}

export function BreachResponse() {
  const { data: plans, reload } = useApi<{ plans: BreachPlanSummary[] }>(breach.plansPath);
  const { can } = useSession();
  const toast = useToast();
  const [selected, setSelected] = useSelected();
  const [vendor, setVendor] = useState("");
  const [reason, setReason] = useState("");
  const [inv, setInv] = useState<BreachInventory | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const allowed = can("secrets.rotate");

  const list = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!vendor.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setInv(await breach.inventory(vendor.trim()));
    } catch (err) {
      setInv(null);
      setError(msg(err));
    } finally {
      setBusy(false);
    }
  };
  const create = async () => {
    setBusy(true);
    try {
      const p = await breach.create(vendor.trim(), reason.trim());
      toast(`Plan recorded with ${p.report.counts.total} credentials. Review it, then run it.`);
      setInv(null);
      setReason("");
      reload();
      setSelected(p.id);
    } catch (err) {
      toast(msg(err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Page
      title="Breach response"
      crumbs={[["Identity"], ["Secret rotation", "/rotation/secrets"], ["Breach response"]]}
      sub="A vendor was breached: list every credential tied to it (secrets, OAuth grants, GitHub tokens, service accounts), rotate and revoke them as one tracked plan, and verify each by re-reading. Listing changes nothing."
      tabs={<RotationTabs />}
    >
      <form className="card stack-sm" onSubmit={list} aria-label="Find the credentials of a vendor">
        <div className="row" style={{ alignItems: "flex-end", flexWrap: "wrap", gap: 12 }}>
          <label className="field" style={{ minWidth: 240 }}>Vendor or integration
            <input className="input" value={vendor} placeholder="e.g. github, railway" maxLength={64} onChange={(e) => { setVendor(e.target.value); setInv(null); setError(null); }} />
          </label>
          <Button type="submit" disabled={!vendor.trim() || busy}>{busy && !inv ? "Listing…" : "List credentials (dry run)"}</Button>
        </div>
        {error && <Callout tone="bad">{error}</Callout>}
      </form>

      {inv && (
        <div className="card stack-sm mt">
          <h2>{inv.total} credential{inv.total === 1 ? "" : "s"} tied to {inv.vendor}</h2>
          {inv.total === 0 ? <EmptyState title="Nothing is recorded for this vendor">Check the name as it appears in your connections and OAuth apps.</EmptyState> : (
            <>
              <Credentials rows={inv.credentials} />
              <label className="field">Why (recorded in the audit log, at least 10 characters)
                <textarea className="input" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Vendor breach notice of 21 Oct: secrets stored with them may be exposed" />
              </label>
              <div className="row" style={{ justifyContent: "flex-end" }}>
                <Button variant="primary" icon={<ShieldAlert size={16} />} disabled={!allowed || busy || reason.trim().length < 10} onClick={create}
                  title={!allowed ? "Needs the secrets.rotate permission and a fresh phishing-resistant sign-in" : undefined}>Record the plan</Button>
              </div>
            </>
          )}
        </div>
      )}

      <h2 className="mt">Plans</h2>
      {!plans ? <Loading kind="block" /> : plans.plans.length === 0 ? <EmptyState title="No breach plans yet">Plans you record here are tracked until every credential is verified.</EmptyState> : (
        <div className="card flush table-scroll">
          <table>
            <thead><tr><th>Vendor</th><th>Status</th><th>Done</th><th>By</th><th>When</th></tr></thead>
            <tbody>
              {plans.plans.map((p) => (
                <tr key={p.id}>
                  <td><button className="name-link" onClick={() => setSelected(p.id)}>{p.vendor}</button></td>
                  <td><Badge tone={PLAN_TONE[p.status]} dot>{p.status}</Badge></td>
                  <td className="small">{p.counts.verified + p.counts.attested} of {p.counts.total}{p.counts.failed > 0 && <span> · {p.counts.failed} failed</span>}</td>
                  <td className="small">{p.created_by}</td>
                  <td className="small nowrap">{fmtDate(p.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {selected && <PlanPanel id={selected} onClose={() => setSelected(null)} onChanged={reload} />}
    </Page>
  );
}
