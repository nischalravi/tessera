import { FormEvent, useState } from "react";
import { Play, SlidersHorizontal } from "lucide-react";
import { DriftAction, DriftClass, DriftItem, DriftList, DriftStatus, RemediationPolicy, drift, fmtDate, relTime, useApi } from "../../api";
import { Badge, Button, Callout, DataTable, GovernanceTabs, Page, SidePanel, useToast } from "../../components";

const CLASS: Record<DriftClass, { label: string; help: string }> = {
  missing: { label: "Missing", help: "Access that was approved but the system does not show." },
  rogue: { label: "Rogue", help: "Access the system shows that nothing approved." },
  orphan: { label: "Orphan", help: "An account in the system that belongs to no identity." },
  stale: { label: "Stale", help: "Access the system still shows after the approval ended." },
};
const STATUS: Record<DriftStatus, { label: string; tone: "ok" | "critical" | "warning" | "info" | "neutral" }> = {
  open: { label: "Open", tone: "critical" }, remediating: { label: "Remediating", tone: "warning" },
  resolved: { label: "Resolved", tone: "ok" }, accepted: { label: "Accepted", tone: "neutral" },
};
const ACTION: Record<DriftAction | "none", string> = {
  none: "Not yet evaluated", report_only: "Report only", owner_task: "Task for the owner", auto_provision: "Provision automatically", auto_revoke: "Revoke automatically",
};
const CLASSES = Object.keys(CLASS) as DriftClass[];
const STATUSES = Object.keys(STATUS) as DriftStatus[];
const actionsFor = (c: DriftClass): DriftAction[] => (c === "missing" ? ["auto_provision", "owner_task", "report_only"] : ["auto_revoke", "owner_task", "report_only"]);

/** Governance → Drift: where intended access (what was approved) and observed access (what systems report) differ (issue #301). */
export function Drift() {
  const { data, error, reload } = useApi<DriftList>("/access-drift?limit=500");
  const [open, setOpen] = useState<string | null>(null);
  const [policies, setPolicies] = useState(false);
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      const r = await drift.run();
      toast(`${r.opened} opened, ${r.reopened} reopened, ${r.resolved} resolved, ${r.actions} remediation action${r.actions === 1 ? "" : "s"}`);
      reload();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const item = data?.items.find((d) => d.id === open) ?? null;
  return (
    <Page tabs={<GovernanceTabs />} title="Drift" crumbs={[["Access"], ["Access reviews", "/governance/reviews"], ["Drift"]]}
      sub="Tessera keeps what was approved apart from what each system reports, and shows where they differ."
      actions={<>
        <Button icon={<SlidersHorizontal size={15} />} onClick={() => setPolicies(true)}>Remediation policies</Button>
        <Button icon={<Play size={15} />} disabled={busy} onClick={run}>Reconcile now</Button>
      </>}>
      <div className="stack">
        <div className="row wrap" style={{ gap: 6 }} aria-label="Drift by class">
          {CLASSES.filter((c) => (data?.counts.by_class[c] ?? 0) > 0).map((c) => <Badge key={c} tone="outline" title={CLASS[c].help}>{CLASS[c].label} {data?.counts.by_class[c]}</Badge>)}
        </div>
        <DataTable
          id="access-drift"
          rows={data?.items ?? null}
          error={error}
          rowKey={(r) => r.id}
          initialSort={["detected", -1]}
          onRowClick={(r) => setOpen(r.id)}
          activeKey={open}
          onRefresh={reload}
          rowLabel={(r) => `${CLASS[r.class].label} ${r.system} ${r.entitlement_name || r.entitlement || r.account_ref} ${STATUS[r.status].label}`}
          columns={[
            { id: "detected", header: "Found", sort: (r) => r.detected_at, cell: (r) => <span className="small nowrap" title={fmtDate(r.detected_at)}>{relTime(r.detected_at.replace("Z", ""))}</span> },
            { id: "class", header: "Class", sort: (r) => r.class, cell: (r) => <Badge tone="outline" title={CLASS[r.class].help}>{CLASS[r.class].label}</Badge> },
            { id: "who", header: "Identity / account", sort: (r) => r.identity?.name ?? r.account_ref, cell: (r) => <span className="small">{r.identity?.name ?? <i>no identity</i>}{r.account_ref ? <span className="faint"> · {r.account_ref}</span> : null}</span> },
            { id: "ent", header: "Entitlement", sort: (r) => r.entitlement_name || r.entitlement, cell: (r) => <span className="small">{r.entitlement_name || r.entitlement || <span className="faint">—</span>}</span> },
            { id: "system", header: "System", sort: (r) => r.system, cell: (r) => <span className="small">{r.system}</span>, hideNarrow: true },
            { id: "status", header: "Status", sort: (r) => STATUSES.indexOf(r.status), cell: (r) => <Badge tone={STATUS[r.status].tone}>{STATUS[r.status].label}</Badge> },
            { id: "action", header: "Action", sort: (r) => r.action, cell: (r) => <span className="small">{ACTION[r.action]}</span>, hideNarrow: true },
          ]}
          searchText={(r) => `${r.class} ${r.system} ${r.entitlement} ${r.entitlement_name} ${r.account_ref} ${r.identity?.name ?? ""} ${r.status}`}
          searchPlaceholder="Search identity, account, entitlement or system…"
          chips={3}
          filters={[
            { id: "class", label: "Class", options: CLASSES.map((c) => ({ value: c, label: CLASS[c].label })), get: (r) => r.class },
            { id: "status", label: "Status", options: STATUSES.map((s) => ({ value: s, label: STATUS[s].label })), get: (r) => r.status },
            { id: "system", label: "System", options: [...new Set((data?.items ?? []).map((r) => r.system))].sort().map((s) => ({ value: s, label: s })), get: (r) => r.system },
          ]}
          empty="No drift. Intended and observed access agree, or no connector has been synced yet."
        />
      </div>
      {item && <DriftPanel item={item} onClose={() => setOpen(null)} onDone={reload} />}
      {policies && <PolicyPanel onClose={() => setPolicies(false)} />}
    </Page>
  );
}

function DriftPanel({ item, onClose, onDone }: { item: DriftItem; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const act = async (name: string, fn: () => Promise<DriftItem>) => {
    setBusy(true);
    try {
      await fn();
      toast(name);
      onDone();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <SidePanel title={`${CLASS[item.class].label} access in ${item.system}`}
      sub={<span className="row tight"><Badge tone={STATUS[item.status].tone}>{STATUS[item.status].label}</Badge></span>} onClose={onClose}>
      <div className="stack-sm">
        <p className="small muted" style={{ margin: 0 }}>{CLASS[item.class].help}</p>
        <dl className="kv small">
          <dt>Identity</dt><dd>{item.identity?.name ?? "none"}</dd>
          <dt>Account</dt><dd>{item.account || item.account_ref || "—"}</dd>
          <dt>Entitlement</dt><dd>{item.entitlement_name || item.entitlement || "—"}</dd>
          <dt>Owner</dt><dd>{item.owner?.name ?? "the people who decide access"}</dd>
          <dt>Found</dt><dd>{fmtDate(item.detected_at)}</dd>
          <dt>Action</dt><dd>{ACTION[item.action]}</dd>
          {item.remediation_note && (<><dt>Note</dt><dd>{item.remediation_note}</dd></>)}
          {item.accepted_by && (<><dt>Accepted by</dt><dd>{item.accepted_by}: {item.accepted_reason}</dd></>)}
        </dl>
        {item.can_remediate && (
          <div className="stack-sm">
            <b className="small">Remediate</b>
            <div className="row wrap" style={{ gap: 8 }}>
              {actionsFor(item.class).map((a) => (
                <Button key={a} size="sm" disabled={busy} onClick={() => act(`${ACTION[a]}: done`, () => drift.remediate(item.id, a))}>{ACTION[a]}</Button>
              ))}
            </div>
          </div>
        )}
        {item.can_accept && (
          <form className="stack-sm" onSubmit={(e: FormEvent) => { e.preventDefault(); act("Risk accepted", () => drift.accept(item.id, reason)); }}>
            <label className="field">Accept the risk
              <input className="input" required maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why this is acceptable" />
            </label>
            <Button type="submit" size="sm" disabled={busy || !reason.trim()}>Accept</Button>
          </form>
        )}
      </div>
    </SidePanel>
  );
}

function PolicyPanel({ onClose }: { onClose: () => void }) {
  const toast = useToast();
  const { data, reload } = useApi<RemediationPolicy[]>("/remediation-policies");
  const [system, setSystem] = useState("");
  const [ref, setRef] = useState("");
  const [cls, setCls] = useState<DriftClass>("rogue");
  const [action, setAction] = useState<DriftAction>("owner_task");
  const [err, setErr] = useState<string | null>(null);
  const pick = (c: DriftClass) => { setCls(c); if (!actionsFor(c).includes(action)) setAction("report_only"); };
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      await drift.putPolicy({ system: system.trim(), entitlement_ref: ref.trim(), drift_class: cls, action });
      toast("Policy saved");
      reload();
    } catch (e2) {
      setErr((e2 as Error).message);
    }
  };
  const remove = async (id: string) => {
    try {
      await drift.deletePolicy(id);
      reload();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };
  return (
    <SidePanel title="Remediation policies" onClose={onClose}>
      <div className="stack-sm">
        <p className="small muted" style={{ margin: 0 }}>What Tessera does when it finds each class of drift. An entitlement's policy wins over its system's; with none, drift is only recorded.</p>
        {data && data.length === 0 && <p className="small faint" style={{ margin: 0 }}>No policy: every difference is report only.</p>}
        {data?.map((p) => (
          <div key={p.id} className="row wrap small" style={{ gap: 8, justifyContent: "space-between" }}>
            <span><b>{p.system}</b>{p.entitlement_ref ? ` / ${p.entitlement_ref}` : ""} · {CLASS[p.drift_class].label}: {ACTION[p.action]}</span>
            <Button size="sm" onClick={() => remove(p.id)} aria-label={`Remove the policy for ${p.system} ${p.drift_class}`}>Remove</Button>
          </div>
        ))}
        <form className="stack-sm" onSubmit={save}>
          {err && <Callout tone="bad">{err}</Callout>}
          <label className="field">System<input className="input" required value={system} onChange={(e) => setSystem(e.target.value)} placeholder="e.g. okta" /></label>
          <label className="field">Entitlement (optional)<input className="input" value={ref} onChange={(e) => setRef(e.target.value)} placeholder="the group's external id; empty for the whole system" /></label>
          <label className="field">Class
            <select className="input" value={cls} onChange={(e) => pick(e.target.value as DriftClass)}>{CLASSES.map((c) => <option key={c} value={c}>{CLASS[c].label}</option>)}</select>
          </label>
          <label className="field">Action
            <select className="input" value={action} onChange={(e) => setAction(e.target.value as DriftAction)}>{actionsFor(cls).map((a) => <option key={a} value={a}>{ACTION[a]}</option>)}</select>
          </label>
          <Button type="submit" variant="primary" disabled={!system.trim()}>Save policy</Button>
        </form>
      </div>
    </SidePanel>
  );
}
