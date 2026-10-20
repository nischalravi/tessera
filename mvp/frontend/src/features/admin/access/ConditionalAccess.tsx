/**
 * Settings → Conditional access (issue #163): named network ranges, policies on the Tessera
 * sign-in and on privileged actions (allow, step up or deny; enforce or report only), the
 * admin-set device-compliance signal, and a what-if check. The server decides; this page only
 * edits the policies. Changes need a fresh phishing-resistant sign-in (the step-up dialog
 * appears when the API asks for it).
 */
import { FormEvent, ReactNode, useId, useState } from "react";
import { MonitorSmartphone, Network, Plus, ShieldAlert, Trash2 } from "lucide-react";
import {
  AccessDecision, AccessMode, AccessOutcome, AccessPolicy, AccessPolicyInput, AccessScope, AccessUser, DeviceSignal, NetworkRange,
  conditionalAccess, describeConditions, fmtDate, useApi,
} from "../../../api";
import { useSession } from "../../../app/auth";
import { Badge, Button, Callout, DataTable, Drawer, EmptyState, Page, Tabs, Tone, useConfirm, useToast } from "../../../components";

type Tab = "policies" | "networks" | "signals";

const SCOPE: Record<AccessScope, string> = { signin: "Tessera sign-in", privileged: "Privileged actions" };
const MODE: Record<AccessMode, { label: string; tone: Tone }> = {
  enforce: { label: "Enforced", tone: "ok" },
  report_only: { label: "Report only", tone: "info" },
  disabled: { label: "Disabled", tone: "neutral" },
};
const OUTCOME: Record<AccessOutcome, { label: string; tone: Tone }> = {
  allow: { label: "Allow", tone: "ok" },
  step_up: { label: "Require step-up", tone: "warning" },
  deny: { label: "Deny", tone: "critical" },
};
const ACR = { "urn:tessera:acr:aal2": "Multi-factor sign-in", "urn:tessera:acr:phr": "Phishing-resistant sign-in (passkey)", "urn:tessera:acr:phrh": "Device-bound security key" } as const;

export function ConditionalAccess() {
  const [tab, setTab] = useState<Tab>("policies");
  const { can } = useSession();
  return (
    <Page
      title="Conditional access"
      crumbs={[["Settings"], ["Conditional access"]]}
      sub="Decide who may sign in to Tessera, and who may take privileged actions, by network location and device posture. The first enforced policy that matches decides; with no match the action is allowed. Try a policy in report-only mode before enforcing it: the decision is recorded in the audit log with the inputs that drove it."
      tabs={<Tabs<Tab> label="Conditional access" value={tab} onChange={setTab} tabs={[
        { id: "policies", label: "Policies" }, { id: "networks", label: "Network ranges" }, { id: "signals", label: "Device signals" },
      ]} />}
    >
      {!can("conditional_access.manage") && <Callout tone="neutral">You can view these settings. Changing them needs the tenant admin role and a fresh passkey sign-in.</Callout>}
      <div role="tabpanel" className="stack">
        {tab === "policies" && <Policies />}
        {tab === "networks" && <Networks />}
        {tab === "signals" && <Signals />}
      </div>
    </Page>
  );
}

// ---------------------------------------------------------------- shared
function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return <label className="field">{label}{children}{hint && <span className="hint">{hint}</span>}</label>;
}

function useSave() {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = async (what: () => Promise<unknown>, done: string, after?: () => void) => {
    setBusy(true);
    try {
      await what();
      toast(done);
      after?.();
    } catch (e) {
      // a step-up request opens the step-up dialog by itself; everything else is shown here
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return { busy, run };
}

// ---------------------------------------------------------------- policies
const blankPolicy: AccessPolicyInput = {
  name: "", description: "", scope: "privileged", mode: "report_only", outcome: "step_up", step_up_acr: "urn:tessera:acr:phr", step_up_max_age: 300,
  network_op: "any", network_range_ids: [], device: "any", priority: 100,
};

function Policies() {
  const { data, error, reload } = useApi<AccessPolicy[]>("/access/policies");
  const { data: ranges } = useApi<NetworkRange[]>("/access/networks");
  const { can } = useSession();
  const [editing, setEditing] = useState<AccessPolicy | "new" | null>(null);
  return (
    <>
      <DataTable<AccessPolicy>
        id="access-policies"
        rows={data}
        error={error}
        rowKey={(p) => p.id}
        onRefresh={reload}
        searchText={(p) => `${p.name} ${p.description} ${p.scope} ${p.mode} ${p.outcome}`}
        columns={[
          {
            id: "name", header: "Policy", sort: (p) => p.name,
            cell: (p) => <div><b className="name-link">{p.name}</b>{p.description && <div className="xs faint">{p.description}</div>}</div>,
          },
          { id: "scope", header: "Applies to", sort: (p) => p.scope, cell: (p) => SCOPE[p.scope] },
          { id: "when", header: "When", hideNarrow: true, cell: (p) => <span className="small">{describeConditions(p, ranges ?? [])}</span>, csv: (p) => describeConditions(p, ranges ?? []) },
          {
            id: "outcome", header: "Then", sort: (p) => p.outcome, csv: (p) => p.outcome,
            cell: (p) => <Badge tone={OUTCOME[p.outcome].tone}>{OUTCOME[p.outcome].label}</Badge>,
          },
          { id: "mode", header: "Mode", sort: (p) => p.mode, csv: (p) => p.mode, cell: (p) => <Badge tone={MODE[p.mode].tone} dot>{MODE[p.mode].label}</Badge> },
          { id: "priority", header: "Priority", num: true, hideNarrow: true, sort: (p) => p.priority, cell: (p) => p.priority },
        ]}
        filters={[
          { id: "scope", label: "Applies to", options: Object.entries(SCOPE).map(([value, label]) => ({ value, label })), get: (p) => p.scope },
          { id: "mode", label: "Mode", options: Object.entries(MODE).map(([value, m]) => ({ value, label: m.label })), get: (p) => p.mode },
        ]}
        commands={[can("conditional_access.manage") && { label: "New policy", icon: <Plus size={16} />, onClick: () => setEditing("new") }]}
        onRowClick={(p) => setEditing(p)}
        activeKey={editing && editing !== "new" ? editing.id : null}
        initialSort={["priority", 1]}
        empty={<EmptyState icon={<ShieldAlert size={18} />} title="No conditional access policies">Every sign-in and privileged action is allowed until a policy says otherwise.</EmptyState>}
      />
      <WhatIf />
      {editing && <PolicyEditor key={editing === "new" ? "new" : editing.id} policy={editing === "new" ? null : editing} ranges={ranges ?? []} onClose={() => setEditing(null)} />}
    </>
  );
}

function PolicyEditor({ policy, ranges, onClose }: { policy: AccessPolicy | null; ranges: NetworkRange[]; onClose: () => void }) {
  const { can } = useSession();
  const confirm = useConfirm();
  const { busy, run } = useSave();
  const ro = !can("conditional_access.manage");
  const [v, setV] = useState<AccessPolicyInput>(policy ? { ...policy } : blankPolicy);
  const set = <K extends keyof AccessPolicyInput>(k: K, x: AccessPolicyInput[K]) => setV((p) => ({ ...p, [k]: x }));
  const setOutcome = (o: AccessOutcome) => setV((p) => ({ ...p, outcome: o, step_up_acr: o === "step_up" ? (p.step_up_acr ?? "urn:tessera:acr:phr") : null, step_up_max_age: o === "step_up" ? p.step_up_max_age : 0 }));
  const setNetwork = (op: AccessPolicyInput["network_op"]) => setV((p) => ({ ...p, network_op: op, network_range_ids: op === "any" ? [] : p.network_range_ids }));
  const toggle = (id: string) => set("network_range_ids", v.network_range_ids.includes(id) ? v.network_range_ids.filter((x) => x !== id) : [...v.network_range_ids, id]);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const body = { ...v, name: v.name.trim() };
    void run(() => (policy ? conditionalAccess.updatePolicy(policy.id, body) : conditionalAccess.createPolicy(body)), policy ? "Policy saved" : "Policy created", onClose);
  };
  const remove = async () => {
    if (!policy) return;
    const ok = await confirm({ title: `Delete “${policy.name}”?`, body: "Requests it matched are decided by the remaining policies from now on.", confirmLabel: "Delete policy", danger: true });
    if (ok !== null) void run(() => conditionalAccess.deletePolicy(policy.id), "Policy deleted", onClose);
  };
  const needsRange = v.network_op !== "any" && v.network_range_ids.length === 0;
  const formId = useId();
  return (
    <Drawer
      title={policy ? policy.name : "New policy"}
      sub={policy ? `${SCOPE[policy.scope]} · updated ${fmtDate(policy.updated_at)}` : "Start in report-only mode to see what it would do."}
      onClose={onClose}
      footer={
        <>
          {policy && !ro && <Button variant="danger" icon={<Trash2 size={14} />} onClick={remove} disabled={busy}>Delete</Button>}
          <span className="grow" />
          <Button onClick={onClose}>{ro ? "Close" : "Cancel"}</Button>
          {!ro && <Button type="submit" form={formId} variant="primary" disabled={busy || !v.name.trim() || needsRange}>{busy ? "Saving…" : "Save policy"}</Button>}
        </>
      }
    >
      <form id={formId} className="stack" onSubmit={submit}>
        <fieldset disabled={ro || busy} style={{ border: 0, padding: 0, margin: 0 }} className="stack">
          <Field label="Name"><input className="input" value={v.name} maxLength={80} required data-autofocus onChange={(e) => set("name", e.target.value)} /></Field>
          <Field label="Description"><textarea className="input" rows={2} maxLength={500} value={v.description} onChange={(e) => set("description", e.target.value)} /></Field>
          <Field label="Applies to" hint={v.scope === "signin" ? "Checked when someone signs in to Tessera through your identity provider." : "Checked on actions that already need a fresh sign-in: approving access, revoking grants, changing connections."}>
            <select className="input" value={v.scope} onChange={(e) => set("scope", e.target.value as AccessScope)}>
              {Object.entries(SCOPE).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
          </Field>
          <Field label="Network" hint="The client address as the server sees it: behind your load balancer that is the address it forwards, never a header from the client itself.">
            <select className="input" value={v.network_op} onChange={(e) => setNetwork(e.target.value as AccessPolicyInput["network_op"])}>
              <option value="any">Any network</option><option value="in">Is in one of these ranges</option><option value="not_in">Is not in any of these ranges</option>
            </select>
          </Field>
          {v.network_op !== "any" && (
            <div className="stack-sm" role="group" aria-label="Network ranges">
              {ranges.length === 0 && <Callout tone="warn">Create a network range first (Network ranges tab).</Callout>}
              {ranges.map((r) => (
                <label key={r.id} className="row tight">
                  <input type="checkbox" checked={v.network_range_ids.includes(r.id)} onChange={() => toggle(r.id)} />
                  <span><b>{r.name}</b> <span className="xs faint">{r.cidrs.join(", ")}</span></span>
                </label>
              ))}
            </div>
          )}
          <Field label="Device" hint="From the IdP's device claims and the device signal. A device the IdP says nothing about counts as unmanaged and not compliant.">
            <select className="input" value={v.device} onChange={(e) => set("device", e.target.value as AccessPolicyInput["device"])}>
              <option value="any">Any device</option><option value="unmanaged">Is not managed</option><option value="not_compliant">Is not known to be compliant</option>
            </select>
          </Field>
          <Field label="Then">
            <select className="input" value={v.outcome} onChange={(e) => setOutcome(e.target.value as AccessOutcome)}>
              {Object.entries(OUTCOME).map(([k, o]) => <option key={k} value={k}>{o.label}</option>)}
            </select>
          </Field>
          {v.outcome === "step_up" && (
            <>
              <Field label="Required sign-in" hint={v.scope === "signin" ? "The sign-in itself must already meet this; otherwise it is refused." : "A fresh sign-in of this strength is asked for before the action runs."}>
                <select className="input" value={v.step_up_acr ?? "urn:tessera:acr:phr"} onChange={(e) => set("step_up_acr", e.target.value as AccessPolicyInput["step_up_acr"])}>
                  {Object.entries(ACR).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
                </select>
              </Field>
              <Field label="Sign-in no older than (seconds)" hint="0 keeps the action's own limit (15 minutes for most actions). At most 900.">
                <input className="input" type="number" min={0} max={900} value={v.step_up_max_age} onChange={(e) => set("step_up_max_age", Math.max(0, Math.min(900, Number(e.target.value) || 0)))} />
              </Field>
            </>
          )}
          <Field label="Mode" hint={v.mode === "report_only" ? "Evaluated and recorded in the audit log, never enforced." : v.mode === "enforce" ? "Enforced now." : "Ignored."}>
            <select className="input" value={v.mode} onChange={(e) => set("mode", e.target.value as AccessMode)}>
              <option value="report_only">Report only</option><option value="enforce">Enforce</option><option value="disabled">Disabled</option>
            </select>
          </Field>
          <Field label="Priority" hint="Lower numbers are checked first (0 to 10000).">
            <input className="input" type="number" min={0} max={10000} value={v.priority} onChange={(e) => set("priority", Math.max(0, Math.min(10000, Number(e.target.value) || 0)))} />
          </Field>
          {v.mode === "enforce" && v.outcome === "deny" && v.scope === "signin" && <Callout tone="warn">A deny on sign-in can lock people out. Check it in report-only mode first. The operator bootstrap and these settings are never blocked.</Callout>}
        </fieldset>
      </form>
    </Drawer>
  );
}

function WhatIf() {
  const [scope, setScope] = useState<AccessScope>("privileged");
  const [ip, setIp] = useState("");
  const [managed, setManaged] = useState<"unknown" | "yes" | "no">("unknown");
  const [compliance, setCompliance] = useState<"unknown" | "compliant" | "not_compliant">("unknown");
  const [result, setResult] = useState<AccessDecision | null>(null);
  const { busy, run } = useSave();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => setResult(await conditionalAccess.evaluate({ scope, client_ip: ip.trim() || undefined, device_managed: managed === "unknown" ? null : managed === "yes", device_compliance: compliance })), "Checked");
  };
  return (
    <div className="card stack-sm">
      <h2>What would happen?</h2>
      <p className="small muted" style={{ margin: 0 }}>Try the current policies on a made-up request. Nothing is recorded.</p>
      <form className="row" onSubmit={submit} style={{ alignItems: "flex-end" }}>
        <Field label="Applies to"><select className="input" value={scope} onChange={(e) => setScope(e.target.value as AccessScope)}>{Object.entries(SCOPE).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
        <Field label="Client IP address"><input className="input" value={ip} placeholder="203.0.113.9" inputMode="decimal" onChange={(e) => setIp(e.target.value)} /></Field>
        <Field label="Device managed"><select className="input" value={managed} onChange={(e) => setManaged(e.target.value as typeof managed)}><option value="unknown">Not asserted</option><option value="yes">Managed</option><option value="no">Unmanaged</option></select></Field>
        <Field label="Device compliance"><select className="input" value={compliance} onChange={(e) => setCompliance(e.target.value as typeof compliance)}><option value="unknown">Unknown</option><option value="compliant">Compliant</option><option value="not_compliant">Not compliant</option></select></Field>
        <Button type="submit" variant="primary" disabled={busy}>Check</Button>
      </form>
      {result && (
        <div role="status" className="stack-sm">
          <div className="row tight">
            <Badge tone={OUTCOME[result.outcome].tone}>{OUTCOME[result.outcome].label}</Badge>
            <span className="small">{result.decided_by ? <>decided by <b>{result.decided_by.name}</b></> : `no enforced policy matched (${result.policies_evaluated} checked)`}</span>
          </div>
          {result.report_only?.map((h) => <div key={h.policy_id} className="small muted">Report only: “{h.name}” would {OUTCOME[h.outcome].label.toLowerCase()}.</div>)}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- network ranges
function Networks() {
  const { data, error, reload } = useApi<NetworkRange[]>("/access/networks");
  const { can } = useSession();
  const [editing, setEditing] = useState<NetworkRange | "new" | null>(null);
  return (
    <>
      <DataTable<NetworkRange>
        id="access-networks"
        rows={data}
        error={error}
        rowKey={(n) => n.id}
        onRefresh={reload}
        searchText={(n) => `${n.name} ${n.description} ${n.cidrs.join(" ")}`}
        columns={[
          { id: "name", header: "Range", sort: (n) => n.name, cell: (n) => <div><b className="name-link">{n.name}</b>{n.description && <div className="xs faint">{n.description}</div>}</div> },
          { id: "cidrs", header: "Addresses", csv: (n) => n.cidrs.join(" "), cell: (n) => <span className="small mono">{n.cidrs.join(", ")}</span> },
          { id: "used", header: "Used by", hideNarrow: true, sort: (n) => n.used_by.length, csv: (n) => n.used_by.join("; "), cell: (n) => (n.used_by.length ? <span className="small">{n.used_by.join(", ")}</span> : <span className="faint small">No policy</span>) },
          { id: "updated", header: "Last change", hideNarrow: true, sort: (n) => n.updated_at, cell: (n) => <span className="small">{fmtDate(n.updated_at)}</span> },
        ]}
        commands={[can("conditional_access.manage") && { label: "New range", icon: <Plus size={16} />, onClick: () => setEditing("new") }]}
        onRowClick={(n) => setEditing(n)}
        activeKey={editing && editing !== "new" ? editing.id : null}
        empty={<EmptyState icon={<Network size={18} />} title="No network ranges">Name your office and VPN ranges here, then use them in a policy.</EmptyState>}
      />
      {editing && <NetworkEditor key={editing === "new" ? "new" : editing.id} range={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );
}

function NetworkEditor({ range, onClose }: { range: NetworkRange | null; onClose: () => void }) {
  const { can } = useSession();
  const confirm = useConfirm();
  const { busy, run } = useSave();
  const ro = !can("conditional_access.manage");
  const [name, setName] = useState(range?.name ?? "");
  const [description, setDescription] = useState(range?.description ?? "");
  const [cidrs, setCidrs] = useState((range?.cidrs ?? []).join("\n"));
  const list = cidrs.split(/[\s,]+/).filter(Boolean);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const body = { name: name.trim(), description, cidrs: list };
    void run(() => (range ? conditionalAccess.updateNetwork(range.id, body) : conditionalAccess.createNetwork(body)), range ? "Range saved" : "Range created", onClose);
  };
  const remove = async () => {
    if (!range) return;
    const ok = await confirm({ title: `Delete “${range.name}”?`, confirmLabel: "Delete range", danger: true });
    if (ok !== null) void run(() => conditionalAccess.deleteNetwork(range.id), "Range deleted", onClose);
  };
  const formId = useId();
  return (
    <Drawer
      title={range ? range.name : "New network range"}
      sub="Addresses are matched against the client IP the server resolves through your trusted proxies."
      onClose={onClose}
      footer={
        <>
          {range && !ro && <Button variant="danger" icon={<Trash2 size={14} />} onClick={remove} disabled={busy || range.used_by.length > 0} title={range.used_by.length ? `Used by ${range.used_by.join(", ")}` : undefined}>Delete</Button>}
          <span className="grow" />
          <Button onClick={onClose}>{ro ? "Close" : "Cancel"}</Button>
          {!ro && <Button type="submit" form={formId} variant="primary" disabled={busy || !name.trim() || list.length === 0}>{busy ? "Saving…" : "Save range"}</Button>}
        </>
      }
    >
      <form id={formId} className="stack" onSubmit={submit}>
        <fieldset disabled={ro || busy} style={{ border: 0, padding: 0, margin: 0 }} className="stack">
          <Field label="Name"><input className="input" value={name} maxLength={80} required data-autofocus onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Description"><input className="input" value={description} maxLength={500} onChange={(e) => setDescription(e.target.value)} /></Field>
          <Field label="CIDR ranges" hint="One per line, for example 203.0.113.0/24 or 2001:db8::/32. A single address is a /32 (or /128). Up to 64.">
            <textarea className="input mono" rows={6} value={cidrs} onChange={(e) => setCidrs(e.target.value)} spellCheck={false} />
          </Field>
        </fieldset>
      </form>
    </Drawer>
  );
}

// ---------------------------------------------------------------- device signals
function Signals() {
  const { data, error, reload } = useApi<DeviceSignal[]>("/access/device-signals");
  const { can } = useSession();
  const confirm = useConfirm();
  const { run } = useSave();
  const [adding, setAdding] = useState(false);
  return (
    <>
      <Callout tone="neutral">The IdP's own device claims (managed, compliant) are read at sign-in. A signal set here is for what the IdP cannot see yet: it overrides a compliant claim when it says not compliant. Signals from your device-management tool will arrive through the shared signals receiver (not built yet) and appear here with source “caep”.</Callout>
      <DataTable<DeviceSignal>
        id="device-signals"
        rows={data}
        error={error}
        rowKey={(s) => s.user_id}
        onRefresh={reload}
        searchText={(s) => `${s.user} ${s.status} ${s.reason}`}
        columns={[
          { id: "user", header: "User", sort: (s) => s.user, cell: (s) => <b>{s.user || s.user_id}</b> },
          { id: "status", header: "Device", sort: (s) => s.status, csv: (s) => s.status, cell: (s) => <Badge tone={s.status === "compliant" ? "ok" : "critical"} dot>{s.status === "compliant" ? "Compliant" : "Not compliant"}</Badge> },
          { id: "source", header: "Source", hideNarrow: true, sort: (s) => s.source, cell: (s) => s.source === "manual" ? "Admin" : "Shared signals (CAEP)" },
          { id: "reason", header: "Reason", hideNarrow: true, cell: (s) => <span className="small">{s.reason || "–"}</span>, csv: (s) => s.reason },
          { id: "set", header: "Set", hideNarrow: true, sort: (s) => s.set_at, cell: (s) => <span className="small">{fmtDate(s.set_at)}</span> },
          { id: "exp", header: "Expires", hideNarrow: true, cell: (s) => <span className="small">{s.expires_at ? <>{fmtDate(s.expires_at)}{!s.active && <> <Badge>Expired</Badge></>}</> : "Never"}</span>, csv: (s) => s.expires_at ?? "" },
          ...(can("conditional_access.manage") ? [{
            id: "clear", header: "", cell: (s: DeviceSignal) => (
              <Button size="sm" variant="ghost" label={`Clear the signal for ${s.user}`} icon={<Trash2 size={14} />}
                onClick={async () => { if ((await confirm({ title: `Clear the signal for ${s.user}?`, confirmLabel: "Clear signal" })) !== null) void run(() => conditionalAccess.clearSignal(s.user_id), "Signal cleared"); }} />
            ),
          }] : []),
        ]}
        commands={[can("conditional_access.manage") && { label: "Set a signal", icon: <MonitorSmartphone size={16} />, onClick: () => setAdding(true) }]}
        empty={<EmptyState icon={<MonitorSmartphone size={18} />} title="No device signals">Devices count as compliant only when the IdP says so.</EmptyState>}
      />
      {adding && <SignalEditor onClose={() => setAdding(false)} />}
    </>
  );
}

function SignalEditor({ onClose }: { onClose: () => void }) {
  const { data: users } = useApi<AccessUser[]>("/access/users");
  const { busy, run } = useSave();
  const [user, setUser] = useState("");
  const [status, setStatus] = useState<DeviceSignal["status"]>("not_compliant");
  const [reason, setReason] = useState("");
  const [hours, setHours] = useState(24);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(() => conditionalAccess.setSignal(user, { status, reason, expires_in_hours: hours }), "Signal saved", onClose);
  };
  const formId = useId();
  return (
    <Drawer
      title="Set a device signal"
      sub="Replaces any earlier signal for the user."
      onClose={onClose}
      footer={<><span className="grow" /><Button onClick={onClose}>Cancel</Button><Button type="submit" form={formId} variant="primary" disabled={busy || !user}>{busy ? "Saving…" : "Save signal"}</Button></>}
    >
      <form id={formId} className="stack" onSubmit={submit}>
        <Field label="User">
          <select className="input" value={user} required data-autofocus onChange={(e) => setUser(e.target.value)}>
            <option value="">Choose a user</option>
            {(users ?? []).map((u) => <option key={u.id} value={u.id}>{u.email || u.name}</option>)}
          </select>
        </Field>
        <Field label="Device is">
          <select className="input" value={status} onChange={(e) => setStatus(e.target.value as DeviceSignal["status"])}>
            <option value="not_compliant">Not compliant</option><option value="compliant">Compliant</option>
          </select>
        </Field>
        <Field label="Reason" hint="Shown in the audit log. Up to 200 characters."><input className="input" value={reason} maxLength={200} onChange={(e) => setReason(e.target.value)} /></Field>
        <Field label="Expires after (hours)" hint="0 keeps it until someone clears it. Up to 2160 (90 days).">
          <input className="input" type="number" min={0} max={2160} value={hours} onChange={(e) => setHours(Math.max(0, Math.min(2160, Number(e.target.value) || 0)))} />
        </Field>
      </form>
    </Drawer>
  );
}
