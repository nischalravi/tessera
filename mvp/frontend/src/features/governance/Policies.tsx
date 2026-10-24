import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ClipboardCheck, FlaskConical, ShieldCheck } from "lucide-react";
import { Group, IdentityDetail, IdentityRow, Policy, SimResult, Violation, simulate, useApi } from "../../api";
import { useIdentityActions } from "../../app/actions";
import { Badge, Button, Callout, DataTable, EmptyState, Loading, Page, Sev, SimulationView, Tabs, useSelected } from "../../components";
import { ViolationPanel } from "../directory/Panels";
import { SodFunctionsView, SodRisksView, SodRulesetsView } from "./SodModelViews";

function Simulator() {
  const { data: idents } = useApi<IdentityRow[]>("/identities?status=active");
  const { data: groups } = useApi<Group[]>("/groups");
  const [iid, setIid] = useState("");
  const { data: ident } = useApi<IdentityDetail>(iid ? `/identities/${iid}` : null);
  const [remove, setRemove] = useState<number[]>([]);
  const [addAcct, setAddAcct] = useState("");
  const [addGroup, setAddGroup] = useState("");
  const [res, setRes] = useState<SimResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setErr(null);
    setBusy(true);
    try {
      setRes(await simulate({ remove_edge_ids: remove, add_edges: addAcct && addGroup ? [{ src: `account:${addAcct}`, dst: `group:${addGroup}` }] : [] }));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="card stack">
      <h2 className="row tight"><FlaskConical size={16} aria-hidden /> What-if simulation</h2>
      <div className="small muted">Pick an identity, then remove grants or add a membership. Nothing changes: Tessera recomputes effective permissions and every policy on a copy of the graph.</div>
      <label className="field">Identity
        <select className="input" value={iid} onChange={(e) => { setIid(e.target.value); setRemove([]); setAddAcct(""); setRes(null); }}>
          <option value="">Select…</option>
          {(idents ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)).map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}
        </select>
      </label>
      {iid && !ident && <Loading kind="block" />}
      {ident && (
        <>
          <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
            <legend className="small muted" style={{ marginBottom: 4 }}>Remove grants</legend>
            {ident.grants.filter((g) => g.edge_id).map((g) => (
              <label key={g.edge_id} className="row small" style={{ flexWrap: "nowrap" }}>
                <input type="checkbox" checked={remove.includes(g.edge_id!)} onChange={(e) => setRemove(e.target.checked ? [...remove, g.edge_id!] : remove.filter((x) => x !== g.edge_id))} />
                <span className="truncate"><span className="sys faint">{g.account}</span> → <b>{g.label}</b></span>
              </label>
            ))}
          </fieldset>
          <div className="grid g2">
            <label className="field">Add: account
              <select className="input" value={addAcct} onChange={(e) => setAddAcct(e.target.value)}>
                <option value="">None</option>
                {ident.accounts.filter((a) => a.status === "active").map((a) => <option key={a.id} value={a.id}>{a.system}: {a.username}</option>)}
              </select>
            </label>
            <label className="field">to group or role
              <select className="input" value={addGroup} onChange={(e) => setAddGroup(e.target.value)}>
                <option value="">None</option>
                {(groups ?? []).map((g) => <option key={g.id} value={g.id}>{g.system}: {g.name}</option>)}
              </select>
            </label>
          </div>
        </>
      )}
      {err && <Callout tone="bad">{err}</Callout>}
      <Button variant="primary" disabled={busy || !iid || (!remove.length && !(addAcct && addGroup))} onClick={run}>Run simulation</Button>
      {res && <SimulationView r={res} />}
    </div>
  );
}

type View = "violations" | "policies" | "simulate" | "functions" | "risks" | "rulesets";

export function Policies() {
  const { data: policies, error, reload: reloadPolicies } = useApi<Policy[]>("/policies");
  const { data: violations, error: vErr, reload } = useApi<Violation[]>("/violations");
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useSelected();
  const acts = useIdentityActions();
  const nav = useNavigate();
  const [yaml, setYaml] = useState<string | null>(null);
  const view = (params.get("view") ?? "violations") as View;
  const policyFilter = params.get("policy") ?? "";
  const setView = (v: View, policy?: string) => {
    const next = new URLSearchParams();
    if (v !== "violations") next.set("view", v);
    if (policy) next.set("policy", policy);
    setParams(next, { replace: true });
  };
  const open = violations?.find((v) => v.key === selected);
  const crumbs: [string, string?][] = [["Protection"], ["Policies & SoD"]];
  const tabs = (
    <Tabs<View> label="Policies" value={view} onChange={(v) => setView(v)} tabs={[
      { id: "violations", label: `Violations${violations ? ` (${violations.length})` : ""}` },
      { id: "policies", label: `Policies${policies ? ` (${policies.length})` : ""}` },
      { id: "simulate", label: "What-if simulation" },
      { id: "functions", label: "Functions" },
      { id: "risks", label: "Risks" },
      { id: "rulesets", label: "Rulesets" },
    ]} />
  );
  if (!policies) return <Page title="Policies & SoD" crumbs={crumbs} tabs={tabs}><Loading error={error} kind="page" /></Page>;
  const sevOrder = ["low", "medium", "high", "critical"];
  return (
    <Page
      title="Policies & SoD"
      count={violations ? `${violations.length} open violation${violations.length === 1 ? "" : "s"}` : undefined}
      crumbs={crumbs}
      tabs={tabs}
      sub={view === "functions" ? "Reusable sets of entitlements, such as “Create supplier payments”. Risks name the functions nobody should hold together."
        : view === "risks" ? "A risk is a prioritised conflict between two or more functions. An identity violates it by holding an entitlement of each, through any path."
        : view === "rulesets" ? "Rulesets group risks, can be switched off per tenant, keep their versions and round-trip as YAML files."
        : view === "policies" ? <>Policies are YAML files in <code>server/policies/</code>, evaluated against the effective-permission graph. Edit a file and reload; no restart needed.</> : undefined}
    >
      {view === "violations" && (
        <>
          <DataTable
            key={policyFilter}
            id="violations"
            rows={violations}
            error={vErr}
            rowKey={(v) => v.key}
            columns={[
              { id: "who", header: "Identity", sort: (v) => v.identity_name, cell: (v) => <span className="name-link">{v.identity_name}</span> },
              { id: "msg", header: "Finding", csv: (v) => v.message, cell: (v) => <span>{v.message}<span className="xs faint" style={{ display: "block" }}>{v.policy_name}</span></span> },
              { id: "sev", header: "Severity", sort: (v) => sevOrder.indexOf(v.severity), csv: (v) => v.severity, cell: (v) => <Sev s={v.severity} /> },
            ]}
            initialSort={["sev", -1]}
            initialFilters={policyFilter ? { policy: policyFilter } : undefined}
            searchText={(v) => `${v.identity_name} ${v.message} ${v.policy_name}`}
            searchPlaceholder="Search findings…"
            filters={[
              { id: "sev", label: "Severity", options: ["critical", "high", "medium", "low"].map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) })), get: (v) => v.severity },
              { id: "policy", label: "Policy", options: policies.map((p) => ({ value: p.id, label: p.name })), get: (v) => v.policy_id },
            ]}
            commands={[
              { label: "Start review", icon: <ClipboardCheck size={16} />, onClick: () => acts.startCampaign() },
              { label: "Simulate a fix", icon: <FlaskConical size={16} />, onClick: () => setView("simulate") },
            ]}
            onRefresh={() => { reload(); reloadPolicies(); }}
            bulkActions={[{ label: "Review this identity", icon: <ClipboardCheck size={16} />, run: (vs) => { const id = vs.find((v) => v.identity_id)?.identity_id; if (id) nav(`/governance/reviews?identity=${id}`); } }]}
            rowLabel={(v) => `${v.identity_name}: ${v.policy_name}`}
            onRowClick={(v) => setSelected(v.key)}
            activeKey={selected}
            empty={<EmptyState title="No violations" icon={<ShieldCheck size={18} />}>Every policy passes.</EmptyState>}
          />
          {open && <ViolationPanel v={open} description={policies.find((p) => p.id === open.policy_id)?.description} onClose={() => setSelected(null)} />}
        </>
      )}
      {view === "policies" && (
        <div className="grid g3">
          {policies.map((p) => (
            <div key={p.id} className="card stack-sm">
              <div className="spread"><Sev s={p.severity} /><Badge tone={p.violations ? "critical" : "ok"}>{p.violations} violation{p.violations === 1 ? "" : "s"}</Badge></div>
              <b>{p.name}</b>
              <div className="small muted">{p.description}</div>
              <div className="spread">
                <code className="xs faint">{p.type}</code>
                <div className="row tight">
                  <Button size="sm" variant="ghost" aria-expanded={yaml === p.id} onClick={() => setYaml(yaml === p.id ? null : p.id)}>{yaml === p.id ? "Hide" : "View"} YAML</Button>
                  <Button size="sm" disabled={!p.violations} onClick={() => setView("violations", p.id)}>Show violations</Button>
                </div>
              </div>
              {yaml === p.id && <pre className="yaml">{p.source}</pre>}
            </div>
          ))}
        </div>
      )}
      {view === "simulate" && <div style={{ maxWidth: 820 }}><Simulator /></div>}
      {view === "functions" && <SodFunctionsView />}
      {view === "risks" && <SodRisksView />}
      {view === "rulesets" && <SodRulesetsView />}
    </Page>
  );
}
