import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { FlaskConical, ShieldCheck } from "lucide-react";
import { Group, IdentityDetail, IdentityRow, Policy, SimResult, Violation, simulate, useApi } from "../../api";
import { Badge, Button, Callout, DataTable, EmptyState, Loading, Page, Sev, SimulationView } from "../../components";

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

export function Policies() {
  const { data: policies, error } = useApi<Policy[]>("/policies");
  const { data: violations, error: vErr } = useApi<Violation[]>("/violations");
  const [pid, setPid] = useState("");
  const [yaml, setYaml] = useState<string | null>(null);
  const rows = useMemo(() => (violations ? violations.filter((v) => !pid || v.policy_id === pid) : null), [violations, pid]);
  const crumbs: [string, string?][] = [["Governance", "/governance"], ["Policies & violations"]];
  if (!policies) return <Page title="Policies & violations" crumbs={crumbs}><Loading error={error} kind="page" /></Page>;
  return (
    <Page title="Policies & violations" crumbs={crumbs} sub={<>Policies are YAML files in <code>backend/policies/</code>, evaluated against the effective-permission graph. Edit a file and reload; no restart needed.</>}>
      <div className="grid g3">
        {policies.map((p) => (
          <div key={p.id} className="card stack-sm" style={pid === p.id ? { boxShadow: "0 0 0 2px var(--accent)" } : undefined}>
            <div className="spread"><Sev s={p.severity} /><Badge tone={p.violations ? "critical" : "ok"}>{p.violations} violation{p.violations === 1 ? "" : "s"}</Badge></div>
            <b>{p.name}</b>
            <div className="small muted">{p.description}</div>
            <div className="spread">
              <code className="xs faint">{p.type}</code>
              <div className="row tight">
                <Button size="sm" variant="ghost" aria-expanded={yaml === p.id} onClick={() => setYaml(yaml === p.id ? null : p.id)}>{yaml === p.id ? "Hide" : "View"} YAML</Button>
                <Button size="sm" aria-pressed={pid === p.id} onClick={() => setPid(pid === p.id ? "" : p.id)}>{pid === p.id ? "Show all" : "Filter"}</Button>
              </div>
            </div>
            {yaml === p.id && <pre className="yaml">{p.source}</pre>}
          </div>
        ))}
      </div>
      <div className="grid g21 mt">
        <div className="stack-sm">
          <h2>Violations{pid && <span className="muted"> in {policies.find((p) => p.id === pid)?.name}</span>}</h2>
          <DataTable
            id="violations"
            rows={rows}
            error={vErr}
            rowKey={(v) => v.key}
            columns={[
              { id: "sev", header: "Severity", sort: (v) => ["low", "medium", "high", "critical"].indexOf(v.severity), csv: (v) => v.severity, cell: (v) => <Sev s={v.severity} /> },
              { id: "who", header: "Identity", sort: (v) => v.identity_name, cell: (v) => (v.identity_id ? <Link to={`/directory/identities/${v.identity_id}`}>{v.identity_name}</Link> : v.identity_name) },
              { id: "msg", header: "Finding", csv: (v) => v.message, cell: (v) => <span className="small">{v.message}{v.evidence.slice(0, 2).map((e, i) => <span key={i} className="xs faint sys" style={{ display: "block" }}>{e}</span>)}</span> },
            ]}
            initialSort={["sev", -1]}
            searchText={(v) => `${v.identity_name} ${v.message} ${v.policy_name}`}
            searchPlaceholder="Search findings…"
            filters={[{ id: "sev", label: "Severity", options: ["critical", "high", "medium", "low"].map((s) => ({ value: s, label: s })), get: (v) => v.severity }]}
            empty={<EmptyState title="No violations" icon={<ShieldCheck size={18} />}>Every policy passes.</EmptyState>}
          />
        </div>
        <Simulator />
      </div>
    </Page>
  );
}
