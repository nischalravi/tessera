/**
 * Attribute policies (issue #162): named, versioned conditions over identity, resource and
 * context attributes. Birthright rules and catalog eligibility point at them; SoD policies carry
 * the same language in their YAML. A missing attribute never grants. Every change is simulated
 * first: who would gain and who would lose, against the saved version.
 */
import { FormEvent, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Archive, FlaskConical, History, Link2, Pencil, Plus } from "lucide-react";
import {
  AbacBinding, AbacList, AbacPolicy, AbacSimulation, CatalogView, abac, abacPaths, fmtDate, relTime, useApi,
} from "../../api";
import { Badge, Button, Callout, CommandBar, DataTable, Drawer, EmptyState, Loading, Page, SidePanel, Tabs, useSelected, useToast } from "../../components";
import { EXAMPLE_CONDITION, describeCondition, parseConditionText } from "./abacText";

const I = 16;
const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const pretty = (c: unknown) => JSON.stringify(c, null, 2);

export function AttributePolicies() {
  const { data: view, error, reload } = useApi<AbacList>(abacPaths.list);
  const [selected, setSelected] = useSelected();
  const [creating, setCreating] = useState(false);
  const rows = view?.policies ?? null;
  const open = rows?.find((p) => p.id === selected);
  return (
    <Page title="Attribute policies" count={rows ? plural(rows.length, "policy", "policies") : null} crumbs={[["Protection"], ["Attribute policies"]]}
      sub="Conditions over who someone is, what they ask for and when. Birthright rules and request eligibility use them; a missing attribute never grants.">
      <DataTable
        id="abac-policies"
        rows={rows}
        error={error}
        rowKey={(p) => p.id}
        columns={[
          { id: "name", header: "Policy", sort: (p) => p.name, cell: (p) => <div><span className="name-link">{p.name}</span><div className="xs faint truncate" style={{ maxWidth: 520 }}>{describeCondition(p.condition)}</div></div> },
          { id: "uses", header: "Used by", num: true, sort: (p) => p.used_by.roles.length + p.used_by.catalog_items.length, cell: (p) => p.used_by.roles.length + p.used_by.catalog_items.length },
          { id: "version", header: "Version", num: true, sort: (p) => p.version, cell: (p) => `v${p.version}` },
          { id: "status", header: "Status", sort: (p) => p.status, cell: (p) => (p.status === "retired" ? <Badge>Retired</Badge> : <span className="small faint">Active</span>) },
          { id: "updated", header: "Updated", sort: (p) => p.updated_at, cell: (p) => <span className="small nowrap" title={fmtDate(p.updated_at)}>{relTime(p.updated_at)}</span>, hideNarrow: true },
        ]}
        searchText={(p) => `${p.name} ${p.description} ${describeCondition(p.condition)}`}
        searchPlaceholder="Search policies or their conditions…"
        filters={[{ id: "status", label: "Status", options: [{ value: "active", label: "Active" }, { value: "retired", label: "Retired" }], get: (p) => p.status }]}
        commands={[view?.can_manage && { label: "New policy", icon: <Plus size={I} />, onClick: () => setCreating(true) }]}
        onRefresh={reload}
        rowLabel={(p) => p.name}
        onRowClick={(p) => setSelected(p.id)}
        activeKey={selected}
        empty={<EmptyState title="No attribute policies yet">{view?.can_manage ? "Create one, simulate it, then use it in a birthright rule or on a catalog entitlement." : "Policy admins create attribute policies here."}</EmptyState>}
      />
      {open && view && <PolicyPanel id={open.id} summary={open} view={view} onClose={() => setSelected(null)} onChanged={reload} />}
      {creating && view && <PolicyEditor attrs={view} onClose={() => setCreating(false)} onSaved={(p) => { reload(); setSelected(p.id); }} />}
    </Page>
  );
}

type Tab = "overview" | "history";

function PolicyPanel({ id, summary, view, onClose, onChanged }: { id: string; summary: AbacPolicy; view: AbacList; onClose: () => void; onChanged: () => void }) {
  const { data: detail, reload } = useApi<AbacPolicy>(abacPaths.one(id));
  const p = detail ?? summary;
  const [tab, setTab] = useState<Tab>("overview");
  const [drawer, setDrawer] = useState<null | "edit" | "bind" | "retire">(null);
  useEffect(() => setTab("overview"), [id]);
  const done = () => { reload(); onChanged(); };
  const manage = view.can_manage && p.status === "active";
  return (
    <>
      <SidePanel title={p.name} sub={<>{p.status === "retired" ? <Badge>Retired</Badge> : <Badge tone="info">Version {p.version}</Badge>}</>} onClose={onClose}
        commands={<CommandBar label={`Actions for ${p.name}`} items={[
          manage && { label: "Edit", icon: <Pencil size={I} />, onClick: () => setDrawer("edit") },
          manage && { label: "Use on a catalog item", icon: <Link2 size={I} />, onClick: () => setDrawer("bind") },
          manage && { label: "Retire", icon: <Archive size={I} />, danger: true, onClick: () => setDrawer("retire") },
        ]} />}
        tabs={<Tabs label="Policy details" value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "history", label: <><History size={13} aria-hidden /> History</> }]} />}>
        {tab === "overview" ? (
          <div className="stack">
            <p className="muted">{p.description || <span className="faint">No description</span>}</p>
            <div><div className="small muted">In words</div><p>{describeCondition(p.condition)}</p></div>
            <div><div className="small muted">Condition</div><pre className="yaml" tabIndex={0} aria-label="Condition JSON">{pretty(p.condition)}</pre></div>
            <dl className="kv">
              <dt>Birthright rules</dt><dd>{p.used_by.roles.length ? p.used_by.roles.map((r) => <Badge key={r} tone="outline">{r}</Badge>) : <span className="faint">None</span>}</dd>
              <dt>Catalog items</dt><dd>{p.used_by.catalog_items.length ? p.used_by.catalog_items.map((r) => <Badge key={r} tone="outline">{r}</Badge>) : <span className="faint">None</span>}</dd>
              <dt>Updated</dt><dd title={fmtDate(p.updated_at)}>{relTime(p.updated_at)}{p.updated_by && ` by ${p.updated_by.display_name}`}</dd>
            </dl>
            <p className="xs faint">A role rule picks up a new version when the role is next reconciled or saved. Use it on a role from <Link to="/directory/roles">Roles</Link>.</p>
          </div>
        ) : !detail?.versions ? <Loading kind="block" /> : (
          <ol className="timeline">
            {detail.versions.map((v) => (
              <li key={v.version}>
                <b>Version {v.version}</b> by {v.actor} <span className="faint" title={fmtDate(v.changed_at)}>{relTime(v.changed_at)}</span>
                {v.snapshot.condition && <div className="small muted">{describeCondition(v.snapshot.condition)}</div>}
                {v.snapshot.status === "retired" && <div className="small muted">Retired</div>}
                {v.note && <div className="small">{v.note}</div>}
              </li>
            ))}
          </ol>
        )}
      </SidePanel>
      {drawer === "edit" && <PolicyEditor policy={p} attrs={view} onClose={() => setDrawer(null)} onSaved={done} />}
      {drawer === "bind" && <BindDrawer policy={p} onClose={() => setDrawer(null)} onSaved={done} />}
      {drawer === "retire" && <RetireDrawer policy={p} onClose={() => setDrawer(null)} onSaved={done} />}
    </>
  );
}

function PolicyEditor({ policy, attrs, onClose, onSaved }: { policy?: AbacPolicy; attrs: AbacList; onClose: () => void; onSaved: (p: AbacPolicy) => void }) {
  const toast = useToast();
  const [name, setName] = useState(policy?.name ?? "");
  const [description, setDescription] = useState(policy?.description ?? "");
  const [text, setText] = useState(pretty(policy?.condition ?? EXAMPLE_CONDITION));
  const [note, setNote] = useState("");
  const [sim, setSim] = useState<AbacSimulation | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const parsed = useMemo(() => parseConditionText(text), [text]);
  useEffect(() => setSim(null), [text]);
  const ready = name.trim() !== "" && !!parsed.condition && !busy;
  const simulate = async () => {
    if (!parsed.condition) return;
    setBusy(true);
    setErr(null);
    try {
      setSim(await abac.simulate(parsed.condition, policy?.id));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!parsed.condition || !ready) return;
    setBusy(true);
    setErr(null);
    try {
      const spec = { name, description, condition: parsed.condition, note };
      const saved = policy ? await abac.update(policy.id, policy.version, spec) : await abac.create(spec);
      toast(`Policy “${saved.name}” saved as version ${saved.version}`);
      onSaved(saved);
      onClose();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={policy ? `Edit ${policy.name}` : "New attribute policy"} onClose={onClose} wide
      footer={<>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={simulate} disabled={!parsed.condition || busy} icon={<FlaskConical size={I} />}>{sim ? "Simulate again" : "Simulate"}</Button>
        <Button type="submit" form="abac-form" variant="primary" disabled={!ready || !sim}>{policy ? "Save new version" : "Create policy"}</Button>
      </>}>
      <form id="abac-form" className="stack" onSubmit={save}>
        <label className="field">Name<input className="input" data-autofocus value={name} onChange={(e) => setName(e.target.value)} maxLength={120} placeholder="e.g. Finance employees" /></label>
        <label className="field">Description<textarea className="input" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What it is for" /></label>
        <label className="field">Condition (JSON)
          <textarea className="input mono" rows={12} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} aria-invalid={!!parsed.error} aria-describedby="abac-cond-help" />
        </label>
        <p id="abac-cond-help" className={parsed.error ? "small" : "small muted"} role={parsed.error ? "alert" : undefined}>
          {parsed.error ?? `In words: ${describeCondition(parsed.condition!)}`}
        </p>
        <details>
          <summary className="small">Language and attributes</summary>
          <div className="stack-sm small">
            <p><code>all</code>, <code>any</code> and <code>not</code> combine tests. A test is <code>{`{"attr": "identity.department", "op": "eq", "value": "Finance"}`}</code> with op one of eq, ne, in (a list), prefix, exists, gt, gte, lt, lte (numbers or RFC 3339 times). A missing attribute is never true, and not of a missing attribute is still not true.</p>
            <table>
              <thead><tr><th>Attribute</th><th>Type</th><th>Note</th></tr></thead>
              <tbody>{attrs.attributes.map((a) => <tr key={a.name}><td className="sys">{a.name}</td><td>{a.type}</td><td className="muted">{a.note}</td></tr>)}</tbody>
            </table>
          </div>
        </details>
        <label className="field">Why this change (kept with the version)<input className="input" value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
        {sim ? <SimulationResult sim={sim} /> : <p className="small faint">Simulate to see who would gain or lose access before you save.</p>}
      </form>
    </Drawer>
  );
}

function SimPeople({ title, people, total }: { title: string; people: AbacSimulation["gains"]; total: number }) {
  return (
    <section className="stack-sm" aria-label={title}>
      <h3>{title} ({total})</h3>
      {total === 0 ? <p className="small muted">Nobody.</p> : (
        <div className="table-scroll" style={{ maxHeight: 220 }}>
          <table>
            <thead><tr><th>Person</th><th>Type</th><th>Department</th><th>Status</th></tr></thead>
            <tbody>{people.map((p) => <tr key={p.id}><td><Link to={`/directory/identities/${p.id}`}>{p.name}</Link></td><td className="small">{p.type}</td><td className="small">{p.department || <span className="faint">-</span>}</td><td className="small">{p.status}</td></tr>)}</tbody>
          </table>
        </div>
      )}
      {total > people.length && <p className="xs faint">and {total - people.length} more</p>}
    </section>
  );
}

export function SimulationResult({ sim }: { sim: AbacSimulation }) {
  return (
    <div className="stack" aria-live="polite">
      <div className="row tight" role="list" aria-label="Simulation summary">
        <span role="listitem"><Badge tone="info">{plural(sim.matching, "identity", "identities")} match</Badge></span>
        <span role="listitem"><Badge tone="ok">{plural(sim.gain_count, "identity", "identities")} gain</Badge></span>
        <span role="listitem"><Badge tone="warning">{plural(sim.lose_count, "identity", "identities")} lose</Badge></span>
        {sim.missing_attributes > 0 && <span role="listitem"><Badge tone="neutral" title="The condition tests an attribute these identities do not have, so it does not grant">{sim.missing_attributes} lack an attribute it tests</Badge></span>}
      </div>
      <p className="xs faint">{sim.current_version ? `Compared with version ${sim.current_version}` : "A new policy: compared with nobody"} across {plural(sim.evaluated, "identity", "identities")}.</p>
      <SimPeople title="Gain" people={sim.gains} total={sim.gain_count} />
      <SimPeople title="Lose" people={sim.loses} total={sim.lose_count} />
    </div>
  );
}

function BindDrawer({ policy, onClose, onSaved }: { policy: AbacPolicy; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const { data: cat } = useApi<CatalogView>("/catalog?all=1");
  const { data: bindings } = useApi<AbacBinding[]>(abacPaths.bindings);
  const [group, setGroup] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const items = (cat?.items ?? []).filter((e) => e.id);
  const current = bindings?.find((b) => b.target_id === items.find((e) => String(e.group.id) === group)?.id);
  const run = async (policyId: string | null) => {
    setBusy(true);
    setErr(null);
    try {
      await abac.bindCatalog(Number(group), policyId);
      toast(policyId ? "Eligibility policy set" : "Eligibility policy removed");
      onSaved();
      onClose();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={`Use ${policy.name} on a catalog item`} onClose={onClose}
      footer={<>
        <Button onClick={onClose}>Cancel</Button>
        {current && <Button onClick={() => run(null)} disabled={busy}>Remove its policy</Button>}
        <Button variant="primary" onClick={() => run(policy.id)} disabled={!group || busy || current?.policy_id === policy.id}>Use here</Button>
      </>}>
      <div className="stack">
        <p className="small muted">People must satisfy the policy on top of the item's type and department lists to request it. Requests already made stay.</p>
        <label className="field">Catalog item
          <select className="input" value={group} onChange={(e) => setGroup(e.target.value)} data-autofocus>
            <option value="">Select…</option>
            {items.map((e) => <option key={e.id} value={e.group.id}>{e.group.system}:{e.group.name}</option>)}
          </select>
        </label>
        {current && <Callout tone="neutral">{current.policy_id === policy.id ? "It already uses this policy." : "It uses another policy; this replaces it."}</Callout>}
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}

function RetireDrawer({ policy, onClose, onSaved }: { policy: AbacPolicy; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [why, setWhy] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const inUse = policy.used_by.roles.length + policy.used_by.catalog_items.length > 0;
  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      await abac.retire(policy.id, why.trim());
      toast("Policy retired");
      onSaved();
      onClose();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={`Retire ${policy.name}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="danger" onClick={run} disabled={busy || inUse || !why.trim()}>Retire policy</Button></>}>
      <div className="stack">
        {inUse
          ? <Callout tone="warn">It is still used by {plural(policy.used_by.roles.length, "role rule")} and {plural(policy.used_by.catalog_items.length, "catalog item")}. Detach it first.</Callout>
          : <p className="small muted">A retired policy cannot be edited or used. Its history stays.</p>}
        <label className="field">Reason<input className="input" data-autofocus value={why} onChange={(e) => setWhy(e.target.value)} maxLength={500} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}
