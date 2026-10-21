/**
 * Organization settings (issue #298): assigned owners, the organization's policies and the source of the
 * hierarchy. The tree itself still comes from the HR data. Saving needs catalog.manage and a fresh
 * phishing-resistant sign-in, and is audited.
 */
import { FormEvent, useEffect, useState } from "react";
import { IdentityRow, OrgDetail, OrgHierarchySourceView, OrgSettingsView, orgHierarchySourcePath, orgSettings, orgSettingsPath, useApi } from "../../api";
import { Button, Callout, Loading, useToast } from "../../components";
import { STAGES, draftPolicies, policiesOf, samePolicies } from "./orgSettingsModel";

function Form({ org, view, onSaved }: { org: OrgDetail; view: OrgSettingsView; onSaved: () => void }) {
  const { data: people } = useApi<IdentityRow[]>("/identities?type=human");
  const toast = useToast();
  const [owners, setOwners] = useState<number[]>(view.owner_ids);
  const [d, setD] = useState(draftPolicies(view.policies));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setOwners(view.owner_ids);
    setD(draftPolicies(view.policies));
  }, [view.version, view.owner_ids.join()]); // eslint-disable-line react-hooks/exhaustive-deps
  const can = view.can_manage;
  const { policies, problem } = policiesOf(d);
  const changed = owners.join() !== view.owner_ids.join() || !samePolicies(policies, view.policies);
  const name = (id: number) => (people ?? []).find((p) => p.id === id)?.name ?? view.owners.find((o) => o.id === id)?.name ?? `#${id}`;
  const addable = (people ?? []).filter((p) => p.status === "active" && !owners.includes(p.id));
  const set = (patch: Partial<typeof d>) => setD({ ...d, ...patch });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || !changed || busy || !can) return;
    setBusy(true);
    setErr(null);
    try {
      await orgSettings.save(org.id, view.version, owners, policies);
      toast(`${org.name} settings saved`);
      onSaved();
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card stack mt" onSubmit={submit} aria-label="Organization settings">
      <div className="card-h"><h2>Settings</h2></div>
      {!can && <Callout tone="neutral">You can read these settings. A policy admin changes them.</Callout>}
      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h3>Owners</h3></legend>
        <p className="xs faint">{org.owners_source === "assigned" ? "Named here." : "None named: the owners shown are derived from the reporting lines."} Named owners replace the derived ones while at least one is active. Organization-owner reviews go to them.</p>
        <div className="row">
          {owners.map((id) => (
            <span key={id} className="chip">{name(id)}{can && <button type="button" className="chip-x" aria-label={`Remove ${name(id)}`} onClick={() => setOwners(owners.filter((x) => x !== id))}>×</button>}</span>
          ))}
          {owners.length === 0 && <span className="small faint">No named owners</span>}
        </div>
        {can && owners.length < 5 && (
          <select className="input" aria-label="Add an owner" value="" onChange={(e) => e.target.value && setOwners([...owners, Number(e.target.value)])} style={{ maxWidth: 320 }}>
            <option value="">Add an owner…</option>
            {addable.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        )}
      </fieldset>
      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h3>Default approval workflow</h3></legend>
        <p className="xs faint">Used for a request by someone in this organization when the item has no approval policy of its own. Stages run in the order shown.</p>
        {STAGES.map((st) => (
          <label key={st.id} className="row small"><input type="checkbox" checked={d.stages.includes(st.id)} onChange={(e) => set({ stages: STAGES.map((x) => x.id).filter((x) => (x === st.id ? e.target.checked : d.stages.includes(x))) })} /> {st.label}</label>
        ))}
        {d.stages.length > 0 && (
          <label className="field" style={{ maxWidth: 240 }}>Escalate after (hours)
            <input className="input" inputMode="decimal" value={d.escalate} placeholder="48" onChange={(e) => set({ escalate: e.target.value })} />
          </label>
        )}
      </fieldset>
      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h3>Request settings for this organization</h3></legend>
        <p className="xs faint">Tighten the tenant's request settings for this organization's people. A looser value than the tenant's changes nothing.</p>
        <label className="row small"><input type="checkbox" checked={d.requireJustification} onChange={(e) => set({ requireJustification: e.target.checked })} /> Always require a justification</label>
        <div className="grid g3">
          <label className="field">Minimum justification (characters)<input className="input" inputMode="numeric" value={d.minLength} onChange={(e) => set({ minLength: e.target.value })} placeholder="Tenant's" /></label>
          <label className="field">Default duration (hours)<input className="input" inputMode="decimal" value={d.defaultHours} onChange={(e) => set({ defaultHours: e.target.value })} placeholder="Tenant's" /></label>
          <label className="field">Maximum duration (hours)<input className="input" inputMode="decimal" value={d.maxHours} onChange={(e) => set({ maxHours: e.target.value })} placeholder="Tenant's" /></label>
        </div>
      </fieldset>
      {problem && changed && <p className="small" role="alert">{problem}</p>}
      {err && <Callout tone="bad">{err}</Callout>}
      {can && <div className="row" style={{ justifyContent: "flex-end" }}><Button type="submit" variant="primary" disabled={!!problem || !changed || busy}>{busy ? "Saving…" : "Save settings"}</Button></div>}
    </form>
  );
}

/** The settings card of one organization, on its page. */
export function OrgSettingsPanel({ org, onChanged }: { org: OrgDetail; onChanged: () => void }) {
  const { data, error, reload } = useApi<OrgSettingsView>(orgSettingsPath(org.id));
  if (!data) return <div className="card mt"><Loading error={error} what="organization settings" /></div>;
  return <Form org={org} view={data} onSaved={() => { reload(); onChanged(); }} />;
}

/** Where the hierarchy comes from, on the organizations list. */
export function HierarchySourceCard({ onSaved }: { onSaved: () => void }) {
  const { data, error, reload } = useApi<OrgHierarchySourceView>(orgHierarchySourcePath);
  const toast = useToast();
  const [system, setSystem] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setSystem(data?.system ?? ""), [data?.version]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!data) return error ? null : <div className="card mt"><Loading error={error} what="hierarchy source" /></div>;
  const changed = system !== (data.system ?? "");
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await orgSettings.saveSource(data.version, system || null);
      toast("Hierarchy source saved");
      reload();
      onSaved();
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card stack mt" onSubmit={save} aria-label="Hierarchy source">
      <div className="card-h"><h2>Hierarchy source</h2></div>
      <p className="small muted">Organizations are the departments in the HR data. Limit them to the people one source provided, so a contractor feed or a directory with its own department names does not add organizations.</p>
      <label className="field" style={{ maxWidth: 320 }}>People from
        <select className="input" value={system} disabled={!data.can_manage} onChange={(e) => setSystem(e.target.value)}>
          <option value="">Every source</option>
          {data.sources.map((s) => <option key={s} value={s}>{s}</option>)}
          {data.system && !data.sources.includes(data.system) && <option value={data.system}>{data.system}</option>}
        </select>
      </label>
      {err && <Callout tone="bad">{err}</Callout>}
      {data.can_manage && <div className="row" style={{ justifyContent: "flex-end" }}><Button type="submit" variant="primary" disabled={!changed || busy}>{busy ? "Saving…" : "Save source"}</Button></div>}
    </form>
  );
}
