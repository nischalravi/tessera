import { FormEvent, useEffect, useState } from "react";
import { CatalogView, IdentityRow, Risk, StageKind, putCatalogItem, useApi } from "../../api";
import { Badge, Button, Callout } from "../../components";
import { useToast } from "../../components/Toast";

/**
 * A group's request-catalog settings (issue #164): whether people can request it, its risk,
 * who is eligible and how long access lasts. Everyone sees them; holders of catalog.manage
 * edit them (the API also asks for a fresh phishing-resistant sign-in).
 */
const TYPES: [string, string][] = [["human", "People"], ["service", "Service accounts"], ["ai_agent", "AI agents"]];
const STAGES: [StageKind, string][] = [["manager", "The person's manager"], ["owner", "The item's owner"], ["decider", "An access approver (requests.decide)"]];
const hrs = (h: number | null) => (h == null ? "" : String(h));
const num = (s: string) => (s.trim() === "" ? null : Number(s));

export function CatalogSettings({ groupId, privileged }: { groupId: number; privileged: boolean }) {
  const first = useApi<CatalogView>("/catalog");
  const manage = !!first.data?.can_manage;
  const full = useApi<CatalogView>(manage ? "/catalog?all=1" : null);
  const view = manage ? full.data : first.data;
  const entry = view?.items.find((c) => c.group.id === groupId);
  const toast = useToast();
  const [requestable, setRequestable] = useState(true);
  const [risk, setRisk] = useState<Risk>("low");
  const [description, setDescription] = useState("");
  const [types, setTypes] = useState<string[]>([]);
  const [depts, setDepts] = useState("");
  const [def, setDef] = useState("");
  const [max, setMax] = useState("");
  const [stages, setStages] = useState<StageKind[]>(["decider"]);
  const [escalate, setEscalate] = useState("48");
  const [owner, setOwner] = useState("");
  const people = useApi<IdentityRow[]>(manage ? "/identities?type=human" : null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!entry) return;
    setRequestable(entry.id ? entry.requestable : true);
    setRisk(entry.id ? entry.risk : privileged ? "high" : "low");
    setDescription(entry.id ? entry.description : "");
    setTypes(entry.eligible_types);
    setDepts(entry.eligible_departments.join(", "));
    setDef(hrs(entry.default_hours));
    setMax(hrs(entry.max_hours));
    setStages(entry.approval.stages);
    setEscalate(String(entry.approval.escalate_after_hours));
    setOwner(entry.owner ? String(entry.owner.id) : "");
  }, [entry, privileged]);

  if (!view) return <p className="small muted">{first.error?.message ?? "Loading…"}</p>;
  if (!manage) {
    if (!entry) return <p className="small muted">Not in the request catalog. Ask a policy admin to make it requestable.</p>;
    return (
      <dl className="kv">
        <dt>Requestable</dt><dd>Yes</dd>
        <dt>Risk</dt><dd><Badge tone={entry.risk === "high" ? "warning" : "outline"}>{entry.risk}</Badge></dd>
        <dt>Duration</dt><dd>{entry.default_hours ? `${entry.default_hours} h by default` : "Until removed"}{entry.max_hours ? `, at most ${entry.max_hours} h` : ""}</dd>
        <dt>Who can ask</dt><dd>{[entry.eligible_types.join(", "), entry.eligible_departments.join(", ")].filter(Boolean).join(" in ") || "Anyone"}</dd>
        <dt>Owner</dt><dd>{entry.owner?.name ?? "None"}</dd>
        <dt>Approval</dt><dd>{entry.approval.stages.map((k) => STAGES.find(([v]) => v === k)?.[1] ?? k).join(", then ")}</dd>
      </dl>
    );
  }
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await putCatalogItem(groupId, {
        requestable, risk, description, owner_identity_id: owner ? Number(owner) : null, eligible_types: types,
        eligible_departments: depts.split(",").map((d) => d.trim()).filter(Boolean), default_hours: num(def), max_hours: num(max),
        approval_stages: stages, escalate_after_hours: Number(escalate),
      });
      toast("Catalog settings saved");
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="stack" onSubmit={save}>
      {!entry?.id && <Callout tone="neutral">Not in the request catalog yet. Saving adds it.</Callout>}
      <label className="row tight small"><input type="checkbox" checked={requestable} onChange={(e) => setRequestable(e.target.checked)} /> People can request this</label>
      <label className="field">Risk
        <select className="input" value={risk} onChange={(e) => setRisk(e.target.value as Risk)}>
          <option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option>
        </select>
      </label>
      <label className="field">Description shown in the catalog
        <textarea className="input" value={description} maxLength={1000} onChange={(e) => setDescription(e.target.value)} />
      </label>
      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="small strong">Who can be given it (none ticked: anyone)</legend>
        {TYPES.map(([v, l]) => (
          <label key={v} className="row tight small"><input type="checkbox" checked={types.includes(v)} onChange={(e) => setTypes(e.target.checked ? [...types, v] : types.filter((t) => t !== v))} /> {l}</label>
        ))}
      </fieldset>
      <label className="field">Departments (comma-separated; empty: any)
        <input className="input" value={depts} onChange={(e) => setDepts(e.target.value)} placeholder="Finance, Engineering" />
      </label>
      <div className="row">
        <label className="field" style={{ flex: 1 }}>Default hours
          <input className="input" inputMode="decimal" value={def} onChange={(e) => setDef(e.target.value)} placeholder="Until removed" />
        </label>
        <label className="field" style={{ flex: 1 }}>Maximum hours
          <input className="input" inputMode="decimal" value={max} onChange={(e) => setMax(e.target.value)} placeholder="No limit" />
        </label>
      </div>
      {privileged && <span className="small muted">Privileged access needs a default duration.</span>}
      <label className="field">Owner
        <select className="input" value={owner} onChange={(e) => setOwner(e.target.value)}>
          <option value="">No owner</option>
          {(people.data ?? []).filter((p) => p.status === "active").map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </label>
      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="small strong">Approved by, in this order</legend>
        {STAGES.map(([v, l]) => (
          <label key={v} className="row tight small">
            <input type="checkbox" checked={stages.includes(v)} onChange={(e) => setStages(STAGES.map(([k]) => k).filter((k) => (k === v ? e.target.checked : stages.includes(k))))} /> {l}
          </label>
        ))}
        {stages.length === 0 && <span className="small" style={{ color: "var(--critical)" }}>Pick at least one stage.</span>}
      </fieldset>
      <label className="field">Escalate a waiting stage to access approvers after (hours)
        <input className="input" inputMode="decimal" value={escalate} onChange={(e) => setEscalate(e.target.value)} />
        <span className="hint">A stage with no manager or owner who signs in escalates at once.</span>
      </label>
      {error && <Callout tone="bad">{error}</Callout>}
      <div className="row"><Button type="submit" variant="primary" disabled={busy || stages.length === 0}>{busy ? "Saving…" : "Save"}</Button></div>
    </form>
  );
}
