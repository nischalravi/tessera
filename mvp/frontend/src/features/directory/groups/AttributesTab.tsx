import { FormEvent, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { AttrAssignment, AttrDef, AttrName, groups } from "../../../api";
import { Badge, Button, Callout, Drawer, EmptyState, Loading, useConfirm, useToast } from "../../../components";
import { fmtWhen } from "./common";
import { errText, useLoad } from "./hooks";
import { parseAttrValue } from "./model";

type Kind = "group" | "folder";

/**
 * Attributes of a group or folder: its object types (with the lint findings of the group), and the attribute
 * assignments on it. Each change needs the privileges the server names in its refusal.
 */
export function AttributesTab({ kind, id, name, canWrite }: { kind: Kind; id: string; name: string; canWrite: boolean }) {
  const toast = useToast();
  const confirm = useConfirm();
  const types = useLoad(() => groups.objectTypes(kind, id), `otypes:${kind}:${id}`);
  const list = useLoad(() => groups.assignments(kind, id), `assigns:${kind}:${id}`);
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);

  const current = draft ?? types.data?.types ?? [];
  const toggle = (t: string) => setDraft(current.includes(t) ? current.filter((x) => x !== t) : [...current, t]);
  const saveTypes = async () => {
    setBusy(true);
    try {
      await groups.setObjectTypes(kind, id, current);
      setDraft(null);
      toast("Object types saved");
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const remove = async (a: AttrAssignment) => {
    const ok = await confirm({ title: "Remove this attribute?", body: `${a.name} will be removed from ${name}.`, confirmLabel: "Remove", danger: true });
    if (ok === null) return;
    try {
      await groups.unassign(a.id);
      toast("Attribute removed");
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };

  return (
    <div className="stack">
      <section className="stack-sm">
        <h3 style={{ fontSize: "var(--fs-lg)" }}>Object types</h3>
        <p className="small faint">Types classify {kind === "group" ? "a group" : "a folder"} (for example reference, policy or application) and drive the checks below.</p>
        {!types.data && <Loading error={types.error} kind="block" />}
        {types.data && (
          <fieldset className="row" style={{ border: 0, padding: 0, margin: 0 }} disabled={!canWrite}>
            <legend className="sr-only">Object types</legend>
            {types.data.vocabulary.map((t) => (
              <label key={t} className="row tight fchip" style={{ cursor: canWrite ? "pointer" : "default" }}>
                <input type="checkbox" checked={current.includes(t)} onChange={() => toggle(t)} />
                {t}
              </label>
            ))}
          </fieldset>
        )}
        {draft && <div className="row"><Button variant="primary" onClick={saveTypes} disabled={busy}>Save types</Button><Button onClick={() => setDraft(null)}>Discard</Button></div>}
        {types.data?.lint.map((f) => <Callout key={f.rule} tone={f.severity === "info" ? "info" : "warn"}>{f.message}</Callout>)}
      </section>

      <section className="stack-sm">
        <div className="spread">
          <h3 style={{ fontSize: "var(--fs-lg)" }}>Attribute assignments</h3>
          {canWrite && <Button icon={<Plus size={14} />} onClick={() => setAdding(true)}>Assign an attribute</Button>}
        </div>
        {!list.data && <Loading error={list.error} kind="block" />}
        {list.data && list.data.items.length === 0 && <EmptyState title="No attributes assigned">Attributes add structured information, such as an owner or a limit, to {name}.</EmptyState>}
        {list.data && list.data.items.length > 0 && (
          <div className="table-scroll">
            <table>
              <caption className="sr-only">Attribute assignments on {name}</caption>
              <thead><tr><th scope="col">Attribute</th><th scope="col">Action</th><th scope="col">Values</th><th scope="col">Active</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {list.data.items.map((a) => (
                  <tr key={a.id}>
                    <td><span className="sys">{a.name}</span>{a.disallowed && <> <Badge tone="warning">Disallowed</Badge></>}</td>
                    <td>{a.action}</td>
                    <td>{a.values.length ? a.values.join(", ") : <span className="faint">No value</span>}</td>
                    <td>{a.active ? "Yes" : "No"}{a.disabled_at && <span className="faint small"> until {fmtWhen(a.disabled_at)}</span>}</td>
                    <td>{canWrite && <Button size="sm" variant="ghost" icon={<Trash2 size={14} />} label={`Remove ${a.name}`} onClick={() => remove(a)} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {adding && <AssignDrawer kind={kind} id={id} name={name} onClose={() => setAdding(false)} />}
    </div>
  );
}

function AssignDrawer({ kind, id, name, onClose }: { kind: Kind; id: string; name: string; onClose: () => void }) {
  const toast = useToast();
  const names = useLoad(() => groups.attrNames(), "attrnames");
  const defs = useLoad(() => groups.attrDefs(), "attrdefs");
  const [nameId, setNameId] = useState("");
  const [action, setAction] = useState("assign");
  const [value, setValue] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const picked: AttrName | undefined = names.data?.items.find((n) => n.id === nameId);
  const def: AttrDef | undefined = defs.data?.items.find((d) => d.id === picked?.def_id);
  const valueType = def?.value_type ?? "marker";
  const parsed = valueType === "marker" ? {} : parseAttrValue(valueType, value);
  const ready = !!picked && !!action.trim() && (valueType === "marker" || parsed.value !== undefined);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!picked || !ready) return;
    setBusy(true);
    setErr(null);
    try {
      await groups.assign({ name: picked.name, action: action.trim(), owner_type: kind, owner: id, ...(parsed.value !== undefined ? { values: [parsed.value] } : {}) });
      toast("Attribute assigned");
      onClose();
    } catch (x) {
      setErr(errText(x));
      setBusy(false);
    }
  };
  return (
    <Drawer title="Assign an attribute" sub={name} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="assign" variant="primary" disabled={!ready || busy}>{busy ? "Assigning…" : "Assign"}</Button></>}>
      <form id="assign" className="stack" onSubmit={submit}>
        {(names.error || defs.error) && <Callout tone="bad">{names.error ?? defs.error}</Callout>}
        <label className="field">
          <span>Attribute</span>
          <select className="input" value={nameId} onChange={(e) => { setNameId(e.target.value); setValue(""); }} data-autofocus>
            <option value="">Select…</option>
            {(names.data?.items ?? []).map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
          </select>
        </label>
        {def && <p className="small faint">Type: {def.attr_type}, value: {def.value_type}{def.multi_valued ? " (several allowed)" : ""}. {def.description}</p>}
        <label className="field"><span>Action</span><input className="input" value={action} onChange={(e) => setAction(e.target.value)} /></label>
        {valueType !== "marker" && (
          <label className="field">
            <span>Value ({valueType})</span>
            <input className="input" value={value} onChange={(e) => setValue(e.target.value)} />
            {value && parsed.problem && <span className="hint">{parsed.problem}</span>}
          </label>
        )}
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}
