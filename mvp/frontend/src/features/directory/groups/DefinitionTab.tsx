import { useState } from "react";
import { Plus, X } from "lucide-react";
import { GrpGroup, GrpList, groups } from "../../../api";
import { Button, Callout, Loading, useToast } from "../../../components";
import { ChangePreview } from "./ChangePreview";
import { GroupLink, OP_LABEL } from "./common";
import { useLoad } from "./hooks";
import { compositeChange, compositeExpression, compositeProblem } from "./model";

/**
 * The Definition tab. A basic group lists direct members and can be turned into a composite; a composite shows its
 * operator and factors as a set expression and can be edited. Saving shows the effect first.
 */
export function DefinitionTab({ g, canWrite }: { g: GrpGroup; canWrite: boolean }) {
  const toast = useToast();
  const composite = g.definition !== "basic";
  const [edit, setEdit] = useState(false);
  const [op, setOp] = useState<string>(g.composite_op ?? "complement");
  const [factors, setFactors] = useState<string[]>(g.factors ?? ["", ""]);
  const [discard, setDiscard] = useState(false);
  const [preview, setPreview] = useState(false);
  const { data: all } = useLoad<GrpList<GrpGroup>>(edit ? () => groups.listGroups({ limit: 500 }) : null, `defpick:${g.id}`);
  const names = useLoad(composite && g.factors?.length ? () => Promise.all(g.factors!.map((id) => groups.group(id).then((x) => x.name).catch(() => "a group you cannot see"))) : null, `factors:${g.id}:${(g.factors ?? []).join(",")}`);

  const problem = edit ? compositeProblem(op, factors, g.id) : null;
  const left = op === "complement";
  const label = (i: number) => (left ? (i === 0 ? "Members of" : "Except members of") : `Factor ${i + 1}`);
  const startEdit = () => {
    setOp(g.composite_op ?? "complement");
    setFactors(g.factors?.length ? g.factors : ["", ""]);
    setEdit(true);
  };
  const setFactor = (i: number, v: string) => setFactors(factors.map((f, j) => (j === i ? v : f)));

  return (
    <div className="stack">
      {g.definition === "policy" && (
        <Callout tone="info">This is a policy group: its membership is computed from a policy source kept in a repository. The source, its commit and the &ldquo;propose a change&rdquo; flow arrive with policy groups as code (GR-9).</Callout>
      )}
      {!edit && (
        <section className="stack-sm">
          <dl className="kv">
            <dt>Definition</dt><dd>{composite ? "Composite" : "Basic: members are listed directly"}</dd>
            {composite && <><dt>Operator</dt><dd>{OP_LABEL[g.composite_op ?? ""] ?? g.composite_op}</dd></>}
          </dl>
          {composite && (
            <>
              <h3 style={{ fontSize: "var(--fs-lg)" }}>Set expression</h3>
              {!names.data && g.factors?.length ? <Loading kind="block" error={names.error} /> : (
                <p className="sys" data-testid="expression">{compositeExpression(g.composite_op, names.data ?? [])}</p>
              )}
              <ol className="stack-sm" style={{ listStyle: "none", padding: 0 }} aria-label="Factors">
                {(g.factors ?? []).map((f, i) => (
                  <li key={f} className="row tight">
                    <span className="faint small" style={{ minWidth: 130 }}>{g.composite_op === "complement" ? (i === 0 ? "Members of" : "Except members of") : `Factor ${i + 1}`}</span>
                    <GroupLink id={f}>{names.data?.[i] ?? f}</GroupLink>
                  </li>
                ))}
              </ol>
            </>
          )}
          {canWrite && <Button onClick={startEdit}>{composite ? "Edit definition" : "Convert to composite"}</Button>}
        </section>
      )}
      {edit && (
        <form className="stack" onSubmit={(e) => { e.preventDefault(); if (!problem) setPreview(true); }}>
          <label className="field">
            <span>How the groups combine</span>
            <select className="input" value={op} onChange={(e) => { setOp(e.target.value); if (e.target.value === "complement") setFactors(factors.slice(0, 2).concat(["", ""]).slice(0, 2)); }}>
              {Object.entries(OP_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          {factors.map((f, i) => (
            <div key={i} className="row">
              <label className="field grow">
                <span>{label(i)}</span>
                <select className="input" value={f} onChange={(e) => setFactor(i, e.target.value)}>
                  <option value="">Select a group…</option>
                  {(all?.items ?? []).filter((x) => x.id !== g.id).map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
                </select>
              </label>
              {!left && factors.length > 2 && <Button variant="ghost" icon={<X size={16} />} label={`Remove factor ${i + 1}`} onClick={() => setFactors(factors.filter((_, j) => j !== i))} />}
            </div>
          ))}
          {!left && <div><Button icon={<Plus size={14} />} size="sm" onClick={() => setFactors([...factors, ""])}>Add a factor</Button></div>}
          {!composite && (
            <label className="row tight">
              <input type="checkbox" checked={discard} onChange={(e) => setDiscard(e.target.checked)} />
              <span>Discard the direct members this group has now (a composite cannot keep them; the conversion is refused while any remain)</span>
            </label>
          )}
          {problem && <Callout tone="bad">{problem}</Callout>}
          <div className="row">
            <Button onClick={() => setEdit(false)}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={!!problem}>Preview</Button>
          </div>
        </form>
      )}
      {preview && (
        <ChangePreview
          title={composite ? "Change the definition" : "Convert to a composite group"}
          changes={[compositeChange(g.id, op, factors, !composite, discard)]}
          confirmLabel="Save definition"
          onClose={() => setPreview(false)}
          onConfirm={async () => {
            if (composite) await groups.setComposite(g.id, { op, factors });
            else await groups.convertToComposite(g.id, { op, factors, discard_members: discard });
            toast("Definition saved");
            setEdit(false);
          }}
        />
      )}
    </div>
  );
}
