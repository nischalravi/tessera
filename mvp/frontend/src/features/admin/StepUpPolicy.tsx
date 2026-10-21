/**
 * Admin → Step-up (issue #298): which sensitive actions need a fresh sign-in, and how strong. The code's own
 * requirements are the floor: a setting here adds step-up to an action or tightens it, and never removes or
 * weakens what the code requires. Saving needs admin.change.request and a fresh phishing-resistant sign-in
 * within five minutes (the client asks for it), and is audited.
 */
import { FormEvent, useEffect, useState } from "react";
import { StepUpPolicyView, stepUpPolicy, stepUpPolicyPath, useApi } from "../../api";
import { Badge, Button, Callout, Loading, Page, useToast } from "../../components";
import { Drafts, acrLabel, draftsOf, entriesOf, requirementText, sameEntries, savedEntries } from "./stepUpModel";

function Form({ view, onSaved }: { view: StepUpPolicyView; onSaved: () => void }) {
  const toast = useToast();
  const [d, setD] = useState<Drafts>(draftsOf(view));
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setD(draftsOf(view)), [view.version]); // eslint-disable-line react-hooks/exhaustive-deps

  const { entries, problem } = entriesOf(view, d);
  const changed = !sameEntries(entries, savedEntries(view));
  const can = view.can_manage;
  const set = (action: string, patch: Partial<Drafts[string]>) => setD((p) => ({ ...p, [action]: { ...p[action], ...patch } }));
  const rows = view.actions.filter((a) => a.action.includes(q.trim().toLowerCase()));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || !changed || busy || !can) return;
    setBusy(true);
    setErr(null);
    try {
      await stepUpPolicy.save(view.version, entries);
      toast("Step-up settings saved");
      onSaved();
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card stack" onSubmit={submit} aria-label="Step-up per action">
      {!can && <Callout tone="neutral">You can read these settings. A tenant admin changes them.</Callout>}
      {view.allow_weaker && <Callout tone="warn">This deployment lets a setting go below the code's requirement (TESSERA_STEPUP_ALLOW_WEAKER). Production refuses that.</Callout>}
      <Callout tone="neutral">
        What the code requires today is the floor. A setting adds step-up to an action that has none, or makes it stricter. It never removes or weakens the floor.
        The action is the permission it needs, and the setting covers its state-changing calls (reading is never held up). Machine clients cannot step up, so an action with a setting refuses them.
      </Callout>
      <label className="field" style={{ maxWidth: 320 }}>Find an action
        <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="catalog, sod, connections…" />
      </label>
      <div className="table-scroll">
        <table>
          <thead><tr><th>Action</th><th>The code requires</th><th>Your setting</th><th className="hide-narrow">Applies</th></tr></thead>
          <tbody>
            {rows.map((a) => {
              const row = d[a.action] ?? { acr: "", minutes: "" };
              return (
                <tr key={a.action}>
                  <td><b className="sys">{a.action}</b><div className="xs faint">{a.routes} call{a.routes === 1 ? "" : "s"}{a.unguarded && a.floor ? ", some with no step-up" : ""}</div></td>
                  <td className="small">{requirementText(a.floor)}</td>
                  <td>
                    <div className="row tight">
                      <select className="input" aria-label={`Level for ${a.action}`} value={row.acr} disabled={!can} onChange={(e) => set(a.action, { acr: e.target.value, minutes: row.minutes || String((a.floor?.max_age_s ?? 300) / 60) })}>
                        <option value="">No setting</option>
                        {view.acrs.map((x) => <option key={x} value={x}>{acrLabel(x)}</option>)}
                      </select>
                      {row.acr && (
                        <label className="row tight small">within
                          <input className="input" aria-label={`Minutes for ${a.action}`} inputMode="decimal" value={row.minutes} disabled={!can} style={{ width: 70 }} onChange={(e) => set(a.action, { minutes: e.target.value })} /> min
                        </label>
                      )}
                    </div>
                  </td>
                  <td className="small hide-narrow">
                    {requirementText(a.effective)} {a.policy && <Badge tone="info">Set</Badge>}
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && <tr><td colSpan={4} className="faint">No action matches.</td></tr>}
          </tbody>
        </table>
      </div>
      {problem && changed && <p className="small" role="alert">{problem}</p>}
      {err && <Callout tone="bad">{err}</Callout>}
      {can && (
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <Button type="submit" variant="primary" disabled={!!problem || !changed || busy}>{busy ? "Saving…" : "Save settings"}</Button>
        </div>
      )}
    </form>
  );
}

export function StepUpPolicy() {
  const { data, error, reload } = useApi<StepUpPolicyView>(stepUpPolicyPath);
  return (
    <Page title="Step-up per action" crumbs={[["Settings"], ["Admin", "/admin"], ["Step-up"]]}
      sub="Choose which sensitive actions need a fresh sign-in and at what assurance level. The requirements built into Tessera stay as the minimum.">
      {!data ? <Loading kind="block" error={error} what="step-up settings" /> : <Form view={data} onSaved={reload} />}
    </Page>
  );
}
