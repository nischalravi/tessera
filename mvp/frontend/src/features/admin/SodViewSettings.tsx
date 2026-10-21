/**
 * Admin → SoD page (issue #298): which optional columns and filters SoD reviewers see on the conflicts page.
 * It is a display choice for the whole tenant, not an access control: the person, priority, status and
 * system are always shown. Saving needs sod.manage and a fresh phishing-resistant sign-in, and is audited.
 */
import { FormEvent, useEffect, useState } from "react";
import { SodViewKey, SodViewView, sodView, sodViewPath, useApi } from "../../api";
import { Button, Callout, Loading, Page, useToast } from "../../components";
import { SOD_VIEW_LABEL, sameKeys, sodViewProblem } from "../insights/sodViewModel";

function Form({ view, onSaved }: { view: SodViewView; onSaved: () => void }) {
  const toast = useToast();
  const [cols, setCols] = useState<SodViewKey[]>(view.columns);
  const [filters, setFilters] = useState<SodViewKey[]>(view.filters);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setCols(view.columns);
    setFilters(view.filters);
  }, [view.version]); // eslint-disable-line react-hooks/exhaustive-deps
  const can = view.can_manage;
  const problem = sodViewProblem(cols);
  const changed = !sameKeys(cols, view.columns) || !sameKeys(filters, view.filters);
  const toggle = (list: SodViewKey[], set: (l: SodViewKey[]) => void, k: SodViewKey, on: boolean) =>
    set(view.available.filter((x) => (x === k ? on : list.includes(x))));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || !changed || busy || !can) return;
    setBusy(true);
    setErr(null);
    try {
      await sodView.save(view.version, { columns: cols, filters });
      toast("SoD page settings saved");
      onSaved();
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const group = (title: string, list: SodViewKey[], set: (l: SodViewKey[]) => void, hint: string) => (
    <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
      <legend><h2>{title}</h2></legend>
      <p className="xs faint">{hint}</p>
      {view.available.map((k) => (
        <label key={k} className="row small">
          <input type="checkbox" checked={list.includes(k)} onChange={(e) => toggle(list, set, k, e.target.checked)} /> {SOD_VIEW_LABEL[k]}
        </label>
      ))}
    </fieldset>
  );

  return (
    <form className="card stack" onSubmit={submit} aria-label="SoD page configuration">
      {!can && <Callout tone="neutral">You can read these settings. A policy admin changes them.</Callout>}
      {view.version === 0 && <Callout tone="neutral">Nothing saved yet: reviewers see every column and filter.</Callout>}
      {group("Columns", cols, setCols, "Shown on the conflicts table, next to the person, priority, system and status.")}
      {group("Filters", filters, setFilters, "Offered as filter chips above the table, next to priority, system and status.")}
      {problem && <p className="small" role="alert">{problem}</p>}
      {err && <Callout tone="bad">{err}</Callout>}
      {can && (
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <Button type="submit" variant="primary" disabled={!!problem || !changed || busy}>{busy ? "Saving…" : "Save settings"}</Button>
        </div>
      )}
    </form>
  );
}

export function SodViewSettings() {
  const { data, error, reload } = useApi<SodViewView>(sodViewPath);
  return (
    <Page title="SoD page" crumbs={[["Settings"], ["Admin", "/admin"], ["SoD page"]]}
      sub="Choose which columns and filters reviewers see on the SoD conflicts page: risk, function, entitlement, ruleset, mitigating control and business process.">
      {!data ? <Loading kind="block" error={error} what="SoD page settings" /> : <Form view={data} onSaved={reload} />}
    </Page>
  );
}
