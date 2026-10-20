import { useEffect, useState } from "react";
import { ApiError, SimChange, SimulationResult, groups } from "../../../api";
import { Button, Callout, Drawer, Loading } from "../../../components";
import { errText } from "./hooks";
import { summarizeSimulation } from "./model";

/**
 * Every save of a membership change, composite definition or privilege shows what it would do first
 * (design §10.13): the simulation runs the real operations and rolls them back, so nothing is written
 * until the person confirms here. `onConfirm` makes the real change; it throws to keep the dialog open.
 */
export function ChangePreview({ title, changes, confirmLabel = "Apply change", onConfirm, onClose, danger }: {
  title: string;
  changes: SimChange[];
  confirmLabel?: string;
  onConfirm: () => Promise<unknown>;
  onClose: () => void;
  danger?: boolean;
}) {
  const [res, setRes] = useState<SimulationResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tooBig, setTooBig] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saveErr, setSaveErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    groups.simulate(changes)
      .then((r) => alive && setRes(r))
      .catch((e) => {
        if (!alive) return;
        setErr(errText(e));
        setTooBig(e instanceof ApiError && e.body?.error === "simulation_too_large");
      });
    return () => {
      alive = false;
    };
    // the preview is of the changes it was opened with
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const sum = res ? summarizeSimulation(res) : null;
  const run = async () => {
    setBusy(true);
    setSaveErr(null);
    try {
      await onConfirm();
      onClose();
    } catch (e) {
      setSaveErr(errText(e));
      setBusy(false);
    }
  };
  const ready = !!res || tooBig;
  return (
    <Drawer
      title={title}
      sub="Preview: nothing is saved until you apply the change."
      onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant={danger ? "danger" : "primary"} onClick={run} disabled={!ready || busy}>{busy ? "Applying…" : confirmLabel}</Button></>}
    >
      <div className="stack" aria-live="polite">
        {!res && !err && <Loading kind="block" />}
        {err && <Callout tone={tooBig ? "warn" : "bad"}>{tooBig ? `This change is too large to preview (${err}). You can still apply it.` : `The change cannot be applied: ${err}`}</Callout>}
        {sum && (
          <>
            <p data-testid="preview-headline"><strong>{sum.headline}</strong></p>
            {sum.noEffect && <Callout tone="neutral">This change does not alter who is a member of any group.</Callout>}
            {sum.truncated && <Callout tone="warn">The change touches more than the preview can read back, so these counts are lower bounds.</Callout>}
            {sum.groups.length > 0 && (
              <div className="table-scroll">
                <table>
                  <caption className="sr-only">Groups whose members change</caption>
                  <thead><tr><th scope="col">Group</th><th scope="col" className="num">Now</th><th scope="col" className="num">After</th><th scope="col" className="num">Change</th></tr></thead>
                  <tbody>
                    {sum.groups.map((g) => (
                      <tr key={g.id}>
                        <td><span className="sys">{g.name}</span>{!g.targeted && <span className="faint small"> (downstream)</span>}</td>
                        <td className="num">{g.before.toLocaleString("en-US")}</td>
                        <td className="num">{g.after.toLocaleString("en-US")}</td>
                        <td className="num">{g.delta}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {res?.groups.filter((g) => g.targeted).map((g) => (g.added_sample.length || g.removed_sample.length) ? (
              <div key={g.group_id} className="small">
                <strong>{g.name}</strong>
                {g.added_sample.length > 0 && <div>Joins: {g.added_sample.map((m) => m.name).join(", ")}{g.added > g.added_sample.length ? `, and ${g.added - g.added_sample.length} more` : ""}</div>}
                {g.removed_sample.length > 0 && <div>Leaves: {g.removed_sample.map((m) => m.name).join(", ")}{g.removed > g.removed_sample.length ? `, and ${g.removed - g.removed_sample.length} more` : ""}</div>}
              </div>
            ) : null)}
          </>
        )}
        {saveErr && <Callout tone="bad">{saveErr}</Callout>}
      </div>
    </Drawer>
  );
}
