import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { DeletionGuardView, DeletionMode, DeletionPolicy, DeletionPolicyInput, DeletionSourceRow, deletionGuard, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, useToast } from "../../components";
import { errText, outcome } from "./common";
import { CATEGORY_HELP, CATEGORY_LABEL, MODE_LABEL, PolicyEdit, SOURCE_KIND_LABEL, checkEdit, editOf, inputOf, looksLooser, sourceLink, thresholdText, usageRatio, windowText } from "./deletionGuardModel";

/**
 * Admin → Deletion guard: the threshold window that stops a mistake (a bad admin action, a bad source feed, a
 * misconfigured connector or loader) from deleting everything. Past a category's threshold in the window,
 * Tessera applies only up to it, holds the rest and alerts; a second admin releases or discards the rest
 * (Admin → Held deletions). Tightening a setting is one admin's change; loosening one needs a second admin.
 */
export function DeletionGuard() {
  const { data, error, reload } = useApi<DeletionGuardView>("/admin/deletion-guard");
  const { can } = useSession();
  const toast = useToast();
  const [edits, setEdits] = useState<Record<string, PolicyEdit>>({});
  const [hours, setHours] = useState("");
  const [busy, setBusy] = useState(false);
  if (error) return <Callout tone="bad">{error.message}</Callout>;
  if (!data) return <div className="card"><p className="small muted" style={{ margin: 0 }}>Loading…</p></div>;

  const allowed = can("admin.change.request");
  const changes: { p: DeletionPolicy; input: DeletionPolicyInput }[] = [];
  const errors: Record<string, string> = {};
  for (const p of data.categories) {
    const e = edits[p.category];
    if (!e) continue;
    const err = checkEdit(e);
    if (err) errors[p.category] = err;
    else {
      const input = inputOf(p, e);
      if (input) changes.push({ p, input });
    }
  }
  const hoursErr = hours.trim() !== "" && !(/^\d{1,4}$/.test(hours.trim()) && Number(hours) >= 1 && Number(hours) <= 8760) ? "Hold expiry is 1 to 8760 hours." : null;
  const expiry = hours.trim() !== "" && !hoursErr && Number(hours) !== data.hold_expiry_hours ? Number(hours) : undefined;
  const loosening = changes.filter((c) => looksLooser(c.p, c.input));
  const nothing = changes.length === 0 && expiry === undefined;

  const set = (p: DeletionPolicy, patch: Partial<PolicyEdit>) => setEdits({ ...edits, [p.category]: { ...(edits[p.category] ?? editOf(p)), ...patch } });
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (nothing || Object.keys(errors).length || hoursErr) return;
    setBusy(true);
    try {
      toast(outcome(await deletionGuard.change(changes.map((c) => c.input), expiry)));
      setEdits({});
      setHours("");
      reload?.();
    } catch (err) {
      toast(errText(err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <Callout tone="ok">
        Protection is on for every category. When deletions in a category pass the threshold within its window, Tessera applies only up to the threshold,
        holds the rest, raises an alert and waits for a second admin.{" "}
        {data.open_holds > 0
          ? <><b>{data.open_holds} held {data.open_holds === 1 ? "deletion is" : "deletions are"} waiting.</b> <Link to="/admin/held-deletions">Open held deletions</Link></>
          : <Link to="/admin/held-deletions">Held deletions</Link>}
      </Callout>
      <form className="card stack-sm" onSubmit={submit} aria-label="Deletion thresholds">
        <h2>Thresholds</h2>
        <p className="small muted" style={{ margin: 0 }}>
          The window slides: it counts what was deleted in the last period, whoever did it. A percent is of the tenant's size in that category, and never less than 5 deletions.
          When both a count and a percent are set, the lower applies.
        </p>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th scope="col">Category</th><th scope="col">Now</th><th scope="col">Window use</th>
                <th scope="col">Count</th><th scope="col">Percent</th><th scope="col">Window (min)</th><th scope="col">When over</th>
              </tr>
            </thead>
            <tbody>
              {data.categories.map((p) => {
                const e = edits[p.category] ?? editOf(p);
                const err = errors[p.category];
                const id = `dg-${p.category}`;
                const ratio = usageRatio(p);
                return (
                  <tr key={p.category}>
                    <th scope="row">
                      <b>{CATEGORY_LABEL[p.category]}</b> {p.default ? <Badge>Default</Badge> : <Badge tone="info">Set</Badge>}
                      <div className="xs faint" style={{ fontWeight: 400, maxWidth: 260 }}>{CATEGORY_HELP[p.category]}</div>
                    </th>
                    <td className="small">{thresholdText(p)}</td>
                    <td className="small">
                      <div className="tnum">{p.limit === null ? `${p.used} used` : `${p.used} of ${p.limit}`} {windowText(p.window_minutes)}</div>
                      {p.limit !== null && (
                        <div role="progressbar" aria-label={`${CATEGORY_LABEL[p.category]} window use`} aria-valuemin={0} aria-valuemax={p.limit} aria-valuenow={Math.min(p.used, p.limit)}
                          style={{ height: 6, width: 110, background: "var(--border, #d0d5dd)", borderRadius: 3 }}>
                          <div style={{ height: 6, width: `${Math.round(ratio * 110)}px`, background: ratio >= 1 ? "var(--critical-text, #b42318)" : "var(--accent, #175cd3)", borderRadius: 3 }} />
                        </div>
                      )}
                    </td>
                    <td><input className="input tnum" style={{ width: 90 }} inputMode="numeric" aria-label={`${CATEGORY_LABEL[p.category]}: count`} aria-invalid={err ? true : undefined} aria-describedby={err ? `${id}-err` : undefined}
                      value={e.max_count} disabled={!allowed} onChange={(ev) => set(p, { max_count: ev.target.value })} /></td>
                    <td><input className="input tnum" style={{ width: 80 }} inputMode="decimal" aria-label={`${CATEGORY_LABEL[p.category]}: percent`} aria-invalid={err ? true : undefined}
                      value={e.max_percent} disabled={!allowed} onChange={(ev) => set(p, { max_percent: ev.target.value })} /></td>
                    <td><input className="input tnum" style={{ width: 80 }} inputMode="numeric" aria-label={`${CATEGORY_LABEL[p.category]}: window in minutes`} aria-invalid={err ? true : undefined}
                      value={e.window_minutes} disabled={!allowed} onChange={(ev) => set(p, { window_minutes: ev.target.value })} /></td>
                    <td>
                      <select className="input" aria-label={`${CATEGORY_LABEL[p.category]}: when over the threshold`} value={e.mode} disabled={!allowed}
                        onChange={(ev) => set(p, { mode: ev.target.value as DeletionMode })}>
                        {(Object.keys(MODE_LABEL) as DeletionMode[]).map((m) => <option key={m} value={m}>{MODE_LABEL[m]}</option>)}
                      </select>
                      {err && <div id={`${id}-err`} className="xs" role="alert" style={{ color: "var(--critical-text, #b42318)" }}>{err}</div>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <label className="stack-sm" style={{ maxWidth: 360 }}>
          <span className="small"><b>Hold expiry (hours)</b>: a held deletion nobody decides on is discarded after this long. Now {data.hold_expiry_hours} hours.</span>
          <input className="input tnum" style={{ width: 110 }} inputMode="numeric" aria-label="Hold expiry in hours" aria-invalid={hoursErr ? true : undefined} placeholder={String(data.hold_expiry_hours)}
            value={hours} disabled={!allowed} onChange={(ev) => setHours(ev.target.value)} />
          {hoursErr && <span className="xs" role="alert" style={{ color: "var(--critical-text, #b42318)" }}>{hoursErr}</span>}
        </label>
        {loosening.length > 0 && (
          <Callout tone="warn">
            {loosening.map((c) => CATEGORY_LABEL[c.p.category]).join(", ")} would be set looser than now. Loosening a safety setting needs a second admin to approve it, with a fresh passkey sign-in.
            Tightening needs only you.
          </Callout>
        )}
        {!allowed && <p className="small muted" style={{ margin: 0 }}>Your role can read these settings but not request a change.</p>}
        <div className="row wrap" style={{ gap: 8 }}>
          <Button type="submit" variant="primary" disabled={!allowed || busy || nothing || Object.keys(errors).length > 0 || !!hoursErr}>
            {loosening.length > 0 ? "Request change" : "Save"}
          </Button>
          {!nothing && <Button type="button" size="sm" onClick={() => { setEdits({}); setHours(""); }}>Clear</Button>}
          <Link className="small" to="/admin/change-requests">Change requests</Link>
        </div>
      </form>
      <SourceList rows={data.sources ?? []} />
    </div>
  );
}

/** The sources that have their own threshold or feed checks; each is edited on its own settings page. */
function SourceList({ rows }: { rows: DeletionSourceRow[] }) {
  return (
    <section className="card stack-sm" aria-label="Sources with their own settings">
      <h2>Sources with their own settings</h2>
      <p className="small muted" style={{ margin: 0 }}>
        A connection, group loader or contractor feed can carry its own threshold and feed checks. Edit them on the source's own page: a connection's settings,
        a loader's Source tab, a contractor feed's settings.
      </p>
      {rows.length === 0 ? <p className="small muted" style={{ margin: 0 }}>No source has settings of its own. Each uses the thresholds above and the default feed checks.</p> : (
        <div className="table-scroll">
          <table>
            <caption className="sr-only">Sources with their own deletion guard settings</caption>
            <thead><tr><th scope="col">Source</th><th scope="col">Category</th><th scope="col">Threshold</th><th scope="col">Feed checks</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.kind}:${r.source_id}:${r.category}`}>
                  <th scope="row">
                    <Link to={sourceLink(r.kind, r.source_id)}>{r.name || r.source_id}</Link>
                    <div className="xs faint" style={{ fontWeight: 400 }}>{SOURCE_KIND_LABEL[r.kind]}</div>
                  </th>
                  <td>{CATEGORY_LABEL[r.category]}</td>
                  <td className="small">{r.mode ? `${MODE_LABEL[r.mode]}: ${thresholdText({ ...r.effective, limit: null })}` : "The category's"}</td>
                  <td className="small">Drop limit {r.effective.feed.drop_percent}%, empty feed {r.effective.feed.empty_check ? "held" : "not held on its own"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
