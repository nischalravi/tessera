import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { DeletionMode, DeletionSourceInput, DeletionSourceKind, DeletionSourceView, deletionGuard, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, useToast } from "../../components";
import { errText, outcome } from "./common";
import { CATEGORY_LABEL, MODE_LABEL, SourceEdit, checkSourceEdit, sourceEditOf, sourceInputOf, sourceLooksLooser, thresholdText } from "./deletionGuardModel";

/**
 * The deletion guard settings of one source (a connection, a group loader, a contractor feed): its own threshold
 * per category in place of the category's, and its feed checks (how far its record count may fall against its last
 * good run, and whether an empty feed is held). Changes go through the same admin change request as the category
 * thresholds: tightening needs one admin, loosening a second one.
 */
export function SourceDeletionGuard({ kind, id, heading = "Deletion guard" }: { kind: DeletionSourceKind; id: string; heading?: string }) {
  const { can } = useSession();
  return can("admin.read") ? <SourceSettings kind={kind} id={id} heading={heading} /> : null;
}

function SourceSettings({ kind, id, heading }: { kind: DeletionSourceKind; id: string; heading: string }) {
  const { data, error, reload } = useApi<DeletionSourceView>(deletionGuard.sourcePath(kind, id));
  const { can } = useSession();
  const toast = useToast();
  const [edits, setEdits] = useState<Record<string, SourceEdit>>({});
  const [busy, setBusy] = useState(false);
  if (error) return <Callout tone="bad">{error.message}</Callout>;
  if (!data) return <p className="small muted">Loading deletion guard settings…</p>;

  const allowed = can("admin.change.request");
  const changes: DeletionSourceInput[] = [];
  const errors: Record<string, string> = {};
  const looser: string[] = [];
  for (const c of data.categories) {
    const e = edits[c.category];
    if (!e) continue;
    const err = checkSourceEdit(e);
    if (err) { errors[c.category] = err; continue; }
    const input = sourceInputOf(kind, id, c, e);
    if (!input) continue;
    changes.push(input);
    if (sourceLooksLooser(c, input, data.feed_defaults.drop_percent)) looser.push(CATEGORY_LABEL[c.category]);
  }
  const bad = Object.keys(errors).length > 0;
  const set = (cat: string, patch: Partial<SourceEdit>) => {
    const c = data.categories.find((x) => x.category === cat)!;
    setEdits({ ...edits, [cat]: { ...(edits[cat] ?? sourceEditOf(c)), ...patch } });
  };
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (!changes.length || bad) return;
    setBusy(true);
    try {
      toast(outcome(await deletionGuard.change([], undefined, changes)));
      setEdits({});
      reload?.();
    } catch (err) {
      toast(errText(err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card stack-sm" onSubmit={submit} aria-label={`Deletion guard for ${data.name}`}>
      <h2>{heading}</h2>
      <p className="small muted" style={{ margin: 0 }}>
        What this source may remove in a window, and when its feed is not trusted. A source with no setting of its own uses the category's threshold
        (<Link to="/admin/deletion-guard">Admin → Deletion guard</Link>) and the default feed checks: held when the record count falls more than {data.feed_defaults.drop_percent}%
        against the last good run, or the feed is empty.
      </p>
      {data.categories.map((c) => {
        const e = edits[c.category] ?? sourceEditOf(c);
        const err = errors[c.category];
        const id0 = `dgs-${c.category}`;
        const own = e.mode !== "inherit";
        return (
          <fieldset key={c.category} className="stack-sm" style={{ border: "1px solid var(--border, #d0d5dd)", borderRadius: 6, padding: 12 }}>
            <legend><b>{CATEGORY_LABEL[c.category]}</b> {c.override ? <Badge tone="info">Own settings</Badge> : <Badge>Category settings</Badge>}</legend>
            <p className="xs faint" style={{ margin: 0 }}>
              Applies now: {c.effective.mode === "off" ? "no limit" : thresholdText({ ...c.effective, limit: c.limit })}, {MODE_LABEL[c.effective.mode].toLowerCase()}.
              {" "}Used in the window: {c.used}{c.limit !== null ? ` of ${c.limit}` : ""}.
              {c.last_count !== null ? ` Last good run: ${c.last_count} records.` : " No good run recorded yet."}
            </p>
            <div className="row wrap" style={{ gap: 12 }}>
              <label className="field">When over the threshold
                <select className="input" value={e.mode} disabled={!allowed} onChange={(ev) => set(c.category, { mode: ev.target.value as SourceEdit["mode"] })}>
                  <option value="inherit">Use the category's threshold</option>
                  {(Object.keys(MODE_LABEL) as DeletionMode[]).map((m) => <option key={m} value={m}>{MODE_LABEL[m]}</option>)}
                </select>
              </label>
              <label className="field">Count
                <input className="input tnum" style={{ width: 90 }} inputMode="numeric" value={e.max_count} disabled={!allowed || !own} aria-invalid={err ? true : undefined} aria-describedby={err ? `${id0}-err` : undefined}
                  onChange={(ev) => set(c.category, { max_count: ev.target.value })} />
              </label>
              <label className="field">Percent
                <input className="input tnum" style={{ width: 80 }} inputMode="decimal" value={e.max_percent} disabled={!allowed || !own} onChange={(ev) => set(c.category, { max_percent: ev.target.value })} />
              </label>
              <label className="field">Window (min)
                <input className="input tnum" style={{ width: 80 }} inputMode="numeric" value={e.window_minutes} disabled={!allowed || !own} onChange={(ev) => set(c.category, { window_minutes: ev.target.value })} />
              </label>
            </div>
            <div className="row wrap" style={{ gap: 12 }}>
              <label className="field">Feed drop limit (%)
                <input className="input tnum" style={{ width: 90 }} inputMode="decimal" placeholder={String(data.feed_defaults.drop_percent)} value={e.feed_drop} disabled={!allowed}
                  aria-describedby={`${id0}-feed`} onChange={(ev) => set(c.category, { feed_drop: ev.target.value })} />
              </label>
              <label className="row tight small" style={{ alignSelf: "end" }}>
                <input type="checkbox" checked={e.empty_check} disabled={!allowed} onChange={(ev) => set(c.category, { empty_check: ev.target.checked })} /> Hold the removals of an empty feed
              </label>
            </div>
            <span id={`${id0}-feed`} className="xs faint">A feed with more than this share fewer records than its last good run holds every removal it asks for. 100 never holds on the drop.</span>
            {err && <div id={`${id0}-err`} className="xs" role="alert" style={{ color: "var(--critical-text, #b42318)" }}>{err}</div>}
          </fieldset>
        );
      })}
      {looser.length > 0 && (
        <Callout tone="warn">
          {looser.join(", ")} would be set looser than now. Loosening a safety setting needs a second admin to approve it, with a fresh passkey sign-in. Tightening needs only you.
        </Callout>
      )}
      {!allowed && <p className="small muted" style={{ margin: 0 }}>Your role can read these settings but not request a change.</p>}
      <div className="row wrap" style={{ gap: 8 }}>
        <Button type="submit" variant="primary" disabled={!allowed || busy || changes.length === 0 || bad}>{looser.length > 0 ? "Request change" : "Save"}</Button>
        {changes.length > 0 && <Button type="button" size="sm" onClick={() => setEdits({})}>Clear</Button>}
      </div>
    </form>
  );
}
