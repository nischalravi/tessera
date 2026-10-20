/**
 * Admin → Request settings (issue #298): the tenant-wide rules for access requests. The server
 * enforces them on submit, so changing a setting changes what every client may send. Saving needs
 * catalog.manage and a fresh phishing-resistant sign-in (the client asks for it) and is audited.
 */
import { FormEvent, useEffect, useState } from "react";
import { RequestSettings as Settings, RequestSettingsView, requestSettingsPath, requestSettings, useApi } from "../../api";
import { Button, Callout, Loading, Page, useToast } from "../../components";
import { FOR_OTHERS, HISTORY, parseHours, sameSettings, settingsError } from "../access/requestSettings";

const pick = (v: RequestSettingsView): Settings => ({
  justification_required: v.justification_required, justification_min_length: v.justification_min_length, default_hours: v.default_hours,
  max_hours: v.max_hours, attachments_allowed: v.attachments_allowed, history_visibility: v.history_visibility, for_others: v.for_others,
});
const hoursText = (h: number | null) => (h === null ? "" : String(h));

function Form({ view, onSaved }: { view: RequestSettingsView; onSaved: () => void }) {
  const toast = useToast();
  const saved = pick(view);
  const [d, setD] = useState<Settings>(saved);
  const [min, setMin] = useState(String(saved.justification_min_length));
  const [def, setDef] = useState(hoursText(saved.default_hours));
  const [max, setMax] = useState(hoursText(saved.max_hours));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // a reload after a save (or someone else's) replaces the form
  useEffect(() => {
    const s = pick(view);
    setD(s);
    setMin(String(s.justification_min_length));
    setDef(hoursText(s.default_hours));
    setMax(hoursText(s.max_hours));
  }, [view.version]); // eslint-disable-line react-hooks/exhaustive-deps

  const dh = parseHours(def);
  const mh = parseHours(max);
  const minN = Number(min);
  const draft: Settings = { ...d, justification_min_length: Number.isFinite(minN) ? minN : 0, default_hours: dh === "invalid" ? 0 : dh, max_hours: mh === "invalid" ? 0 : mh };
  const problem = settingsError(draft, view.max_hours_limit, view.max_justification_length);
  const changed = !sameSettings(draft, saved);
  const can = view.can_manage;
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setD((p) => ({ ...p, [k]: v }));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || !changed || busy || !can) return;
    setBusy(true);
    setErr(null);
    try {
      await requestSettings.save(view.version, draft);
      toast("Request settings saved");
      onSaved();
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card stack" onSubmit={submit} aria-label="Request settings">
      {!can && <Callout tone="neutral">You can read these settings. A policy admin changes them.</Callout>}
      {view.version === 0 && <Callout tone="neutral">Nothing saved yet: these are the defaults.</Callout>}

      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h2>Justification</h2></legend>
        <label className="row small"><input type="checkbox" checked={d.justification_required} onChange={(e) => set("justification_required", e.target.checked)} /> A justification is required</label>
        <label className="field">Minimum length (characters)
          <input className="input" inputMode="numeric" value={min} onChange={(e) => setMin(e.target.value)} disabled={!d.justification_required} style={{ maxWidth: 140 }} aria-describedby="rs-min-hint" />
          <span className="hint" id="rs-min-hint">Between 1 and {view.max_justification_length}. Counted after trimming spaces.</span>
        </label>
      </fieldset>

      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h2>Duration</h2></legend>
        <div className="grid g2">
          <label className="field">Default duration (hours)
            <input className="input" inputMode="decimal" value={def} onChange={(e) => setDef(e.target.value)} placeholder="None" aria-invalid={dh === "invalid"} aria-describedby="rs-def-hint" />
            <span className="hint" id="rs-def-hint">Used when the person and the item name none. Empty: until removed.</span>
          </label>
          <label className="field">Maximum duration (hours)
            <input className="input" inputMode="decimal" value={max} onChange={(e) => setMax(e.target.value)} placeholder="None" aria-invalid={mh === "invalid"} aria-describedby="rs-max-hint" />
            <span className="hint" id="rs-max-hint">Up to {view.max_hours_limit} (a year). With a maximum, "until removed" is no longer possible.</span>
          </label>
        </div>
      </fieldset>

      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h2>Attachments</h2></legend>
        <label className="row small"><input type="checkbox" checked={d.attachments_allowed} onChange={(e) => set("attachments_allowed", e.target.checked)} /> Allow attachments on a request</label>
        <p className="xs faint">An attachment is a reference (a ticket or document link, at most {view.max_attachments}). Tessera stores no files; the references are kept in the audit event of the request.</p>
      </fieldset>

      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h2>Request history</h2></legend>
        {HISTORY.map((h) => (
          <label key={h.id} className="row small" style={{ alignItems: "flex-start", flexWrap: "nowrap" }}>
            <input type="radio" name="history" checked={d.history_visibility === h.id} onChange={() => set("history_visibility", h.id)} />
            <span><b>{h.label}</b><span className="faint"> · {h.hint}</span></span>
          </label>
        ))}
      </fieldset>

      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h2>Request for others</h2></legend>
        {FOR_OTHERS.map((o) => (
          <label key={o.id} className="row small" style={{ alignItems: "flex-start", flexWrap: "nowrap" }}>
            <input type="radio" name="for-others" checked={d.for_others === o.id} onChange={() => set("for_others", o.id)} />
            <span><b>{o.label}</b><span className="faint"> · {o.hint}</span></span>
          </label>
        ))}
      </fieldset>

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

export function RequestSettings() {
  const { data, error, reload } = useApi<RequestSettingsView>(requestSettingsPath);
  return (
    <Page title="Request settings" crumbs={[["Settings"], ["Admin", "/admin"], ["Request settings"]]}
      sub="The rules every access request follows: justification, duration, attachments, who can see request history and who can request for others. The server enforces them when a request is submitted.">
      {!data ? <Loading kind="block" error={error} what="request settings" /> : <Form view={data} onSaved={reload} />}
    </Page>
  );
}
