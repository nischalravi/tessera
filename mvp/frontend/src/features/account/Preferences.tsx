/**
 * My account → Preferences (issue #298): the signed-in user's time zone, date format, locale and landing
 * page. They are stored for this user only and used by every page to show dates, and to open the app on
 * the chosen page. Empty means the default (the browser's zone and locale).
 */
import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { preferences } from "../../api";
import { usePreferences } from "../../app/PrefsGate";
import { Button, Callout, Page, useToast } from "../../components";
import { DATE_FORMAT_LABEL, Preferences as Prefs, browserZone, formatDateTime } from "../../prefs";

const PAGE_LABEL: Record<string, string> = {
  "/": "Home",
  "/inbox": "Inbox",
  "/access/request": "Request access",
  "/access/mine": "My access",
  "/access/requests": "My requests",
  "/governance/reviews": "Access reviews",
  "/insights/risk": "Risk overview",
  "/insights/sod": "SoD conflicts",
  "/directory/people": "Users",
  "/alerts": "Alerts",
};

export function Preferences() {
  const { view, apply } = usePreferences();
  const toast = useToast();
  const [d, setD] = useState<Prefs | null>(view);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setD(view), [view]);
  if (!view || !d) {
    return (
      <Page title="Preferences" crumbs={[["My account"], ["Preferences"]]}>
        <Callout tone="bad">Your preferences could not be loaded. Reload the page to try again.</Callout>
      </Page>
    );
  }
  const changed = (Object.keys(d) as (keyof Prefs)[]).some((k) => d[k] !== view[k]);
  const set = <K extends keyof Prefs>(k: K, v: Prefs[K]) => setD({ ...d, [k]: v });
  const sample = formatDateTime(new Date("2026-10-21T15:30:00Z"), d);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!changed || busy) return;
    setBusy(true);
    setErr(null);
    try {
      apply(await preferences.save(d));
      toast("Preferences saved");
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Page title="Preferences" crumbs={[["My account"], ["Preferences"]]}
      sub={<>How Tessera shows dates to you and where it opens. They apply to you only. Your <Link to="/sessions">sessions</Link> and notification choices are separate.</>}>
      <form className="card stack" onSubmit={submit} aria-label="Preferences">
        <label className="field">Time zone
          <input className="input" list="pref-zones" value={d.time_zone} onChange={(e) => set("time_zone", e.target.value)} placeholder={`Browser default (${browserZone()})`}
            autoComplete="off" spellCheck={false} style={{ maxWidth: 320 }} aria-describedby="pref-zone-hint" />
          <datalist id="pref-zones">{view.time_zones.map((z) => <option key={z} value={z} />)}</datalist>
          <span className="hint" id="pref-zone-hint">An IANA name such as Europe/Berlin or America/New_York. Empty: your browser's.</span>
        </label>
        <label className="field">Date format
          <select className="input" value={d.date_format} onChange={(e) => set("date_format", e.target.value as Prefs["date_format"])} style={{ maxWidth: 320 }}>
            <option value="">{DATE_FORMAT_LABEL[""]}</option>
            {view.date_formats.map((f) => <option key={f} value={f}>{DATE_FORMAT_LABEL[f] ?? f}</option>)}
          </select>
        </label>
        <label className="field">Locale
          <select className="input" value={d.locale} onChange={(e) => set("locale", e.target.value)} style={{ maxWidth: 320 }}>
            <option value="">Browser default</option>
            {view.locales.map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
          <span className="hint">Sets month names and the 12 or 24 hour clock.</span>
        </label>
        <label className="field">Landing page
          <select className="input" value={d.landing_page} onChange={(e) => set("landing_page", e.target.value)} style={{ maxWidth: 320 }}>
            <option value="">Home</option>
            {view.landing_pages.filter((p) => p !== "/").map((p) => <option key={p} value={p}>{PAGE_LABEL[p] ?? p}</option>)}
          </select>
          <span className="hint">Where Tessera opens when you arrive at its address. The Home link in the rail still goes to Home. A page you cannot use shows what you may do there.</span>
        </label>
        <p className="small" aria-live="polite">Example: <b>{sample}</b></p>
        {err && <Callout tone="bad">{err}</Callout>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <Button type="submit" variant="primary" disabled={!changed || busy}>{busy ? "Saving…" : "Save preferences"}</Button>
        </div>
      </form>
    </Page>
  );
}
