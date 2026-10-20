/**
 * Guest self-registration (/register, issue #66): public, no sign-in, no navigation. A visitor says who
 * they are and picks the person who will vouch for them (a name-only search, or a code that person
 * shared). Nothing is created until that person approves. Whatever happens to the request, the page
 * answers the same: "Check your email". It never says whether an address or a sponsor is known.
 *
 * Accessibility: every field has a visible label; a failed submit moves focus to the error, which is
 * announced (role="alert") and marks the field; search results are a radio group, so they work with a
 * keyboard and a screen reader, and the number of results is announced.
 */
import { FormEvent, useEffect, useRef, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { SponsorChoice, searchSponsors, submitRegistration } from "../../api";
import { Button } from "../../components/Button";
import { t } from "../../i18n";
import { ErrorAlert, PublicHeading, PublicShell, StatusRegion } from "../PublicShell";
import { tenantSlug } from "../claim/model";

const isoDay = (d: Date) => d.toISOString().slice(0, 10);

export default function RegisterPage() {
  const slug = tenantSlug(window.location.hostname, import.meta.env.VITE_TESSERA_TENANT as string | undefined);
  const today = new Date();
  const [form, setForm] = useState({ given_name: "", family_name: "", email: "", purpose: "", ends_at: isoDay(new Date(today.getTime() + 7 * 864e5)) });
  const [mode, setMode] = useState<"search" | "code">("search");
  const [q, setQ] = useState("");
  const [choices, setChoices] = useState<SponsorChoice[]>([]);
  const [searched, setSearched] = useState(false);
  const [sponsor, setSponsor] = useState("");
  const [code, setCode] = useState("");
  const [state, setState] = useState<"ready" | "sending" | "sent">("ready");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [bad, setBad] = useState<"" | "sponsor" | "code">("");
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const sponsorInput = useRef<HTMLInputElement>(null);
  const codeInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setSearched(false);
    if (mode !== "search" || q.trim().length < 2) {
      setChoices([]);
      return;
    }
    let alive = true;
    const timer = window.setTimeout(() => {
      searchSponsors(slug, q)
        .then((c) => { if (alive) { setChoices(c); setSearched(true); } })
        .catch(() => { if (alive) { setChoices([]); setSearched(false); } });
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [q, mode, slug]);

  const fail = (text: string, field: "" | "sponsor" | "code" = "") => {
    setError(text);
    setBad(field);
    // the message is announced by its alert region; focus goes to the field that needs the fix
    window.setTimeout(() => (field === "sponsor" ? sponsorInput : field === "code" ? codeInput : null)?.current?.focus(), 0);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setBad("");
    if (mode === "search" && !sponsor) return fail(t("register.error.pick_sponsor"), "sponsor");
    if (mode === "code" && !code.trim()) return fail(t("register.error.enter_code"), "code");
    setState("sending");
    try {
      // challenge_token: a bot challenge widget (Turnstile or equivalent) fills it where one is configured
      setMessage(await submitRegistration(slug, { ...form, sponsor: mode === "search" ? sponsor : undefined, code: mode === "code" ? code : undefined }));
      setState("sent");
    } catch (err: any) {
      fail(String(err.message ?? err));
      setState("ready");
    }
  };

  return (
    <PublicShell titleKey="register.title">
      {state === "sent" ? (
        <>
          <PublicHeading>{t("register.sent_title")}</PublicHeading>
          <p role="status" className="row tight"><CheckCircle2 size={18} aria-hidden /> {message} {t("register.sent_suffix")}</p>
        </>
      ) : (
        <>
          <PublicHeading>{t("register.title")}</PublicHeading>
          <form onSubmit={submit} className="stack" style={{ gap: 12 }}>
            <p>{t("register.intro")}</p>
            <ErrorAlert message={error} />
            <label className="field">{t("register.given_name")}<input className="input" required maxLength={100} autoComplete="given-name" value={form.given_name} onChange={set("given_name")} /></label>
            <label className="field">{t("register.family_name")}<input className="input" maxLength={100} autoComplete="family-name" value={form.family_name} onChange={set("family_name")} /></label>
            <label className="field">{t("register.email")}<input className="input" type="email" required maxLength={320} autoComplete="email" value={form.email} onChange={set("email")} /></label>
            <label className="field">{t("register.purpose")}<textarea className="input" required maxLength={500} rows={3} value={form.purpose} onChange={set("purpose")} /></label>
            <label className="field">{t("register.until")}<input className="input" type="date" required min={isoDay(today)} value={form.ends_at} onChange={set("ends_at")} /></label>
            <fieldset className="claim-choices">
              <legend>{t("register.sponsor_legend")}</legend>
              <div className="row">
                <label className="row tight"><input type="radio" name="mode" checked={mode === "search"} onChange={() => { setMode("search"); setBad(""); }} /> {t("register.mode_search")}</label>
                <label className="row tight"><input type="radio" name="mode" checked={mode === "code"} onChange={() => { setMode("code"); setBad(""); }} /> {t("register.mode_code")}</label>
              </div>
              {mode === "search" ? (
                <>
                  <label className="field">{t("register.sponsor_name")}
                    <input ref={sponsorInput} className="input" value={q} onChange={(e) => { setQ(e.target.value); setSponsor(""); }} autoComplete="off"
                      aria-describedby="sponsor-help" aria-invalid={bad === "sponsor" ? true : undefined} />
                  </label>
                  <p id="sponsor-help" className="small muted">{t("register.sponsor_help")}</p>
                  <StatusRegion>{searched && (choices.length === 0 ? t("register.results_none") : t("register.results_count", { count: choices.length }))}</StatusRegion>
                  {choices.length > 0 && (
                    <fieldset className="claim-choices">
                      <legend className="sr-only">{t("register.sponsor_results")}</legend>
                      {choices.map((c) => (
                        <label key={c.handle} className="row tight">
                          <input type="radio" name="sponsor" checked={sponsor === c.handle} onChange={() => { setSponsor(c.handle); setBad(""); }} /> {c.name}
                        </label>
                      ))}
                    </fieldset>
                  )}
                </>
              ) : (
                <label className="field">{t("register.sponsor_code")}
                  <input ref={codeInput} className="input" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" maxLength={32} placeholder="ABCDE-FGHJK"
                    aria-invalid={bad === "code" ? true : undefined} />
                </label>
              )}
            </fieldset>
            <Button variant="primary" type="submit" disabled={state === "sending"}>{state === "sending" ? t("common.sending") : t("register.submit")}</Button>
          </form>
        </>
      )}
    </PublicShell>
  );
}
