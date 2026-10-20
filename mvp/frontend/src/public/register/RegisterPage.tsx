/**
 * Guest self-registration (/register, issue #66): public, no sign-in, no navigation. A visitor says who
 * they are and picks the person who will vouch for them (a name-only search, or a code that person
 * shared). Nothing is created until that person approves. Whatever happens to the request, the page
 * answers the same: "Check your email". It never says whether an address or a sponsor is known.
 */
import { FormEvent, useEffect, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { SponsorChoice, searchSponsors, submitRegistration } from "../../api";
import { Button } from "../../components/Button";
import { Callout } from "../../components/Feedback";
import { tenantSlug } from "../claim/model";

const isoDay = (d: Date) => d.toISOString().slice(0, 10);

export default function RegisterPage() {
  const slug = tenantSlug(window.location.hostname, import.meta.env.VITE_TESSERA_TENANT as string | undefined);
  const today = new Date();
  const [form, setForm] = useState({ given_name: "", family_name: "", email: "", purpose: "", ends_at: isoDay(new Date(today.getTime() + 7 * 864e5)) });
  const [mode, setMode] = useState<"search" | "code">("search");
  const [q, setQ] = useState("");
  const [choices, setChoices] = useState<SponsorChoice[]>([]);
  const [sponsor, setSponsor] = useState("");
  const [code, setCode] = useState("");
  const [state, setState] = useState<"ready" | "sending" | "sent">("ready");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  useEffect(() => {
    if (mode !== "search" || q.trim().length < 2) {
      setChoices([]);
      return;
    }
    let alive = true;
    const t = window.setTimeout(() => {
      searchSponsors(slug, q).then((c) => alive && setChoices(c)).catch(() => alive && setChoices([]));
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(t);
    };
  }, [q, mode, slug]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    if (mode === "search" && !sponsor) return setError("Pick the person who will sponsor you from the search results.");
    if (mode === "code" && !code.trim()) return setError("Enter the code your sponsor gave you.");
    setState("sending");
    try {
      // challenge_token: a bot challenge widget (Turnstile or equivalent) fills it where one is configured
      setMessage(await submitRegistration(slug, { ...form, sponsor: mode === "search" ? sponsor : undefined, code: mode === "code" ? code : undefined }));
      setState("sent");
    } catch (err: any) {
      setError(String(err.message ?? err));
      setState("ready");
    }
  };

  return (
    <div className="claim-wrap">
      <main className="claim" aria-labelledby="register-title">
        <p className="claim-brand">Tessera</p>
        <h1 id="register-title" className="claim-h">Register as a guest</h1>
        {state === "sent" ? (
          <p role="status" className="row tight"><CheckCircle2 size={18} aria-hidden /> {message} If your sponsor approves, we will send you a link to set up your sign-in.</p>
        ) : (
          <form onSubmit={submit} className="stack" style={{ gap: 12 }}>
            <p>Tell us who you are and who invited you. Nothing is created until they approve.</p>
            {error && <Callout tone="bad">{error}</Callout>}
            <label>First name<input className="input" required maxLength={100} autoComplete="given-name" value={form.given_name} onChange={set("given_name")} /></label>
            <label>Last name<input className="input" maxLength={100} autoComplete="family-name" value={form.family_name} onChange={set("family_name")} /></label>
            <label>Email<input className="input" type="email" required maxLength={320} autoComplete="email" value={form.email} onChange={set("email")} /></label>
            <label>Why do you need access?<textarea className="input" required maxLength={500} rows={3} value={form.purpose} onChange={set("purpose")} /></label>
            <label>Until<input className="input" type="date" required min={isoDay(today)} value={form.ends_at} onChange={set("ends_at")} /></label>
            <fieldset className="stack" style={{ gap: 8, border: 0, padding: 0, margin: 0 }}>
              <legend>Your sponsor</legend>
              <div className="row">
                <label className="row tight"><input type="radio" name="mode" checked={mode === "search"} onChange={() => setMode("search")} /> Search by name</label>
                <label className="row tight"><input type="radio" name="mode" checked={mode === "code"} onChange={() => setMode("code")} /> I have a code</label>
              </div>
              {mode === "search" ? (
                <>
                  <label>Sponsor's name<input className="input" value={q} onChange={(e) => { setQ(e.target.value); setSponsor(""); }} autoComplete="off" aria-describedby="sponsor-help" /></label>
                  <p id="sponsor-help" className="small muted">Type at least two letters.</p>
                  {choices.length > 0 && (
                    <ul role="listbox" aria-label="Matching sponsors" className="stack" style={{ listStyle: "none", margin: 0, padding: 0, gap: 4 }}>
                      {choices.map((c) => (
                        <li key={c.handle}>
                          <button type="button" role="option" aria-selected={sponsor === c.handle} className={`btn ${sponsor === c.handle ? "primary" : ""}`} onClick={() => setSponsor(c.handle)}>{c.name}</button>
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              ) : (
                <label>Sponsor code<input className="input" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" maxLength={32} placeholder="ABCDE-FGHJK" /></label>
              )}
            </fieldset>
            <Button variant="primary" type="submit" disabled={state === "sending"}>{state === "sending" ? "Sending…" : "Ask my sponsor"}</Button>
          </form>
        )}
      </main>
    </div>
  );
}
