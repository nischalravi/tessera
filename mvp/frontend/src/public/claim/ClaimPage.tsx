/**
 * The guest's claim page (/claim), outside the admin shell: it has no sign-in, no navigation and no
 * third-party scripts. It reads the claim token from the URL fragment, removes it from the address
 * bar at once, starts the claim with a key it generated (proof.ts), and then walks the guest through
 * the steps the API reports: confirm the email address, verify identity when the access needs it,
 * the "do you already have an account?" question, terms and consent, choose how to sign in, done.
 * Which step is open is the API's decision; this page only shows it.
 *
 * Accessibility (WCAG 2.2 AA): every step's heading takes focus when the step appears; every field has
 * a visible label and its help linked with aria-describedby; errors go to a role="alert" region and
 * the invalid field is marked; progress is a labelled ordered list; nothing depends on colour alone.
 * Text comes from the catalog in src/i18n, never from literals here.
 */
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { ClaimError, ClaimSigner, ClaimStatus, ClaimStep, ClaimTerms, claimApi, claimResend, fmtDay } from "../../api";
import { Button } from "../../components/Button";
import { Callout } from "../../components/Feedback";
import { MessageKey, t } from "../../i18n";
import { ErrorAlert, PublicHeading as Heading, PublicShell, StatusRegion } from "../PublicShell";
import { usePublicBranding } from "../useBranding";
import { dropKey, loadKey, loadNonce, newKey, dropNonce, saveNonce } from "./keystore";
import { ClaimResult, ClaimView, codeReady, consentChoice, emailOk, normalizeCode, resultFromSearch, signInRedirect, stepIndex, tenantSlug, termsReady, tokenFromHash, viewOf, visibleSteps } from "./model";
import { publicJwk, signerFor } from "./proof";

const message = (e: unknown) => (e instanceof ClaimError ? e.message : t("common.generic_error"));
const POPULATIONS = ["visitor", "contractor", "volunteer", "partner"];
const populationPhrase = (p: string) => t((POPULATIONS.includes(p) ? `claim.population.${p}` : "claim.population.default") as MessageKey);

interface Conn {
  slug: string;
  signer: ClaimSigner;
  nonce: string;
}

export default function ClaimPage() {
  const slug = tenantSlug(window.location.hostname, import.meta.env.VITE_TESSERA_TENANT as string | undefined);
  const branding = usePublicBranding(slug);
  const [conn, setConn] = useState<Conn | null>(null);
  const [status, setStatus] = useState<ClaimStatus | null>(null);
  const [view, setView] = useState<ClaimView>({ kind: "loading" });
  const [result, setResult] = useState<ClaimResult | null>(null);
  const started = useRef(false);

  const show = useCallback((s: ClaimStatus) => {
    setStatus(s);
    setView(viewOf(s));
  }, []);

  // read the link, remove it from the address bar, start (or resume) the claim
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const token = tokenFromHash(window.location.hash);
    const result = resultFromSearch(window.location.search);
    // the token never stays in the address bar, history or a bookmark
    window.history.replaceState(null, "", window.location.pathname);
    setResult(result);
    (async () => {
      try {
        if (token) {
          const pair = await newKey(slug);
          const signer = signerFor(pair);
          const r = await claimApi.start(slug, token, await publicJwk(pair), signer);
          if (r.next === "check_link" || !r.nonce || !r.status) {
            await dropKey(slug).catch(() => undefined);
            setView({ kind: "check_link" });
            return;
          }
          saveNonce(slug, r.nonce);
          setConn({ slug, signer, nonce: r.nonce });
          show(r.status);
          return;
        }
        const pair = await loadKey(slug);
        const nonce = loadNonce(slug);
        if (!pair || !nonce) {
          setView({ kind: "check_link" });
          return;
        }
        const signer = signerFor(pair);
        setConn({ slug, signer, nonce });
        show(await claimApi.status(slug, signer, nonce));
      } catch {
        setView({ kind: "check_link" });
      }
    })();
  }, [slug, show]);

  // the claim is over: forget the key
  useEffect(() => {
    if (view.kind === "complete") {
      dropKey(slug).catch(() => undefined);
      dropNonce(slug);
    }
  }, [view.kind, slug]);

  return (
    <PublicShell titleKey="claim.title" brand={status?.tenant} branding={branding}>
      {view.kind === "loading" && <p role="status">{t("claim.opening")}</p>}
      {view.kind === "check_link" && <CheckLink slug={slug} />}
      {status && view.kind !== "check_link" && view.kind !== "loading" && (
        <>
          {view.kind !== "complete" && <Progress status={status} />}
          {result === "failed" && view.kind === "step" && view.step === "credential" && <Callout tone="bad">{t("claim.banner.failed")}</Callout>}
          {status.purpose === "recovery" && view.kind !== "complete" && <Callout tone="info">{t("claim.banner.recovery")}</Callout>}
          {result === "cooling_off" && <Callout tone="info">{t("claim.banner.cooling_off")}</Callout>}
          {result === "continue" && view.kind === "step" && view.step === "credential" && <Callout tone="info">{t("claim.banner.continue")}</Callout>}
          {view.kind === "step" && conn && (
            <StepView step={view.step} status={status} conn={conn} onStatus={(s) => { setResult(null); show(s); }} />
          )}
          {view.kind === "waiting" && (view.why === "identity_verification" ? <IdentityStep status={status} /> : <Waiting />)}
          {view.kind === "complete" && <Done status={status} cooling={result === "cooling_off"} />}
        </>
      )}
    </PublicShell>
  );
}

function Progress({ status }: { status: ClaimStatus }) {
  const steps = visibleSteps(status).filter((s) => s !== "complete");
  const at = stepIndex(status);
  return (
    <ol className="claim-steps" aria-label={t("common.progress")}>
      {steps.map((s, i) => (
        <li key={s} aria-current={i === at ? "step" : undefined} className={i < at ? "done" : i === at ? "now" : ""}>
          <span className="sr-only">{i < at ? t("common.step_done") : i === at ? t("common.step_current") : t("common.step_later")}</span>
          {t(`claim.step.${s}` as MessageKey)}
        </li>
      ))}
    </ol>
  );
}

// ------------------------------------------------------------------ the link did not work

function CheckLink({ slug }: { slug: string }) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [answer, setAnswer] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const send = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      setAnswer(await claimResend(slug, email.trim()));
    } catch (x) {
      setErr(message(x));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Heading>{t("claim.check.title")}</Heading>
      <p>{t("claim.check.body")}</p>
      <form onSubmit={send} className="stack" noValidate>
        <label className="field">{t("claim.check.email")}
          <input className="input" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} aria-describedby="resend-note" />
        </label>
        <p id="resend-note" className="xs">{t("claim.check.note")}</p>
        <div><Button variant="primary" type="submit" disabled={!emailOk(email) || busy}>{t("claim.check.send")}</Button></div>
      </form>
      <StatusRegion>{answer && <Callout tone="ok">{answer}</Callout>}</StatusRegion>
      <ErrorAlert message={err} />
    </>
  );
}

// ------------------------------------------------------------------ steps

function StepView({ step, status, conn, onStatus }: { step: ClaimStep; status: ClaimStatus; conn: Conn; onStatus: (s: ClaimStatus) => void }) {
  const refresh = useCallback(async () => onStatus(await claimApi.status(conn.slug, conn.signer, conn.nonce)), [conn, onStatus]);
  switch (step) {
    case "verify_contact":
      return <VerifyContact status={status} conn={conn} onDone={refresh} />;
    case "existing_account":
      return <ExistingAccount status={status} conn={conn} onDone={refresh} />;
    case "credential":
      // step 5 (terms, then the attribute-release consent) comes before the credential
      return status.pending === "terms" || status.pending === "consent"
        ? <TermsStep status={status} conn={conn} onDone={refresh} />
        : <Credential status={status} conn={conn} />;
    default:
      return <IdentityStep status={status} />;
  }
}

function useAction() {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
    } catch (e) {
      setErr(message(e));
    } finally {
      setBusy(false);
    }
  };
  return { busy, err, run, setErr };
}

function VerifyContact({ status, conn, onDone }: { status: ClaimStatus; conn: Conn; onDone: () => Promise<void> }) {
  const [code, setCode] = useState("");
  const [sent, setSent] = useState<string | null>(null);
  const a = useAction();
  const input = useRef<HTMLInputElement>(null);
  const send = () => a.run(async () => {
    setSent((await claimApi.sendCode(conn.slug, conn.signer, conn.nonce)).message);
  });
  // the code field appears once the code is sent: move the keyboard (and a screen reader) to it
  useEffect(() => { if (sent) input.current?.focus(); }, [sent]);
  const check = (e: FormEvent) => {
    e.preventDefault();
    return a.run(async () => {
      await claimApi.checkCode(conn.slug, conn.signer, conn.nonce, normalizeCode(code));
      await onDone();
    });
  };
  return (
    <>
      <Heading>{t("claim.verify.title", { name: status.first_name })}</Heading>
      <p>{t("claim.verify.intro", { sponsor: status.sponsor, tenant: status.tenant, population: populationPhrase(status.population), date: fmtDay(status.ends_at) })}</p>
      {!sent ? (
        <div><Button variant="primary" onClick={send} disabled={a.busy}>{t("claim.verify.send")}</Button></div>
      ) : (
        <form onSubmit={check} className="stack" noValidate>
          <label className="field">{t("claim.verify.code")}
            <input ref={input} className="input claim-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]*" maxLength={7} required
              value={code} onChange={(e) => setCode(e.target.value)} aria-describedby="code-help" aria-invalid={a.err ? true : undefined} />
          </label>
          <p id="code-help" className="xs">{t("claim.verify.help", { sent })}</p>
          <div className="row tight">
            <Button variant="primary" type="submit" disabled={!codeReady(code) || a.busy}>{t("claim.verify.check")}</Button>
            <Button onClick={send} disabled={a.busy}>{t("claim.verify.resend")}</Button>
          </div>
        </form>
      )}
      <ErrorAlert message={a.err} />
    </>
  );
}

/** Identity verification (IAL 2): in person at a proofing agent, or online when a provider is set up. */
function IdentityStep({ status }: { status: ClaimStatus }) {
  return (
    <>
      <Heading>{t("claim.idv.title")}</Heading>
      <p>{t("claim.idv.intro")}</p>
      <section aria-labelledby="idv-agent" className="stack-sm">
        <h2 id="idv-agent" className="h-sm">{t("claim.idv.agent_title")}</h2>
        <p>{t("claim.idv.agent_body", { sponsor: status.sponsor })}</p>
      </section>
      <section aria-labelledby="idv-online" className="stack-sm">
        <h2 id="idv-online" className="h-sm">{t("claim.idv.online_title")}</h2>
        <p>{t("claim.idv.online_body")}</p>
      </section>
      <Callout tone="info">{t("claim.idv.keep_open")}</Callout>
    </>
  );
}

function ExistingAccount({ status, conn, onDone }: { status: ClaimStatus; conn: Conn; onDone: () => Promise<void> }) {
  const [answer, setAnswer] = useState<"yes" | "no" | "">("");
  const a = useAction();
  const go = (e: FormEvent) => {
    e.preventDefault();
    if (!answer) return;
    return a.run(async () => {
      const r = await claimApi.existingAccount(conn.slug, conn.signer, conn.nonce, answer);
      // "yes": sign in with that account. If it is the account this invitation is for, the invitation
      // is added to it; if not, nothing changes and the claim goes on. Either way the page says nothing
      // about whether an account was expected.
      const to = signInRedirect(r);
      if (to) {
        window.location.assign(to);
        return;
      }
      await onDone();
    });
  };
  return (
    <>
      <Heading>{t("claim.existing.title", { tenant: status.tenant })}</Heading>
      <p>{t("claim.existing.body")}</p>
      <form onSubmit={go} className="stack">
        <fieldset className="claim-choices">
          <legend className="sr-only">{t("claim.existing.title", { tenant: status.tenant })}</legend>
          <label className="row tight"><input type="radio" name="existing" value="no" checked={answer === "no"} onChange={() => setAnswer("no")} /> {t("claim.existing.no")}</label>
          <label className="row tight"><input type="radio" name="existing" value="yes" checked={answer === "yes"} onChange={() => setAnswer("yes")} aria-describedby={answer === "yes" ? "existing-yes-note" : undefined} /> {t("claim.existing.yes")}</label>
        </fieldset>
        {answer === "yes" && <p id="existing-yes-note" className="xs">{t("claim.existing.yes_note")}</p>}
        <div><Button variant="primary" type="submit" disabled={!answer || a.busy}>{answer === "yes" ? t("claim.existing.signin") : t("claim.existing.continue")}</Button></div>
      </form>
      <ErrorAlert message={a.err} />
    </>
  );
}

/** Step 5: the terms that apply, and (federated sign-ins) the choice of attributes to release. */
function TermsStep({ status, conn, onDone }: { status: ClaimStatus; conn: Conn; onDone: () => Promise<void> }) {
  const [t0, setT] = useState<ClaimTerms | null>(null);
  const [ticked, setTicked] = useState<Record<string, boolean>>({});
  const [chosen, setChosen] = useState<Record<string, boolean>>({});
  const a = useAction();
  const load = useCallback(async () => setT(await claimApi.terms(conn.slug, conn.signer, conn.nonce)), [conn]);
  useEffect(() => { load().catch((e) => a.setErr(message(e))); }, [load]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!t0) return <><Heading>{t("claim.terms.title")}</Heading><p role="status">{t("common.loading")}</p><ErrorAlert message={a.err} /></>;
  const docs = t0.terms;
  const askConsent = t0.consent.applies && !t0.consent.given;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    return a.run(async () => {
      if (docs.length) await claimApi.acceptTerms(conn.slug, conn.signer, conn.nonce, docs.map((d) => ({ id: d.id, sha256: d.sha256 })));
      if (askConsent) await claimApi.consent(conn.slug, conn.signer, conn.nonce, consentChoice(t0.consent.attributes, chosen));
      await onDone();
    }).then(() => load().catch(() => undefined));
  };
  return (
    <>
      <Heading>{t("claim.terms.title")}</Heading>
      <form onSubmit={submit} className="stack">
        {docs.map((d) => (
          <section key={d.id} aria-labelledby={`terms-${d.id}`} className="stack-sm">
            <h2 id={`terms-${d.id}`} className="h-sm">{d.title} <span className="faint">{t("claim.terms.version", { version: d.version })}</span></h2>
            <div className="claim-terms" tabIndex={0} role="region" aria-label={t("claim.terms.text", { title: d.title })}>{d.body}</div>
            <label className="row tight">
              <input type="checkbox" checked={!!ticked[d.id]} onChange={(e) => setTicked({ ...ticked, [d.id]: e.target.checked })} /> {t("claim.terms.accept_label", { title: d.title })}
            </label>
          </section>
        ))}
        {askConsent && (
          <fieldset className="stack-sm claim-choices">
            <legend className="h-sm">{t("claim.terms.consent_legend", { tenant: status.tenant })}</legend>
            {t0.consent.attributes.map((x) => (
              <label key={x.name} className="row tight">
                <input type="checkbox" checked={x.required || !!chosen[x.name]} disabled={x.required} onChange={(e) => setChosen({ ...chosen, [x.name]: e.target.checked })} />
                <span><strong>{x.name}</strong>{x.required ? t("claim.terms.needed") : ""}: {x.why}</span>
              </label>
            ))}
          </fieldset>
        )}
        <div>
          <Button variant="primary" type="submit" disabled={a.busy || (docs.length > 0 && !termsReady(docs, ticked))}>
            {docs.length ? t("claim.terms.submit") : t("claim.terms.continue")}
          </Button>
        </div>
      </form>
      <ErrorAlert message={a.err} />
    </>
  );
}

function Credential({ status, conn }: { status: ClaimStatus; conn: Conn }) {
  const [pending, setPending] = useState<string | null>(status.pending === "organization" ? t("claim.credential.pending") : null);
  const a = useAction();
  const go = () => a.run(async () => {
    const r = await claimApi.credential(conn.slug, conn.signer, conn.nonce);
    if (r.status === "redirect" && r.redirect) {
      window.location.assign(r.redirect);
      return;
    }
    setPending(r.message ?? t("claim.credential.pending_short"));
  });
  return (
    <>
      <Heading>{t("claim.credential.title")}</Heading>
      {pending ? (
        <>
          <Callout tone="info">{pending}</Callout>
          <p>{t("claim.credential.stays_open")}</p>
        </>
      ) : (
        <>
          <p>{t("claim.credential.body")}</p>
          <div><Button variant="primary" onClick={go} disabled={a.busy}>{t("claim.credential.go")}</Button></div>
        </>
      )}
      <ErrorAlert message={a.err} />
    </>
  );
}

function Waiting() {
  return (
    <>
      <Heading>{t("claim.waiting.title")}</Heading>
      <Callout tone="info">{t("claim.credential.pending_short")}</Callout>
    </>
  );
}

function Done({ status, cooling }: { status: ClaimStatus; cooling: boolean }) {
  return (
    <>
      <Heading>{cooling ? t("claim.done.title_cooling", { name: status.first_name }) : t("claim.done.title", { name: status.first_name })}</Heading>
      <Callout tone="ok" icon={<CheckCircle2 size={16} />}>{cooling ? t("claim.done.cooling", { tenant: status.tenant }) : t("claim.done.ready", { tenant: status.tenant })}</Callout>
      <p>{t("claim.done.access", { date: fmtDay(status.ends_at), sponsor: status.sponsor })}</p>
      <section aria-labelledby="recovery-note" className="stack-sm">
        <h2 id="recovery-note" className="h-sm">{t("claim.done.recovery_title")}</h2>
        <p>{t("claim.done.recovery_body", { sponsor: status.sponsor })}</p>
      </section>
    </>
  );
}
