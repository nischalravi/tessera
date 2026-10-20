/**
 * The guest's claim page (/claim), outside the admin shell: it has no sign-in, no navigation and no
 * third-party scripts. It reads the claim token from the URL fragment, removes it from the address
 * bar at once, starts the claim with a key it generated (proof.ts), and then walks the guest through
 * the steps the API reports: confirm the email address, the "do you already have an account?"
 * question, choose how to sign in, done. Which step is open is the API's decision; this page only
 * shows it.
 */
import { FormEvent, ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { ClaimError, ClaimSigner, ClaimStatus, ClaimStep, claimApi, claimResend, fmtDay } from "../../api";
import { Button } from "../../components/Button";
import { Callout } from "../../components/Feedback";
import { dropKey, loadKey, loadNonce, newKey, dropNonce, saveNonce } from "./keystore";
import { POPULATION_PHRASE, STEP_LABEL, ClaimView, codeReady, emailOk, normalizeCode, resultFromSearch, stepIndex, tenantSlug, tokenFromHash, viewOf, visibleSteps } from "./model";
import { publicJwk, signerFor } from "./proof";

const message = (e: unknown) => (e instanceof ClaimError ? e.message : "Something went wrong. Try again.");

interface Conn {
  slug: string;
  signer: ClaimSigner;
  nonce: string;
}

export default function ClaimPage() {
  const slug = tenantSlug(window.location.hostname, import.meta.env.VITE_TESSERA_TENANT as string | undefined);
  const [conn, setConn] = useState<Conn | null>(null);
  const [status, setStatus] = useState<ClaimStatus | null>(null);
  const [view, setView] = useState<ClaimView>({ kind: "loading" });
  const [failed, setFailed] = useState(false);
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
    setFailed(result === "failed");
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
    <div className="claim-wrap">
      <main className="claim" aria-labelledby="claim-title">
        <p className="claim-brand">{status?.tenant ?? "Tessera"}</p>
        {view.kind === "loading" && <p role="status">Opening your invitation…</p>}
        {view.kind === "check_link" && <CheckLink slug={slug} />}
        {status && view.kind !== "check_link" && view.kind !== "loading" && (
          <>
            {view.kind !== "complete" && <Progress status={status} />}
            {failed && view.kind === "step" && view.step === "credential" && (
              <Callout tone="bad">We could not finish your sign-in. It may not have been strong enough, or it was for a different account. Try again.</Callout>
            )}
            {view.kind === "step" && conn && (
              <StepView step={view.step} status={status} conn={conn} onStatus={(s) => { setFailed(false); show(s); }} />
            )}
            {view.kind === "waiting" && <Waiting why={view.why} />}
            {view.kind === "complete" && <Done status={status} />}
          </>
        )}
      </main>
    </div>
  );
}

function Heading({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => ref.current?.focus(), []);
  return <h1 id="claim-title" tabIndex={-1} ref={ref} className="claim-h">{children}</h1>;
}

function Progress({ status }: { status: ClaimStatus }) {
  const steps = visibleSteps(status).filter((s) => s !== "complete");
  const at = stepIndex(status);
  return (
    <ol className="claim-steps" aria-label="Progress">
      {steps.map((s, i) => (
        <li key={s} aria-current={i === at ? "step" : undefined} className={i < at ? "done" : i === at ? "now" : ""}>
          <span className="sr-only">{i < at ? "Done: " : i === at ? "Current step: " : "Later: "}</span>
          {STEP_LABEL[s]}
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
      <Heading>Check your link</Heading>
      <p>This link did not work. It may have expired or been used already, or it may have been copied incompletely. Open the link in your invitation email again, or ask for a new one.</p>
      <form onSubmit={send} className="stack">
        <label className="field">Your email address
          <input className="input" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} aria-describedby="resend-note" />
        </label>
        <p id="resend-note" className="xs">We send a new link only if an invitation exists for this address, and we do not say whether one does.</p>
        <div><Button variant="primary" type="submit" disabled={!emailOk(email) || busy}>Send me a new link</Button></div>
      </form>
      <div role="status" aria-live="polite">
        {answer && <Callout tone="ok">{answer}</Callout>}
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
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
      return <Credential status={status} conn={conn} />;
    default:
      return <Waiting why="identity_verification" />;
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
  const send = () => a.run(async () => setSent((await claimApi.sendCode(conn.slug, conn.signer, conn.nonce)).message));
  const check = (e: FormEvent) => {
    e.preventDefault();
    return a.run(async () => {
      await claimApi.checkCode(conn.slug, conn.signer, conn.nonce, normalizeCode(code));
      await onDone();
    });
  };
  return (
    <>
      <Heading>Hello {status.first_name}, confirm your email</Heading>
      <p>{status.sponsor} invited you to {status.tenant} as {POPULATION_PHRASE[status.population] ?? "a guest"}, until {fmtDay(status.ends_at)}. We will send a six-digit code to the email address they gave us to check it is yours.</p>
      {!sent ? (
        <div><Button variant="primary" onClick={send} disabled={a.busy}>Send me a code</Button></div>
      ) : (
        <form onSubmit={check} className="stack">
          <label className="field">Six-digit code
            <input className="input claim-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]*" maxLength={7} required
              value={code} onChange={(e) => setCode(e.target.value)} aria-describedby="code-help" />
          </label>
          <p id="code-help" className="xs">The code works for ten minutes and five tries. {sent}</p>
          <div className="row tight">
            <Button variant="primary" type="submit" disabled={!codeReady(code) || a.busy}>Check the code</Button>
            <Button onClick={send} disabled={a.busy}>Send a new code</Button>
          </div>
        </form>
      )}
      <div role="status" aria-live="polite">{a.err && <Callout tone="bad">{a.err}</Callout>}</div>
    </>
  );
}

function ExistingAccount({ status, conn, onDone }: { status: ClaimStatus; conn: Conn; onDone: () => Promise<void> }) {
  const [answer, setAnswer] = useState<"yes" | "no" | "">("");
  const [note, setNote] = useState<string | null>(null);
  const a = useAction();
  const go = (e: FormEvent) => {
    e.preventDefault();
    if (!answer) return;
    return a.run(async () => {
      const r = await claimApi.existingAccount(conn.slug, conn.signer, conn.nonce, answer);
      if (r.message) setNote(r.message);
      await onDone();
    });
  };
  return (
    <>
      <Heading>Do you already have an account with {status.tenant}?</Heading>
      <p>Everyone is asked this. Your answer does not change what happens next: this account is set up either way.</p>
      <form onSubmit={go} className="stack">
        <fieldset className="claim-choices">
          <legend className="sr-only">Do you already have an account with {status.tenant}?</legend>
          <label className="row tight"><input type="radio" name="existing" value="no" checked={answer === "no"} onChange={() => setAnswer("no")} /> No, I do not</label>
          <label className="row tight"><input type="radio" name="existing" value="yes" checked={answer === "yes"} onChange={() => setAnswer("yes")} /> Yes, I do</label>
        </fieldset>
        {answer === "yes" && <p className="xs">An administrator will follow up about your existing account. You can carry on setting up this one.</p>}
        <div><Button variant="primary" type="submit" disabled={!answer || a.busy}>Continue</Button></div>
      </form>
      {note && <div role="status" aria-live="polite"><Callout tone="ok">{note}</Callout></div>}
      <div role="status" aria-live="polite">{a.err && <Callout tone="bad">{a.err}</Callout>}</div>
    </>
  );
}

function Credential({ status, conn }: { status: ClaimStatus; conn: Conn }) {
  const [pending, setPending] = useState<string | null>(status.pending === "organization" ? "Your organization will finish setting up your sign-in. We will email you when it is ready." : null);
  const a = useAction();
  const go = () => a.run(async () => {
    const r = await claimApi.credential(conn.slug, conn.signer, conn.nonce);
    if (r.status === "redirect" && r.redirect) {
      window.location.assign(r.redirect);
      return;
    }
    setPending(r.message ?? "Your organization will finish setting up your sign-in.");
  });
  return (
    <>
      <Heading>Choose how you sign in</Heading>
      {pending ? (
        <>
          <Callout tone="info">{pending}</Callout>
          <p>Your invitation stays open. You can close this page.</p>
        </>
      ) : (
        <>
          <p>Next you sign in with your organization's login, using a passkey. That sign-in is what you use from now on.</p>
          <div><Button variant="primary" onClick={go} disabled={a.busy}>Continue to sign-in</Button></div>
        </>
      )}
      <div role="status" aria-live="polite">{a.err && <Callout tone="bad">{a.err}</Callout>}</div>
    </>
  );
}

function Waiting({ why }: { why: "organization" | "identity_verification" }) {
  return (
    <>
      <Heading>{why === "identity_verification" ? "Your identity needs to be verified" : "Almost there"}</Heading>
      <Callout tone="info">
        {why === "identity_verification"
          ? "This invitation needs an identity check that is not available online yet. Your sponsor or your organization will contact you."
          : "Your organization will finish setting up your sign-in."}
      </Callout>
    </>
  );
}

function Done({ status }: { status: ClaimStatus }) {
  return (
    <>
      <Heading>You are all set, {status.first_name}</Heading>
      <Callout tone="ok" icon={<CheckCircle2 size={16} />}>Your sign-in for {status.tenant} is ready. Use the same login whenever you are asked to sign in.</Callout>
      <p>Your access runs until {fmtDay(status.ends_at)}. {status.sponsor} has been told. You can close this page.</p>
    </>
  );
}
