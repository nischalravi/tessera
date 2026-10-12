import { FormEvent, ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { DevUser, SIGNED_OUT, STEP_UP, SessionInfo, devLogin, devLoginUsers, getSession, isRateLimited, logout } from "../api";
import { Button } from "../components/Button";
import { Callout } from "../components/Feedback";

/**
 * Who is signed in (design §17). The session lives in an HttpOnly cookie the API sets; this
 * provider only loads GET /api/auth/session, which also hands over the CSRF token. Signed out,
 * the app shows the sign-in page instead of its routes. Hiding controls with can() is for
 * usability only: the API enforces every permission itself.
 */
interface SessionCtx {
  session: SessionInfo;
  can: (permission: string) => boolean;
  signOut: () => Promise<void>;
  /** End this session and show sign-in again (e.g. to get a fresh phishing-resistant sign-in). */
  reauthenticate: () => Promise<void>;
}

const Ctx = createContext<SessionCtx | null>(null);

/** The signed-in session. Only used under SessionProvider, which renders nothing else signed out. */
export function useSession(): SessionCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useSession outside SessionProvider");
  return c;
}

/** The session if there is one (for components that also render outside the provider). */
export const useOptionalSession = () => useContext(Ctx);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null | undefined>(undefined);
  const [error, setError] = useState<unknown>(null);
  const [stepUp, setStepUp] = useState<string | null>(null);
  const [lastEmail, setLastEmail] = useState<string | null>(null);
  const [lastTenant, setLastTenant] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setSession(await getSession());
      setError(null);
    } catch (e: unknown) {
      setError(e);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    const out = () => setSession(null);
    const up = (e: Event) => {
      const d = (e as CustomEvent).detail;
      setStepUp(d?.max_age ? `This action needs a phishing-resistant sign-in in the last ${Math.round(d.max_age / 60)} minutes.` : "This action needs a fresh phishing-resistant sign-in.");
    };
    window.addEventListener(SIGNED_OUT, out);
    window.addEventListener(STEP_UP, up);
    return () => {
      window.removeEventListener(SIGNED_OUT, out);
      window.removeEventListener(STEP_UP, up);
    };
  }, []);

  const value = useMemo<SessionCtx | null>(() => {
    if (!session) return null;
    const perms = new Set(session.permissions);
    const end = async () => {
      setLastEmail(session.user.email);
      setLastTenant(session.tenant.slug);
      await logout().catch(() => undefined);
      setSession(null);
    };
    return { session, can: (p) => perms.has(p), signOut: end, reauthenticate: end };
  }, [session]);

  if (session === undefined) {
    if (isRateLimited(error)) return <SignInFrame><RateLimited secs={error.retryAfter ?? 1} onRetry={load} /></SignInFrame>;
    return error ? <SignInFrame><Callout tone="bad">Tessera is unreachable: {String((error as Error).message ?? error)}</Callout></SignInFrame> : null;
  }
  if (!value) {
    return <SignIn preferEmail={lastEmail} preferTenant={lastTenant} onSignedIn={async () => { setStepUp(null); await load(); }} />;
  }
  return (
    <Ctx.Provider value={value}>
      {stepUp && <StepUpNotice reason={stepUp} onClose={() => setStepUp(null)} onSignIn={value.reauthenticate} />}
      {children}
    </Ctx.Provider>
  );
}

function SignInFrame({ children }: { children: ReactNode }) {
  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: "var(--s-4)", background: "var(--bg)" }}>
      <div className="card stack" style={{ width: "min(520px, 100%)" }}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <span className="brand" aria-label="Tessera"><span className="logo" aria-hidden><i /><i /><i /><i /></span> <strong>Tessera</strong></span>
        </div>
        {children}
      </div>
    </div>
  );
}

const METHOD_LABELS: Record<string, string> = {
  passkey: "Passkey (phishing-resistant)",
  hardware_key: "Hardware security key (phishing-resistant)",
  password_otp: "Password + OTP",
  password: "Password only",
};

/** The demo tenant the dev sign-in page starts with. */
const DEMO_TENANT = "larkspur";

/**
 * The sign-in page. Until sign-in through the tenant's identity provider lands (Phase 0 PR6
 * and PR7), a development server (TESSERA_ENV=dev, or test with TESSERA_DEV_LOGIN on loopback)
 * offers dev sign-in: name the tenant, pick one of its seeded dev IdP users and how they
 * authenticate. Admin roles are active only after a phishing-resistant method (passkey or
 * hardware key).
 */
function SignIn({ onSignedIn, preferEmail, preferTenant }: { onSignedIn: () => Promise<void>; preferEmail: string | null; preferTenant: string | null }) {
  const [tenant, setTenant] = useState(preferTenant ?? DEMO_TENANT);
  const [shown, setShown] = useState(preferTenant ?? DEMO_TENANT);
  const [dev, setDev] = useState<{ users: DevUser[]; methods: string[] } | null | undefined>(undefined);
  const [choice, setChoice] = useState("");
  const [method, setMethod] = useState("passkey");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [limited, setLimited] = useState<number | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let alive = true;
    devLoginUsers(shown)
      .then((d) => {
        if (!alive) return;
        setDev(d);
        setError(null);
        const preferred = d?.users.find((u) => u.email === preferEmail) ?? d?.users[0];
        setChoice(preferred ? preferred.subject : "");
        setLimited(null);
      })
      .catch((e) => {
        if (!alive) return;
        if (isRateLimited(e)) setLimited(e.retryAfter ?? 1);
        else setError(String(e.message ?? e));
      });
    return () => {
      alive = false;
    };
  }, [shown, preferEmail, attempt]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await devLogin(shown, choice, method);
      await onSignedIn();
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };

  if (limited !== null) return <SignInFrame><RateLimited secs={limited} onRetry={() => setAttempt((a) => a + 1)} /></SignInFrame>;
  if (dev === undefined && !error) return <SignInFrame><p className="faint">Loading…</p></SignInFrame>;
  if (dev === null) {
    return (
      <SignInFrame>
        <h1 style={{ fontSize: "var(--fs-xl)" }}>Sign in</h1>
        <Callout tone="info">Sign-in through your organization's identity provider is not available on this server yet.</Callout>
      </SignInFrame>
    );
  }
  const users = dev?.users ?? [];
  return (
    <SignInFrame>
      <h1 style={{ fontSize: "var(--fs-xl)" }}>Sign in to Tessera</h1>
      <Callout tone="warn">
        Development sign-in. This server runs with TESSERA_ENV=dev (or test, opted in) and signs you in as a user of its dev
        identity provider. Production servers sign you in through your organization's identity provider.
      </Callout>
      <form className="stack" onSubmit={submit}>
        <label className="stack-sm" style={{ display: "block" }}>
          <span className="small strong">Tenant</span>
          <span className="row tight">
            <input className="input" value={tenant} onChange={(e) => setTenant(e.target.value.trim())}
              onBlur={() => setShown(tenant)} onKeyDown={(e) => { if (e.key === "Enter" && tenant !== shown) { e.preventDefault(); setShown(tenant); } }}
              autoComplete="organization" spellCheck={false} style={{ flex: 1 }} required />
            <Button type="button" variant="ghost" onClick={() => setShown(tenant)} disabled={!tenant || tenant === shown}>Show users</Button>
          </span>
        </label>
        <label className="stack-sm" style={{ display: "block" }}>
          <span className="small strong">User</span>
          <select className="input" value={choice} onChange={(e) => setChoice(e.target.value)} style={{ width: "100%" }} required disabled={users.length === 0}>
            {users.length === 0 && <option value="">No dev sign-in users for this tenant</option>}
            {users.map((u) => (
              <option key={u.subject} value={u.subject}>
                {u.display_name} · {u.email} · {u.roles.join(", ") || "no roles"}
              </option>
            ))}
          </select>
        </label>
        <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="small strong">How they sign in</legend>
          {(dev?.methods ?? []).map((m) => (
            <label key={m} className="row tight small">
              <input type="radio" name="method" value={m} checked={method === m} onChange={() => setMethod(m)} />
              {METHOD_LABELS[m] ?? m}
            </label>
          ))}
        </fieldset>
        {error && <Callout tone="bad">{error}</Callout>}
        <div className="row">
          <Button type="submit" variant="primary" disabled={busy || !choice || tenant !== shown}>{busy ? "Signing in…" : "Sign in"}</Button>
        </div>
      </form>
    </SignInFrame>
  );
}

/** Shown when an action needs a fresh phishing-resistant sign-in (401 step_up_required). A bottom sheet on phones. */
function StepUpNotice({ reason, onClose, onSignIn }: { reason: string; onClose: () => void; onSignIn: () => Promise<void> }) {
  return (
    <div role="alertdialog" aria-labelledby="stepup-h" aria-describedby="stepup-d" className="card stack stepup">
      <strong id="stepup-h">Sign in again to continue</strong>
      <p id="stepup-d" className="small">{reason} Sign in again with a passkey, then retry the action.</p>
      <div className="row wrap">
        <Button variant="primary" onClick={onSignIn} autoFocus>Sign in again</Button>
        <Button variant="ghost" onClick={onClose}>Not now</Button>
      </div>
    </div>
  );
}

/** 429 from the sign-in endpoints: say why, count down Retry-After, then offer a retry. */
function RateLimited({ secs, onRetry }: { secs: number; onRetry: () => void }) {
  const [left, setLeft] = useState(secs);
  useEffect(() => {
    setLeft(secs);
    const t = window.setInterval(() => setLeft((l) => Math.max(0, l - 1)), 1000);
    return () => window.clearInterval(t);
  }, [secs]);
  return (
    <div className="stack">
      <h1 style={{ fontSize: "var(--fs-xl)" }}>Too many sign-in attempts</h1>
      <p className="small">
        Tessera limits how often one network can sign in, to slow down password-guessing and abuse. Nothing is wrong with your
        account. {left > 0 ? `You can try again in ${left} second${left === 1 ? "" : "s"}.` : "You can try again now."}
      </p>
      <span className="sr-only" aria-live="polite">{left === 0 ? "You can try again now." : ""}</span>
      <div><Button variant="primary" disabled={left > 0} onClick={onRetry}>Try again</Button></div>
    </div>
  );
}
