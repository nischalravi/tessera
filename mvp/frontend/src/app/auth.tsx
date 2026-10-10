import { FormEvent, ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { DevUser, SIGNED_OUT, STEP_UP, SessionInfo, devLogin, devLoginUsers, getSession, logout } from "../api";
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
  const [error, setError] = useState<string | null>(null);
  const [stepUp, setStepUp] = useState<string | null>(null);
  const [lastEmail, setLastEmail] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setSession(await getSession());
      setError(null);
    } catch (e: any) {
      setError(String(e.message ?? e));
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
      await logout().catch(() => undefined);
      setSession(null);
    };
    return { session, can: (p) => perms.has(p), signOut: end, reauthenticate: end };
  }, [session]);

  if (session === undefined) {
    return error ? <SignInFrame><Callout tone="bad">Tessera is unreachable: {error}</Callout></SignInFrame> : null;
  }
  if (!value) {
    return <SignIn preferEmail={lastEmail} onSignedIn={async () => { setStepUp(null); await load(); }} />;
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

/**
 * The sign-in page. Until sign-in through the tenant's identity provider lands (Phase 0 PR6
 * and PR7), a development server (TESSERA_ENV=dev or test) offers dev sign-in: pick a seeded
 * user of the dev IdP and how they authenticate. Admin roles are active only after a
 * phishing-resistant method (passkey or hardware key).
 */
function SignIn({ onSignedIn, preferEmail }: { onSignedIn: () => Promise<void>; preferEmail: string | null }) {
  const [dev, setDev] = useState<{ users: DevUser[]; methods: string[] } | null | undefined>(undefined);
  const [choice, setChoice] = useState("");
  const [method, setMethod] = useState("passkey");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    devLoginUsers()
      .then((d) => {
        setDev(d);
        const preferred = d?.users.find((u) => u.email === preferEmail) ?? d?.users[0];
        if (preferred) setChoice(`${preferred.tenant}|${preferred.subject}`);
      })
      .catch((e) => setError(String(e.message ?? e)));
  }, [preferEmail]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const [tenant, subject] = choice.split("|");
    setBusy(true);
    setError(null);
    try {
      await devLogin(tenant, subject, method);
      await onSignedIn();
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };

  if (dev === undefined && !error) return <SignInFrame><p className="faint">Loading…</p></SignInFrame>;
  if (dev === null) {
    return (
      <SignInFrame>
        <h1 style={{ fontSize: "var(--fs-xl)" }}>Sign in</h1>
        <Callout tone="info">Sign-in through your organization's identity provider is not available on this server yet.</Callout>
      </SignInFrame>
    );
  }
  const tenants = [...new Set((dev?.users ?? []).map((u) => u.tenant_name))];
  return (
    <SignInFrame>
      <h1 style={{ fontSize: "var(--fs-xl)" }}>Sign in to Tessera</h1>
      <Callout tone="warn">
        Development sign-in. This server runs with TESSERA_ENV=dev or test and signs you in as a user of its dev identity
        provider. Production servers sign you in through your organization's identity provider.
      </Callout>
      <form className="stack" onSubmit={submit}>
        <label className="stack-sm" style={{ display: "block" }}>
          <span className="small strong">User</span>
          <select className="input" value={choice} onChange={(e) => setChoice(e.target.value)} style={{ width: "100%" }} required>
            {tenants.map((t) => (
              <optgroup key={t} label={t}>
                {(dev?.users ?? []).filter((u) => u.tenant_name === t).map((u) => (
                  <option key={`${u.tenant}|${u.subject}`} value={`${u.tenant}|${u.subject}`}>
                    {u.display_name} · {u.email} · {u.roles.join(", ") || "no roles"}
                  </option>
                ))}
              </optgroup>
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
          <Button type="submit" variant="primary" disabled={busy || !choice}>{busy ? "Signing in…" : "Sign in"}</Button>
        </div>
      </form>
    </SignInFrame>
  );
}

/** Shown when an action needs a fresh phishing-resistant sign-in (401 step_up_required). */
function StepUpNotice({ reason, onClose, onSignIn }: { reason: string; onClose: () => void; onSignIn: () => Promise<void> }) {
  return (
    <div role="alertdialog" aria-labelledby="stepup-h" className="card stack"
      style={{ position: "fixed", right: "var(--s-4)", bottom: "var(--s-4)", zIndex: 90, width: "min(420px, calc(100vw - 32px))", boxShadow: "var(--shadow-lg, 0 8px 24px rgba(0,0,0,.18))" }}>
      <strong id="stepup-h">Sign in again to continue</strong>
      <p className="small">{reason} Sign in again with a passkey, then retry the action.</p>
      <div className="row">
        <Button variant="primary" onClick={onSignIn}>Sign in again</Button>
        <Button variant="ghost" onClick={onClose}>Not now</Button>
      </div>
    </div>
  );
}
