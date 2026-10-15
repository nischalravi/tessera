import { FormEvent, ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import {
  LoginConnection, RateLimitedError, SIGNED_OUT, STEP_UP, SessionInfo, clearPendingAction, discover, getSession, logout,
  runPendingAction, startLogin, stepUpHref, takePendingAction,
} from "../api";
import { useConfirm } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { Button } from "../components/Button";
import { Callout } from "../components/Feedback";
import { store } from "./storage";

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
  const [stepUp, setStepUp] = useState<{ reason: string; href: string } | null>(null);

  const [limited, setLimited] = useState<number | null>(null); // seconds until the sign-in limit lets this browser retry

  const load = useCallback(async () => {
    try {
      setSession(await getSession());
      setError(null);
      setLimited(null);
    } catch (e: any) {
      if (e instanceof RateLimitedError) {
        setLimited(e.retryAfter);
        return;
      }
      setError(String(e.message ?? e));
    }
  }, []);

  // While rate limited: count down and retry on its own when the wait is over.
  useEffect(() => {
    if (limited === null) return;
    if (limited <= 0) {
      load();
      return;
    }
    const t = window.setTimeout(() => setLimited((s) => (s === null ? null : s - 1)), 1000);
    return () => window.clearTimeout(t);
  }, [limited, load]);

  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    const out = () => setSession(null);
    const up = (e: Event) => {
      const d = (e as CustomEvent).detail;
      const reason = d?.max_age
        ? `This action needs a phishing-resistant sign-in in the last ${Math.round(d.max_age / 60)} minutes.`
        : "This action needs a fresh phishing-resistant sign-in.";
      setStepUp({ reason, href: stepUpHref(d ?? {}) });
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
    const tenant = session.tenant.slug;
    store.set(LAST_TENANT, tenant);
    const signOut = async () => {
      await logout().catch(() => undefined);
      setSession(null);
    };
    // A fresh sign-in through the same tenant's IdP, back to this page.
    const reauthenticate = async () => {
      const here = window.location.pathname + window.location.search;
      await logout().catch(() => undefined);
      startLogin(tenant, null, here);
    };
    return { session, can: (p) => perms.has(p), signOut, reauthenticate };
  }, [session]);

  if (session === undefined) {
    if (limited !== null) return <RateLimited seconds={limited} onRetry={() => setLimited(0)} />;
    if (error) {
      return (
        <SignInFrame>
          <Callout tone="bad">Tessera is unreachable: {error}</Callout>
          <div><Button onClick={() => { setError(null); load(); }}>Try again</Button></div>
        </SignInFrame>
      );
    }
    return null;
  }
  if (!value) {
    return <SignIn />;
  }
  return (
    <Ctx.Provider value={value}>
      {stepUp && (
        <StepUpDialog reason={stepUp.reason} onClose={() => { clearPendingAction(); setStepUp(null); }}
          onContinue={() => window.location.assign(stepUp.href)} />
      )}
      <PendingActionResumer />
      {children}
    </Ctx.Provider>
  );
}

/** The sign-in limit's page: what happened, the countdown, and a way to try now. */
function RateLimited({ seconds, onRetry }: { seconds: number; onRetry: () => void }) {
  return (
    <SignInFrame>
      <h1 style={{ fontSize: "var(--fs-4)", margin: 0 }}>Too many sign-in attempts</h1>
      <Callout tone="warn">
        Tessera limits how often one network can sign in. <span role="status" aria-live="polite">
          {seconds > 0 ? `Trying again in ${seconds} second${seconds === 1 ? "" : "s"}…` : "Trying again…"}</span>
      </Callout>
      <div><Button variant="primary" onClick={onRetry} disabled={seconds <= 0}>Try again now</Button></div>
    </SignInFrame>
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

/** localStorage key of the last tenant signed in to (a per-browser convenience). */
const LAST_TENANT = "lastTenant";

/** The sign-in error the API sent the browser back with (/login?error=login_failed&request_id=…). */
function loginError(): { requestId: string | null } | null {
  const q = new URLSearchParams(window.location.search);
  return q.get("error") ? { requestId: q.get("request_id") } : null;
}

/** Where to go after signing in: the page the user was on (never /login itself). */
function returnTo(): string {
  const { pathname, search } = window.location;
  return pathname.startsWith("/login") ? "/" : pathname + search;
}

/**
 * The sign-in page (design §17). Tessera never sees a password: the user names their
 * organization (the tenant), picks its identity provider and signs in there. Admin roles are
 * active only after a phishing-resistant sign-in (a passkey or security key at the IdP).
 */
function SignIn() {
  const [tenant, setTenant] = useState(() => store.get<string>(LAST_TENANT, ""));
  const [connections, setConnections] = useState<LoginConnection[] | null>(null);
  const [asked, setAsked] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const failed = useMemo(loginError, []);

  const find = async (e: FormEvent) => {
    e.preventDefault();
    const slug = tenant.trim().toLowerCase();
    if (!slug) return;
    setBusy(true);
    setError(null);
    try {
      setConnections(await discover(slug));
      setAsked(slug);
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };

  const go = (c: LoginConnection) => {
    store.set(LAST_TENANT, asked);
    startLogin(asked, c.id, returnTo());
  };

  return (
    <SignInFrame>
      <h1 style={{ fontSize: "var(--fs-xl)" }}>Sign in to Tessera</h1>
      {failed && (
        <Callout tone="bad">
          Sign-in did not complete. Try again, or ask your administrator
          {failed.requestId ? <> and give them the reference <code>{failed.requestId}</code></> : null}.
        </Callout>
      )}
      <form className="stack" onSubmit={find}>
        <label className="stack-sm" style={{ display: "block" }}>
          <span className="small strong">Organization</span>
          <input className="input" value={tenant} onChange={(e) => { setTenant(e.target.value); setConnections(null); }}
            placeholder="your-company" autoComplete="organization" spellCheck={false} autoCapitalize="none"
            aria-describedby="tenant-help" style={{ width: "100%" }} required autoFocus />
          <span id="tenant-help" className="faint small">The name your administrator gave you, for example larkspur.</span>
        </label>
        {error && <Callout tone="bad">{error}</Callout>}
        {connections === null && (
          <div className="row">
            <Button type="submit" variant="primary" disabled={busy || !tenant.trim()}>{busy ? "Looking up…" : "Continue"}</Button>
          </div>
        )}
      </form>
      {connections !== null && connections.length === 0 && (
        <Callout tone="info">There is no sign-in for that organization. Check the name, or ask your administrator.</Callout>
      )}
      {connections !== null && connections.length > 0 && (
        <div className="stack-sm" role="group" aria-label="Sign in with">
          {connections.map((c) => (
            <Button key={c.id} variant={c.default ? "primary" : "ghost"} onClick={() => go(c)}>Sign in with {c.name}</Button>
          ))}
          <p className="faint small">You will sign in at your identity provider. Use a passkey or security key to activate admin roles.</p>
        </div>
      )}
    </SignInFrame>
  );
}

/**
 * Shown when an action needs a fresh phishing-resistant sign-in (401 step_up_required): it explains
 * why and, on Continue, re-authenticates at the IdP and comes back here (design §9.4, §17).
 */
function StepUpDialog({ reason, onClose, onContinue }: { reason: string; onClose: () => void; onContinue: () => void }) {
  return (
    <div role="alertdialog" aria-labelledby="stepup-h" aria-describedby="stepup-d" className="card stack"
      style={{ position: "fixed", right: "var(--s-4)", top: "calc(48px + var(--s-4))", zIndex: 90, width: "min(420px, calc(100vw - 32px))", boxShadow: "var(--shadow-lg, 0 8px 24px rgba(0,0,0,.18))" }}>
      <strong id="stepup-h">Confirm it's you</strong>
      <p id="stepup-d" className="small">
        {reason} Sign in again at your identity provider with a passkey or security key; you'll come back here and can
        finish the action.
      </p>
      <div className="row">
        <Button variant="primary" onClick={onContinue} autoFocus>Continue</Button>
        <Button variant="ghost" onClick={onClose}>Not now</Button>
      </div>
    </div>
  );
}

/**
 * After a step-up (?stepup=ok) offers to resume the action that needed it; after a refused one
 * (?stepup=failed) says so. A pending action older than ten minutes is dropped, and it is never
 * sent without the user confirming.
 */
function PendingActionResumer() {
  const confirm = useConfirm();
  const toast = useToast();
  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const result = q.get("stepup");
    if (!result) return;
    const requestId = q.get("request_id");
    q.delete("stepup");
    q.delete("request_id");
    window.history.replaceState(null, "", window.location.pathname + (q.size ? `?${q}` : "") + window.location.hash);
    const pending = takePendingAction();
    if (result !== "ok") {
      toast(`Your identity provider did not confirm a phishing-resistant sign-in, so nothing was changed.${requestId ? ` Reference: ${requestId}` : ""}`, { kind: "error" });
      return;
    }
    if (!pending) {
      toast("Signed in again. You can retry the action now.", { kind: "info" });
      return;
    }
    (async () => {
      const ok = await confirm({ title: `Resume: ${pending.label}?`, body: "You signed in again. Finish the action you started?", confirmLabel: "Resume" });
      if (ok === null) return;
      try {
        await runPendingAction(pending);
        toast(`Done: ${pending.label}`);
      } catch (e: any) {
        toast(String(e.message ?? e), { kind: "error" });
      }
    })();
  }, [confirm, toast]);
  return null;
}
