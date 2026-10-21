/**
 * Loads the signed-in user's preferences (issue #298) before the app renders, so every date on every page
 * is shown in their time zone and format, and sends them to their landing page when they open the app at
 * the root. It mounts only while signed in (inside SessionProvider), so each sign-in loads its own user's
 * copy. A failed load is not fatal: the defaults apply and the app carries on.
 */
import { Fragment, ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { Navigate } from "react-router-dom";
import { api } from "../api";
import { NO_PREFERENCES, PreferencesView, landingTarget, preferencesPath, setDisplayPrefs } from "../prefs";

interface Ctx {
  /** The user's preferences and the choices on offer; null when they could not be loaded. */
  view: PreferencesView | null;
  /** Takes a saved copy into use: dates everywhere re-render with it. */
  apply: (v: PreferencesView) => void;
}
const PrefsCtx = createContext<Ctx>({ view: null, apply: () => undefined });
export const usePreferences = () => useContext(PrefsCtx);

export function PrefsGate({ children }: { children: ReactNode }) {
  const [view, setView] = useState<PreferencesView | null | undefined>(undefined);
  const [rev, setRev] = useState(0);
  const [landing, setLanding] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api<PreferencesView>(preferencesPath)
      .then((v) => {
        if (!alive) return;
        setDisplayPrefs(v);
        setLanding(landingTarget(v, window.location.pathname, v.landing_pages));
        setView(v);
      })
      .catch(() => {
        if (!alive) return;
        setDisplayPrefs(NO_PREFERENCES);
        setView(null);
      });
    return () => {
      alive = false;
    };
  }, []);
  // the redirect happens once, when the app opens; the Home link later goes to Home
  useEffect(() => {
    if (landing) setLanding(null);
  }, [landing]);
  const apply = useCallback((v: PreferencesView) => {
    setDisplayPrefs(v);
    setView(v);
    setRev((r) => r + 1);
  }, []);
  const value = useMemo(() => ({ view: view ?? null, apply }), [view, apply]);
  if (view === undefined) return null;
  return (
    <PrefsCtx.Provider value={value}>
      {landing && <Navigate to={landing} replace />}
      <Fragment key={rev}>{children}</Fragment>
    </PrefsCtx.Provider>
  );
}
