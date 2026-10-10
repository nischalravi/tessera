import { ReactNode, createContext, useContext, useEffect, useState } from "react";
import { store } from "./storage";

export type ThemePref = "system" | "light" | "dark";
interface ThemeCtx { pref: ThemePref; resolved: "light" | "dark"; setPref: (p: ThemePref) => void }

const Ctx = createContext<ThemeCtx>({ pref: "system", resolved: "light", setPref: () => {} });
export const useTheme = () => useContext(Ctx);

const mq = () => window.matchMedia("(prefers-color-scheme: dark)");

/** Follows the OS preference by default; an explicit choice is stored per browser. */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [pref, setPrefState] = useState<ThemePref>(() => store.get<ThemePref>("theme", "system"));
  const [sysDark, setSysDark] = useState(() => mq().matches);
  useEffect(() => {
    const m = mq();
    const on = () => setSysDark(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  useEffect(() => {
    const el = document.documentElement;
    if (pref === "system") el.removeAttribute("data-theme");
    else el.setAttribute("data-theme", pref);
  }, [pref]);
  const resolved = pref === "system" ? (sysDark ? "dark" : "light") : pref;
  const setPref = (p: ThemePref) => {
    setPrefState(p);
    store.set("theme", p);
  };
  return <Ctx.Provider value={{ pref, resolved, setPref }}>{children}</Ctx.Provider>;
}
