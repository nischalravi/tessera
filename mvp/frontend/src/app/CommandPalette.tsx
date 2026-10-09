import { KeyboardEvent, ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Ban, CircleCheck, ClipboardCheck, Command, KeyRound, Layers, Moon, Network, RotateCcw, Search, ShoppingCart, Sun, Upload, UserCog, UserRound,
} from "lucide-react";
import { IdentityRow } from "../api";
import { useModal } from "../components/overlay";
import { useIdentityActions } from "./actions";
import { PERSONAS, usePersona } from "./persona";
import { Entry, ResultList, rankEntries, useEntityEntries } from "./search";
import { useTheme } from "./theme";

interface PaletteCtx { open: (q?: string) => void }
const Ctx = createContext<PaletteCtx>({ open: () => {} });
export const usePalette = () => useContext(Ctx);

export const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
export const MOD = isMac ? "⌘" : "Ctrl";

export function PaletteProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ q: string } | null>(null);
  const open = useCallback((q = "") => setState({ q }), []);
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setState((s) => (s ? null : { q: "" }));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <Ctx.Provider value={{ open }}>
      {children}
      {state && <Palette initial={state.q} onClose={() => setState(null)} />}
    </Ctx.Provider>
  );
}

function Palette({ initial, onClose }: { initial: string; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const [q, setQ] = useState(initial);
  const [stack, setStack] = useState<{ scope: string; entries: () => Entry[] }[]>([]);
  const [active, setActive] = useState(0);
  const nav = useNavigate();
  const acts = useIdentityActions();
  const { setPref, resolved } = useTheme();
  const { setPersona, persona } = usePersona();
  const entities = useEntityEntries();
  useModal(ref, () => (stack.length ? setStack((s) => s.slice(0, -1)) : onClose()));

  const people = entities.filter((e) => e.identity);
  const humans = people.filter((e) => e.identity!.type === "human");

  /** Entries that pick an identity and then run `fn` on it. */
  const pickIdentity = (scope: string, pool: Entry[], fn: (i: IdentityRow) => void, hint: string): Entry["next"] => ({
    scope,
    entries: () => pool.map((e) => ({ ...e, group: "Choose an identity", next: undefined, hint, run: () => fn(e.identity!) })),
  });

  const identityActions = (i: IdentityRow): Entry[] => {
    const g = i.name;
    const list: Entry[] = [
      { id: "ia-open", group: g, label: "Open profile", icon: <UserRound size={15} />, run: () => acts.open(i) },
      { id: "ia-graph", group: g, label: "Open in access graph", icon: <Network size={15} />, run: () => acts.openGraph(i) },
      { id: "ia-req", group: g, label: `Request access for ${i.name}`, icon: <ShoppingCart size={15} />, run: () => acts.requestFor(i) },
      { id: "ia-rev", group: g, label: "Review their access", icon: <ClipboardCheck size={15} />, run: () => acts.reviewAccess(i) },
    ];
    if (i.type === "human") list.push({ id: "ia-pw", group: g, label: "Reset password…", icon: <RotateCcw size={15} />, run: () => acts.resetPassword(i) });
    list.push({ id: "ia-dis", group: g, label: "Disable…", icon: <Ban size={15} />, run: () => acts.disable(i) });
    return list;
  };

  const actions: Entry[] = useMemo(() => [
    { id: "a-request", group: "Actions", label: "Request access", icon: <ShoppingCart size={15} />, keywords: "new ask catalog", run: () => nav("/access/request") },
    { id: "a-approve", group: "Actions", label: "Approve pending requests", icon: <CircleCheck size={15} />, keywords: "inbox approvals jit", run: () => nav("/inbox?filter=approval") },
    { id: "a-disable", group: "Actions", label: "Disable user…", icon: <Ban size={15} />, keywords: "deactivate suspend block offboard", next: pickIdentity("Disable user", people, (i) => acts.disable(i), "Disable") },
    { id: "a-reset", group: "Actions", label: "Reset password…", icon: <RotateCcw size={15} />, keywords: "credential login", next: pickIdentity("Reset password", humans, (i) => acts.resetPassword(i), "Reset") },
    { id: "a-review", group: "Actions", label: "Start access review", icon: <ClipboardCheck size={15} />, keywords: "certification campaign attestation", run: () => acts.startCampaign() },
    { id: "a-graph", group: "Actions", label: "Open graph for…", icon: <Network size={15} />, keywords: "paths explorer", next: pickIdentity("Open graph for", people, (i) => acts.openGraph(i), "Open graph") },
    { id: "a-reqfor", group: "Actions", label: "Request access for someone…", icon: <KeyRound size={15} />, keywords: "on behalf", next: pickIdentity("Request access for", people, (i) => acts.requestFor(i), "Request") },
    { id: "a-role", group: "Actions", label: "Create role", icon: <Layers size={15} />, keywords: "new business role", hint: "Preview", run: () => nav("/directory/roles?new=1") },
    { id: "a-import", group: "Actions", label: "Import users", icon: <Upload size={15} />, keywords: "csv upload bulk people", run: () => nav("/directory/people?import=1") },
    { id: "a-joiner", group: "Actions", label: "Onboard a new person", icon: <UserRound size={15} />, keywords: "create user joiner hire new", run: () => nav("/directory/people?new=1") },
    { id: "a-theme", group: "Actions", label: resolved === "dark" ? "Switch to light theme" : "Switch to dark theme", icon: resolved === "dark" ? <Sun size={15} /> : <Moon size={15} />, keywords: "theme dark light appearance", run: () => setPref(resolved === "dark" ? "light" : "dark") },
    ...PERSONAS.filter((p) => p.id !== persona).map((p) => ({ id: `a-persona-${p.id}`, group: "Actions", label: `View as ${p.label.toLowerCase()}`, icon: <UserCog size={15} />, keywords: "persona switch role demo", run: () => setPersona(p.id) })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [people, humans, resolved, persona]);

  const pool: Entry[] = useMemo(() => {
    if (stack.length) return stack[stack.length - 1].entries();
    const withDrill = entities.map((e) => (e.identity ? { ...e, next: { scope: e.identity.name, entries: () => identityActions(e.identity!) } } : e));
    return q.trim() ? [...actions, ...withDrill] : actions;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stack, entities, actions, q]);

  const results = useMemo(() => rankEntries(q, pool, stack.length ? 50 : q.trim() ? 6 : 20), [q, pool, stack.length]);
  useEffect(() => setActive(0), [q, stack.length]);
  useEffect(() => {
    document.getElementById(`pal-${active}`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const pick = (e: Entry) => {
    if (e.next) {
      setStack([...stack, e.next]);
      setQ("");
      inputRef.current?.focus();
      return;
    }
    onClose();
    e.run?.();
  };

  const onKey = (ev: KeyboardEvent<HTMLInputElement>) => {
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      setActive((a) => Math.min(results.length - 1, a + 1));
    } else if (ev.key === "ArrowUp") {
      ev.preventDefault();
      setActive((a) => Math.max(0, a - 1));
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      const r = results[active];
      if (r) pick(r.e);
    } else if (ev.key === "Backspace" && !q && stack.length) {
      ev.preventDefault();
      setStack(stack.slice(0, -1));
    }
  };

  const scope = stack[stack.length - 1]?.scope;
  return (
    <div className="palette-wrap">
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className="palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <div className="palette-input">
          <Search size={18} aria-hidden style={{ color: "var(--text-3)" }} />
          {scope && <span className="palette-scope">{scope}</span>}
          <input
            ref={inputRef}
            data-autofocus
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
            placeholder={scope ? "Search identities…" : "Search people, roles, apps, pages, or type a command…"}
            role="combobox"
            aria-expanded="true"
            aria-controls="pal"
            aria-activedescendant={results.length ? `pal-${active}` : undefined}
            aria-label="Command"
            autoComplete="off"
            spellCheck={false}
          />
          <kbd>Esc</kbd>
        </div>
        <div className="results">
          {results.length ? (
            <ResultList id="pal" items={results} active={active} onPick={pick} onHover={setActive} />
          ) : (
            <div className="empty">No matches for “{q}”. Try a name, a system like “aws”, or an action like “disable”.</div>
          )}
        </div>
        <div className="palette-foot" aria-hidden>
          <span><kbd>↑</kbd> <kbd>↓</kbd> move</span>
          <span><kbd>↵</kbd> {results[active]?.e.next ? "show actions" : "run"}</span>
          {stack.length > 0 && <span><kbd>⌫</kbd> back</span>}
          <span><kbd>Esc</kbd> {stack.length ? "back" : "close"}</span>
          <span style={{ marginLeft: "auto" }} className="row tight"><Command size={11} /> Search a person, then press enter for actions on them</span>
        </div>
      </div>
    </div>
  );
}
