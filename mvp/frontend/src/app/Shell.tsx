import { KeyboardEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { Check, ChevronRight, Command, Inbox, Menu as MenuIcon, Monitor, Moon, PanelLeftClose, PanelLeftOpen, Search, Sun } from "lucide-react";
import { Button } from "../components/Button";
import { Menu } from "../components/Menu";
import { Avatar } from "../components/domain";
import { isTyping, modalOpen } from "../components/overlay";
import { useInbox } from "../features/inbox/model";
import { MOD, usePalette } from "./CommandPalette";
import { NAV, NavSection, sectionFor } from "./nav";
import { PERSONAS, usePersona } from "./persona";
import { ResultList, rankEntries, useEntityEntries } from "./search";
import { store } from "./storage";
import { ThemePref, useTheme } from "./theme";

function useInboxCount() {
  const { items } = useInbox("mine");
  return items?.length ?? null;
}

function SidebarSection({ s, count, onNavigate, collapsed }: { s: NavSection; count?: number | null; onNavigate: () => void; collapsed: boolean }) {
  const { pathname } = useLocation();
  const nav = useNavigate();
  const inSection = sectionFor(pathname)?.id === s.id;
  const [open, setOpen] = useState(inSection);
  useEffect(() => {
    if (inSection) setOpen(true);
  }, [inSection]);
  const Icon = s.icon;
  if (!s.children) {
    return (
      <NavLink to={s.path} end={s.path === "/"} className={({ isActive }) => `sb-link ${isActive ? "active" : ""}`} onClick={onNavigate} title={s.label}>
        <Icon size={17} aria-hidden />
        <span className="sb-label">{s.label}</span>
        {count ? <span className="count" aria-label={`${count} items`}>{count}</span> : null}
      </NavLink>
    );
  }
  return (
    <div className="sb-section">
      <button className={`sb-link ${inSection && (!open || collapsed) ? "active" : ""}`} aria-expanded={collapsed ? undefined : open} onClick={() => (collapsed ? nav(s.children![0].path) : setOpen(!open))} title={s.label}>
        <Icon size={17} aria-hidden />
        <span className="sb-label">{s.label}</span>
        <ChevronRight size={14} className="chev" aria-hidden />
      </button>
      {open && (
        <div className="sb-sub">
          {s.children.map((c) => (
            <NavLink key={c.path} to={c.path} className={({ isActive }) => `sb-link ${isActive ? "active" : ""}`} onClick={onNavigate}>
              <span className="sb-label">{c.label}</span>
            </NavLink>
          ))}
        </div>
      )}
    </div>
  );
}

function Sidebar({ collapsed, setCollapsed, onNavigate, count }: { collapsed: boolean; setCollapsed: (v: boolean) => void; onNavigate: () => void; count: number | null }) {
  return (
    <aside className="sidebar" aria-label="Main navigation">
      <div className="sb-brand">
        <div className="logo" aria-hidden><i /><i /><i /><i /></div>
        <div className="sb-brand-text">
          Tessera
          <small>Larkspur Labs (demo)</small>
        </div>
      </div>
      <nav className="stack-sm" style={{ marginTop: 0 }}>
        {NAV.map((s) => (
          <SidebarSection
            key={s.id}
            s={s}
            count={s.id === "inbox" ? count : undefined}
            collapsed={collapsed}
            onNavigate={onNavigate}
          />
        ))}
      </nav>
      <div className="sb-foot">
        <div className="sb-foot-text">Connectors: Workday, Okta, AWS, GitHub, Snowflake. All data is fictional.</div>
        <Button className="sb-collapse" variant="ghost" size="sm" icon={collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />} onClick={() => setCollapsed(!collapsed)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} title={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
          {collapsed ? null : <span className="sb-label">Collapse</span>}
        </Button>
      </div>
    </aside>
  );
}

function GlobalSearch() {
  const entries = useEntityEntries();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const ref = useRef<HTMLInputElement>(null);
  const results = useMemo(() => (q.trim() ? rankEntries(q, entries, 5) : []), [q, entries]);
  useEffect(() => setActive(0), [q]);
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "/" && !isTyping(e) && !modalOpen()) {
        e.preventDefault();
        ref.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const go = (i: number) => {
    const r = results[i];
    if (!r) return;
    r.e.run?.();
    setQ("");
    setOpen(false);
    ref.current?.blur();
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(results.length - 1, a + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
    else if (e.key === "Enter") { e.preventDefault(); go(active); }
    else if (e.key === "Escape") { setQ(""); setOpen(false); ref.current?.blur(); }
  };
  const show = open && q.trim().length > 0;
  return (
    <div className="search-wrap">
      <label className="search-trigger">
        <Search size={15} aria-hidden />
        <span className="sr-only">Search</span>
        <input
          ref={ref}
          value={q}
          onChange={(e) => { setQ(e.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onKeyDown={onKey}
          placeholder="Search people, apps, roles…"
          role="combobox"
          aria-expanded={show}
          aria-controls="gs"
          aria-activedescendant={show && results.length ? `gs-${active}` : undefined}
          autoComplete="off"
        />
        <kbd className="hide-narrow" aria-hidden>/</kbd>
      </label>
      {show && (
        <div className="search-pop">
          <div className="results pop">
            {results.length ? <ResultList id="gs" items={results} active={active} onPick={(e) => go(results.findIndex((r) => r.e === e))} onHover={setActive} /> : <div className="empty">No results for “{q}”.</div>}
          </div>
        </div>
      )}
    </div>
  );
}

function ThemeToggle() {
  const { pref, resolved, setPref } = useTheme();
  const icon = pref === "system" ? <Monitor size={16} /> : resolved === "dark" ? <Moon size={16} /> : <Sun size={16} />;
  const opts: [ThemePref, string, ReactNode][] = [["light", "Light", <Sun size={14} />], ["dark", "Dark", <Moon size={14} />], ["system", "Match system", <Monitor size={14} />]];
  return (
    <Menu
      label="Theme"
      items={opts.map(([v, l, i]) => ({ label: l, icon: i, checked: pref === v, onSelect: () => setPref(v) }))}
      trigger={(t) => <Button variant="ghost" icon={icon} label={`Theme: ${pref === "system" ? "match system" : pref}`} {...t} />}
    />
  );
}

function UserMenu() {
  const { persona, setPersona, actor, me } = usePersona();
  const p = PERSONAS.find((x) => x.id === persona)!;
  return (
    <Menu
      label="User menu"
      items={[
        { heading: `Signed in as ${actor} (demo)` },
        "divider",
        { heading: "View as" },
        ...PERSONAS.map((x) => ({
          label: (
            <span className="grow">
              {x.label}
              <span className="faint small" style={{ display: "block" }}>{x.who} · {x.blurb}</span>
            </span>
          ),
          icon: persona === x.id ? <Check size={14} /> : <span style={{ width: 14 }} />,
          checked: persona === x.id,
          onSelect: () => setPersona(x.id),
        })),
        "divider",
        { label: <span className="faint small">Persona is a demo stand-in until sign-in (Phase 0). It changes what Home shows, not what you're allowed to do.</span> },
      ]}
      trigger={(t) => (
        <button className="btn ghost" style={{ paddingLeft: 4 }} aria-label={`User menu: ${actor}, viewing as ${p.label}`} {...t}>
          <Avatar name={actor} />
          <span className="hide-narrow small" style={{ textAlign: "left", lineHeight: 1.2 }}>
            {me?.name ?? actor}
            <span className="faint" style={{ display: "block", fontSize: 11 }}>{p.label}</span>
          </span>
        </button>
      )}
    />
  );
}

function useMedia(query: string) {
  const [m, setM] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const mq = window.matchMedia(query);
    const on = () => setM(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [query]);
  return m;
}

export function Shell({ children }: { children: ReactNode }) {
  const [collapsedPref, setCollapsedState] = useState(() => store.get("sidebar.collapsed", false));
  const narrow = useMedia("(max-width: 860px)");
  const collapsed = collapsedPref && !narrow;
  const [drawer, setDrawer] = useState(false);
  const { pathname } = useLocation();
  const palette = usePalette();
  const count = useInboxCount();
  const nav = useNavigate();
  const setCollapsed = (v: boolean) => {
    setCollapsedState(v);
    store.set("sidebar.collapsed", v);
  };
  useEffect(() => setDrawer(false), [pathname]);
  useEffect(() => {
    if (!drawer) return;
    const onKey = (e: globalThis.KeyboardEvent) => e.key === "Escape" && setDrawer(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawer]);
  return (
    <div className={`shell ${collapsed ? "collapsed" : ""} ${drawer ? "drawer-open" : ""}`}>
      <a href="#main" className="skip-link">Skip to content</a>
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} onNavigate={() => setDrawer(false)} count={count} />
      {drawer && <div className="overlay" style={{ zIndex: 64 }} onClick={() => setDrawer(false)} aria-hidden />}
      <div className="content-col">
        <header className="topbar">
          <Button className="menu-btn" variant="ghost" icon={<MenuIcon size={18} />} label="Open navigation" onClick={() => setDrawer(true)} aria-expanded={drawer} />
          <GlobalSearch />
          <Button variant="ghost" className="hide-narrow" onClick={() => palette.open()} aria-label="Open command palette" title="Command palette">
            <Command size={15} aria-hidden /> <kbd>{MOD} K</kbd>
          </Button>
          <div className="spacer" />
          <Button variant="ghost" icon={<Inbox size={17} />} onClick={() => nav("/inbox")} aria-label={`Inbox${count ? `, ${count} waiting` : ""}`} title="Inbox">
            {count ? <span className="badge accent tnum">{count}</span> : null}
          </Button>
          <ThemeToggle />
          <UserMenu />
        </header>
        <main id="main" className="main" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
