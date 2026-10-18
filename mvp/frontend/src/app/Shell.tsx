import { KeyboardEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { Bell, Check, CircleHelp, Inbox, Menu as MenuIcon, Monitor, Moon, Search, Settings, Sun } from "lucide-react";
import { IdentityRow, markNotificationsRead, relTime, useApi } from "../api";
import { Menu } from "../components/Menu";
import { initials } from "../components";
import { useToast } from "../components/Toast";
import { isTyping, modalOpen } from "../components/overlay";
import { useInbox } from "../features/inbox/model";
import { useOpenNotification } from "../features/notifications/open";
import { useNotifications } from "../features/notifications/model";
import { MOD, usePalette } from "./CommandPalette";
import { RAIL, isActive } from "./nav";
import { PERSONAS, usePersona } from "./persona";
import { ResultList, rankEntries, useEntityEntries } from "./search";
import { store } from "./storage";
import { useSession } from "./auth";
import { ThemePref, useTheme } from "./theme";


function useInboxCount() {
  const { items } = useInbox("mine");
  return items?.length ?? null;
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

// ------------------------------------------------------------------ rail
function Rail({ counts, onNavigate, id }: { counts: Record<string, number | null>; onNavigate: () => void; id: string }) {
  const { pathname } = useLocation();
  const ref = useRef<HTMLElement>(null);
  // arrow keys move between rail links; Home/End jump to the ends
  const onKey = (e: KeyboardEvent) => {
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;
    const links = Array.from(ref.current?.querySelectorAll<HTMLElement>("a.rail-item") ?? []);
    const i = links.indexOf(document.activeElement as HTMLElement);
    if (i < 0) return;
    e.preventDefault();
    const next = e.key === "Home" ? 0 : e.key === "End" ? links.length - 1 : (i + (e.key === "ArrowDown" ? 1 : links.length - 1)) % links.length;
    links[next]?.focus();
  };
  return (
    <nav className="rail" id={id} aria-label="Main navigation" ref={ref} onKeyDown={onKey}>
      {RAIL.map((g, gi) => (
        <div key={gi} role="group" aria-labelledby={g.label ? `rg-${gi}` : undefined}>
          {g.label && <div className="rail-group" id={`rg-${gi}`}>{g.label}</div>}
          {g.items.map((it) => {
            const Icon = it.icon;
            const on = isActive(it, pathname) || (it.id === "users" && pathname.startsWith("/directory/identities"));
            const n = counts[it.id];
            return (
              <NavLink
                key={it.id}
                to={it.path}
                end={it.path === "/"}
                className={() => `rail-item ${on ? "active" : ""}`}
                aria-current={on ? "page" : undefined}
                onClick={onNavigate}
                title={it.label}
              >
                <Icon size={18} strokeWidth={1.7} aria-hidden />
                <span className="rail-label">{it.label}</span>
                {n ? <span className="ct" aria-label={`${n} items`}>{n}</span> : null}
                {n ? <span className="dot-ct" aria-hidden /> : null}
              </NavLink>
            );
          })}
        </div>
      ))}
      <div className="rail-foot">
        <span className="rail-foot-text">Connectors: Workday, Okta, AWS, GitHub, Snowflake. All data is fictional.</span>
      </div>
    </nav>
  );
}

// --------------------------------------------------------------- search
function GlobalSearch() {
  const entries = useEntityEntries();
  const palette = usePalette();
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
        <Search size={16} aria-hidden />
        <span className="sr-only">Search</span>
        <input
          ref={ref}
          value={q}
          onChange={(e) => { setQ(e.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onKeyDown={onKey}
          placeholder="Search people, groups, apps, access and settings (/)"
          role="combobox"
          aria-expanded={show}
          aria-controls="gs"
          aria-activedescendant={show && results.length ? `gs-${active}` : undefined}
          autoComplete="off"
        />
        <button type="button" className="kbd-btn hide-narrow" onClick={() => palette.open(q)} aria-label="Open command palette" title="Command palette">
          <kbd>{MOD} K</kbd>
        </button>
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

// ---------------------------------------------------------- top bar menus
type Trigger = { onClick: () => void; "aria-expanded": boolean; "aria-haspopup": "menu" };
const TbBtn = ({ label, children, t }: { label: string; children: ReactNode; t: Trigger }) => (
  <button type="button" className="tb-btn" aria-label={label} title={label} {...t}>{children}</button>
);

function Notifications() {
  const { data, reload } = useNotifications();
  const open = useOpenNotification();
  const toast = useToast();
  const nav = useNavigate();
  const items = (data?.items ?? []).slice(0, 8);
  const unread = data?.unread ?? 0;
  const markAll = async () => {
    try {
      await markNotificationsRead({ all: true });
      reload();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };
  return (
    <Menu
      label="Notifications"
      items={[
        { heading: unread ? `Notifications · ${unread} unread` : "Notifications" },
        ...(items.length
          ? items.map((n) => ({
              label: (
                <span className="grow">
                  <span className={n.read_at ? "" : "notif-unread"}>{n.subject}</span>
                  <span className="faint small" style={{ display: "block" }}>{relTime(n.created_at)}</span>
                </span>
              ),
              onSelect: () => open(n),
            }))
          : [{ label: <span className="faint">Nothing new</span> }]),
        "divider",
        ...(unread ? [{ label: "Mark all as read", icon: <Check size={14} />, onSelect: markAll }] : []),
        { label: "All notifications and settings", onSelect: () => nav("/notifications") },
      ]}
      trigger={(t) => (
        <button type="button" className="tb-btn" aria-label={`Notifications${unread ? `, ${unread} unread` : ""}`} title="Notifications" {...t}>
          <Bell size={18} strokeWidth={1.7} aria-hidden />
          {unread ? <span className="tb-badge" aria-hidden>{unread > 99 ? "99+" : unread}</span> : null}
        </button>
      )}
    />
  );
}

function SettingsMenu() {
  const { pref, setPref } = useTheme();
  const nav = useNavigate();
  const opts: [ThemePref, string, ReactNode][] = [["light", "Light", <Sun size={14} />], ["dark", "Dark", <Moon size={14} />], ["system", "Match system", <Monitor size={14} />]];
  return (
    <Menu
      label="Settings"
      items={[
        { heading: "Theme" },
        ...opts.map(([v, l, i]) => ({ label: l, icon: i, checked: pref === v, onSelect: () => setPref(v) })),
        "divider",
        { label: "Admin settings", icon: <Settings size={14} />, onSelect: () => nav("/admin") },
      ]}
      trigger={(t) => <TbBtn label="Settings and theme" t={t}><Settings size={18} strokeWidth={1.7} /></TbBtn>}
    />
  );
}

function HelpMenu() {
  const palette = usePalette();
  return (
    <Menu
      label="Help"
      items={[
        { label: <span className="grow">Command palette <kbd style={{ float: "right" }}>{MOD} K</kbd></span>, onSelect: () => palette.open() },
        { heading: "Shortcuts" },
        { label: <span className="small">/ search · Esc closes a panel</span> },
        { label: <span className="small">Inbox: j/k move, a approve, d deny, r revoke, ? help</span> },
        "divider",
        { label: <span className="faint small">Tessera demo. All data is fictional.</span> },
      ]}
      trigger={(t) => <TbBtn label="Help" t={t}><CircleHelp size={18} strokeWidth={1.7} /></TbBtn>}
    />
  );
}

function UserMenu() {
  const { persona, setPersona } = usePersona();
  const { session, signOut, reauthenticate } = useSession();
  const navigate = useNavigate();
  const p = PERSONAS.find((x) => x.id === persona)!;
  const name = session.user.display_name;
  const a = session.authn;
  const assurance = `AAL${a.aal}${a.phishing_resistant ? " · phishing-resistant" : ""}`;
  return (
    <Menu
      label="User menu"
      items={[
        { heading: `Signed in as ${session.user.email ?? name}` },
        { label: <span className="faint small">{session.tenant.name} · {assurance} · signed in {relTime(a.auth_time.replace("Z", ""))}</span> },
        { label: <span className="faint small">Roles: {session.active_roles.join(", ") || "none active"}</span> },
        ...session.inactive_roles.map((r) => ({
          label: <span className="small" style={{ color: "var(--warning, #9a6700)" }}>{r.role} is inactive: sign in with a passkey to use it</span>,
          onSelect: () => { reauthenticate(); },
        })),
        ...(session.inactive_roles.length ? [{ label: "Re-authenticate", onSelect: () => { reauthenticate(); } }] : []),
        { label: "My sessions", onSelect: () => navigate("/sessions") },
        "divider",
        { heading: "View as (demo)" },
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
        { label: <span className="faint small">The view changes what Home emphasises, not what you're allowed to do: that comes from your roles.</span> },
        "divider",
        { label: "Sign out", onSelect: () => { signOut(); } },
      ]}
      trigger={(t) => (
        <button type="button" className="me" aria-label={`User menu: ${name}, ${session.tenant.name}, viewing as ${p.label}`} {...t}>
          <span className="tb-hide-sm">
            {name}
            <small>{session.tenant.name} · {p.label}</small>
          </span>
          <span className="avatar" aria-hidden>{initials(name)}</span>
        </button>
      )}
    />
  );
}

// ------------------------------------------------------------------ shell
export function Shell({ children }: { children: ReactNode }) {
  const [collapsedPref, setCollapsedState] = useState(() => store.get("sidebar.collapsed", false));
  const narrow = useMedia("(max-width: 768px)");
  const collapsed = collapsedPref && !narrow;
  const [drawer, setDrawer] = useState(false);
  const { pathname } = useLocation();
  const count = useInboxCount();
  const { data: people } = useApi<IdentityRow[]>("/identities?type=human");
  const nav = useNavigate();
  const menuBtn = useRef<HTMLButtonElement>(null);
  const setCollapsed = (v: boolean) => {
    setCollapsedState(v);
    store.set("sidebar.collapsed", v);
  };
  useEffect(() => setDrawer(false), [pathname]);
  useEffect(() => {
    if (!narrow) setDrawer(false);
  }, [narrow]);
  useEffect(() => {
    if (!drawer) return;
    const rail = document.getElementById("rail");
    (rail?.querySelector<HTMLElement>("a.rail-item.active") ?? rail?.querySelector<HTMLElement>("a.rail-item"))?.focus();
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") {
        setDrawer(false);
        menuBtn.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawer]);
  const toggleRail = () => (narrow ? setDrawer(!drawer) : setCollapsed(!collapsed));
  const railLabel = narrow ? (drawer ? "Close navigation" : "Open navigation") : collapsed ? "Expand navigation" : "Collapse navigation";
  return (
    <div className={`shell ${collapsed ? "collapsed" : ""} ${drawer ? "drawer-open" : ""}`}>
      <a href="#main" className="skip-link">Skip to content</a>
      <header className="topbar">
        <div className="tb-start">
          <button ref={menuBtn} type="button" className="tb-btn" onClick={toggleRail} aria-label={railLabel} title={railLabel} aria-controls="rail" aria-expanded={narrow ? drawer : !collapsed}>
            <MenuIcon size={18} strokeWidth={1.7} aria-hidden />
          </button>
          <Link to="/" className="brand" aria-label="Tessera home">
            <span className="logo" aria-hidden><i /><i /><i /><i /></span>
            <span className="brand-name">Tessera</span>
          </Link>
        </div>
        <GlobalSearch />
        <div className="tb-actions">
          <button type="button" className="tb-btn" onClick={() => nav("/inbox")} aria-label={`Inbox${count ? `, ${count} waiting` : ""}`} title="Inbox">
            <Inbox size={18} strokeWidth={1.7} aria-hidden />
            {count ? <span className="tb-badge" aria-hidden>{count > 99 ? "99+" : count}</span> : null}
          </button>
          <span className="tb-hide-sm"><Notifications /></span>
          <span className="tb-hide-sm"><SettingsMenu /></span>
          <span className="tb-hide-md"><HelpMenu /></span>
          <UserMenu />
        </div>
      </header>
      <div className="body">
        <Rail id="rail" counts={{ inbox: count, users: people?.length ?? null }} onNavigate={() => setDrawer(false)} />
        {drawer && <div className="overlay" style={{ zIndex: 64, top: "var(--topbar-h)" }} onClick={() => setDrawer(false)} aria-hidden />}
        <main id="main" className="main" tabIndex={-1}>
          {children}
        </main>
      </div>
      {/* keeps the collapse state discoverable for screen readers without a second control */}
      <span className="sr-only" aria-live="polite">{collapsed ? "Navigation collapsed to icons" : ""}</span>
    </div>
  );
}
