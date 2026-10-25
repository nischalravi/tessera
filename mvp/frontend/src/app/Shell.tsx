import { KeyboardEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { Bell, BellRing, Check, CircleHelp, Inbox, Menu as MenuIcon, Monitor, Moon, Search, Settings, Sun } from "lucide-react";
import { AlertRow, IdentityRow, markNotificationsRead, relTime, severityTone, useApi } from "../api";
import { Menu } from "../components/Menu";
import { Badge, initials } from "../components";
import { useToast } from "../components/Toast";
import { isTyping, modalOpen } from "../components/overlay";
import { useInbox } from "../features/inbox/model";
import { useOpenNotification } from "../features/notifications/open";
import { useNotifications } from "../features/notifications/model";
import { MOD, usePalette } from "./CommandPalette";
import { isActive, visibleRail } from "./nav";
import { inactiveRoleHint } from "./roles";
import { PERSONAS, usePersona } from "./persona";
import { ResultList, rankEntries, useEntityEntries } from "./search";
import { store } from "./storage";
import { useSession } from "./auth";
import { ThemePref, useTheme } from "./theme";
import { applyLabels } from "../labels";
import { safeBrandVars, safeLogoUrl } from "../branding";
import { consoleBrandStyle, productName, useConsoleBranding } from "./consoleBranding";


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
  const { can } = useSession();
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
      {visibleRail(can).map((g, gi) => (
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
                title={applyLabels(it.label)}
              >
                <Icon size={18} strokeWidth={1.7} aria-hidden />
                <span className="rail-label">{applyLabels(it.label)}</span>
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
        <button type="button" className="kbd-btn hide-narrow" onClick={() => palette.open(q)} aria-label={`${MOD} K, open command palette`} title="Command palette">
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

/** Live alerts (#168), newest first, with a count badge. */
function AlertBell() {
  const { data } = useApi<AlertRow[]>("/alerts?status=open");
  const nav = useNavigate();
  const items = (data ?? []).slice(0, 6);
  const n = data?.length ?? 0;
  return (
    <Menu
      label="Alerts"
      items={[
        { heading: n ? `${n} open ${n === 1 ? "alert" : "alerts"}` : "Alerts" },
        ...(items.length
          ? items.map((a) => ({
              label: (
                <span className="grow">
                  <Badge tone={severityTone(a.severity)}>{a.severity}</Badge> {a.title}
                  <span className="faint small" style={{ display: "block" }}>{a.rule_name} · {relTime(a.last_seen_at)}</span>
                </span>
              ),
              onSelect: () => nav(`/alerts?selected=${encodeURIComponent(a.id)}`),
            }))
          : [{ label: <span className="faint">No open alerts</span> }]),
        "divider",
        { label: "Open alerts", onSelect: () => nav("/alerts") },
      ]}
      trigger={(t) => (
        <button type="button" className="tb-btn" aria-label={`Alerts${n ? `, ${n} open` : ""}`} title="Alerts" {...t}>
          <BellRing size={18} strokeWidth={1.7} aria-hidden />
          {n ? <span className="tb-badge" aria-hidden>{n > 99 ? "99+" : n}</span> : null}
        </button>
      )}
    />
  );
}

function AlertBellGate() {
  const { can } = useSession();
  return can("alerts.read") ? <span className="tb-hide-sm"><AlertBell /></span> : null;
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
          label: <span className="small" style={{ color: "var(--warning, #9a6700)" }}>{inactiveRoleHint(r.role, r.reason)}</span>,
          onSelect: () => { reauthenticate(); },
        })),
        ...(session.inactive_roles.length ? [{ label: "Re-authenticate", onSelect: () => { reauthenticate(); } }] : []),
        { label: "My preferences", onSelect: () => navigate("/account/preferences") },
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
        <button type="button" className="me" {...t}>
          <span className="sr-only">User menu: </span>
          <span className="tb-hide-sm">
            {name}{" "}
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
  const { session } = useSession();
  const { resolved } = useTheme();
  const branding = useConsoleBranding(session.tenant.slug);
  const product = productName(branding);
  const logoUrl = branding?.configured ? safeLogoUrl(branding.logo_url) : null;
  const brandVars = safeBrandVars(consoleBrandStyle(branding, resolved));
  // On the root element so menus and dialogs rendered outside the shell take the button colour too.
  useEffect(() => {
    if (!brandVars) return;
    const el = document.documentElement;
    for (const [k, v] of Object.entries(brandVars)) el.style.setProperty(k, v);
    return () => { for (const k of Object.keys(brandVars)) el.style.removeProperty(k); };
  // Only the two colours the user chose are listed: the hover colour is derived from them, and the object is new on every render.
  // Only the two colours the user chose are listed: the hover colour derives from them, and `brandVars` is a new object on every render.
  }, [brandVars?.["--accent"], brandVars?.["--on-accent"]]); // eslint-disable-line react-hooks/exhaustive-deps
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
          <Link to="/" className="brand" aria-label={`${product} home`}>
            {logoUrl && branding ? (
              <img className="brand-logo" src={logoUrl} alt="" width={branding.logo_width} height={branding.logo_height} />
            ) : (
              <span className="logo" aria-hidden><i /><i /><i /><i /></span>
            )}
            <span className="brand-name">{product}</span>
          </Link>
        </div>
        <GlobalSearch />
        <div className="tb-actions">
          <button type="button" className="tb-btn" onClick={() => nav("/inbox")} aria-label={`Inbox${count ? `, ${count} waiting` : ""}`} title="Inbox">
            <Inbox size={18} strokeWidth={1.7} aria-hidden />
            {count ? <span className="tb-badge" aria-hidden>{count > 99 ? "99+" : count}</span> : null}
          </button>
          <AlertBellGate />
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
          {session.step_up_bypass && (
            <div className="stepup-banner" role="status">Step-up is off (dev/test)</div>
          )}
          {children}
        </main>
      </div>
      {/* keeps the collapse state discoverable for screen readers without a second control */}
      <span className="sr-only" aria-live="polite">{collapsed ? "Navigation collapsed to icons" : ""}</span>
    </div>
  );
}
