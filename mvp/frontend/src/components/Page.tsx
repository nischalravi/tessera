import { productName, useConsoleBranding } from "../app/consoleBranding";
import { KeyboardEvent, ReactNode, useEffect, useRef } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { applyLabels } from "../labels";

export type Crumb = [label: string, to?: string];

export function Breadcrumbs({ items }: { items: Crumb[] }) {
  if (!items.length) return null;
  return (
    <nav aria-label="Breadcrumb" className="crumbs">
      {items.map(([label, to], i) => (
        <span key={i} className="row tight">
          {i > 0 && <ChevronRight size={12} aria-hidden />}
          {to && i < items.length - 1 ? <Link to={to}>{applyLabels(label)}</Link> : <span aria-current={i === items.length - 1 ? "page" : undefined}>{applyLabels(label)}</span>}
        </span>
      ))}
    </nav>
  );
}

export function Page({ title, crumbs = [], sub, actions, badge, count, tabs, commands, children }: {
  title: ReactNode;
  /** Trail after "Home"; pass `false` for no breadcrumb (Home itself). */
  crumbs?: Crumb[] | false;
  sub?: ReactNode;
  actions?: ReactNode;
  badge?: ReactNode;
  /** Muted count after the title, e.g. "88 identities". */
  count?: ReactNode;
  /** Sub-page tabs under the title. */
  tabs?: ReactNode;
  /** Command bar under the title (see CommandBar). */
  commands?: ReactNode;
  children: ReactNode;
}) {
  const product = productName(useConsoleBranding());
  useEffect(() => {
    if (typeof title === "string") document.title = `${applyLabels(title)} · ${product}`;
  }, [title, product]);
  return (
    <div>
      {crumbs !== false && <Breadcrumbs items={[["Home", "/"], ...(crumbs.length || typeof title !== "string" ? crumbs : [[title] as Crumb])]} />}
      <div className="page-head">
        <div className="grow">
          <div className="title-row">
            <h1>{typeof title === "string" ? applyLabels(title) : title}</h1>
            {count !== undefined && count !== null && <span className="count">{count}</span>}
            {badge}
          </div>
          {sub && <div className="sub">{sub}</div>}
        </div>
        {actions && <div className="actions">{actions}</div>}
      </div>
      {tabs && <div className="page-tabs">{tabs}</div>}
      {commands}
      {children}
    </div>
  );
}

export interface Command {
  label: string;
  icon?: ReactNode;
  onClick?: () => void;
  danger?: boolean;
  disabled?: boolean;
  title?: string;
}

/** Fluent-style command bar: flat icon+label buttons on one line, wrapping on narrow screens. */
export function CommandBar({ items, end, label = "Commands" }: { items: (Command | null | false | undefined)[]; end?: ReactNode; label?: string }) {
  return (
    <div className="cmdbar" role="toolbar" aria-label={label}>
      {items.filter((c): c is Command => !!c).map((c) => (
        <button key={c.label} type="button" className={`cmd ${c.danger ? "danger" : ""}`} onClick={c.onClick} disabled={c.disabled} title={c.title}>
          {c.icon}
          {c.label}
        </button>
      ))}
      {end && <><span className="spacer" />{end}</>}
    </div>
  );
}

/** Controlled tabs with roving arrow-key focus. */
export function Tabs<T extends string>({ tabs, value, onChange, label }: { tabs: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void; label: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const onKey = (e: KeyboardEvent) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const i = tabs.findIndex((t) => t.id === value);
    const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    onChange(next.id);
    requestAnimationFrame(() => ref.current?.querySelector<HTMLElement>('[aria-selected="true"]')?.focus());
  };
  return (
    <div className="tabs" role="tablist" aria-label={label} ref={ref} onKeyDown={onKey}>
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={t.id === value} tabIndex={t.id === value ? 0 : -1} onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

/** Tabs that are routes (Directory, Insights...). */
export function LinkTabs({ tabs, label }: { tabs: { to: string; label: ReactNode; end?: boolean }[]; label: string }) {
  const ref = useRef<HTMLElement>(null);
  const { pathname } = useLocation();
  // keep the active tab visible when the strip scrolls horizontally on narrow screens
  useEffect(() => {
    ref.current?.querySelector<HTMLElement>("a.active")?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [pathname]);
  return (
    <nav className="tabs" aria-label={label} ref={ref}>
      {tabs.map((t) => (
        <NavLink key={t.to} to={t.to} end={t.end}>{t.label}</NavLink>
      ))}
    </nav>
  );
}

export function FilterChips<T extends string>({ options, value, onChange, label }: { options: { id: T; label: string; count?: number }[]; value: T; onChange: (v: T) => void; label: string }) {
  return (
    <div className="chips" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.id} className="fchip" aria-pressed={o.id === value} onClick={() => onChange(o.id)}>
          {o.label}
          {o.count !== undefined && <span className="n">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Segmented<T extends string>({ options, value, onChange, label }: { options: [T, string][]; value: T; onChange: (v: T) => void; label: string }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map(([v, l]) => (
        <button key={v} aria-pressed={v === value} onClick={() => onChange(v)}>{l}</button>
      ))}
    </div>
  );
}
