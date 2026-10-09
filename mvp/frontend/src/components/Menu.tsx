import { KeyboardEvent, ReactNode, useEffect, useRef, useState } from "react";

export interface MenuItem {
  label: ReactNode;
  icon?: ReactNode;
  onSelect?: () => void;
  checked?: boolean;
  danger?: boolean;
}
export type MenuEntry = MenuItem | { heading: string } | "divider";

/** Small accessible dropdown menu (button + role=menu), closes on outside click and Escape. */
export function Menu({ trigger, items, label }: { trigger: (p: { onClick: () => void; "aria-expanded": boolean; "aria-haspopup": "menu" }) => ReactNode; items: MenuEntry[]; label: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    requestAnimationFrame(() => ref.current?.querySelector<HTMLElement>('[role^="menuitem"]')?.focus());
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);
  const onKey = (e: KeyboardEvent) => {
    if (!open) return;
    const els = Array.from(ref.current?.querySelectorAll<HTMLElement>('[role^="menuitem"]') ?? []);
    const i = els.indexOf(document.activeElement as HTMLElement);
    if (e.key === "Escape") {
      e.stopPropagation();
      setOpen(false);
      (ref.current?.querySelector("button") as HTMLElement | null)?.focus();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      els[(i + 1) % els.length]?.focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      els[(i - 1 + els.length) % els.length]?.focus();
    }
  };
  return (
    <div className="menu-anchor" ref={ref} onKeyDown={onKey}>
      {trigger({ onClick: () => setOpen((o) => !o), "aria-expanded": open, "aria-haspopup": "menu" })}
      {open && (
        <div className="menu" role="menu" aria-label={label}>
          {items.map((it, i) => {
            if (it === "divider") return <hr key={i} />;
            if ("heading" in it) return <div key={i} className="mlabel" role="presentation">{it.heading}</div>;
            return (
              <button
                key={i}
                className="mi"
                role={it.checked !== undefined ? "menuitemradio" : "menuitem"}
                aria-checked={it.checked}
                style={it.danger ? { color: "var(--critical)" } : undefined}
                onClick={() => {
                  setOpen(false);
                  it.onSelect?.();
                }}
              >
                {it.icon}
                {it.label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
