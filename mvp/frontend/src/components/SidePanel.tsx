import { ReactNode, useCallback, useEffect, useId, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ExternalLink, X } from "lucide-react";
import { useModal } from "./overlay";

/**
 * The selected row of a list, kept in the URL (`?selected=<id>`) so a detail panel is
 * deep-linkable and survives a reload. Other query parameters are preserved.
 */
export function useSelected(param = "selected") {
  const [params, setParams] = useSearchParams();
  const selected = params.get(param);
  const setSelected = useCallback(
    (v: string | number | null) =>
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (v === null) next.delete(param);
          else next.set(param, String(v));
          return next;
        },
        { replace: true },
      ),
    [param, setParams],
  );
  return [selected, setSelected] as const;
}

/**
 * Detail panel that slides in from the right over a list. The list stays visible (on wide
 * screens the page makes room for it) and the selected row stays highlighted. It behaves as a
 * dialog for keyboard users: focus moves in, Tab is trapped, Escape closes and focus returns to
 * the row that opened it.
 */
export function SidePanel({ title, avatar, sub, commands, tabs, fullHref, fullLabel = "Open full page", onClose, children, footer }: {
  title: string;
  avatar?: ReactNode;
  sub?: ReactNode;
  commands?: ReactNode;
  tabs?: ReactNode;
  fullHref?: string;
  fullLabel?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  useModal(ref, onClose);
  useEffect(() => {
    const el = document.documentElement;
    el.classList.add("panel-open");
    return () => el.classList.remove("panel-open");
  }, []);
  return (
    <aside ref={ref} className="panel" role="dialog" aria-modal="true" aria-labelledby={id} tabIndex={-1}>
      <div className="panel-head">
        <div className="panel-title">
          {avatar}
          <div className="grow">
            <h2 id={id} tabIndex={-1} data-autofocus className="truncate">{title}</h2>
            {sub && <div className="small faint row tight" style={{ marginTop: 2 }}>{sub}</div>}
          </div>
          <button type="button" className="btn ghost icon" onClick={onClose} aria-label="Close details (Esc)" title="Close (Esc)">
            <X size={18} aria-hidden />
          </button>
        </div>
        {commands}
        {tabs}
      </div>
      <div className="panel-body" role={tabs ? "tabpanel" : undefined}>{children}</div>
      {(fullHref || footer) && (
        <div className="panel-foot">
          {fullHref ? <Link to={fullHref} className="row tight"><ExternalLink size={14} aria-hidden /> {fullLabel}</Link> : <span />}
          {footer}
        </div>
      )}
    </aside>
  );
}
