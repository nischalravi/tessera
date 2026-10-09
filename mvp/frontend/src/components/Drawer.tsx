import { ReactNode, useId, useRef } from "react";
import { X } from "lucide-react";
import { Button } from "./Button";
import { useModal } from "./overlay";

export function Drawer({ title, sub, onClose, children, footer, wide }: { title: ReactNode; sub?: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  useModal(ref, onClose);
  return (
    <>
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className={`drawer ${wide ? "wide" : ""}`} role="dialog" aria-modal="true" aria-labelledby={id} tabIndex={-1}>
        <div className="dh">
          <div className="grow">
            <h2 id={id} style={{ fontSize: "var(--fs-xl)" }}>{title}</h2>
            {sub && <div className="muted small" style={{ marginTop: 4 }}>{sub}</div>}
          </div>
          <Button variant="ghost" icon={<X size={18} />} label="Close" onClick={onClose} />
        </div>
        <div className="db">{children}</div>
        {footer && <div className="df">{footer}</div>}
      </div>
    </>
  );
}
