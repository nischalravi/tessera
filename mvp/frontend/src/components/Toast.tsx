import { ReactNode, createContext, useCallback, useContext, useRef, useState } from "react";
import { CircleAlert, CircleCheck, Info, X } from "lucide-react";

type Kind = "ok" | "error" | "info";
interface ToastItem { id: number; kind: Kind; text: ReactNode; action?: { label: string; run: () => void } }
type ToastFn = (text: ReactNode, opts?: { kind?: Kind; action?: { label: string; run: () => void } }) => void;

const Ctx = createContext<ToastFn>(() => {});
export const useToast = () => useContext(Ctx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);
  const dismiss = (id: number) => setItems((xs) => xs.filter((x) => x.id !== id));
  const toast = useCallback<ToastFn>((text, opts) => {
    const id = ++seq.current;
    const kind = opts?.kind ?? "ok";
    setItems((xs) => [...xs.slice(-3), { id, kind, text, action: opts?.action }]);
    setTimeout(() => dismiss(id), kind === "error" ? 8000 : 4500);
  }, []);
  return (
    <Ctx.Provider value={toast}>
      {children}
      <div className="toasts" role="region" aria-label="Notifications">
        <div aria-live="polite" style={{ display: "contents" }}>
          {items.map((t) => (
            <div key={t.id} className={`toast ${t.kind}`} role={t.kind === "error" ? "alert" : "status"}>
              <span className="t-ic" aria-hidden>
                {t.kind === "error" ? <CircleAlert size={16} /> : t.kind === "info" ? <Info size={16} /> : <CircleCheck size={16} />}
              </span>
              <span className="grow">{t.text}</span>
              {t.action && (
                <button className="t-action" onClick={() => { t.action!.run(); dismiss(t.id); }}>{t.action.label}</button>
              )}
              <button onClick={() => dismiss(t.id)} aria-label="Dismiss notification"><X size={14} /></button>
            </div>
          ))}
        </div>
      </div>
    </Ctx.Provider>
  );
}
