import { ReactNode, createContext, useCallback, useContext, useId, useRef, useState } from "react";
import { Button } from "./Button";
import { useModal } from "./overlay";

export interface ConfirmOptions {
  title: string;
  body?: ReactNode;
  confirmLabel?: string;
  /** Destructive actions get a red confirm button. */
  danger?: boolean;
  /** Ask for a reason (e.g. high-risk certifications); `required` blocks confirm until filled. */
  reason?: { label: string; required?: boolean; placeholder?: string; /** the API's minimum, so confirm waits for it */ minLength?: number };
}

/** Resolves to the entered reason ("" when none was asked) on confirm, or null on cancel. */
type ConfirmFn = (o: ConfirmOptions) => Promise<string | null>;

const Ctx = createContext<ConfirmFn>(async () => null);
export const useConfirm = () => useContext(Ctx);

function ConfirmDialog({ o, done }: { o: ConfirmOptions; done: (v: string | null) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  const [reason, setReason] = useState("");
  useModal(ref, () => done(null));
  const blocked = !!o.reason?.required && reason.trim().length < (o.reason.minLength ?? 1);
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={() => done(null)} aria-hidden />
      <div ref={ref} className="dialog" role="alertdialog" aria-modal="true" aria-labelledby={id}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!blocked) done(reason.trim());
          }}
        >
          <div className="dlg-b">
            <h2 id={id}>{o.title}</h2>
            {o.body && <div className="muted">{o.body}</div>}
            {o.reason && (
              <label className="field mt">
                {o.reason.label}
                <textarea className="input" data-autofocus value={reason} onChange={(e) => setReason(e.target.value)} placeholder={o.reason.placeholder} />
                {o.reason.minLength ? <span className="small muted">At least {o.reason.minLength} characters.</span> : null}
              </label>
            )}
          </div>
          <div className="dlg-f">
            <Button onClick={() => done(null)}>Cancel</Button>
            <Button type="submit" variant={o.danger ? "danger-solid" : "primary"} disabled={blocked} data-autofocus={o.reason ? undefined : true}>
              {o.confirmLabel ?? "Confirm"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ o: ConfirmOptions; resolve: (v: string | null) => void } | null>(null);
  const confirm = useCallback<ConfirmFn>((o) => new Promise((resolve) => setState({ o, resolve })), []);
  return (
    <Ctx.Provider value={confirm}>
      {children}
      {state && (
        <ConfirmDialog
          o={state.o}
          done={(v) => {
            state.resolve(v);
            setState(null);
          }}
        />
      )}
    </Ctx.Provider>
  );
}
