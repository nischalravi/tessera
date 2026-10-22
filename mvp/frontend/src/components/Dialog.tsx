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
  /** Ask the user to pick one option (radio group); the first is preselected. */
  choice?: { label: string; options: { value: string; label: string; hint?: string }[] };
  /** Ask the user to type this phrase (an object's name) before confirm enables, for what cannot be undone. */
  typeToConfirm?: string;
}

/** Resolves to the entered reason ("" when none was asked) on confirm, or null on cancel. */
type ConfirmFn = (o: ConfirmOptions) => Promise<string | null>;
/** Like ConfirmFn, with the chosen option ("" when none was asked). */
type ChoiceFn = (o: ConfirmOptions) => Promise<{ reason: string; choice: string } | null>;

const Ctx = createContext<ConfirmFn>(async () => null);
const ChoiceCtx = createContext<ChoiceFn>(async () => null);
export const useConfirm = () => useContext(Ctx);
export const useConfirmChoice = () => useContext(ChoiceCtx);

function ConfirmDialog({ o, done }: { o: ConfirmOptions; done: (v: { reason: string; choice: string } | null) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  const [reason, setReason] = useState("");
  const [choice, setChoice] = useState(o.choice?.options[0]?.value ?? "");
  const [typed, setTyped] = useState("");
  useModal(ref, () => done(null));
  const blocked = (!!o.reason?.required && reason.trim().length < (o.reason.minLength ?? 1)) || (!!o.typeToConfirm && typed.trim() !== o.typeToConfirm);
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={() => done(null)} aria-hidden />
      <div ref={ref} className="dialog" role="alertdialog" aria-modal="true" aria-labelledby={id}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!blocked) done({ reason: reason.trim(), choice });
          }}
        >
          <div className="dlg-b">
            <h2 id={id}>{o.title}</h2>
            {o.body && <div className="muted">{o.body}</div>}
            {o.choice && (
              <fieldset className="field mt" style={{ border: 0, padding: 0 }}>
                <legend>{o.choice.label}</legend>
                {o.choice.options.map((opt) => (
                  <label key={opt.value} className="row tight" style={{ alignItems: "flex-start", marginTop: 6 }}>
                    <input type="radio" name={`${id}-choice`} value={opt.value} checked={choice === opt.value} onChange={() => setChoice(opt.value)} />
                    <span>{opt.label}{opt.hint && <span className="xs faint" style={{ display: "block" }}>{opt.hint}</span>}</span>
                  </label>
                ))}
              </fieldset>
            )}
            {o.typeToConfirm && (
              <label className="field mt">
                <span>Type <strong className="sys">{o.typeToConfirm}</strong> to confirm</span>
                <input className="input" data-autofocus value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" autoCapitalize="off" spellCheck={false} />
              </label>
            )}
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
            <Button type="submit" variant={o.danger ? "danger-solid" : "primary"} disabled={blocked} data-autofocus={o.reason || o.typeToConfirm ? undefined : true}>
              {o.confirmLabel ?? "Confirm"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ o: ConfirmOptions; resolve: (v: { reason: string; choice: string } | null) => void } | null>(null);
  const withChoice = useCallback<ChoiceFn>((o) => new Promise((resolve) => setState({ o, resolve })), []);
  const confirm = useCallback<ConfirmFn>(async (o) => (await withChoice(o))?.reason ?? null, [withChoice]);
  return (
    <Ctx.Provider value={confirm}>
      <ChoiceCtx.Provider value={withChoice}>
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
      </ChoiceCtx.Provider>
    </Ctx.Provider>
  );
}
