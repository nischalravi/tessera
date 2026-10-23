import { ReactNode, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { AdminChange, adminChanges } from "../../api";
import { Button, Callout } from "../../components";
import { useModal } from "../../components/overlay";
import { errText, outcome } from "./common";
import { TWO_ADMIN_TITLE, TwoAdminType } from "./twoAdmin";

/**
 * Shown when the API answers 409 two_admin_change_required: a second admin must approve, so offer to file the matching
 * admin change with the form's payload, then show it as pending with a link to Change requests (issue #526).
 */
export function TwoAdminDialog({ type, payload, what, onClose }: { type: TwoAdminType; payload: Record<string, unknown>; what: ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  const [busy, setBusy] = useState(false);
  const [filed, setFiled] = useState<AdminChange | null>(null);
  const [error, setError] = useState<string | null>(null);
  useModal(ref, onClose);
  const file = async () => {
    setBusy(true);
    setError(null);
    try {
      setFiled(await adminChanges.submit(type, payload));
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className="dialog" role="alertdialog" aria-modal="true" aria-labelledby={id}>
        <div className="dlg-b">
          <h2 id={id}>{filed ? "Change requested" : TWO_ADMIN_TITLE[type]}</h2>
          {filed ? (
            <div className="stack-sm" role="status">
              <Callout tone="ok">{outcome(filed)}</Callout>
              <p className="muted">{filed.summary}. Nothing has changed yet. It takes effect when a different admin approves it.</p>
              <Link to={`/admin/change-requests?selected=${encodeURIComponent(filed.id)}`} onClick={onClose}>Open it in Change requests</Link>
            </div>
          ) : (
            <div className="stack-sm">
              <p className="muted">{what}</p>
              <p className="muted">Request this change and a different admin will be asked to approve it. You cannot approve your own request. Other edits in the form are not part of it: save them separately.</p>
              {error && <div role="alert"><Callout tone="bad">{error}</Callout></div>}
            </div>
          )}
        </div>
        <div className="dlg-f">
          {filed ? (
            <Button variant="primary" onClick={onClose} data-autofocus>Close</Button>
          ) : (
            <>
              <Button onClick={onClose}>Cancel</Button>
              <Button variant="primary" disabled={busy} onClick={file} data-autofocus>Request this change</Button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
