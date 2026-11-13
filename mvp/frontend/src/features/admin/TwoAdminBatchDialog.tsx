import { useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { AdminChange, adminChanges } from "../../api";
import { Button, Callout } from "../../components";
import { useModal } from "../../components/overlay";
import { errText, outcome } from "./common";
import { ChannelChange } from "./twoAdmin";

type Result = { change?: AdminChange; error?: string };

/**
 * Shown when one form save needs several two-admin changes (issue #973): files every one of them, shows each result, and lists
 * what it cannot file (`notFiled`) so nothing is dropped without notice. A new signing secret is shown here once, because it goes
 * to the API only as the request's sealed client_secret.
 */
export function TwoAdminBatchDialog({ items, notFiled, onClose }: { items: ChannelChange[]; notFiled: string[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<Record<string, Result>>({});
  useModal(ref, onClose);
  const pending = items.filter((i) => !results[i.type]?.change);
  const file = async () => {
    setBusy(true);
    const next = { ...results };
    for (const i of pending) {
      try {
        next[i.type] = { change: await adminChanges.submit(i.type, i.payload, i.secret) };
      } catch (e) {
        next[i.type] = { error: errText(e) };
      }
      setResults({ ...next });
    }
    setBusy(false);
  };
  const filed = items.filter((i) => results[i.type]?.change);
  const secret = filed.find((i) => i.secret)?.secret;
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className="dialog" role="alertdialog" aria-modal="true" aria-labelledby={id}>
        <div className="dlg-b">
          <h2 id={id}>{items.length ? `${items.length} change${items.length === 1 ? "" : "s"} need a second admin` : "Nothing could be filed"}</h2>
          <div className="stack-sm">
            <ul>
              {items.map((i) => {
                const r = results[i.type];
                return (
                  <li key={i.type}>
                    {i.what}
                    {r?.change && <> <b>Requested.</b> {outcome(r.change)} <Link to={`/admin/change-requests?selected=${encodeURIComponent(r.change.id)}`} onClick={onClose}>Open it</Link></>}
                    {r?.error && <div role="alert"><Callout tone="bad">Not filed: {r.error}</Callout></div>}
                  </li>
                );
              })}
            </ul>
            {secret && (
              <Callout tone="warn">
                New signing secret, shown once. Give it to the receiver once the change is approved: <code>{secret}</code>
              </Callout>
            )}
            {notFiled.length > 0 && (
              <div role="status">
                <Callout tone="warn">
                  <b>Not filed:</b>
                  <ul>{notFiled.map((n) => <li key={n}>{n}</li>)}</ul>
                </Callout>
              </div>
            )}
            {pending.length > 0 && <p className="muted">Request these and a different admin will be asked to approve each. You cannot approve your own requests. Other edits in the form were not saved: save them separately.</p>}
          </div>
        </div>
        <div className="dlg-f">
          {pending.length === 0 || items.length === 0 ? (
            <Button variant="primary" onClick={onClose} data-autofocus>Close</Button>
          ) : (
            <>
              <Button onClick={onClose}>Cancel</Button>
              <Button variant="primary" disabled={busy} onClick={file} data-autofocus>{filed.length ? "Retry the rest" : `Request ${pending.length === 1 ? "this change" : "all " + pending.length}`}</Button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
