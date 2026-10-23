import { FormEvent, useId, useRef, useState } from "react";
import { Button } from "../../components";
import { useModal } from "../../components/overlay";
import { MAX_PAUSE_REASON, pauseHours, pauseProblem } from "./twoAdmin";

/** Pausing a security schedule: a reason for the audit log and 1 to 24 hours, after which it resumes by itself (issue #512). */
export function PauseScheduleDialog({ label, onConfirm, onClose }: { label: string; onConfirm: (reason: string, hours: number) => void; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  const [reason, setReason] = useState("");
  const [hours, setHours] = useState("24");
  const [touched, setTouched] = useState(false);
  useModal(ref, onClose);
  const problem = pauseProblem(reason, hours);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!problem) onConfirm(reason.trim(), pauseHours(hours));
  };
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className="dialog" role="dialog" aria-modal="true" aria-labelledby={id}>
        <form onSubmit={submit} noValidate>
          <div className="dlg-b">
            <h2 id={id}>Pause {label}?</h2>
            <p className="muted">It is a security schedule. It resumes by itself after the hours you choose (24 at most). Work already queued still runs.</p>
            <label className="field mt">Reason
              <textarea className="input" data-autofocus value={reason} onChange={(e) => setReason(e.target.value)} maxLength={MAX_PAUSE_REASON} required aria-required="true" aria-invalid={touched && !reason.trim()} />
              <span className="small muted">Kept in the audit log.</span>
            </label>
            <label className="field mt">Resume after (hours, 1 to 24)
              <input className="input" inputMode="numeric" value={hours} onChange={(e) => setHours(e.target.value)} aria-invalid={touched && Number.isNaN(pauseHours(hours))} style={{ maxWidth: 120 }} />
            </label>
            {touched && problem && <p className="small" role="alert" style={{ color: "var(--bad, #b42318)" }}>{problem}</p>}
          </div>
          <div className="dlg-f">
            <Button onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary">Pause {label}</Button>
          </div>
        </form>
      </div>
    </div>
  );
}
