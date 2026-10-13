import { FormEvent, useId, useMemo, useRef, useState } from "react";
import { IdentityRow, MergeRequest, isPendingMerge, mergeIdentity, useApi } from "../../api";
import { Button } from "../../components/Button";
import { Callout } from "../../components/Feedback";
import { useModal } from "../../components/overlay";

/**
 * Account correlation building blocks (issue #160), shared by the Account matches page and the
 * identity page. Hiding controls with can() is for usability only: the API enforces
 * identities.correlate / identities.merge and a fresh phishing-resistant sign-in itself.
 */

export const RULE_LABEL: Record<string, string> = {
  email: "Login is their email",
  email_local_part: "Same name before @",
};

/** Search for a person to link or merge into. Merged identities are not offered. */
export function PersonPicker({ value, onChange, exclude, type = "human", label = "Person" }: {
  value: number | null;
  onChange: (id: number | null) => void;
  exclude?: number;
  type?: string;
  label?: string;
}) {
  const { data } = useApi<IdentityRow[]>("/identities");
  const [q, setQ] = useState("");
  const id = useId();
  const people = useMemo(
    () => (data ?? []).filter((i) => i.type === type && i.status !== "merged" && i.id !== exclude),
    [data, type, exclude],
  );
  const needle = q.trim().toLowerCase();
  const shown = needle ? people.filter((p) => `${p.name} ${p.email ?? ""}`.toLowerCase().includes(needle)).slice(0, 8) : [];
  const chosen = people.find((p) => p.id === value);
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {chosen ? (
        <div className="row tight">
          <span><b>{chosen.name}</b> <span className="small muted">{chosen.email}</span></span>
          <Button size="sm" variant="ghost" onClick={() => onChange(null)}>Change</Button>
        </div>
      ) : (
        <>
          <input id={id} className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by name or email…" autoComplete="off" />
          {shown.length > 0 && (
            <ul className="pick-list" aria-label="Matching people">
              {shown.map((p) => (
                <li key={p.id}>
                  <button type="button" className="pick-item" onClick={() => { onChange(p.id); setQ(""); }}>
                    <b>{p.name}</b> <span className="small muted">{p.email}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {needle && shown.length === 0 && <div className="small muted">No one matches.</div>}
        </>
      )}
    </div>
  );
}

/** Merge one identity into another. The survivor keeps its id; the merge can be undone for 180 days. */
export function MergeDialog({ merged, onClose, onMerged }: {
  merged: { id: number; name: string; type: string };
  onClose: () => void;
  /** `request` is set when the merge did not happen: it waits for a second reviewer. */
  onMerged: (survivorId: number, request: MergeRequest | null) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const [survivor, setSurvivor] = useState<number | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useModal(ref, onClose);
  const ready = survivor != null && reason.trim().length > 0 && !busy;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready || survivor == null) return;
    setBusy(true);
    setError(null);
    try {
      const r = await mergeIdentity(merged.id, survivor, reason.trim());
      onMerged(survivor, isPendingMerge(r) ? r.request : null);
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <form onSubmit={submit}>
          <div className="dlg-b">
            <h2 id={titleId}>Merge {merged.name} into another identity</h2>
            <p className="muted">
              {merged.name}'s accounts, the identities they own, their reports and their agent delegations move to the identity you
              pick. History stays where it is. Sign-in credentials never move, so an identity that signs in to Tessera can only be the
              one kept. You can undo the merge for 180 days.
            </p>
            <p className="muted">
              If either person holds privileged access, has IAL 2 or more, or is an employee, a second reviewer must approve before anything moves.
            </p>
            <div className="mt">
              <PersonPicker value={survivor} onChange={setSurvivor} exclude={merged.id} type={merged.type} label="Keep" />
            </div>
            <label className="field mt">
              Reason
              <textarea className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} placeholder="For example: same person, two HR records" />
            </label>
            {error && <div className="mt"><Callout tone="bad">{error}</Callout></div>}
          </div>
          <div className="dlg-f">
            <Button onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="danger-solid" disabled={!ready}>{busy ? "Merging…" : "Merge"}</Button>
          </div>
        </form>
      </div>
    </div>
  );
}
