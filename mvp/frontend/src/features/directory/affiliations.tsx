import { FormEvent, useId, useRef, useState } from "react";
import { CalendarX2, Plus } from "lucide-react";
import { Affiliation, AffiliationType, PersonAffiliations, PersonIdentifier, addAffiliation, endAffiliation, fmtDay, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Callout, EmptyState, Loading } from "../../components/Feedback";
import { useModal } from "../../components/overlay";
import { useToast } from "../../components/Toast";
import {
  AFFILIATION_LABEL, IDENTIFIER_LABEL, MANUAL_TYPES, NEEDS_END, SOURCE_LABEL, STATE_LABEL, STATE_TONE, VERIFIED_LABEL, addProblem, canEnd, endOfDayUtc,
} from "./affiliationModel";

/**
 * A person's affiliations and identifiers (issue #64). One person has many affiliations; the
 * lifecycle state is derived from them by the API. Hiding the add and end controls with can() is for
 * usability only: the API enforces identities.affiliate and a fresh phishing-resistant sign-in itself.
 */

const EFFECTIVE_TONE = { pending: "info", active: "ok", ended: "neutral", revoked: "critical" } as const;

function Dates({ a }: { a: Affiliation }) {
  const end = a.status === "ended" || a.status === "revoked" ? a.ended_at : a.ends_at;
  return (
    <span className="small nowrap">
      {fmtDay(a.starts_at)} to {end ? fmtDay(end) : "no end date"}
    </span>
  );
}

export function AffiliationsSection({ identityId, name, human }: { identityId: number; name: string; human: boolean }) {
  const { data, error, reload } = useApi<PersonAffiliations>(`/identities/${identityId}/affiliations`);
  const { can } = useSession();
  const toast = useToast();
  const [adding, setAdding] = useState(false);
  const [ending, setEnding] = useState<Affiliation | null>(null);
  const mayEdit = can("identities.affiliate") && human && data?.lifecycle_state !== "merged";

  if (!data) return <Loading error={error} kind="block" />;
  return (
    <section className="stack-sm" aria-labelledby={`aff-${identityId}`}>
      <div className="spread">
        <h3 id={`aff-${identityId}`} style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Affiliations</h3>
        <span className="row tight">
          <Badge tone={STATE_TONE[data.lifecycle_state]} dot title="Derived from the affiliations below">{STATE_LABEL[data.lifecycle_state]}</Badge>
          {mayEdit && <Button size="sm" icon={<Plus size={14} />} onClick={() => setAdding(true)}>Add</Button>}
        </span>
      </div>
      {data.affiliations.length === 0 ? (
        <EmptyState title="No affiliations">{human ? "This person has no relationship with the organization on record." : "Affiliations belong to people, not machine identities."}</EmptyState>
      ) : (
        <ul className="stack-sm" style={{ listStyle: "none", padding: 0, margin: 0 }}>
          {data.affiliations.map((a) => (
            <li key={a.id} className="card stack-sm">
              <div className="spread">
                <span className="row tight">
                  <b>{AFFILIATION_LABEL[a.type]}</b>
                  <Badge tone={EFFECTIVE_TONE[a.effective_status]} dot>{a.effective_status[0]!.toUpperCase() + a.effective_status.slice(1)}</Badge>
                </span>
                {mayEdit && canEnd(a) && (
                  <Button size="sm" variant="danger" icon={<CalendarX2 size={14} />} onClick={() => setEnding(a)} aria-label={`End ${AFFILIATION_LABEL[a.type]} affiliation`}>End…</Button>
                )}
              </div>
              <Dates a={a} />
              <div className="small muted">
                {SOURCE_LABEL[a.source]}
                {a.org_unit ? ` · ${a.org_unit}` : ""}
                {a.population ? ` · ${a.population} population` : ""}
              </div>
              {a.end_reason && <div className="small muted">Ended: {a.end_reason}</div>}
            </li>
          ))}
        </ul>
      )}
      {adding && (
        <AddAffiliationDialog
          identityId={identityId}
          name={name}
          onClose={() => setAdding(false)}
          onDone={() => { setAdding(false); toast("Affiliation added"); reload(); }}
        />
      )}
      {ending && (
        <EndAffiliationDialog
          affiliation={ending}
          name={name}
          onClose={() => setEnding(null)}
          onDone={() => { setEnding(null); toast("Affiliation ended"); reload(); }}
        />
      )}
    </section>
  );
}

export function IdentifiersSection({ identityId }: { identityId: number }) {
  const { data, error } = useApi<PersonIdentifier[]>(`/identities/${identityId}/identifiers`);
  if (!data) return <Loading error={error} kind="block" />;
  return (
    <section className="stack-sm" aria-labelledby={`ids-${identityId}`}>
      <h3 id={`ids-${identityId}`} style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Identifiers</h3>
      {data.length === 0 ? (
        <EmptyState title="No identifiers">No email, ID or federated subject is recorded for this identity.</EmptyState>
      ) : (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Type</th><th>Value</th><th>Verified</th></tr></thead>
            <tbody>
              {data.map((x) => (
                <tr key={x.id}>
                  <td>{IDENTIFIER_LABEL[x.type] ?? x.type}{x.status === "retired" && <> <Badge>Retired</Badge></>}</td>
                  <td className="small" style={{ overflowWrap: "anywhere" }}>
                    {x.value ?? <span className="faint">Not stored (hash only)</span>}
                    {x.issuer && <div className="xs faint">{x.issuer}</div>}
                  </td>
                  <td className="small">
                    {x.verified_by ? (
                      <>{VERIFIED_LABEL[x.verified_by]}{x.source_system && <span className="faint"> ({x.source_system})</span>}<div className="xs faint">{fmtDay(x.verified_at)}</div></>
                    ) : <Badge tone="warning">Not verified</Badge>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function Shell({ title, onClose, onSubmit, submit, busy, ready, error, danger, children }: {
  title: string;
  onClose: () => void;
  onSubmit: (e: FormEvent) => void;
  submit: string;
  busy: boolean;
  ready: boolean;
  error: string | null;
  danger?: boolean;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useModal(ref, onClose);
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <form onSubmit={onSubmit}>
          <div className="dlg-b">
            <h2 id={titleId}>{title}</h2>
            {children}
            {error && <div className="mt"><Callout tone="bad">{error}</Callout></div>}
          </div>
          <div className="dlg-f">
            <Button onClick={onClose}>Cancel</Button>
            <Button type="submit" variant={danger ? "danger-solid" : "primary"} disabled={!ready || busy}>{busy ? "Saving…" : submit}</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

function AddAffiliationDialog({ identityId, name, onClose, onDone }: { identityId: number; name: string; onClose: () => void; onDone: () => void }) {
  const [type, setType] = useState<AffiliationType>("guest_visitor");
  const [orgUnit, setOrgUnit] = useState("");
  const [endDay, setEndDay] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const problem = addProblem(type, endDay, reason);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem) return;
    setBusy(true);
    setError(null);
    try {
      await addAffiliation(identityId, {
        type, reason: reason.trim(), ...(orgUnit.trim() ? { org_unit: orgUnit.trim() } : {}), ...(endDay ? { ends_at: endOfDayUtc(endDay) } : {}),
      });
      onDone();
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Shell title={`Add an affiliation for ${name}`} onClose={onClose} onSubmit={submit} submit="Add affiliation" busy={busy} ready={!problem} error={error}>
      <p className="muted">
        This adds a relationship to the same person; it never creates a second identity. Employee, student and applicant affiliations come from the HR and student systems, not from this form.
      </p>
      <label className="field mt">
        Type
        <select className="input" value={type} onChange={(e) => setType(e.target.value as AffiliationType)}>
          {MANUAL_TYPES.map((t) => <option key={t} value={t}>{AFFILIATION_LABEL[t]}</option>)}
        </select>
      </label>
      <label className="field mt">
        Organization unit <span className="hint">optional</span>
        <input className="input" value={orgUnit} maxLength={100} onChange={(e) => setOrgUnit(e.target.value)} />
      </label>
      <label className="field mt">
        Ends on {!NEEDS_END.includes(type) && <span className="hint">optional</span>}
        <input className="input" type="date" value={endDay} onChange={(e) => setEndDay(e.target.value)} />
      </label>
      <label className="field mt">
        Reason
        <textarea className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} placeholder="For example: visiting scholar, host is Prof. Rao" />
      </label>
      {problem && reason.trim() !== "" && <div className="small muted mt">{problem}</div>}
    </Shell>
  );
}

function EndAffiliationDialog({ affiliation, name, onClose, onDone }: { affiliation: Affiliation; name: string; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!reason.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await endAffiliation(affiliation.id, reason.trim());
      onDone();
    } catch (err: any) {
      setError(String(err.message ?? err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Shell title={`End ${AFFILIATION_LABEL[affiliation.type]} affiliation`} onClose={onClose} onSubmit={submit} submit="End affiliation" busy={busy} ready={reason.trim().length > 0} error={error} danger>
      <p className="muted">
        {name} stays in the directory. Access that depends on this affiliation ends once the groups engine reads the change; their other affiliations are not touched.
      </p>
      <label className="field mt">
        Reason
        <textarea className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} />
      </label>
    </Shell>
  );
}
