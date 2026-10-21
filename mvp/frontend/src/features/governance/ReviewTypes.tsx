/**
 * Governance → Review types (issue #298): campaign configuration per review type. A type says who reviews
 * a grant (the user's manager, or the owner of the application, entitlement, role, organization or service
 * account), who steps in when there is no reachable owner, and what happens to items nobody decided by the
 * due date. A review schedule runs as a type from its own form. Saving needs reviews.manage and a fresh
 * phishing-resistant sign-in, and is audited.
 */
import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { IdentityRow, OnIncomplete, ReviewTypeList, ReviewTypeRow, ReviewerSource, reviewTypes, reviewTypesPath, useApi } from "../../api";
import { Badge, Button, Callout, Drawer, Loading, Page, useToast } from "../../components";
import { INCOMPLETE_HINT, INCOMPLETE_LABEL, SOURCE_LABEL, reviewTypeProblem, summary } from "./reviewTypeModel";

function TypeForm({ row, onClose, onSaved }: { row: ReviewTypeRow; onClose: () => void; onSaved: () => void }) {
  const { data: people } = useApi<IdentityRow[]>("/identities?type=human");
  const toast = useToast();
  const [f, setF] = useState({
    enabled: row.enabled, source: row.reviewer_source, reviewer: row.reviewer_id ? String(row.reviewer_id) : "",
    fallback: row.fallback_reviewer_id ? String(row.fallback_reviewer_id) : "", onIncomplete: row.on_incomplete, days: String(row.escalation_days),
  });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const active = (people ?? []).filter((p) => p.status === "active");
  const draft = {
    enabled: f.enabled, reviewer_source: f.source, reviewer_id: f.source === "fixed" && f.reviewer ? Number(f.reviewer) : null,
    fallback_reviewer_id: f.fallback ? Number(f.fallback) : null, on_incomplete: f.onIncomplete, escalation_days: Number(f.days),
  };
  const problem = reviewTypeProblem(draft);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || busy) return;
    setBusy(true);
    setErr(null);
    try {
      await reviewTypes.save(row.type, row.version, draft);
      toast(`${row.label} review settings saved`);
      onSaved();
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const picker = (value: string, onChange: (v: string) => void, none: string, label: string) => (
    <select className="input" aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{none}</option>
      {active.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
    </select>
  );
  return (
    <Drawer title={`${row.label} reviews`} onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <p className="small muted">Reviews of this type go to {row.reviewer}. Scope: {row.scope}.</p>
        <label className="row small"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Turned on (a schedule can run as this type)</label>
        <label className="field">Reviewer
          <select className="input" value={f.source} onChange={(e) => setF({ ...f, source: e.target.value as ReviewerSource })}>
            {(Object.keys(SOURCE_LABEL) as ReviewerSource[]).map((k) => <option key={k} value={k}>{SOURCE_LABEL[k]}</option>)}
          </select>
        </label>
        {f.source === "fixed" && <label className="field">Named reviewer{picker(f.reviewer, (v) => setF({ ...f, reviewer: v }), "Choose a person…", "Named reviewer")}</label>}
        <label className="field">Fallback reviewer
          {picker(f.fallback, (v) => setF({ ...f, fallback: v }), "None: the security lead", "Fallback reviewer")}
          <span className="hint">Reviews what has no reachable reviewer: no owner on record, or the owner is not active.</span>
        </label>
        <label className="field">If a review is not completed by the due date
          <select className="input" value={f.onIncomplete} onChange={(e) => setF({ ...f, onIncomplete: e.target.value as OnIncomplete })}>
            {(Object.keys(INCOMPLETE_LABEL) as OnIncomplete[]).map((k) => <option key={k} value={k}>{INCOMPLETE_LABEL[k]}</option>)}
          </select>
          <span className="hint">{INCOMPLETE_HINT[f.onIncomplete]}</span>
        </label>
        {f.onIncomplete === "escalate" && (
          <label className="field" style={{ maxWidth: 200 }}>Escalation lasts (days)
            <input className="input" inputMode="numeric" value={f.days} onChange={(e) => setF({ ...f, days: e.target.value })} />
          </label>
        )}
        {problem && <p className="small" role="alert">{problem}</p>}
        {err && <Callout tone="bad">{err}</Callout>}
        <div className="row"><Button type="submit" variant="primary" disabled={!!problem || busy}>{busy ? "Saving…" : "Save"}</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
    </Drawer>
  );
}

export function ReviewTypes() {
  const { data, error, reload } = useApi<ReviewTypeList>(reviewTypesPath);
  const [edit, setEdit] = useState<ReviewTypeRow | null>(null);
  return (
    <Page title="Review types" crumbs={[["Protection"], ["Access reviews", "/governance/reviews"], ["Review types"]]}
      sub={<>Who reviews, who steps in, and what happens when a review is not completed, for each kind of review. Pick a type on a <Link to="/governance/reviews">review schedule</Link> to run it. Owners come from <Link to="/directory/ownership">Ownership</Link>.</>}>
      {!data ? <Loading kind="block" error={error} what="review types" /> : (
        <div className="card flush">
          <div className="table-scroll">
            <table>
              <thead><tr><th>Type</th><th>Reviewer</th><th className="hide-narrow">Fallback</th><th>If not completed</th><th className="hide-narrow">Schedules</th><th /></tr></thead>
              <tbody>
                {data.types.map((t) => (
                  <tr key={t.type}>
                    <td><b>{t.label}</b> {!t.enabled && <Badge tone="outline">Off</Badge>}<div className="xs faint">{t.scope}</div></td>
                    <td className="small">{summary(t)}</td>
                    <td className="small hide-narrow">{t.fallback_reviewer_person?.name ?? <span className="faint">Security lead</span>}</td>
                    <td className="small">{INCOMPLETE_LABEL[t.on_incomplete]}{t.on_incomplete === "escalate" && ` for ${t.escalation_days} days`}</td>
                    <td className="small hide-narrow tnum">{t.schedules}</td>
                    <td className="actions-cell">{data.can_manage && <Button size="sm" variant="ghost" onClick={() => setEdit(t)}>Edit</Button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {data && !data.can_manage && <div className="mt"><Callout tone="neutral">You can read these settings. A reviews manager changes them.</Callout></div>}
      {edit && <TypeForm row={edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); reload(); }} />}
    </Page>
  );
}
