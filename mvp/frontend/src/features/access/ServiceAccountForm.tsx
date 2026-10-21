import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { KeyRound } from "lucide-react";
import { AnswersByQuestionnaire, IdentityRow, QuestionnaireNeed, ServiceAccountList, api, neededPath, serviceAccountRequests, serviceAccountsPath, useApi } from "../../api";
import { Button, Callout, Page, Segmented, useToast } from "../../components";
import { QuestionnaireForm } from "./QuestionnaireForm";
import { formReady } from "./QuestionnaireForm";
import { answersPayload } from "../governance/questionnaireModel";
import { KINDS, LIMITS, SaForm, blankForm, formProblem, toInput } from "./serviceAccountModel";

/**
 * Request access → service account (issue #298): create, change or transfer a service account.
 * Owners are mandatory: a primary and a backup, both active people, different people. A transfer
 * is approved by the old and the new owner as well as an access approver; a change by the current
 * owner. The workflow assigned to the request type can add steps and questions; the server
 * checks everything again.
 */
export function ServiceAccountForm() {
  const toast = useToast();
  const nav = useNavigate();
  const list = useApi<ServiceAccountList>(serviceAccountsPath);
  const people = useApi<IdentityRow[]>("/identities?type=human&status=active");
  const [f, setF] = useState<SaForm>(blankForm());
  const [answers, setAnswers] = useState<AnswersByQuestionnaire>({});
  const [asked, setAsked] = useState<QuestionnaireNeed[] | null>([]);
  const [busy, setBusy] = useState(false);
  const accounts = list.data?.accounts ?? [];
  const account = accounts.find((a) => a.id === f.identityId) ?? null;
  const set = (patch: Partial<SaForm>) => setF((x) => ({ ...x, ...patch }));
  const people_ = useMemo(() => (people.data ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)), [people.data]);
  const problem = formProblem(f, account);

  // the questions the request type's workflow asks, once the owner (and the account) are known
  const ownerForAsk = f.kind === "change" ? account?.primary_owner?.id ?? null : f.primary;
  const sig = [f.kind, f.system, f.identityId, ownerForAsk].join("|");
  useEffect(() => {
    if (!ownerForAsk) {
      setAsked([]);
      return;
    }
    let alive = true;
    setAsked(null);
    api<{ questionnaires: QuestionnaireNeed[] }>(neededPath({ serviceAccount: { kind: f.kind, primaryOwnerId: ownerForAsk, system: f.system || undefined, identityId: f.identityId ?? undefined } }))
      .then((r) => alive && setAsked(r.questionnaires))
      .catch(() => alive && setAsked([])); // the server asks again on submit
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig]);
  const needs = asked ?? [];
  const ready = asked !== null && formReady(needs, answers);

  const submit = async () => {
    setBusy(true);
    try {
      const r = await serviceAccountRequests.file({ ...toInput(f), answers: answersPayload(needs, answers) });
      toast(`Submitted. ${r.stages.find((s) => s.status === "waiting")?.label ?? "Approvers"} will see it now.`);
      nav(`/access/requests?selected=${encodeURIComponent(r.id)}`);
    } catch (e: any) {
      toast(`Couldn't submit: ${e.message}`, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  const ownerSelect = (label: string, value: number | null, onChange: (v: number | null) => void, hint?: string, id?: string) => (
    <label className="field">{label}
      <select className="input" value={value ?? ""} onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)} aria-describedby={hint ? id : undefined}>
        <option value="">Choose a person…</option>
        {people_.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
      </select>
      {hint && <span className="hint" id={id}>{hint}</span>}
    </label>
  );

  return (
    <Page title="Service account" crumbs={[["Access"], ["Request access", "/access/request"], ["Service account"]]}
      sub="Create a service account, change its purpose or backup owner, or hand it to a new owner. Every service account has a primary and a backup owner.">
      <div className="card stack" style={{ maxWidth: 640 }}>
        <div className="field">
          What you need
          <Segmented label="Kind of request" value={f.kind} onChange={(v) => { setF(blankForm(v)); setAnswers({}); }} options={KINDS.map((k) => [k.id, k.label] as [typeof k.id, string])} />
          <span className="hint">{KINDS.find((k) => k.id === f.kind)?.hint}</span>
        </div>

        {f.kind !== "create" && (
          <label className="field">Service account
            <select className="input" value={f.identityId ?? ""} onChange={(e) => set({ identityId: e.target.value ? Number(e.target.value) : null, backup: null, purpose: "" })}>
              <option value="">Choose a service account…</option>
              {accounts.map((a) => <option key={a.id} value={a.id}>{a.name}{a.open_request ? " (a request is open)" : ""}</option>)}
            </select>
          </label>
        )}
        {account && (
          <p className="small muted">
            Owner {account.primary_owner?.name ?? "none"}, backup {account.backup_owner?.name ?? "none"}{account.systems.length > 0 && <>, in {account.systems.join(", ")}</>}.
            {account.purpose && <> Purpose: {account.purpose}</>}
            {account.open_request && <> A request about it is already open.</>}
          </p>
        )}

        {f.kind === "create" && (
          <>
            <label className="field">Name
              <input className="input" value={f.name} maxLength={LIMITS.name} onChange={(e) => set({ name: e.target.value, ...(f.username === "" || f.username === f.name ? { username: e.target.value } : {}) })} />
            </label>
            <div className="row wrap">
              <label className="field" style={{ flex: "1 1 200px" }}>Application
                <select className="input" value={f.system} onChange={(e) => set({ system: e.target.value })}>
                  <option value="">Choose…</option>
                  {(list.data?.systems ?? []).map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
              <label className="field" style={{ flex: "1 1 200px" }}>Account name there
                <input className="input" value={f.username} maxLength={LIMITS.username} onChange={(e) => set({ username: e.target.value })} />
              </label>
            </div>
            <label className="field">Description (optional)
              <textarea className="input" rows={2} value={f.description} maxLength={LIMITS.description} onChange={(e) => set({ description: e.target.value })} />
            </label>
          </>
        )}

        {f.kind !== "change" && ownerSelect(f.kind === "transfer" ? "New primary owner" : "Primary owner", f.primary, (v) => set({ primary: v }),
          f.kind === "transfer" ? "The old owner and the new owner both approve." : "An active person who answers for the account.", "sa-primary-hint")}
        {ownerSelect(f.kind === "create" ? "Backup owner" : "Backup owner (optional: it stays as it is)", f.backup, (v) => set({ backup: v }), "Someone else, who takes over if the primary owner is away or leaves.", "sa-backup-hint")}

        <label className="field">{f.kind === "create" ? "Purpose" : "Purpose (optional: it stays as it is)"}
          <textarea className="input" rows={2} value={f.purpose} maxLength={LIMITS.purpose} onChange={(e) => set({ purpose: e.target.value })} placeholder="What the account is for" />
        </label>
        <label className="field">Justification
          <textarea className="input" rows={3} value={f.justification} maxLength={LIMITS.justification} onChange={(e) => set({ justification: e.target.value })} placeholder="Why is this needed? Include a ticket if there is one." />
        </label>

        {asked === null && <p className="small muted" role="status">Checking what approvers ask…</p>}
        {needs.length > 0 && <QuestionnaireForm needs={needs} value={answers} onChange={setAnswers} disabled={busy} />}
        {needs.length > 0 && !ready && <p className="hint" role="status">Answer the required questions to submit.</p>}
        {problem && (f.justification.trim() !== "" || f.name !== "" || f.identityId) && <p className="hint err" role="status">{problem}</p>}
        {f.kind === "transfer" && <Callout tone="neutral" icon={<KeyRound size={16} />}>If you are the old or the new owner, your request stands for your own approval; another person still has to approve.</Callout>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <Button variant="primary" onClick={submit} disabled={!!problem || !ready || busy}>{busy ? "Submitting…" : "Submit request"}</Button>
        </div>
      </div>
    </Page>
  );
}
