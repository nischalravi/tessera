import { FormEvent, useId, useRef, useState } from "react";
import { ApiError, ContainmentReport, ContainmentRetry, containIdentity, fmtDate, retryContainmentNow, useApi } from "../../api";
import { Badge, Button, Callout, Tone, useToast } from "../../components";
import { useModal } from "../../components/overlay";

/**
 * Contain identity (issue #106): the kill switch. It revokes the identity's sessions, refresh
 * tokens and OAuth grants at each connected provider, then re-reads each provider to check.
 * Hiding the button with can("identities.contain") is for usability only: the API enforces the
 * permission and a fresh phishing-resistant sign-in.
 */

const OUTCOME: Record<string, Tone> = { done: "ok", manual: "warning", failed: "critical" };
const OUTCOME_LABEL: Record<string, string> = { done: "Done and verified", manual: "Manual task", failed: "Failed" };
const ACTION_LABEL: Record<string, string> = { revoke_sessions: "Sessions and refresh tokens", revoke_grants: "OAuth grants and credentials" };

export function ContainmentResult({ report }: { report: ContainmentReport }) {
  return (
    <div className="mt">
      <Callout tone={report.ok ? (report.manual_tasks.length ? "warn" : "ok") : "bad"}>
        {report.ok
          ? report.manual_tasks.length
            ? `Contained what the providers allow. ${report.manual_tasks.length} manual task(s) remain.`
            : "Contained and verified at every provider."
          : "Containment failed. The identity may still have live sessions or grants."}{" "}
        Took {report.duration_ms} ms.
      </Callout>
      {report.steps.length === 0 && <p className="small muted mt">This identity has no accounts on a provider Tessera can revoke at.</p>}
      <ul className="steps mt" aria-label="Containment steps">
        {report.steps.map((s, i) => (
          <li key={i} className="step">
            <span className="act"><Badge tone={OUTCOME[s.outcome] ?? "neutral"}>{OUTCOME_LABEL[s.outcome] ?? s.outcome}</Badge></span>
            <span className="small grow">
              {ACTION_LABEL[s.action] ?? s.action} · {s.system} · {s.account}
              {s.detail && <span className="muted"> ({s.detail})</span>}
            </span>
          </li>
        ))}
      </ul>
      {report.manual_tasks.length > 0 && (
        <>
          <h3 className="mt">Still to do by hand</h3>
          <ul className="small">
            {report.manual_tasks.map((m, i) => <li key={i}>{m.instructions}</li>)}
          </ul>
        </>
      )}
    </div>
  );
}

export function ContainDialog({ identity, onClose }: { identity: { id: number; name: string }; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ContainmentReport | null>(null);
  useModal(ref, onClose);
  const ready = reason.trim().length >= 10 && !busy && !report;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      setReport(await containIdentity(identity.id, reason.trim()));
    } catch (err: any) {
      setError(String(err.message ?? err));
      if (err instanceof ApiError && err.body?.report) setReport(err.body.report);
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
            <h2 id={titleId}>Contain {identity.name}</h2>
            <p className="muted">
              Revokes {identity.name}'s sessions, refresh tokens and OAuth grants at the connected identity providers (Okta, Microsoft
              Entra, Google Workspace, GitHub), then checks each provider again. It does not disable their accounts. Anything a provider
              cannot revoke, or has no credential configured, is listed as a manual task and is never reported as done. The run is
              recorded in the audit log.
            </p>
            {!report && (
              <label className="field mt">
                Reason
                <textarea className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} placeholder="For example: suspected token theft, ticket SEC-1234" />
                <span className="small muted">At least 10 characters.</span>
              </label>
            )}
            {error && <div className="mt"><Callout tone="bad">{error}</Callout></div>}
            {report && <ContainmentResult report={report} />}
          </div>
          <div className="dlg-f">
            <Button onClick={onClose}>{report ? "Close" : "Cancel"}</Button>
            {!report && <Button type="submit" variant="danger-solid" disabled={!ready}>{busy ? "Containing…" : "Contain identity"}</Button>}
          </div>
        </form>
      </div>
    </div>
  );
}

/**
 * Containment retries of one identity: failed revoke steps that Tessera keeps retrying (backoff, about 24 hours),
 * and the ones it gave up on, which need a person. Shows nothing when there are none.
 */
export function ContainmentRetries({ identityId, canRetry }: { identityId: number; canRetry: boolean }) {
  const { data, reload } = useApi<{ retries: ContainmentRetry[] }>(`/identities/${identityId}/containment`);
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const open = (data?.retries ?? []).filter((r) => r.status !== "succeeded");
  if (open.length === 0) return null;
  const pending = open.filter((r) => r.status === "pending").length;
  const retry = async (r: ContainmentRetry) => {
    setBusy(r.id);
    try {
      const res = await retryContainmentNow(r.id);
      toast(res.retry.status === "succeeded" ? "Revoked and verified" : "Still failing; Tessera will keep retrying", { kind: res.retry.status === "succeeded" ? "ok" : "error" });
      reload();
    } catch (err: any) {
      toast(String(err.message ?? err), { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="mt" role="region" aria-label="Containment retries">
      {pending > 0 && <Badge tone="warning">Containment retrying ({pending})</Badge>}{" "}
      {open.length > pending && <Badge tone="critical">Gave up ({open.length - pending})</Badge>}
      <ul className="steps mt">
        {open.map((r) => (
          <li key={r.id} className="step">
            <span className="act"><Badge tone={r.status === "pending" ? "warning" : "critical"}>{r.status === "pending" ? "Retrying" : "Gave up"}</Badge></span>
            <span className="small grow">
              {ACTION_LABEL[r.action] ?? r.action} · {r.system} · {r.account} · {r.attempts} attempt(s)
              {r.next_attempt_at && <> · next {fmtDate(r.next_attempt_at)}</>}
              {r.last_error && <span className="muted"> ({r.last_error})</span>}
              {r.manual_action && <b> {r.manual_action}</b>}
            </span>
            {canRetry && r.status === "pending" && (
              <Button size="sm" disabled={busy === r.id} onClick={() => retry(r)}>{busy === r.id ? "Retrying…" : "Retry now"}</Button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
