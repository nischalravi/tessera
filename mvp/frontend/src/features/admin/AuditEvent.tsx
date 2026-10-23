import { Fragment, useState } from "react";
import { Download, ShieldCheck, X } from "lucide-react";
import { AuditProof, AuditRow, fmtDate, useApi } from "../../api";
import { Badge, Button, Callout, SidePanel } from "../../components";
import { AuditQuery, EMPTY_AUDIT_QUERY, isUnfiltered } from "./auditQuery";

/** Filters the server applies before it sends the page: who did it, what it was done to, and when. */
export function AuditFilters({ value, onApply }: { value: AuditQuery; onApply: (q: AuditQuery) => void }) {
  const [f, setF] = useState(value);
  const set = (k: keyof AuditQuery) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  const bad = f.from !== "" && f.to !== "" && f.from > f.to;
  return (
    <form
      className="card stack-sm"
      aria-label="Filter the audit log on the server"
      onSubmit={(e) => {
        e.preventDefault();
        if (!bad) onApply({ ...f, includeHttp: value.includeHttp });
      }}
    >
      <div className="row" style={{ flexWrap: "wrap", gap: 12, alignItems: "end" }}>
        <label className="field">Actor id<input className="input" value={f.actorId} onChange={set("actorId")} maxLength={200} placeholder="user id or system name" /></label>
        <label className="field">Target type<input className="input" value={f.targetType} onChange={set("targetType")} maxLength={200} placeholder="e.g. access_request" /></label>
        <label className="field">Target id<input className="input" value={f.targetId} onChange={set("targetId")} maxLength={200} /></label>
        <label className="field">From (UTC)<input className="input" type="date" value={f.from} onChange={set("from")} /></label>
        <label className="field">To (UTC)<input className="input" type="date" value={f.to} onChange={set("to")} /></label>
        <span className="row tight">
          <Button type="submit" size="sm" variant="primary" disabled={bad}>Filter</Button>
          {!isUnfiltered(value) && (
            <Button type="button" size="sm" icon={<X size={13} />} onClick={() => { setF({ ...EMPTY_AUDIT_QUERY }); onApply({ ...EMPTY_AUDIT_QUERY, includeHttp: value.includeHttp }); }}>Clear</Button>
          )}
        </span>
      </div>
      {bad && <p className="small" role="alert" style={{ margin: 0 }}>The start date is after the end date.</p>}
      <p className="small muted" style={{ margin: 0 }}>The server filters the whole ledger, not only the rows below, and returns the newest 500 matches.</p>
    </form>
  );
}

const AUTHN_LABEL: Record<string, string> = {
  ctx_id: "Session context", aal: "Assurance level (AAL)", phr: "Phishing-resistant", acr: "Authentication class (acr)", auth_time: "Authenticated at", auth_age_s: "Seconds since authentication",
};
const authnValue = (k: string, v: unknown) => (typeof v === "boolean" ? (v ? "yes" : "no") : k === "auth_time" && typeof v === "string" ? fmtDate(v.replace("Z", "")) : String(v));

/** One event, with how its actor signed in and the inclusion proof for an evidence pack. */
export function AuditEventPanel({ event: e, onClose }: { event: AuditRow; onClose: () => void }) {
  const [proofOn, setProofOn] = useState(false);
  const { data: proof, error, loading } = useApi<AuditProof>(proofOn && e.event_id ? `/audit/events/${encodeURIComponent(e.event_id)}/proof?path=true` : null);
  const authn = e.authn ? Object.entries(e.authn).filter(([, v]) => v !== null && v !== undefined) : [];
  const download = () => {
    if (!proof) return;
    const blob = new Blob([JSON.stringify(proof, null, 2) + "\n"], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-proof-${e.seq ?? e.id}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };
  return (
    <SidePanel
      title={e.action}
      sub={<span className="row tight">{e.outcome && <Badge tone={e.outcome === "success" ? "ok" : e.outcome === "denied" || e.outcome === "error" ? "critical" : "warning"}>{e.outcome}</Badge>} <span className="small faint">{fmtDate(e.at)}</span></span>}
      onClose={onClose}
      commands={<Button size="sm" icon={<ShieldCheck size={13} />} disabled={!e.event_id || proofOn} onClick={() => setProofOn(true)}>Inclusion proof</Button>}
    >
      <div className="stack-sm">
        <dl className="kv small">
          <dt>Sequence</dt><dd>{e.seq ?? e.id}</dd>
          <dt>Actor</dt><dd>{e.actor}{e.actor_type && <> <Badge tone="outline">{e.actor_type}</Badge></>}</dd>
          {e.actor_id && <><dt>Actor id</dt><dd><code className="xs">{e.actor_id}</code></dd></>}
          {e.target && (e.target.type || e.target.id) && <><dt>Target</dt><dd>{e.target.type} {e.target.id}</dd></>}
          {e.request_id && <><dt>Request</dt><dd><code className="xs">{e.request_id}</code></dd></>}
          <dt>Hash</dt><dd><code className="xs" style={{ wordBreak: "break-all" }}>{e.hash}</code></dd>
        </dl>
        <h3 style={{ margin: 0 }}>How the actor signed in</h3>
        {authn.length > 0 ? (
          <dl className="kv small">
            {authn.map(([k, v]) => <Fragment key={k}><dt>{AUTHN_LABEL[k] ?? k}</dt><dd>{authnValue(k, v)}</dd></Fragment>)}
          </dl>
        ) : (
          <p className="small muted" style={{ margin: 0 }}>{e.actor_type === "user" ? "No authentication context was recorded." : "Not a signed-in user: no sign-in context applies."}</p>
        )}
        <h3 style={{ margin: 0 }}>Detail</h3>
        <pre className="small sys" style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{JSON.stringify(e.detail, null, 2)}</pre>
        {proofOn && (
          <div className="stack-sm">
            <h3 style={{ margin: 0 }}>Inclusion proof</h3>
            {loading && !proof && <p className="small muted" style={{ margin: 0 }}>Building the proof…</p>}
            {error && <Callout tone="bad">{error.message}</Callout>}
            {proof && (
              <>
                {proof.checkpoint ? (
                  <Callout tone="ok">
                    <b>Covered by a signed checkpoint</b> at sequence {proof.checkpoint.seq} ({proof.events_to_checkpoint} events later, anchor {proof.checkpoint.anchor_status}). The file holds this event and every event up to the checkpoint: recompute each hash and check the last one equals <code className="xs">head_hash</code>.
                  </Callout>
                ) : (
                  <Callout tone="warn"><b>Not covered by a checkpoint yet.</b> The chain still links this event to its neighbours; a signed checkpoint follows within a few minutes.</Callout>
                )}
                <Button size="sm" variant="primary" icon={<Download size={13} />} onClick={download}>Download proof (JSON)</Button>
              </>
            )}
          </div>
        )}
      </div>
    </SidePanel>
  );
}
