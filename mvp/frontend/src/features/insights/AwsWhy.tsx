import { useEffect, useState } from "react";
import { AwsExplanation, AwsReason, awsExplanation } from "../../api";
import { Callout, Loading, SidePanel } from "../../components";
import { fidelityMeaning, fidelityTone, matchedOn, outcomeMeaning, outcomeTone, residualText, resultLabel, resultTone, shortId, stageLabel, stmtText } from "./awsTrace";

/** The fidelity of an answer, in words as well as colour (AA contrast, never colour alone). */
export function FidelityBadge({ f }: { f: string }) {
  return <span className={`badge ${fidelityTone(f)}`} title={fidelityMeaning(f)}>{f.toUpperCase()}</span>;
}

/** The outcome of a decision: ALLOW, DENY or CONDITIONAL. */
export function OutcomeBadge({ o }: { o: string }) {
  return <span className={`badge ${outcomeTone(o)}`}>{o.toUpperCase()}</span>;
}

/** The evaluation profile the answer was computed under (the request context the engine assumed). */
export function ProfileChip({ profile }: { profile: string }) {
  return <span className="chip" title="The request context the engine assumed for this answer">Profile: {profile}</span>;
}

export function ReasonList({ reasons }: { reasons: AwsReason[] }) {
  if (reasons.length === 0) return null;
  return (
    <ul className="small stack-xs" aria-label="Why this is not exact" style={{ paddingLeft: 18 }}>
      {reasons.map((r, i) => (
        <li key={i} style={{ overflowWrap: "anywhere" }}>
          <span className="sys">{r.code}</span>
          {r.outcome_sensitive ? <> <span className="badge warning">CAN CHANGE THE ANSWER</span></> : null}
          {r.detail ? <div className="xs faint">{r.detail}</div> : null}
        </li>
      ))}
    </ul>
  );
}

function Trace({ x }: { x: AwsExplanation }) {
  const d = x.decision;
  const steps = d.steps ?? [];
  const decisive = d.decisive ?? [];
  const reasons = d.fidelity_reasons ?? [];
  const residual = residualText(d.residual);
  return (
    <>
      <section className="stack-sm" aria-label="Answer">
        <div className="row"><OutcomeBadge o={d.outcome} /><FidelityBadge f={d.fidelity} /></div>
        <div className="small">{outcomeMeaning(d.outcome, d.deny_kind)}</div>
        <div className="small muted">{fidelityMeaning(d.fidelity)}</div>
        {d.request && (
          <dl className="kv kv-narrow small">
            <dt>Principal</dt><dd className="sys">{d.request.principal_arn}</dd>
            <dt>Action</dt><dd className="sys">{d.request.action}</dd>
            {d.request.resource_arn ? <><dt>Resource</dt><dd className="sys">{d.request.resource_arn}</dd></> : null}
          </dl>
        )}
        <ReasonList reasons={reasons} />
        {d.outcome === "conditional" && residual && <Callout tone="warn">Allowed only if: <span className="sys">{residual}</span></Callout>}
      </section>

      {decisive.length > 0 && (
        <section className="stack-sm" aria-labelledby="why-decisive-h">
          <h3 id="why-decisive-h">Statements that decided it</h3>
          <ul className="small stack-xs" style={{ paddingLeft: 18 }}>
            {decisive.map((s, i) => <li key={i} style={{ overflowWrap: "anywhere" }}>{stmtText(s)}<div className="xs faint sys">{s.source_arn}</div></li>)}
          </ul>
        </section>
      )}

      <section className="stack-sm" aria-labelledby="why-steps-h">
        <h3 id="why-steps-h">Evaluation, step by step</h3>
        {steps.length === 0 ? <div className="muted small">The engine recorded no steps for this answer.</div> : (
          <ol className="stack-sm" style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {steps.map((st, i) => {
              const cond = st.condition_trace ?? [];
              const matched = matchedOn(st);
              const res = residualText(st.residual);
              return (
                <li key={i} className="card stack-sm">
                  <div className="row">
                    <span className="xs faint">{i + 1}.</span>
                    <b>{stageLabel(st.stage)}</b>
                    <span className={`badge ${resultTone(st.result)}`}>{resultLabel(st.result).toUpperCase()}</span>
                    {st.decisive && <span className="badge info">DECISIVE</span>}
                  </div>
                  {st.statement && (
                    <div className="small" style={{ overflowWrap: "anywhere" }}>
                      {stmtText(st.statement)}
                      <div className="xs faint sys">{st.statement.source_arn}</div>
                      {(st.statement.attachment_path ?? []).length > 0 && <div className="xs faint">Reached through {(st.statement.attachment_path ?? []).join(" > ")}</div>}
                    </div>
                  )}
                  {matched.length > 0 && (
                    <dl className="kv kv-narrow xs">
                      {matched.map(([k, v]) => <div key={k} style={{ display: "contents" }}><dt>Matched {k}</dt><dd className="sys">{v}</dd></div>)}
                    </dl>
                  )}
                  {cond.length > 0 && (
                    <ul className="xs stack-xs" aria-label="Conditions" style={{ paddingLeft: 18 }}>
                      {cond.map((c, j) => (
                        <li key={j} style={{ overflowWrap: "anywhere" }}>
                          <span className="sys">{residualText(c.atom)}</span>: request {c.request_state}
                          {(c.request_values ?? []).length > 0 ? <> (<span className="sys">{(c.request_values ?? []).join(", ")}</span>)</> : null}, so <b>{c.result}</b>
                        </li>
                      ))}
                    </ul>
                  )}
                  {res && <div className="xs" style={{ overflowWrap: "anywhere" }}>Holds only if: <span className="sys">{res}</span></div>}
                  {st.note && <div className="xs muted">{st.note}</div>}
                </li>
              );
            })}
          </ol>
        )}
      </section>

      <div className="xs faint" style={{ overflowWrap: "anywhere" }}>
        Engine {d.engine_version} · catalog {d.catalog_version} · snapshot {shortId(d.snapshot_id)} · explanation {shortId(x.id)}
      </div>
    </>
  );
}

/** The "Why?" side panel: loads one decision's trace by explanation id and renders it step by step. */
export function WhyPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const [x, setX] = useState<AwsExplanation | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tries, setTries] = useState(0);
  useEffect(() => {
    let live = true;
    setX(null);
    setErr(null);
    awsExplanation(id).then(
      (r) => live && setX(r),
      (e) => live && setErr(String((e as Error).message ?? e)),
    );
    return () => { live = false; };
  }, [id, tries]);
  return (
    <SidePanel title="Why this answer?" sub={<span className="sys">{shortId(id)}</span>} onClose={onClose}>
      {err ? <Loading error={err} what="the explanation" onRetry={() => setTries((n) => n + 1)} />
        : !x ? <div role="status" aria-live="polite"><Loading kind="block" /><span className="sr-only">Loading the explanation</span></div>
        : <Trace x={x} />}
    </SidePanel>
  );
}
