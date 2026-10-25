import { FormEvent, useState } from "react";
import { AwsCan, AwsPolicyChange, AwsSimulation, awsCan, awsSimulate } from "../../api";
import { Button, Callout, InsightsTabs, Page, useSelected } from "../../components";
import { FidelityBadge, OutcomeBadge, ProfileChip, ReasonList, WhyPanel } from "./AwsWhy";
import { isExplanationId } from "./awsTrace";

function CanCard({ onWhy }: { onWhy: (id: string) => void }) {
  const [principal, setPrincipal] = useState("");
  const [action, setAction] = useState("s3:GetObject");
  const [resource, setResource] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [out, setOut] = useState<AwsCan | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      setOut(await awsCan(principal.trim(), action.trim(), resource.trim()));
    } catch (x) {
      setOut(null);
      setErr(String((x as Error).message ?? x));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card stack-sm" onSubmit={submit} aria-labelledby="aws-can-h">
      <h2 id="aws-can-h">Can this principal do this?</h2>
      <label className="stack-xs">
        <span className="small muted">Principal ARN</span>
        <input className="input" value={principal} onChange={(e) => setPrincipal(e.target.value)} required placeholder="arn:aws:iam::111111111111:user/alice" />
      </label>
      <label className="stack-xs">
        <span className="small muted">Action</span>
        <input className="input" value={action} onChange={(e) => setAction(e.target.value)} required />
      </label>
      <label className="stack-xs">
        <span className="small muted">Resource ARN (optional)</span>
        <input className="input" value={resource} onChange={(e) => setResource(e.target.value)} placeholder="arn:aws:s3:::bucket/key" />
      </label>
      <div><Button type="submit" variant="primary" disabled={busy}>{busy ? "Evaluating…" : "Evaluate"}</Button></div>
      {err && <Callout tone="bad">{err}</Callout>}
      {out && (
        <div className="stack-sm" role="status">
          <div className="row">
            <OutcomeBadge o={out.decision.outcome} />
            <FidelityBadge f={out.decision.fidelity} />
            <ProfileChip profile={out.profile} />
            <Button type="button" size="sm" aria-label="Why? Show the evaluation trace" onClick={() => onWhy(out.explanation_id)}>Why?</Button>
          </div>
          <div className="small">{out.summary}</div>
          <ReasonList reasons={out.decision.fidelity_reasons ?? []} />
          {out.collection_gaps.length > 0 && <Callout tone="warn">{out.collection_gaps.length} policy could not be read and may change this answer.</Callout>}
          <pre className="sys small" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{out.narrative}</pre>
          <div className="xs faint">Snapshot {out.snapshot.id.slice(0, 8)}… · explanation {out.explanation_id.slice(0, 8)}…</div>
        </div>
      )}
    </form>
  );
}

const SAMPLE = `[
  {"op": "put_policy_version", "target_arn": "arn:aws:iam::111111111111:policy/S3Read",
   "document": "{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"s3:*\\",\\"Resource\\":\\"*\\"}]}"}
]`;

const VERB: Record<string, string> = { gained: "gain", lost: "lose", conditional_changed: "become conditional", fidelity_changed: "change in certainty" };

function SimulateCard() {
  const [text, setText] = useState(SAMPLE);
  const [head, setHead] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [out, setOut] = useState<AwsSimulation | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    let changes: AwsPolicyChange[];
    try {
      changes = JSON.parse(text);
      if (!Array.isArray(changes)) throw new Error("The changes must be a JSON list.");
    } catch (x) {
      setErr(`The changes are not valid JSON: ${(x as Error).message}`);
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      setOut(await awsSimulate(changes, head.trim() || undefined));
    } catch (x) {
      setOut(null);
      setErr(String((x as Error).message ?? x));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card stack-sm" onSubmit={submit} aria-labelledby="aws-sim-h">
      <h2 id="aws-sim-h">Who gains or loses access from a policy change?</h2>
      <label className="stack-xs">
        <span className="small muted">Changes (JSON)</span>
        <textarea className="input sys" rows={8} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} aria-describedby="aws-sim-help" />
      </label>
      <div id="aws-sim-help" className="xs faint">Nothing is applied: the change is evaluated against the latest snapshot in memory.</div>
      <label className="stack-xs">
        <span className="small muted">Label (optional)</span>
        <input className="input" value={head} onChange={(e) => setHead(e.target.value)} maxLength={80} placeholder="PR #12" />
      </label>
      <div><Button type="submit" variant="primary" disabled={busy}>{busy ? "Simulating…" : "Simulate"}</Button></div>
      {err && <Callout tone="bad">{err}</Callout>}
      {out && (
        <div className="stack-sm" role="status">
          <div className="small">
            {out.summary.gained} gained · {out.summary.lost} lost · {out.summary.conditional_changed} conditional · {out.summary.fidelity_changed} certainty changes,
            across {out.summary.principals_affected} principal{out.summary.principals_affected === 1 ? "" : "s"}.
          </div>
          {out.changes.length === 0 && <div className="muted">No one gains or loses anything.</div>}
          {out.changes.map((c, i) => (
            <div key={i} className="card stack-sm">
              <div className="row">
                <b>{c.principals.length} principal{c.principals.length === 1 ? "" : "s"} {VERB[c.kind]}</b>
                {c.after && <FidelityBadge f={c.after.fidelity} />}
                {c.gap && <span className="badge bad">UNREAD POLICY</span>}
              </div>
              <div className="small sys" style={{ overflowWrap: "anywhere" }}>{c.actions.join(", ")}{c.action_count > c.actions.length ? ` (+${c.action_count - c.actions.length})` : ""} on {c.resources.join(", ")}{c.resource_count > c.resources.length ? ` (+${c.resource_count - c.resources.length})` : ""}</div>
              <ul className="small" style={{ overflowWrap: "anywhere" }}>{c.principals.slice(0, 5).map((p) => <li key={p}>{p}</li>)}</ul>
              {c.used_days_ago !== null && <div className="small muted">Used {c.used_days_ago} day{c.used_days_ago === 1 ? "" : "s"} ago.</div>}
              {c.trace.map((t, j) => <div key={j} className="xs faint sys" style={{ overflowWrap: "anywhere" }}>{t}</div>)}
            </div>
          ))}
          {out.omitted_changes > 0 && <div className="small muted">{out.omitted_changes} more change(s) not shown.</div>}
        </div>
      )}
    </form>
  );
}

export function AwsAccess() {
  const [why, setWhy] = useSelected("why");
  return (
    <Page tabs={<InsightsTabs />} title="AWS access" crumbs={[["Protection"], ["Insights", "/insights"], ["AWS access"]]}
      sub="Ask the evaluator whether a principal can do something, and what a policy change would do, before it merges. Answers say how certain they are: approximate or unsupported results are never acted on.">
      <div className="grid g12">
        <CanCard onWhy={setWhy} />
        <SimulateCard />
      </div>
      {isExplanationId(why) && <WhyPanel id={why} onClose={() => setWhy(null)} />}
    </Page>
  );
}
