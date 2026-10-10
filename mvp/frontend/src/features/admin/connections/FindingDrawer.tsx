/** A reconciliation finding: samples, cause, impact, fix link and "Accept with reason" (§10.4). */
import { useState } from "react";
import { Link } from "react-router-dom";
import { Finding, fmtDate, readiness } from "../../../api";
import { Badge, Button, Callout, Drawer, ReasonDialog, Sev, useToast } from "../../../components";

export function FindingStatus({ s }: { s: Finding["status"] }) {
  return <Badge tone={s === "open" ? "warning" : s === "accepted" ? "info" : "ok"} dot>{s[0].toUpperCase() + s.slice(1)}</Badge>;
}

export function FindingDrawer({ connectionId, f, onClose, onChanged, latest }: {
  connectionId: string;
  f: Finding;
  onClose: () => void;
  onChanged: () => void;
  /** Only findings of the latest dry run can be accepted. */
  latest: boolean;
}) {
  const toast = useToast();
  const [accepting, setAccepting] = useState(false);
  return (
    <Drawer
      wide
      title={<span className="row tight"><Sev s={f.severity} /> {f.code}{f.variant && !/^[a-z]$/.test(f.variant) ? "" : f.variant} · {f.title}</span>}
      sub={<>{f.count} of {f.denominator} ({f.percent}%) · first seen {fmtDate(f.first_seen_at)}</>}
      onClose={onClose}
      footer={
        <>
          {f.item_id && <Link className="btn" to={`/admin/connections/${connectionId}?item=${f.item_id}`} onClick={onClose}>Fix: open {f.item_id}</Link>}
          {f.status === "open" && latest && <Button variant="primary" onClick={() => setAccepting(true)}>Accept with reason…</Button>}
        </>
      }
    >
      <div className="stack">
        <div className="row tight"><FindingStatus s={f.status} />{f.status === "accepted" && <span className="small">by {f.accepted_by}: “{f.reason}”{f.expires_at && `, until ${f.expires_at.slice(0, 10)}`}</span>}</div>
        <section className="stack-sm">
          <h3>Impact</h3>
          <p>{f.impact.sentence}</p>
          <div className="stat-row">
            <div className="s"><b>{f.impact.affected_accounts}</b><span>accounts</span></div>
            <div className="s"><b>{f.impact.affected_identities}</b><span>people</span></div>
            <div className="s"><b>{f.impact.privileged_grants}</b><span>privileged memberships</span></div>
            <div className="s"><b>{f.impact.downstream_perms}</b><span>permissions reached</span></div>
          </div>
        </section>
        {f.cause && (
          <section className="stack-sm">
            <h3>Probable cause <span className="faint xs">({f.cause.analyser})</span></h3>
            <Callout tone="neutral">{f.cause.sentence}</Callout>
            <div className="xs faint">Numbers used: {Object.entries(f.cause.numbers).map(([k, v]) => `${k.replace(/_/g, " ")} ${String(v)}`).join(" · ")}</div>
          </section>
        )}
        <section className="stack-sm">
          <h3>Samples <span className="faint xs">(at most 10; ids and names only)</span></h3>
          {f.samples.length === 0 ? <p className="small faint">This finding has no object samples.</p> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Name</th><th>Id</th><th>Why it matched</th></tr></thead>
                <tbody>
                  {f.samples.map((s) => (
                    <tr key={s.ref}><td><b className="small">{s.name}</b></td><td className="xs faint sys truncate" style={{ maxWidth: 220 }}>{s.ref}</td><td className="small">{s.reason}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        {f.severity === "critical" && f.status === "open" && <Callout tone="warn">Accepting a critical finding will need step-up authentication once RBAC lands (DR-10).</Callout>}
        {!latest && <Callout tone="neutral">This finding belongs to an earlier dry run. Accept findings of the latest dry run.</Callout>}
      </div>
      {accepting && (
        <ReasonDialog
          title={`Accept ${f.code}${f.variant}: ${f.title}`}
          body="An accepted finding stays on the dashboard as a known gap, counts half in the score and no longer blocks reconciliation."
          label="Reason"
          minLength={20}
          confirmLabel="Accept"
          date={{ label: "Expires (optional)", hint: "The acceptance lapses then and the finding needs attention again." }}
          onCancel={() => setAccepting(false)}
          onSubmit={async (reason, day) => {
            await readiness.accept(connectionId, f.id, reason, day);
            toast(`${f.code}${f.variant} accepted`);
            setAccepting(false);
            onChanged();
            onClose();
          }}
        />
      )}
    </Drawer>
  );
}
