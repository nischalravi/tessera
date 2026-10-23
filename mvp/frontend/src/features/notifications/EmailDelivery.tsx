import { useState } from "react";
import { Ban, Mail, RefreshCw } from "lucide-react";
import { EmailAttempt, EmailList, EmailMessage, EmailStatus, emailSuppressionsApi, fmtDate, relTime, retryEmail, useApi } from "../../api";
import { Badge, Button, Callout, Column, DataTable, EmptyState, Loading, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { MailRelayCard, SuppressionsCard } from "./NotifyAdmin";

const STATUS_LABEL: Record<EmailStatus, string> = {
  queued: "Queued", sending: "Sending", accepted: "Accepted by relay", deferred: "Deferred", rejected: "Rejected", failed: "Failed", bounced: "Bounced",
};
const STATUS_TONE: Record<EmailStatus, "ok" | "warning" | "critical" | "info" | "neutral"> = {
  queued: "neutral", sending: "info", accepted: "ok", deferred: "warning", rejected: "critical", failed: "critical", bounced: "critical",
};
const STATUS_HELP: Record<EmailStatus, string> = {
  queued: "Waiting for the next attempt.",
  sending: "An attempt is in progress.",
  accepted: "The relay accepted the message (it answered 250 at the end of DATA). That is not proof the message reached the inbox.",
  deferred: "The relay answered with a temporary error (4xx). Tessera retries with a growing delay.",
  rejected: "The relay refused the message (5xx). It is not retried.",
  failed: "The connection or TLS failed. Tessera retries with a growing delay.",
  bounced: "A delivery status report said the address cannot be reached (a hard bounce). The address is suppressed, so it is not emailed again until you lift that.",
};

const StatusBadge = ({ s }: { s: EmailStatus }) => <Badge tone={STATUS_TONE[s]} title={STATUS_HELP[s]}>{STATUS_LABEL[s]}</Badge>;

const age = (m: EmailMessage) => {
  const h = (Date.now() - new Date(m.updated_at.endsWith("Z") ? m.updated_at : m.updated_at + "Z").getTime()) / 3.6e6;
  return h <= 24 ? "Last 24 hours" : h <= 24 * 7 ? "Last 7 days" : h <= 24 * 30 ? "Last 30 days" : "Older";
};

/** Admin → Email delivery: every email Tessera sent, with the relay's answers. */
export function EmailDelivery() {
  const { data, error, reload } = useApi<EmailList>("/email/messages?limit=500");
  const [selected, setSelected] = useSelected();
  if (!data) return <Loading error={error} kind="table" />;
  const cols: Column<EmailMessage>[] = [
    { id: "status", header: "Status", sort: (m) => m.status, cell: (m) => <StatusBadge s={m.status} /> },
    { id: "kind", header: "Kind", sort: (m) => m.kind, cell: (m) => <code className="small">{m.kind}</code>, hideNarrow: true },
    { id: "to", header: "Recipient", sort: (m) => m.recipient, cell: (m) => <span className="small">{m.recipient}</span> },
    { id: "subject", header: "Subject", sort: (m) => m.subject, cell: (m) => <span className="small">{m.subject}</span>, hideNarrow: true },
    { id: "queue", header: "Relay queue id", sort: (m) => m.queue_id ?? "", cell: (m) => <code className="small">{m.queue_id ?? "–"}</code>, hideNarrow: true },
    { id: "n", header: "Attempts", num: true, sort: (m) => m.attempt_count, cell: (m) => m.attempt_count },
    { id: "at", header: "Updated", sort: (m) => m.updated_at, cell: (m) => <span className="small faint nowrap" title={fmtDate(m.updated_at)}>{relTime(m.updated_at)}</span> },
  ];
  return (
    <div className="stack">
      {data.email_mode === "dev" && <Callout tone="warn">Email goes to the development mail sink, so “Accepted” only means it was recorded in a file.</Callout>}
      {data.email_mode === "off" && <Callout tone="neutral">Email is turned off on this server, so nothing is sent and nothing is logged here.</Callout>}
      <Callout tone="info">
        <b>Accepted</b> means the relay took the message (250 at the end of DATA). It does not mean the message reached the inbox: if it bounces later, the relay's delivery status
        report marks it <b>Bounced</b> (post the report to <code>POST /api/email/dsn</code>, for example from the bounce mailbox). Message bodies and credentials are never recorded.
      </Callout>
      <DataTable
        id="email-delivery"
        rows={data.messages}
        error={error}
        rowKey={(m) => m.id}
        columns={cols}
        searchText={(m) => `${m.recipient} ${m.subject} ${m.kind} ${m.queue_id ?? ""}`}
        searchPlaceholder="Search recipient, subject or queue id…"
        filters={[
          { id: "status", label: "Status", options: data.statuses.map((s) => ({ value: s, label: STATUS_LABEL[s] })), get: (m) => m.status },
          { id: "kind", label: "Kind", options: [...new Set(data.messages.map((m) => m.kind))].sort().map((k) => ({ value: k, label: k })), get: (m) => m.kind },
          { id: "date", label: "Date", options: ["Last 24 hours", "Last 7 days", "Last 30 days", "Older"].map((v) => ({ value: v, label: v })), get: age },
        ]}
        onRefresh={reload}
        rowLabel={(m) => `${m.subject} to ${m.recipient}`}
        onRowClick={(m) => setSelected(m.id)}
        activeKey={selected}
        empty={<EmptyState icon={<Mail size={18} />} title="No email sent yet">Every email Tessera sends is listed here with what the relay answered.</EmptyState>}
      />
      {selected && <MessagePanel id={selected} onClose={() => setSelected(null)} onChanged={reload} />}
      <SuppressionsCard />
      <MailRelayCard />
    </div>
  );
}

function MessagePanel({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { data: m, error, reload } = useApi<EmailMessage>(`/email/messages/${encodeURIComponent(id)}`);
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const suppress = async () => {
    if (!m) return;
    const reason = await confirm({ title: `Stop emailing ${m.recipient}?`, body: "No more email goes to this address. It still gets the inbox entries. You can lift this under Suppressed addresses.", confirmLabel: "Suppress", danger: true, reason: { label: "Why (optional)", required: false } });
    if (reason === null) return;
    setBusy(true);
    try {
      await emailSuppressionsApi.add(m.recipient, reason || "");
      toast(`${m.recipient} is suppressed`);
      onChanged();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const retry = async () => {
    setBusy(true);
    try {
      await retryEmail(id);
      toast("Queued: the next dispatcher pass sends it again");
      reload();
      onChanged();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <SidePanel title={m?.subject ?? "Email"} sub={m && <span className="small muted">to {m.recipient}</span>} onClose={onClose}
      footer={m && (
        <div className="row">
          {m.retryable && <Button size="sm" variant="primary" icon={<RefreshCw size={14} />} disabled={busy} onClick={retry}>Send again</Button>}
          <Button size="sm" variant="danger" icon={<Ban size={14} />} disabled={busy} onClick={suppress}>Suppress this address</Button>
        </div>
      )}>
      {!m ? <Loading error={error} kind="block" /> : (
        <div className="stack">
          <div className="stack-sm">
            <div className="row"><StatusBadge s={m.status} />{m.queue_id && <span className="small">relay queue id <code>{m.queue_id}</code></span>}</div>
            <p className="small muted" style={{ margin: 0 }}>{STATUS_HELP[m.status]}</p>
            <dl className="small" style={{ margin: 0, display: "grid", gridTemplateColumns: "max-content 1fr", gap: "4px 12px" }}>
              <dt className="faint">Kind</dt><dd style={{ margin: 0 }}><code>{m.kind}</code></dd>
              <dt className="faint">MAIL FROM</dt><dd style={{ margin: 0 }}><code>{m.mail_from ?? "–"}</code></dd>
              <dt className="faint">RCPT TO</dt><dd style={{ margin: 0 }}><code>{m.rcpt_to ?? "–"}</code></dd>
              <dt className="faint">Attempts</dt><dd style={{ margin: 0 }}>{m.attempt_count}</dd>
            </dl>
          </div>
          <h3 style={{ margin: 0 }}>Attempts</h3>
          {(m.attempts ?? []).length === 0 ? <p className="small muted">No attempt yet.</p> : (
            <ol className="attempt-list">
              {(m.attempts ?? []).map((a, i) => <Attempt key={i} n={i + 1} a={a} />)}
            </ol>
          )}
        </div>
      )}
    </SidePanel>
  );
}

function Attempt({ n, a }: { n: number; a: EmailAttempt }) {
  const ms = new Date(a.finished_at).getTime() - new Date(a.started_at).getTime();
  return (
    <li className="stack-sm">
      <div className="row"><b>Attempt {n}</b><StatusBadge s={a.outcome} /><span className="small faint" title={fmtDate(a.started_at)}>{relTime(a.started_at)} · {Number.isFinite(ms) ? `${ms} ms` : ""}</span></div>
      {a.error && <div className="small" style={{ color: "var(--critical)" }}>{a.error}</div>}
      {a.banner && <div className="small"><span className="faint">Banner</span> <code>{a.banner}</code></div>}
      {a.capabilities && a.capabilities.length > 0 && <div className="small"><span className="faint">Capabilities</span> <code>{a.capabilities.join(", ")}</code></div>}
      {a.tls && (
        <div className="small"><span className="faint">TLS</span>{" "}
          {a.tls.error ? <span style={{ color: "var(--critical)" }}>{a.tls.error}</span> : <code>{a.tls.version} · {a.tls.cipher} · {a.tls.server_subject} (issuer {a.tls.server_issuer})</code>}
        </div>
      )}
      <pre className="transcript" aria-label={`SMTP transcript of attempt ${n}`}>
        {a.steps.map((s) => `${s.command ? `C: ${s.command}\n` : ""}S: ${s.code}${s.reply ? " " + s.reply.replace(/\n/g, "\n      ") : ""}`).join("\n")}
        {a.truncated ? "\n… transcript truncated" : ""}
      </pre>
    </li>
  );
}
