import { FormEvent, useEffect, useState } from "react";
import { Mail, MessageSquare, Send, Trash2 } from "lucide-react";
import {
  ChatInput, ChatProvider, ChatWorkspace, EmailSuppressions, MailRelay, NotificationPolicy, NotificationTemplates, chatApi, chatPath, emailSuppressionsApi,
  emailSuppressionsPath, fmtDate, mailRelayApi, mailRelayPath, notificationPolicyApi, notificationPolicyPath, notificationTemplatesApi,
  notificationTemplatesPath, relTime, useApi,
} from "../../api";
import { Badge, Button, Callout, Loading, useConfirm, useToast } from "../../components";
import { errText } from "../admin/common";
import { SAMPLE, renderTemplate, templateProblem } from "./templates.ts";

/** Admin → Notifications and Email delivery: the tenant's own relay, chat workspace, wording and timings. The server checks every value again. */

const fieldsetStyle = { border: 0, padding: 0, margin: 0 } as const;

// ---------------------------------------------------------------------------- mail relay

const TLS_LABEL: Record<string, string> = { starttls: "STARTTLS (usually port 587)", tls: "TLS from the first byte (usually port 465)", none: "No TLS (development only)" };

/** The tenant's own SMTP relay. The password is sealed on the server and never shown again. */
export function MailRelayCard() {
  const { data, error, reload } = useApi<MailRelay>(mailRelayPath);
  const toast = useToast();
  const confirm = useConfirm();
  const [f, setF] = useState({ enabled: true, host: "", port: "587", tls: "starttls", username: "", password: "", clear: false, from: "" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);
  useEffect(() => {
    if (data) setF({ enabled: data.configured ? data.enabled : true, host: data.host, port: String(data.port), tls: data.tls, username: data.username, password: "", clear: false, from: data.from });
  }, [data?.version]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!data) return <div className="card flush"><Loading error={error} kind="block" /></div>;
  const can = data.can_manage;
  const port = Number(f.port);
  const set = <K extends keyof typeof f>(k: K, v: (typeof f)[K]) => setF((p) => ({ ...p, [k]: v }));
  const problem = !f.host.trim() ? "Enter the relay's host name." : !(Number.isInteger(port) && port >= 1 && port <= 65535) ? "The port is 1 to 65535."
    : !f.from.trim() ? "Enter the address email is sent from."
    : f.username && !f.password && (!data.has_password || f.clear) ? "A login needs a password." : !f.username && f.password ? "A password needs a username." : null;
  const dirty = !data.configured || f.enabled !== data.enabled || f.host.trim().toLowerCase() !== data.host || port !== data.port || f.tls !== data.tls ||
    f.username !== data.username || f.password !== "" || f.clear || f.from.trim() !== data.from;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || busy || !can) return;
    setBusy(true);
    setErr(null);
    try {
      await mailRelayApi.save({ version: data.version, enabled: f.enabled, host: f.host.trim(), port, tls: f.tls, username: f.username.trim(),
        password: f.password || undefined, clear_password: f.clear || undefined, from: f.from.trim() });
      toast("Mail relay saved");
      reload();
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };
  const test = async () => {
    setBusy(true);
    setErr(null);
    setTestResult(null);
    try {
      const r = await mailRelayApi.test();
      setTestResult(r.outcome === "accepted" ? "The relay accepted the test message. It was sent to your own address." : `The relay answered: ${r.outcome}${r.error ? `, ${r.error}` : ""}.`);
      reload();
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if ((await confirm({ title: "Remove this relay?", body: "Email goes through the server's relay again.", confirmLabel: "Remove", danger: true })) === null) return;
    setBusy(true);
    try {
      await mailRelayApi.remove(data.version);
      toast("Mail relay removed");
      reload();
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card stack" onSubmit={submit} aria-label="Mail relay">
      <h2 className="row tight"><Mail size={16} /> Your own mail relay</h2>
      <p className="small muted" style={{ margin: 0 }}>
        Send this organization's notification email through your SMTP relay, from your own address. Without one, email goes through the server's relay
        ({data.server_relay === "smtp" ? "set up" : data.server_relay === "dev" ? "a development sink that sends nothing" : "off"}). Tessera connects only to public relays, never to an internal address.
      </p>
      {!can && <Callout tone="neutral">You can read these settings. A tenant admin changes them.</Callout>}
      <fieldset style={fieldsetStyle} className="stack-sm" disabled={!can}>
        <label className="row small"><input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Send this organization's email through this relay</label>
        <div className="grid g2">
          <label className="field">Host
            <input className="input" value={f.host} onChange={(e) => set("host", e.target.value)} placeholder="smtp.example.com" autoComplete="off" spellCheck={false} />
          </label>
          <label className="field">Port
            <input className="input" inputMode="numeric" value={f.port} onChange={(e) => set("port", e.target.value)} style={{ maxWidth: 120 }} />
          </label>
          <label className="field">Security
            <select className="input" value={f.tls} onChange={(e) => set("tls", e.target.value)}>
              {Object.entries(TLS_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
          </label>
          <label className="field">Send from
            <input className="input" value={f.from} onChange={(e) => set("from", e.target.value)} placeholder="Tessera <tessera@example.com>" autoComplete="off" />
          </label>
          <label className="field">Username <span className="faint">(optional)</span>
            <input className="input" value={f.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" />
          </label>
          <label className="field">Password
            <input className="input" type="password" value={f.password} onChange={(e) => set("password", e.target.value)} autoComplete="new-password"
              placeholder={data.has_password ? "Unchanged" : ""} aria-describedby="relay-pw-help" />
            <span className="xs faint" id="relay-pw-help">Stored sealed and never shown again.{data.has_password && " Leave empty to keep it."}</span>
          </label>
        </div>
        {data.has_password && (
          <label className="row small"><input type="checkbox" checked={f.clear} onChange={(e) => set("clear", e.target.checked)} /> Remove the stored password</label>
        )}
      </fieldset>
      {data.last_test_at && <p className="small muted" style={{ margin: 0 }}>Last test {relTime(data.last_test_at)}: <b>{data.last_test_result || "no result"}</b></p>}
      <div aria-live="polite">{testResult && <Callout tone="info">{testResult}</Callout>}{problem && dirty && <p className="small" role="alert">{problem}</p>}{err && <Callout tone="bad">{err}</Callout>}</div>
      {can && (
        <div className="row" style={{ justifyContent: "flex-end" }}>
          {data.configured && <Button variant="danger" icon={<Trash2 size={14} />} disabled={busy} onClick={remove}>Remove</Button>}
          {data.configured && <Button icon={<Send size={14} />} disabled={busy || dirty} onClick={test} title={dirty ? "Save first" : "Sends one message to your own address"}>Send a test message</Button>}
          <Button type="submit" variant="primary" disabled={!!problem || !dirty || busy}>{busy ? "Working…" : "Save relay"}</Button>
        </div>
      )}
    </form>
  );
}

// ---------------------------------------------------------------------------- chat

const PROVIDER_LABEL: Record<ChatProvider, string> = { slack: "Slack", teams: "Microsoft Teams" };

/** The tenant's chat workspace: a Slack or Teams incoming webhook that gets a message for each event of the kinds chosen. */
export function ChatCard() {
  const { data, error, reload } = useApi<ChatWorkspace>(chatPath);
  const toast = useToast();
  const confirm = useConfirm();
  const [f, setF] = useState<{ provider: ChatProvider; enabled: boolean; url: string; kinds: string[] }>({ provider: "slack", enabled: true, url: "", kinds: [] });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  useEffect(() => {
    if (data) setF({ provider: data.provider, enabled: data.configured ? data.enabled : true, url: "", kinds: data.kinds });
  }, [data?.version]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!data) return <div className="card flush"><Loading error={error} kind="block" /></div>;
  const can = data.can_manage;
  const needsUrl = !data.has_webhook || f.provider !== data.provider;
  const problem = needsUrl && !f.url.trim() ? `Paste the ${PROVIDER_LABEL[f.provider]} incoming webhook URL.` : f.enabled && f.kinds.length === 0 ? "Choose at least one kind to post." : null;
  const dirty = !data.configured || f.provider !== data.provider || f.enabled !== data.enabled || f.url.trim() !== "" || JSON.stringify([...f.kinds].sort()) !== JSON.stringify([...data.kinds].sort());
  const toggle = (k: string) => setF((p) => ({ ...p, kinds: p.kinds.includes(k) ? p.kinds.filter((x) => x !== k) : [...p.kinds, k] }));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || busy || !can) return;
    setBusy(true);
    setErr(null);
    setOk(null);
    try {
      const body: ChatInput = { version: data.version, provider: f.provider, enabled: f.enabled, kinds: f.kinds };
      if (f.url.trim()) body.webhook_url = f.url.trim();
      await chatApi.save(body);
      toast("Chat workspace saved");
      reload();
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };
  const test = async () => {
    setBusy(true);
    setErr(null);
    setOk(null);
    try {
      await chatApi.test();
      setOk(`A test message was posted to ${PROVIDER_LABEL[data.provider]}.`);
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if ((await confirm({ title: "Disconnect the chat workspace?", body: "Nothing more is posted. The webhook URL is deleted.", confirmLabel: "Disconnect", danger: true })) === null) return;
    setBusy(true);
    try {
      await chatApi.remove(data.version);
      toast("Chat workspace removed");
      reload();
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card stack" onSubmit={submit} aria-label="Chat workspace">
      <h2 className="row tight"><MessageSquare size={16} /> Chat workspace</h2>
      <p className="small muted" style={{ margin: 0 }}>
        Post a message to a Slack or Microsoft Teams channel for each event of the kinds you choose, once however many people it is for. Create an incoming webhook
        for the channel and paste its URL. The URL is a credential: it is stored sealed and never shown again. Tessera posts only to {PROVIDER_LABEL[f.provider]}'s own hosts ({data.hosts[f.provider]}).
      </p>
      {!can && <Callout tone="neutral">You can read these settings. A tenant admin changes them.</Callout>}
      <fieldset style={fieldsetStyle} className="stack-sm" disabled={!can}>
        <div className="grid g2">
          <label className="field">Workspace
            <select className="input" value={f.provider} onChange={(e) => setF((p) => ({ ...p, provider: e.target.value as ChatProvider }))}>
              {data.providers.map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p]}</option>)}
            </select>
          </label>
          <label className="field">Incoming webhook URL
            <input className="input" type="password" value={f.url} onChange={(e) => setF((p) => ({ ...p, url: e.target.value }))} autoComplete="off" spellCheck={false}
              placeholder={data.has_webhook && f.provider === data.provider ? `Unchanged (${data.webhook_host})` : f.provider === "slack" ? "https://hooks.slack.com/services/…" : "https://….webhook.office.com/…"} />
          </label>
        </div>
        <label className="row small"><input type="checkbox" checked={f.enabled} onChange={(e) => setF((p) => ({ ...p, enabled: e.target.checked }))} /> Post to this workspace</label>
        <div className="stack-sm">
          <span className="small strong">Post these kinds</span>
          <div className="grid g2">
            {data.available_kinds.map((k) => (
              <label key={k.id} className="row small" title={k.description}>
                <input type="checkbox" checked={f.kinds.includes(k.id)} onChange={() => toggle(k.id)} /> {k.label}
              </label>
            ))}
          </div>
        </div>
      </fieldset>
      {data.configured && (
        <p className="small muted" style={{ margin: 0 }}>
          {data.last_post_at ? `Last posted ${relTime(data.last_post_at)}.` : "Nothing posted yet."}
          {data.fail_count > 0 && <> <Badge tone="warning">retrying</Badge> {data.fail_count} failed {data.fail_count === 1 ? "attempt" : "attempts"}: {data.last_error}</>}
        </p>
      )}
      <div aria-live="polite">{ok && <Callout tone="info">{ok}</Callout>}{problem && dirty && <p className="small" role="alert">{problem}</p>}{err && <Callout tone="bad">{err}</Callout>}</div>
      {can && (
        <div className="row" style={{ justifyContent: "flex-end" }}>
          {data.configured && <Button variant="danger" icon={<Trash2 size={14} />} disabled={busy} onClick={remove}>Disconnect</Button>}
          {data.configured && <Button icon={<Send size={14} />} disabled={busy || dirty} onClick={test} title={dirty ? "Save first" : "Posts one test message"}>Send a test message</Button>}
          <Button type="submit" variant="primary" disabled={!!problem || !dirty || busy}>{busy ? "Working…" : "Save workspace"}</Button>
        </div>
      )}
    </form>
  );
}

// ---------------------------------------------------------------------------- reminder cadence and SLAs

const POLICY_FIELDS: { key: "review_remind_after_days" | "review_remind_every_days" | "request_warn_hours" | "jit_warn_minutes" | "escalate_after_hours"; label: string; unit: string; min: number; max: number; help: string }[] = [
  { key: "review_remind_after_days", label: "First review reminder", unit: "days", min: 1, max: 90, help: "After an access review has been open this long, its reviewers are reminded." },
  { key: "review_remind_every_days", label: "Review reminders repeat", unit: "days", min: 1, max: 90, help: "How often they are reminded after that, while items are still open." },
  { key: "request_warn_hours", label: "Requested access ending", unit: "hours ahead", min: 1, max: 720, help: "How far ahead the end of requested access is announced." },
  { key: "jit_warn_minutes", label: "Just-in-time access ending", unit: "minutes ahead", min: 5, max: 1440, help: "How far ahead the end of time-bound access is announced." },
  { key: "escalate_after_hours", label: "Escalate an approval after", unit: "hours", min: 1, max: 720, help: "How long an approval waits before the deciders may act. For items with no approval policy of their own; an item's own policy, an organization's default and a workflow keep theirs." },
];

export function PolicyCard() {
  const { data, error, reload } = useApi<NotificationPolicy>(notificationPolicyPath);
  const toast = useToast();
  const [v, setV] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (data) setV(Object.fromEntries(POLICY_FIELDS.map((p) => [p.key, String(data[p.key])])));
  }, [data?.version]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!data) return <div className="card flush"><Loading error={error} kind="block" /></div>;
  const can = data.can_manage;
  const num = (k: string) => (/^\d+$/.test((v[k] ?? "").trim()) ? Number(v[k]) : NaN);
  const bad = POLICY_FIELDS.find((p) => !(num(p.key) >= p.min && num(p.key) <= p.max));
  const dirty = POLICY_FIELDS.some((p) => num(p.key) !== data[p.key]);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (bad || !dirty || busy || !can) return;
    setBusy(true);
    setErr(null);
    try {
      await notificationPolicyApi.save({ version: data.version, review_remind_after_days: num("review_remind_after_days"), review_remind_every_days: num("review_remind_every_days"),
        request_warn_hours: num("request_warn_hours"), jit_warn_minutes: num("jit_warn_minutes"), escalate_after_hours: num("escalate_after_hours") });
      toast("Reminder cadence saved");
      reload();
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card stack" onSubmit={submit} aria-label="Reminder cadence and escalation">
      <h2>Reminder cadence and escalation</h2>
      {!can && <Callout tone="neutral">You can read these settings. A tenant admin changes them.</Callout>}
      <fieldset style={fieldsetStyle} className="stack-sm" disabled={!can}>
        <div className="grid g2">
          {POLICY_FIELDS.map((p) => (
            <label key={p.key} className="field">{p.label} ({p.unit})
              <input className="input" inputMode="numeric" value={v[p.key] ?? ""} onChange={(e) => setV((x) => ({ ...x, [p.key]: e.target.value }))} style={{ maxWidth: 140 }}
                aria-invalid={!(num(p.key) >= p.min && num(p.key) <= p.max)} aria-describedby={`pol-${p.key}`} />
              <span className="xs faint" id={`pol-${p.key}`}>{p.help} {p.min} to {p.max}; now {data.defaults[p.key]} unless changed.</span>
            </label>
          ))}
        </div>
      </fieldset>
      {bad && dirty && <p className="small" role="alert">{bad.label} is {bad.min} to {bad.max} {bad.unit}.</p>}
      {err && <Callout tone="bad">{err}</Callout>}
      {can && <div className="row" style={{ justifyContent: "flex-end" }}><Button type="submit" variant="primary" disabled={!!bad || !dirty || busy}>{busy ? "Saving…" : "Save cadence"}</Button></div>}
    </form>
  );
}

// ---------------------------------------------------------------------------- templates

export function TemplatesCard() {
  const { data, error, reload } = useApi<NotificationTemplates>(notificationTemplatesPath);
  const toast = useToast();
  const [kind, setKind] = useState("request.approval_needed");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const current = data?.templates.find((t) => t.kind === kind);
  useEffect(() => {
    if (current) {
      setSubject(current.subject_tpl);
      setBody(current.body_tpl);
      setErr(null);
    }
  }, [kind, current?.customized, current?.subject_tpl, current?.body_tpl]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!data || !current) return <div className="card flush"><Loading error={error} kind="block" /></div>;
  const can = data.can_manage;
  const names = data.variables.map((x) => x.name);
  const problem = templateProblem(subject, body, names, data.max_subject, data.max_body);
  const dirty = subject !== current.subject_tpl || body !== current.body_tpl;
  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || !dirty || busy || !can) return;
    setBusy(true);
    setErr(null);
    try {
      await notificationTemplatesApi.save(kind, subject, body);
      toast(`${current.label}: wording saved`);
      reload();
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };
  const reset = async () => {
    setBusy(true);
    setErr(null);
    try {
      await notificationTemplatesApi.reset(kind);
      toast(`${current.label}: back to the default wording`);
      reload();
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card stack" onSubmit={save} aria-label="Notification wording">
      <h2>Wording of notification emails</h2>
      <p className="small muted" style={{ margin: 0 }}>
        Write your own subject and text for the email of a kind, for example approval, reminder and escalation. The inbox entry does not change. Leave a field empty to keep the
        default for it. Placeholders: {data.variables.map((x) => <code key={x.name} title={x.help} style={{ marginRight: 6 }}>{`{{${x.name}}}`}</code>)}
      </p>
      {!can && <Callout tone="neutral">You can read these. A tenant admin changes them.</Callout>}
      <label className="field">Kind
        <select className="input" value={kind} onChange={(e) => setKind(e.target.value)} style={{ maxWidth: 420 }}>
          {data.templates.map((t) => <option key={t.kind} value={t.kind}>{t.label}{t.customized ? " (customized)" : ""}</option>)}
        </select>
        <span className="xs faint">{current.description}</span>
      </label>
      <fieldset style={fieldsetStyle} className="stack-sm" disabled={!can}>
        <label className="field">Subject
          <input className="input" value={subject} maxLength={data.max_subject} onChange={(e) => setSubject(e.target.value)} placeholder="[{{product}}] {{subject}}" />
        </label>
        <label className="field">Text
          <textarea className="input" rows={7} value={body} maxLength={data.max_body} onChange={(e) => setBody(e.target.value)} placeholder="{{body}}" />
          <span className="xs faint">A link line and the footer are added after your text; put {"{{link}}"} where you want the link and the default line is left out.</span>
        </label>
      </fieldset>
      <div className="stack-sm" aria-live="polite">
        <span className="small strong">Preview with sample values</span>
        <div className="card flat small" style={{ whiteSpace: "pre-wrap" }}>
          <b>{subject.trim() ? renderTemplate(subject) : `[${SAMPLE.product}] ${SAMPLE.subject}`}</b>
          {"\n\n"}
          {body.trim() ? renderTemplate(body) : `${SAMPLE.body}\n\nOpen in ${SAMPLE.product}: ${SAMPLE.link}`}
        </div>
      </div>
      {problem && dirty && <p className="small" role="alert">{problem}</p>}
      {err && <Callout tone="bad">{err}</Callout>}
      {can && (
        <div className="row" style={{ justifyContent: "flex-end" }}>
          {current.customized && <Button disabled={busy} onClick={reset}>Reset to the default</Button>}
          <Button type="submit" variant="primary" disabled={!!problem || !dirty || busy}>{busy ? "Saving…" : "Save wording"}</Button>
        </div>
      )}
    </form>
  );
}

// ---------------------------------------------------------------------------- suppressions

/** Addresses email is not sent to: hard bounces add themselves; an admin can add or lift one. */
export function SuppressionsCard() {
  const { data, error, reload } = useApi<EmailSuppressions>(emailSuppressionsPath);
  const toast = useToast();
  const [address, setAddress] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!data) return <div className="card flush"><Loading error={error} kind="block" /></div>;
  const can = data.can_manage;
  const add = async (e: FormEvent) => {
    e.preventDefault();
    if (!address.trim() || busy) return;
    setBusy(true);
    setErr(null);
    try {
      await emailSuppressionsApi.add(address.trim(), note.trim());
      toast("Address suppressed");
      setAddress("");
      setNote("");
      reload();
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };
  const lift = async (a: string) => {
    setBusy(true);
    try {
      await emailSuppressionsApi.lift(a);
      toast(`${a} can be emailed again`);
      reload();
    } catch (x) {
      toast(errText(x), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="card stack" aria-label="Suppressed addresses">
      <h2>Suppressed addresses</h2>
      <p className="small muted" style={{ margin: 0 }}>
        Tessera does not email these addresses; they still get the inbox entry. A delivery status report that says an address does not exist (a hard bounce) adds it here.
        Lift one to email it again, then send the skipped message again from its panel below.
      </p>
      {data.suppressions.length === 0 ? <p className="small faint" style={{ margin: 0 }}>None.</p> : (
        <ul className="small" style={{ margin: 0, paddingLeft: 0, listStyle: "none" }}>
          {data.suppressions.map((s) => (
            <li key={s.address} className="row spread" style={{ padding: "4px 0" }}>
              <span><b>{s.address}</b> <Badge tone={s.reason === "hard_bounce" ? "warning" : "neutral"}>{s.reason === "hard_bounce" ? "bounced" : "manual"}</Badge>
                <span className="faint"> · {s.created_by}, <span title={fmtDate(s.created_at)}>{relTime(s.created_at)}</span>{s.note ? ` · ${s.note}` : ""}</span></span>
              {can && <Button size="sm" disabled={busy} onClick={() => lift(s.address)}>Lift</Button>}
            </li>
          ))}
        </ul>
      )}
      {can && (
        <form className="row" onSubmit={add} aria-label="Suppress an address" style={{ alignItems: "flex-end", flexWrap: "wrap" }}>
          <label className="field">Address<input className="input" type="email" value={address} onChange={(e) => setAddress(e.target.value)} autoComplete="off" /></label>
          <label className="field">Note <span className="faint">(optional)</span><input className="input" value={note} maxLength={300} onChange={(e) => setNote(e.target.value)} /></label>
          <Button type="submit" disabled={busy || !address.trim()}>Suppress</Button>
        </form>
      )}
      {err && <Callout tone="bad">{err}</Callout>}
    </div>
  );
}
