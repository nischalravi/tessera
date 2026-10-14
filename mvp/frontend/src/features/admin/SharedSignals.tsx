import { FormEvent, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CircleCheck, Copy, Pause, Pencil, Play, Plus, Radio, Trash2 } from "lucide-react";
import {
  SsfEvent,
  SsfEventStatus,
  SsfInput,
  SsfStatus,
  SsfTransmitter,
  createSsfTransmitter,
  deleteSsfTransmitter,
  fmtDate,
  relTime,
  updateSsfTransmitter,
  useApi,
  verifySsfTransmitter,
} from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Chip, Tone } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Column, DataTable } from "../../components/DataTable";
import { useConfirm } from "../../components/Dialog";
import { Drawer } from "../../components/Drawer";
import { Callout, EmptyState } from "../../components/Feedback";
import { Page, Tabs } from "../../components/Page";
import { SidePanel, useSelected } from "../../components/SidePanel";
import { useToast } from "../../components/Toast";

/**
 * Shared Signals (issue #114): the transmitters Tessera accepts OpenID Shared Signals events
 * from (Okta, Entra, ...) and what each event did. A CAEP session-revoked, a credential-change
 * or a RISC account-disabled for a person runs the kill switch on their other linked accounts.
 * An event whose subject matches no one is shown as unmatched, never dropped. Hiding the
 * controls with can("ssf.configure") is for usability only: the API enforces the permission and
 * a fresh phishing-resistant sign-in.
 */

const STATUS_TONE: Record<SsfStatus, Tone> = { enabled: "ok", paused: "warning", disabled: "neutral" };
const EVENT_TONE: Record<SsfEventStatus, Tone> = {
  received: "info", matched: "info", actioned: "ok", no_action: "neutral", unmatched: "warning", ignored: "neutral", failed: "critical",
};
const EVENT_LABEL: Record<SsfEventStatus, string> = {
  received: "Received", matched: "Matched", actioned: "Actioned", no_action: "Nothing to do", unmatched: "Unmatched", ignored: "Ignored", failed: "Failed, retrying",
};
const EVENT_STATUSES = Object.keys(EVENT_LABEL) as SsfEventStatus[];

const ms = (v: number | null) => (v === null ? "–" : v < 1000 ? `${v} ms` : `${(v / 1000).toFixed(v < 10000 ? 1 : 0)} s`);

type Tab = "streams" | "events";
type Loaded<T> = { data: T | null; error: string | null; reload: () => void };

export function SharedSignals() {
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get("tab") === "events" ? "events" : "streams";
  const { can } = useSession();
  const [form, setForm] = useState<{ edit?: SsfTransmitter } | null>(null);
  const tx = useApi<{ transmitters: SsfTransmitter[] }>("/ssf/transmitters");
  const ev = useApi<{ events: SsfEvent[] }>("/ssf/events?limit=300");
  const streams: Loaded<SsfTransmitter[]> = { data: tx.data?.transmitters ?? null, error: tx.error, reload: tx.reload };
  const events: Loaded<SsfEvent[]> = { data: ev.data?.events ?? null, error: ev.error, reload: ev.reload };
  const unmatched = (events.data ?? []).filter((e) => e.status === "unmatched").length;
  const reloadAll = () => { tx.reload(); ev.reload(); };
  return (
    <Page
      title="Shared Signals"
      crumbs={[["Settings"], ["Shared Signals"]]}
      sub="Revocations at one provider reach the others. A trusted transmitter tells Tessera a session was revoked, a credential changed or an account was disabled, and Tessera ends the person's other sessions and grants."
      actions={<Button variant="primary" icon={<Plus size={14} />} disabled={!can("ssf.configure")} title={can("ssf.configure") ? undefined : "Needs the ssf.configure permission (policy admins)"} onClick={() => setForm({})}>Add transmitter</Button>}
      tabs={
        <Tabs
          label="Shared Signals sections"
          value={tab}
          onChange={(t) => setParams(t === "streams" ? {} : { tab: t }, { replace: true })}
          tabs={[
            { id: "streams", label: `Transmitters${streams.data ? ` (${streams.data.length})` : ""}` },
            { id: "events", label: <>Events{events.data ? ` (${events.data.length})` : ""}{unmatched > 0 && <> <Badge tone="warning">{unmatched} unmatched</Badge></>}</> },
          ]}
        />
      }
    >
      {tab === "streams" && <Streams s={streams} events={events.data ?? []} onEdit={(t) => setForm({ edit: t })} onChanged={reloadAll} onAdd={() => setForm({})} />}
      {tab === "events" && <Events e={events} streams={streams.data ?? []} />}
      {form && <TransmitterForm edit={form.edit} onClose={() => setForm(null)} onSaved={reloadAll} />}
    </Page>
  );
}

// ---------------------------------------------------------------- transmitters

function Streams({ s, events, onEdit, onChanged, onAdd }: { s: Loaded<SsfTransmitter[]>; events: SsfEvent[]; onEdit: (t: SsfTransmitter) => void; onChanged: () => void; onAdd: () => void }) {
  const [selected, setSelected] = useSelected();
  const { can } = useSession();
  const open = s.data?.find((t) => t.id === selected);
  const cols: Column<SsfTransmitter>[] = [
    { id: "name", header: "Transmitter", sort: (r) => r.name.toLowerCase(), cell: (r) => <span><b className="name-link">{r.name}</b><div className="small faint truncate" style={{ maxWidth: 320 }}>{r.issuer}</div></span> },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Badge tone={STATUS_TONE[r.status]} dot>{r.status}</Badge> },
    { id: "delivery", header: "Delivery", sort: (r) => r.delivery, cell: (r) => <Chip mono>{r.delivery}</Chip>, hideNarrow: true },
    { id: "system", header: "Subjects in", sort: (r) => r.subject_system, cell: (r) => <Chip mono>{r.subject_system}</Chip>, hideNarrow: true },
    { id: "last", header: "Last event", sort: (r) => r.last_event_at ?? "", cell: (r) => <span className="small nowrap">{r.last_event_at ? relTime(r.last_event_at) : <span className="faint">None yet</span>}</span> },
    { id: "err", header: "Last error", cell: (r) => (r.last_error ? <Badge tone="critical" title={r.last_error}>Error</Badge> : <span className="faint small">None</span>), hideNarrow: true },
  ];
  return (
    <>
      <DataTable
        id="ssf-transmitters"
        rows={s.data}
        error={s.error}
        rowKey={(r) => r.id}
        columns={cols}
        searchText={(r) => `${r.name} ${r.issuer} ${r.subject_system} ${r.delivery}`}
        searchPlaceholder="Search transmitters…"
        filters={[
          { id: "status", label: "Status", options: [{ value: "enabled", label: "Enabled" }, { value: "paused", label: "Paused" }, { value: "disabled", label: "Disabled" }], get: (r) => r.status },
          { id: "delivery", label: "Delivery", options: [{ value: "push", label: "Push" }, { value: "poll", label: "Poll" }], get: (r) => r.delivery },
        ]}
        onRefresh={s.reload}
        rowLabel={(r) => r.name}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        empty={
          <EmptyState title="No transmitters yet" icon={<Radio size={18} />} action={can("ssf.configure") ? <Button variant="primary" icon={<Plus size={14} />} onClick={onAdd}>Add transmitter</Button> : undefined}>
            Add Okta, Entra or another Shared Signals transmitter so a revoked session there ends the person's sessions here.
          </EmptyState>
        }
      />
      {open && <StreamPanel t={open} events={events.filter((e) => e.transmitter_id === open.id).slice(0, 8)} onClose={() => setSelected(null)} onEdit={onEdit} onChanged={onChanged} />}
    </>
  );
}

function Detail({ k, children }: { k: string; children: React.ReactNode }) {
  return <><dt>{k}</dt><dd>{children}</dd></>;
}

function StreamPanel({ t, events, onClose, onEdit, onChanged }: { t: SsfTransmitter; events: SsfEvent[]; onClose: () => void; onEdit: (t: SsfTransmitter) => void; onChanged: () => void }) {
  const { can } = useSession();
  const confirm = useConfirm();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const allowed = can("ssf.configure");
  const url = t.receiver_path ? `${window.location.origin}${t.receiver_path}` : "";
  const run = async (what: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(true);
    try {
      await fn();
      toast(done);
      onChanged();
    } catch (e) {
      toast(`${what}: ${(e as Error).message}`, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const setStatus = (status: SsfStatus) =>
    run("Update", () => updateSsfTransmitter(t.id, toInput(t, { status })), status === "enabled" ? `${t.name} resumed` : `${t.name} ${status}`);
  const remove = async () => {
    const ok = await confirm({
      title: `Delete ${t.name}?`,
      body: "Tessera stops accepting its events and forgets its recorded events and spent event ids. The audit log keeps the history. Events already acted on are not undone.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (ok === null) return;
    await run("Delete", () => deleteSsfTransmitter(t.id), `${t.name} deleted`);
    onClose();
  };
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(url);
      toast("Receiver URL copied");
    } catch {
      toast("Copy failed: select the URL and copy it", { kind: "error" });
    }
  };
  return (
    <SidePanel
      title={t.name}
      onClose={onClose}
      sub={<><Badge tone={STATUS_TONE[t.status]} dot>{t.status}</Badge><span className="small muted">{t.delivery} · subjects in {t.subject_system}</span></>}
      commands={
        <div className="cmdbar" role="toolbar" aria-label="Transmitter commands">
          <button type="button" className="cmd" disabled={!allowed || busy} onClick={() => onEdit(t)}><Pencil size={16} aria-hidden /> Edit</button>
          {t.status === "enabled"
            ? <button type="button" className="cmd" disabled={!allowed || busy} onClick={() => setStatus("paused")}><Pause size={16} aria-hidden /> Pause</button>
            : <button type="button" className="cmd" disabled={!allowed || busy} onClick={() => setStatus("enabled")}><Play size={16} aria-hidden /> Resume</button>}
          <button type="button" className="cmd" disabled={!allowed || busy || !t.verification_url} title={t.verification_url ? undefined : "This transmitter has no verification endpoint"}
            onClick={() => run("Verify", () => verifySsfTransmitter(t.id), "Verification requested: the transmitter sends a verification event")}><CircleCheck size={16} aria-hidden /> Verify</button>
          <button type="button" className="cmd danger" disabled={!allowed || busy} onClick={remove}><Trash2 size={16} aria-hidden /> Delete</button>
        </div>
      }
    >
      {!allowed && <Callout tone="neutral">Changing a transmitter needs the ssf.configure permission (policy admins).</Callout>}
      {t.last_error && <Callout tone="bad"><b>Last error</b> {t.last_error_at ? <span className="small">({relTime(t.last_error_at)})</span> : null}<div className="small">{t.last_error}</div></Callout>}
      <dl className="kv">
        <Detail k="Issuer"><span className="mono break">{t.issuer}</span></Detail>
        <Detail k="Audience"><span className="mono break">{t.audience}</span></Detail>
        <Detail k="Keys">{t.inline_jwks ? "Inline JWKS" : <span className="mono break">{t.jwks_url}</span>}</Detail>
        {t.delivery === "push" && (
          <Detail k="Receiver URL">
            <span className="mono break small">{url}</span>
            <div><Button size="sm" icon={<Copy size={13} />} onClick={copy}>Copy URL</Button></div>
            <div className="small faint">The transmitter sends <code>Authorization: Bearer &lt;secret&gt;</code> and <code>Content-Type: application/secevent+jwt</code>.</div>
          </Detail>
        )}
        {t.delivery === "poll" && <Detail k="Poll endpoint"><span className="mono break">{t.poll_url}</span></Detail>}
        <Detail k="Secret">{t.secret_set ? "Stored sealed (not shown)" : "None"}</Detail>
        <Detail k="Subjects resolve in"><Chip mono>{t.subject_system}</Chip>{t.connection_id && <span className="small faint"> via its connection</span>}</Detail>
        <Detail k="Last event">{t.last_event_at ? fmtDate(t.last_event_at) : "None yet"}</Detail>
        {t.delivery === "poll" && <Detail k="Last poll">{t.last_polled_at ? fmtDate(t.last_polled_at) : "Not yet"}{t.pending_acks > 0 && <span className="small faint"> · {t.pending_acks} to acknowledge</span>}</Detail>}
        <Detail k="Verified">{t.verified_at ? fmtDate(t.verified_at) : t.verification_pending ? "Waiting for the verification event" : "Not verified"}</Detail>
        <Detail k="Added">{fmtDate(t.created_at)} by {t.created_by}</Detail>
      </dl>
      <h3 className="h-sm mt">Recent events</h3>
      {events.length === 0 ? <p className="small muted">No events yet.</p> : (
        <ul className="plain-list" aria-label="Recent events">
          {events.map((e) => (
            <li key={e.id}>
              <div className="row tight"><Badge tone={EVENT_TONE[e.status]}>{EVENT_LABEL[e.status]}</Badge><b className="small">{e.event}</b><span className="small faint nowrap">{relTime(e.received_at)}</span></div>
              <div className="small muted break">{e.subject}</div>
              <div className="small faint">{e.outcome}{e.latency_ms !== null && e.status !== "ignored" && <> · {ms(e.latency_ms)} to act</>}</div>
            </li>
          ))}
        </ul>
      )}
      <p className="small"><Link to={`/admin/shared-signals?tab=events`}>All events</Link></p>
    </SidePanel>
  );
}

/** The input that re-saves a transmitter as it is, with changes (secrets and keys are kept by leaving them out). */
function toInput(t: SsfTransmitter, over: Partial<SsfInput> = {}): SsfInput {
  return {
    name: t.name, issuer: t.issuer, audience: t.audience, delivery: t.delivery, subject_system: t.subject_system, status: t.status,
    poll_url: t.poll_url || undefined, verification_url: t.verification_url || undefined, ...over,
  };
}

// ---------------------------------------------------------------- events

function Events({ e, streams }: { e: Loaded<SsfEvent[]>; streams: SsfTransmitter[] }) {
  const [selected, setSelected] = useSelected();
  const name = useMemo(() => new Map(streams.map((t) => [t.id, t.name])), [streams]);
  const open = e.data?.find((x) => x.id === selected);
  const cols: Column<SsfEvent>[] = [
    { id: "at", header: "Received", sort: (r) => r.received_at, cell: (r) => <span className="small nowrap">{fmtDate(r.received_at)}</span> },
    { id: "event", header: "Event", sort: (r) => r.event, cell: (r) => <b className="small name-link">{r.event}</b> },
    { id: "subject", header: "Subject", sort: (r) => r.subject.toLowerCase(), cell: (r) => <span className="small truncate" style={{ maxWidth: 260, display: "inline-block" }}>{r.subject}</span> },
    { id: "stream", header: "Transmitter", sort: (r) => name.get(r.transmitter_id) ?? "", cell: (r) => <span className="small">{name.get(r.transmitter_id) ?? "(deleted)"}</span>, hideNarrow: true },
    { id: "status", header: "Result", sort: (r) => r.status, cell: (r) => <Badge tone={EVENT_TONE[r.status]}>{EVENT_LABEL[r.status]}</Badge> },
    { id: "latency", header: "Latency", num: true, sort: (r) => r.latency_ms, csv: (r) => r.latency_ms, cell: (r) => <span className="small nowrap">{r.status === "actioned" || r.status === "failed" ? ms(r.latency_ms) : "–"}</span>, hideNarrow: true },
  ];
  return (
    <>
      <DataTable
        id="ssf-events"
        rows={e.data}
        error={e.error}
        rowKey={(r) => r.id}
        columns={cols}
        searchText={(r) => `${r.event} ${r.subject} ${r.outcome} ${r.jti} ${name.get(r.transmitter_id) ?? ""}`}
        searchPlaceholder="Search events by subject or outcome…"
        filters={[
          { id: "status", label: "Result", options: EVENT_STATUSES.map((s) => ({ value: s, label: EVENT_LABEL[s] })), get: (r) => r.status },
          { id: "event", label: "Event", options: [...new Set((e.data ?? []).map((r) => r.event))].sort().map((v) => ({ value: v, label: v })), get: (r) => r.event },
          { id: "stream", label: "Transmitter", options: streams.map((t) => ({ value: t.id, label: t.name })), get: (r) => r.transmitter_id },
        ]}
        chips={3}
        onRefresh={e.reload}
        rowLabel={(r) => `${r.event} for ${r.subject}`}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        empty={<EmptyState title="No events yet" icon={<Radio size={18} />}>Events appear here when a transmitter delivers one, including the ones Tessera could not match to a person.</EmptyState>}
      />
      {open && <EventPanel e={open} stream={name.get(open.transmitter_id)} onClose={() => setSelected(null)} />}
    </>
  );
}

function EventPanel({ e, stream, onClose }: { e: SsfEvent; stream?: string; onClose: () => void }) {
  return (
    <SidePanel title={e.event} sub={<><Badge tone={EVENT_TONE[e.status]}>{EVENT_LABEL[e.status]}</Badge><span className="small muted">via {e.via}</span></>} onClose={onClose}>
      {e.status === "unmatched" && <Callout tone="warn">Tessera could not tie this event to a person, so it did nothing. Check that the person has an account on the transmitter's system in Tessera: {e.outcome}.</Callout>}
      {e.status === "failed" && <Callout tone="bad">A step failed. It is queued for retry and Tessera keeps trying for 24 hours. {e.outcome}.</Callout>}
      <dl className="kv">
        <Detail k="Subject"><span className="break">{e.subject}</span> <span className="small faint">({e.subject_format || "no format"})</span></Detail>
        <Detail k="Person">{e.identity_id !== null ? <Link to={`/directory/identities/${e.identity_id}`}>Open the identity</Link> : <span className="faint">Not matched</span>}</Detail>
        <Detail k="Transmitter">{stream ?? "(deleted)"}</Detail>
        <Detail k="Outcome">{e.outcome || "–"}</Detail>
        <Detail k="Steps">{e.steps}{e.steps_failed > 0 && <span className="small"> ({e.steps_failed} failed)</span>}</Detail>
        <Detail k="Issued by the transmitter">{fmtDate(e.iat_at)}</Detail>
        <Detail k="Received">{fmtDate(e.received_at)}</Detail>
        <Detail k="Last action done">{e.actioned_at ? fmtDate(e.actioned_at) : "–"}</Detail>
        <Detail k="Receipt to action">{ms(e.latency_ms)}</Detail>
        <Detail k="Issued to action">{ms(e.iat_latency_ms)}</Detail>
        <Detail k="Event type"><span className="mono break small">{e.event_type}</span></Detail>
        <Detail k="Event id (jti)"><span className="mono break small">{e.jti}</span></Detail>
      </dl>
    </SidePanel>
  );
}

// ---------------------------------------------------------------- form

function TransmitterForm({ edit, onClose, onSaved }: { edit?: SsfTransmitter; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [v, setV] = useState({
    name: edit?.name ?? "", issuer: edit?.issuer ?? "", audience: edit?.audience ?? "", delivery: (edit?.delivery ?? "push") as "push" | "poll",
    subject_system: edit?.subject_system ?? "okta", status: (edit?.status ?? "enabled") as SsfStatus, jwks_url: edit?.jwks_url ?? "", jwks: "",
    poll_url: edit?.poll_url ?? "", verification_url: edit?.verification_url ?? "", secret: "", api_token: "", discover: false, rotate: false,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const set = (k: keyof typeof v) => (e: { target: { value: string } }) => setV({ ...v, [k]: e.target.value });
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setError(null);
    let jwks: unknown;
    if (v.jwks.trim()) {
      try { jwks = JSON.parse(v.jwks); } catch { setError("The inline JWKS is not valid JSON."); return; }
    }
    const input: SsfInput = {
      name: v.name.trim(), issuer: v.issuer.trim(), audience: v.audience.trim(), delivery: v.delivery, subject_system: v.subject_system.trim(), status: v.status,
      jwks_url: v.jwks_url.trim() || undefined, jwks, poll_url: v.delivery === "poll" ? v.poll_url.trim() || undefined : undefined,
      verification_url: v.verification_url.trim() || undefined, secret: v.secret || undefined, api_token: v.api_token || undefined,
      discover: v.discover || undefined, rotate_secret: v.rotate || undefined,
    };
    setBusy(true);
    try {
      const saved = edit ? await updateSsfTransmitter(edit.id, input) : await createSsfTransmitter(input);
      onSaved();
      if (saved.receiver_secret) setSecret(saved.receiver_secret);
      else {
        toast(edit ? `${v.name} updated` : `${v.name} added`);
        onClose();
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  if (secret) {
    return (
      <Drawer title="Copy the receiver secret" sub="Tessera shows it once and keeps only a sealed copy." onClose={onClose} footer={<Button variant="primary" onClick={onClose}>I have copied it</Button>}>
        <Callout tone="warn">Give this secret to the transmitter as the bearer token of its push delivery. It cannot be shown again; rotate it from Edit if it is lost.</Callout>
        <p><code className="mono break" aria-label="Receiver secret" style={{ userSelect: "all" }}>{secret}</code></p>
        <Button icon={<Copy size={14} />} onClick={() => navigator.clipboard?.writeText(secret).then(() => toast("Secret copied"), () => toast("Copy failed: select the secret and copy it", { kind: "error" }))}>Copy secret</Button>
      </Drawer>
    );
  }
  return (
    <Drawer
      wide
      title={edit ? `Edit ${edit.name}` : "Add a transmitter"}
      sub="Events are accepted only from a transmitter whose signature, issuer and audience match what you enter here."
      onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" type="submit" form="ssf-form" disabled={busy}>{busy ? "Saving…" : edit ? "Save changes" : "Add transmitter"}</Button></>}
    >
      <form id="ssf-form" onSubmit={submit} className="stack">
        {error && <Callout tone="bad">{error}</Callout>}
        <div className="form-grid">
          <label className="field">Name<input className="input" value={v.name} onChange={set("name")} required maxLength={100} placeholder="Okta production" /></label>
          <label className="field">Status
            <select className="input" value={v.status} onChange={set("status")}>
              <option value="enabled">Enabled</option><option value="paused">Paused</option><option value="disabled">Disabled</option>
            </select>
          </label>
          <label className="field">Issuer (iss)<input className="input" value={v.issuer} onChange={set("issuer")} required maxLength={512} placeholder="https://example.okta.com" /></label>
          <label className="field">Audience (aud)<input className="input" value={v.audience} onChange={set("audience")} required maxLength={256} />
            <span className="hint">The audience the transmitter puts in its events for Tessera.</span></label>
          <label className="field">Delivery
            <select className="input" value={v.delivery} onChange={set("delivery")}>
              <option value="push">Push: the transmitter calls Tessera</option><option value="poll">Poll: Tessera calls the transmitter</option>
            </select>
          </label>
          <label className="field">Subjects resolve in (system)<input className="input" value={v.subject_system} onChange={set("subject_system")} required maxLength={40} placeholder="okta" />
            <span className="hint">The account system an event's subject is looked up in: okta, entra, google…</span></label>
        </div>
        <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="h-sm">Signing keys</legend>
          <label className="field">JWKS URL<input className="input" value={v.jwks_url} onChange={set("jwks_url")} placeholder="https://example.okta.com/oauth2/v1/keys" />
            <span className="hint">Fetched through Tessera's outbound guard. Leave both blank when editing to keep the current keys.</span></label>
          <label className="field">Or inline JWKS (public keys)<textarea className="input mono" rows={3} value={v.jwks} onChange={set("jwks")} placeholder='{"keys":[…]}' /></label>
          <label className="row tight small"><input type="checkbox" checked={v.discover} onChange={(e) => setV({ ...v, discover: e.target.checked })} /> Fill the blanks from <code>/.well-known/ssf-configuration</code></label>
        </fieldset>
        {v.delivery === "poll" && (
          <label className="field">Poll endpoint<input className="input" value={v.poll_url} onChange={set("poll_url")} required placeholder="https://transmitter.example/ssf/poll" /></label>
        )}
        <label className="field">{v.delivery === "poll" ? "Bearer token for the poll endpoint" : "Receiver secret"}
          <input className="input" type="password" autoComplete="new-password" value={v.secret} onChange={set("secret")} required={v.delivery === "poll" && !edit?.secret_set}
            placeholder={edit?.secret_set ? "Leave blank to keep the stored secret" : v.delivery === "push" ? "Leave blank to generate one" : ""} />
          <span className="hint">{v.delivery === "push" ? "The bearer secret the transmitter presents. Stored sealed." : "Stored sealed, sent only to the poll endpoint."}</span></label>
        {edit && v.delivery === "push" && <label className="row tight small"><input type="checkbox" checked={v.rotate} onChange={(e) => setV({ ...v, rotate: e.target.checked })} /> Generate a new receiver secret</label>}
        <div className="form-grid">
          <label className="field">Verification endpoint (optional)<input className="input" value={v.verification_url} onChange={set("verification_url")} placeholder="https://transmitter.example/ssf/verify" /></label>
          <label className="field">Transmitter API token (optional)<input className="input" type="password" autoComplete="new-password" value={v.api_token} onChange={set("api_token")} placeholder={edit?.api_token_set ? "Leave blank to keep" : ""} />
            <span className="hint">Sent with verification requests. Stored sealed.</span></label>
        </div>
      </form>
    </Drawer>
  );
}
