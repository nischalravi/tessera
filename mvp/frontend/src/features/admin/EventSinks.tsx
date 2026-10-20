/** Admin → Group event sinks: stream group change events to SQS, SNS, RabbitMQ or Kafka (GR-18, design §10.1). */
import { FormEvent, InputHTMLAttributes, ReactNode, useState } from "react";
import { Plus, Radio, RotateCcw, Trash2 } from "lucide-react";
import {
  DeadLetterStatus, GroupSink, GroupSinkList, SINKS_PATH, SinkConfig, SinkCredentials, SinkDeadLetter, SinkKind, fmtDate, groupSinks, relTime, useApi,
} from "../../api";
import { Badge, Button, Callout, Chip, DataTable, EmptyState, Loading, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import type { Column, Tone } from "../../components";

const KIND_LABEL: Record<SinkKind, string> = { sqs: "AWS SQS", sns: "AWS SNS", rabbitmq: "RabbitMQ", kafka: "Kafka" };
const SASL = ["", "plain", "scram-sha-256", "scram-sha-512"] as const;
const TYPE_HINT = "Event types or prefixes ending in a dot, separated by commas: group.created, membership. Empty sends everything.";

function stateOf(s: GroupSink): { label: string; tone: Tone } {
  if (!s.enabled) return { label: "Disabled", tone: "neutral" };
  if (s.state === "retrying") return { label: "Retrying", tone: "warning" };
  if (s.state === "ok") return { label: "Delivering", tone: "ok" };
  return { label: "Idle", tone: "neutral" };
}

const DEAD_TONE: Record<DeadLetterStatus, Tone> = { dead: "critical", requeued: "warning", delivered: "ok", discarded: "neutral" };

// ---------------------------------------------------------------- form state
interface Draft {
  name: string; kind: SinkKind; enabled: boolean; from: "now" | "start"; types: string;
  region: string; endpoint: string; queue_url: string; topic_arn: string;
  url: string; exchange: string; routing_key: string;
  brokers: string; topic: string; sasl: (typeof SASL)[number]; plaintext: boolean;
  replaceCreds: boolean;
  access_key_id: string; secret_access_key: string; session_token: string; username: string; password: string;
}

const EMPTY: Draft = {
  name: "", kind: "kafka", enabled: true, from: "now", types: "", region: "", endpoint: "", queue_url: "", topic_arn: "", url: "", exchange: "",
  routing_key: "", brokers: "", topic: "", sasl: "", plaintext: false, replaceCreds: false,
  access_key_id: "", secret_access_key: "", session_token: "", username: "", password: "",
};

const list = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

function draftOf(s: GroupSink): Draft {
  const c = s.config;
  return {
    ...EMPTY, name: s.name, kind: s.kind, enabled: s.enabled, types: s.event_types.join(", "), region: c.region ?? "", endpoint: c.endpoint ?? "",
    queue_url: c.queue_url ?? "", topic_arn: c.topic_arn ?? "", url: c.url ?? "", exchange: c.exchange ?? "", routing_key: c.routing_key ?? "",
    brokers: (c.brokers ?? []).join(", "), topic: c.topic ?? "", sasl: c.sasl ?? "", plaintext: !!c.plaintext,
  };
}

/** The config of the kind's own fields only; empty fields are left out. */
function configOf(d: Draft): SinkConfig {
  const t = (v: string) => v.trim() || undefined;
  switch (d.kind) {
    case "sqs": return { region: t(d.region), endpoint: t(d.endpoint), queue_url: t(d.queue_url) };
    case "sns": return { region: t(d.region), endpoint: t(d.endpoint), topic_arn: t(d.topic_arn) };
    case "rabbitmq": return { url: t(d.url), exchange: t(d.exchange), routing_key: t(d.routing_key) };
    default: return { brokers: list(d.brokers), topic: t(d.topic), sasl: d.sasl || undefined, plaintext: d.plaintext || undefined };
  }
}

const needsCreds = (d: Draft) => d.kind !== "kafka" || d.sasl !== "";

function credsOf(d: Draft): SinkCredentials {
  switch (d.kind) {
    case "sqs":
    case "sns": return { access_key_id: d.access_key_id.trim(), secret_access_key: d.secret_access_key, session_token: d.session_token.trim() || undefined };
    default: return { username: d.username.trim(), password: d.password };
  }
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className="field">{label}{children}{hint && <span className="hint">{hint}</span>}</label>;
}

function SinkForm({ sink, allowInsecure, onDone }: { sink?: GroupSink; allowInsecure: boolean; onDone: () => void }) {
  const toast = useToast();
  const [d, setD] = useState<Draft>(() => (sink ? draftOf(sink) : EMPTY));
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((p) => ({ ...p, [k]: v }));
  const text = (k: keyof Draft, props: InputHTMLAttributes<HTMLInputElement> = {}) => (
    <input className="input" value={d[k] as string} onChange={(e) => set(k, e.target.value as never)} maxLength={2048} {...props} />
  );
  const stored = !!sink?.credentials_set;
  const showCreds = needsCreds(d) && (!stored || d.replaceCreds);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const event_types = list(d.types);
      const config = configOf(d);
      // credentials: sent when typed, cleared when the kind no longer needs them, otherwise kept
      let credentials: SinkCredentials | undefined;
      if (showCreds) credentials = credsOf(d);
      else if (!needsCreds(d) && stored) credentials = {};
      const out = sink
        ? await groupSinks.patch(sink.id, { name: d.name.trim(), enabled: d.enabled, config, event_types, credentials })
        : await groupSinks.create({ name: d.name.trim(), kind: d.kind, config, credentials, event_types, enabled: d.enabled, from: d.from });
      toast(sink ? `Sink ${out.name} saved` : `Sink ${out.name} created`);
      onDone();
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="stack" onSubmit={submit} aria-label={sink ? "Edit sink" : "New sink"}>
      {err && <div role="alert"><Callout tone="bad">{err}</Callout></div>}
      <Field label="Name">{text("name", { required: true, maxLength: 80 })}</Field>
      <Field label="Type" hint={sink ? "The type of a sink cannot change. Create another sink instead." : undefined}>
        <select className="input" value={d.kind} disabled={!!sink} onChange={(e) => set("kind", e.target.value as SinkKind)}>
          {(Object.keys(KIND_LABEL) as SinkKind[]).map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
        </select>
      </Field>

      {(d.kind === "sqs" || d.kind === "sns") && (
        <>
          <Field label="AWS region" hint="For example eu-west-1.">{text("region", { required: true, placeholder: "eu-west-1" })}</Field>
          {d.kind === "sqs"
            ? <Field label="Queue URL" hint="A .fifo queue gets the group as its message group, so events stay in order per group.">{text("queue_url", { required: true, placeholder: "https://sqs.eu-west-1.amazonaws.com/123456789012/tessera-groups" })}</Field>
            : <Field label="Topic ARN" hint="A .fifo topic gets the group as its message group.">{text("topic_arn", { required: true, placeholder: "arn:aws:sns:eu-west-1:123456789012:tessera-groups" })}</Field>}
          <Field label="Endpoint override (optional)" hint="A VPC endpoint. Leave empty for the public AWS endpoint.">{text("endpoint", { placeholder: "https://…" })}</Field>
        </>
      )}
      {d.kind === "rabbitmq" && (
        <>
          <Field label="Broker URL" hint={allowInsecure ? "amqps://host[:port]/vhost, no user name or password in it. Plain amqp:// is allowed here (dev)." : "amqps://host[:port]/vhost, no user name or password in it. TLS is required."}>
            {text("url", { required: true, placeholder: "amqps://mq.example.com:5671/tessera" })}
          </Field>
          <Field label="Exchange">{text("exchange", { placeholder: "tessera.groups" })}</Field>
          <Field label="Routing key (optional)" hint="Default: the event type, for example membership.direct.added.">{text("routing_key")}</Field>
        </>
      )}
      {d.kind === "kafka" && (
        <>
          <Field label="Brokers" hint="host:port, separated by commas.">{text("brokers", { required: true, placeholder: "kafka-1.example.com:9093, kafka-2.example.com:9093" })}</Field>
          <Field label="Topic" hint="Events are keyed by group, so one group's events stay in order in one partition.">{text("topic", { required: true, placeholder: "tessera.groups" })}</Field>
          <Field label="SASL">
            <select className="input" value={d.sasl} onChange={(e) => set("sasl", e.target.value as Draft["sasl"])}>
              {SASL.map((s) => <option key={s} value={s}>{s === "" ? "None" : s}</option>)}
            </select>
          </Field>
          {allowInsecure && (
            <label className="row tight"><input type="checkbox" checked={d.plaintext} onChange={(e) => set("plaintext", e.target.checked)} /> Plain text, no TLS (dev only)</label>
          )}
        </>
      )}

      {needsCreds(d) && (
        <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="h-sm">Credentials</legend>
          {stored && (
            <label className="row tight">
              <input type="checkbox" checked={d.replaceCreds} onChange={(e) => set("replaceCreds", e.target.checked)} /> Replace the stored credentials
            </label>
          )}
          {!showCreds && <p className="small muted">Stored sealed. They are never shown again.</p>}
          {showCreds && (d.kind === "sqs" || d.kind === "sns") && (
            <>
              <Field label="Access key id">{text("access_key_id", { required: true, autoComplete: "off" })}</Field>
              <Field label="Secret access key">{text("secret_access_key", { required: true, type: "password", autoComplete: "new-password" })}</Field>
              <Field label="Session token (optional)" hint="For temporary credentials.">{text("session_token", { type: "password", autoComplete: "new-password" })}</Field>
            </>
          )}
          {showCreds && (d.kind === "rabbitmq" || d.kind === "kafka") && (
            <>
              <Field label="User name">{text("username", { required: true, autoComplete: "off" })}</Field>
              <Field label="Password">{text("password", { required: true, type: "password", autoComplete: "new-password" })}</Field>
            </>
          )}
        </fieldset>
      )}

      <Field label="Event types" hint={TYPE_HINT}>{text("types", { placeholder: "membership., group.created" })}</Field>
      {!sink && (
        <Field label="Start from">
          <select className="input" value={d.from} onChange={(e) => set("from", e.target.value as "now" | "start")}>
            <option value="now">Only events from now on</option>
            <option value="start">Every event still in the outbox</option>
          </select>
        </Field>
      )}
      <label className="row tight"><input type="checkbox" checked={d.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Enabled</label>
      <div className="row tight">
        <Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : sink ? "Save changes" : "Create sink"}</Button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------- dead letters
function DeadLetters({ sink }: { sink: GroupSink }) {
  const toast = useToast();
  const { data, error, reload } = useApi<{ items: SinkDeadLetter[] }>(groupSinks.deadLettersPath(sink.id));
  const [busy, setBusy] = useState<number | null>(null);
  const act = async (seq: number, kind: "redeliver" | "discard") => {
    setBusy(seq);
    try {
      await groupSinks[kind](sink.id, seq);
      toast(kind === "redeliver" ? `Event ${seq} will be sent again on the next pass` : `Event ${seq} discarded`);
      reload();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  if (!data) return <Loading error={error} kind="block" />;
  if (data.items.length === 0) return <p className="small muted">No event has failed after its retries.</p>;
  return (
    <div className="table-scroll">
      <table>
        <caption className="sr-only">Events that could not be delivered</caption>
        <thead><tr><th scope="col">Seq</th><th scope="col">Event</th><th scope="col">Status</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>
          {data.items.map((d) => (
            <tr key={d.seq}>
              <td className="small">{d.seq}</td>
              <td>
                <span className="small">{d.event_type}</span>
                <div className="xs faint" style={{ overflowWrap: "anywhere" }}>{d.attempts} attempts · {d.last_error}</div>
              </td>
              <td><Badge tone={DEAD_TONE[d.status]}>{d.status}</Badge></td>
              <td className="actions-cell">
                {(d.status === "dead") && (
                  <Button size="sm" icon={<RotateCcw size={13} />} disabled={busy === d.seq} onClick={() => act(d.seq, "redeliver")} aria-label={`Send event ${d.seq} again`}>Send again</Button>
                )}
                {(d.status === "dead" || d.status === "requeued") && (
                  <Button size="sm" variant="ghost" disabled={busy === d.seq} onClick={() => act(d.seq, "discard")} aria-label={`Discard event ${d.seq}`}>Discard</Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------- panel and page
function SinkPanel({ sink, allowInsecure, onClose }: { sink?: GroupSink; allowInsecure: boolean; onClose: () => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const remove = async () => {
    if (!sink) return;
    const ok = await confirm({
      title: `Delete ${sink.name}?`,
      body: "The sink stops at once. Its position and its dead letters are deleted; the events stay in the outbox. Other sinks are not affected.",
      confirmLabel: "Delete sink", danger: true,
    });
    if (ok === null) return;
    try {
      await groupSinks.remove(sink.id);
      toast(`Sink ${sink.name} deleted`);
      onClose();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };
  const st = sink ? stateOf(sink) : null;
  return (
    <SidePanel
      title={sink ? sink.name : "New sink"}
      sub={sink && st ? <><Chip>{KIND_LABEL[sink.kind]}</Chip> <Badge tone={st.tone} dot>{st.label}</Badge></> : "Stream group events to a broker"}
      onClose={onClose}
      footer={sink ? <Button size="sm" variant="danger" icon={<Trash2 size={14} />} onClick={remove}>Delete</Button> : undefined}
    >
      {sink && (
        <>
          {sink.state === "retrying" && (
            <Callout tone="warn">
              Delivery is failing (attempt {sink.attempts}), next try {sink.next_attempt_at ? relTime(sink.next_attempt_at) : "soon"}. Events behind the failing one wait, to keep the order.
              {sink.last_error && <div className="small" style={{ overflowWrap: "anywhere" }}>{sink.last_error}</div>}
            </Callout>
          )}
          <dl className="kv">
            <dt>Position</dt><dd>Event {sink.cursor}, {sink.lag} behind</dd>
            <dt>Delivered</dt><dd>{sink.delivered_count.toLocaleString()} events{sink.last_delivered_at ? `, last ${relTime(sink.last_delivered_at)} (${fmtDate(sink.last_delivered_at)})` : ""}</dd>
            <dt>Dead letters</dt><dd>{sink.dead_letters}</dd>
            <dt>Credentials</dt><dd>{sink.credentials_set ? "Stored sealed" : "None"}</dd>
            <dt>Created</dt><dd>{fmtDate(sink.created_at)} by {sink.created_by}</dd>
          </dl>
          <h3 className="h-sm">Dead letters</h3>
          <DeadLetters sink={sink} />
          <h3 className="h-sm">Settings</h3>
        </>
      )}
      <SinkForm key={sink ? `${sink.id}:${sink.updated_at}` : "new"} sink={sink} allowInsecure={allowInsecure} onDone={() => { if (!sink) onClose(); }} />
    </SidePanel>
  );
}

export function EventSinks() {
  const { data, error, reload } = useApi<GroupSinkList>(SINKS_PATH);
  const [selected, setSelected] = useSelected();
  const open = selected && selected !== "new" ? data?.items.find((s) => s.id === selected) : undefined;
  const cols: Column<GroupSink>[] = [
    {
      id: "name", header: "Sink", sort: (r) => r.name.toLowerCase(),
      cell: (r) => <div><b className="name-link">{r.name}</b><div className="xs faint">{KIND_LABEL[r.kind]}</div></div>,
    },
    {
      id: "state", header: "State", sort: (r) => stateOf(r).label,
      cell: (r) => { const s = stateOf(r); return <Badge tone={s.tone} dot>{s.label}</Badge>; },
    },
    { id: "lag", header: "Behind", num: true, sort: (r) => r.lag, cell: (r) => r.lag.toLocaleString() },
    {
      id: "dead", header: "Dead letters", num: true, hideNarrow: true, sort: (r) => r.dead_letters,
      cell: (r) => (r.dead_letters ? <Badge tone="critical">{r.dead_letters}</Badge> : 0),
    },
    {
      id: "last", header: "Last delivery", hideNarrow: true, sort: (r) => r.last_delivered_at ?? "",
      cell: (r) => <span className="small">{r.last_delivered_at ? relTime(r.last_delivered_at) : "Never"}</span>,
    },
  ];
  const atLimit = !!data && data.items.length >= data.max_sinks;
  return (
    <Page
      title="Group event sinks"
      crumbs={[["Settings"], ["Admin", "/admin"], ["Event sinks"]]}
      count={data ? `${data.items.length} sink${data.items.length === 1 ? "" : "s"}` : undefined}
      sub="Stream every group change (membership, group and privilege events) to AWS SQS or SNS, RabbitMQ or Kafka as CloudEvents. Delivery is at least once and in order per group: a message can arrive twice after a failure, so receivers should drop a repeated id."
    >
      <DataTable<GroupSink>
        id="group-event-sinks"
        rows={data?.items ?? null}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        searchText={(r) => `${r.name} ${r.kind} ${KIND_LABEL[r.kind]}`}
        searchPlaceholder="Search sinks…"
        filters={[
          { id: "kind", label: "Type", options: (Object.keys(KIND_LABEL) as SinkKind[]).map((k) => ({ value: k, label: KIND_LABEL[k] })), get: (r) => r.kind },
          { id: "state", label: "State", options: ["Delivering", "Retrying", "Idle", "Disabled"].map((s) => ({ value: s, label: s })), get: (r) => stateOf(r).label },
        ]}
        onRefresh={reload}
        rowLabel={(r) => r.name}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        commands={[{ label: "New sink", icon: <Plus size={16} />, disabled: atLimit, title: atLimit ? `A tenant may have at most ${data?.max_sinks} sinks` : undefined, onClick: () => setSelected("new") }]}
        empty={<EmptyState title="No sinks yet" icon={<Radio size={18} />}>Add a sink to send group events to a queue, topic or stream your other systems read.</EmptyState>}
      />
      {selected === "new" && data && <SinkPanel allowInsecure={data.allow_insecure} onClose={() => { setSelected(null); reload(); }} />}
      {open && data && <SinkPanel sink={open} allowInsecure={data.allow_insecure} onClose={() => { setSelected(null); reload(); }} />}
    </Page>
  );
}
