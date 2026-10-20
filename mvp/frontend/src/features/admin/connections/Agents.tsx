/**
 * Admin → Connections → Directory agents (DR-11, design §5.3).
 *
 * A private directory is reached only through a Directory Agent that the customer runs inside their
 * network. It connects outbound, runs a closed set of read-only operations, and refuses any target
 * that is not on its own local allowlist. Here an administrator lists the agents, issues a
 * single-use enrolment code (shown once) and revokes an agent. Everything is enforced by the server.
 */
import { FormEvent, useId, useRef, useState } from "react";
import { Copy, Plus } from "lucide-react";
import { AgentEnrolment, DirectoryAgent, agents, fmtDate, relTime, useApi } from "../../../api";
import { Badge, Button, Callout, Page, SidePanel, Tone, useConfirm, useSelected, useToast, DataTable } from "../../../components";
import { useModal } from "../../../components/overlay";

type Phase = "pending" | "online" | "offline" | "revoked";
const phase = (a: DirectoryAgent): Phase => (a.status === "active" ? (a.online ? "online" : "offline") : a.status);
const PHASE_LABEL: Record<Phase, string> = { pending: "Awaiting enrolment", online: "Online", offline: "Offline", revoked: "Revoked" };
const PHASE_TONE: Record<Phase, Tone> = { pending: "info", online: "ok", offline: "warning", revoked: "neutral" };
const PHASE_ORDER: Phase[] = ["offline", "pending", "online", "revoked"];

export function AgentStatus({ a }: { a: DirectoryAgent }) {
  const p = phase(a);
  return (
    <span className="row tight">
      <Badge tone={PHASE_TONE[p]} dot>{PHASE_LABEL[p]}</Badge>
      {a.status === "active" && a.outdated && <Badge tone="warning" title="This agent is older than the version Tessera treats as current. Update it.">Out of date</Badge>}
    </span>
  );
}

const short = (h?: string) => (h ? h.slice(0, 12) : "");

export function AgentsList() {
  const { data, error, reload } = useApi<DirectoryAgent[]>("/agents");
  const [selected, setSelected] = useSelected();
  const [enrol, setEnrol] = useState(false);
  const open = data?.find((a) => a.id === selected);
  return (
    <Page
      title="Directory agents"
      crumbs={[["Settings"], ["Connections", "/admin/connections"], ["Directory agents"]]}
      count={data ? `${data.length} agent${data.length === 1 ? "" : "s"}` : undefined}
      sub="A directory inside a private network is reached only through a Directory Agent that you run there. It connects outbound to Tessera, runs read-only checks, and refuses any host that is not on its own local allowlist, which only a local administrator can edit."
    >
      <DataTable<DirectoryAgent>
        id="agents"
        rows={data}
        error={error}
        rowKey={(a) => a.id}
        onRefresh={reload}
        columns={[
          {
            id: "name", header: "Agent", sort: (a) => a.name,
            cell: (a) => (
              <div>
                <b className="name-link">{a.name}</b>
                <div className="xs faint">{a.hostname ? `${a.hostname}${a.os ? ` · ${a.os}` : ""}` : "Not enrolled yet"}</div>
              </div>
            ),
          },
          { id: "status", header: "Status", sort: (a) => PHASE_ORDER.indexOf(phase(a)), csv: (a) => PHASE_LABEL[phase(a)], cell: (a) => <AgentStatus a={a} /> },
          { id: "version", header: "Version", hideNarrow: true, sort: (a) => a.version ?? "", cell: (a) => (a.version ? <span className="sys">{a.version}</span> : <span className="faint">–</span>) },
          { id: "seen", header: "Last seen", hideNarrow: true, sort: (a) => a.last_seen_at ?? "", csv: (a) => a.last_seen_at ?? "", cell: (a) => <span className="small">{relTime(a.last_seen_at)}</span> },
          { id: "allow", header: "Allowlist", hideNarrow: true, csv: (a) => a.allowlist_hash ?? "", cell: (a) => (a.allowlist_hash ? <span className="sys" title="SHA-256 of the agent's local allowlist">{short(a.allowlist_hash)}</span> : <span className="faint">–</span>) },
        ]}
        searchText={(a) => `${a.name} ${a.hostname ?? ""} ${a.os ?? ""} ${a.id}`}
        searchPlaceholder="Search agents…"
        filters={[{ id: "status", label: "Status", options: PHASE_ORDER.map((p) => ({ value: p, label: PHASE_LABEL[p] })), get: (a) => phase(a) }]}
        commands={[{ label: "Enrol an agent", icon: <Plus size={16} />, onClick: () => setEnrol(true) }]}
        rowLabel={(a) => a.name}
        onRowClick={(a) => setSelected(a.id)}
        activeKey={selected}
        initialSort={["status", 1]}
        empty={<span>No Directory Agents yet. Enrol one to check a directory that is not reachable from the internet.</span>}
      />
      {open && <AgentPanel a={open} onClose={() => setSelected(null)} onChanged={reload} />}
      {enrol && <EnrolDialog onClose={() => { setEnrol(false); reload(); }} />}
    </Page>
  );
}

function AgentPanel({ a, onClose, onChanged }: { a: DirectoryAgent; onClose: () => void; onChanged: () => void }) {
  const confirm = useConfirm();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const revoke = async () => {
    const ok = await confirm({
      title: `Revoke ${a.name}?`,
      body: "The agent can no longer connect, an unused enrolment code is voided, and connections that use it fail their live checks until another agent is set. Tessera never falls back to a direct connection.",
      confirmLabel: "Revoke agent",
      danger: true,
    });
    if (ok === null) return;
    setBusy(true);
    try {
      await agents.revoke(a.id);
      toast(`Revoked ${a.name}`);
      onChanged();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <SidePanel
      title={a.name}
      sub={<AgentStatus a={a} />}
      onClose={onClose}
      commands={
        a.status !== "revoked" ? (
          <div className="panel-cmds">
            <Button variant="danger" disabled={busy} onClick={revoke}>Revoke agent</Button>
          </div>
        ) : undefined
      }
    >
      <div className="stack">
        {a.status === "pending" && (
          <Callout tone="info">
            Waiting for the agent to enrol with its code. A code is valid for 15 minutes and works once. If it expired, revoke this agent and enrol a new one.
          </Callout>
        )}
        {a.status === "active" && !a.online && (
          <Callout tone="warn">
            This agent has not contacted Tessera recently. Checks on connections that use it fail until it is running again.
          </Callout>
        )}
        {a.status === "active" && a.outdated && (
          <Callout tone="warn">This agent is older than the version Tessera treats as current. Update it.</Callout>
        )}
        <dl className="kv">
          <dt>Agent ID</dt><dd className="sys">{a.id}</dd>
          <dt>Host</dt><dd>{a.hostname || "–"}</dd>
          <dt>Operating system</dt><dd>{a.os || "–"}</dd>
          <dt>Version</dt><dd>{a.version || "–"}</dd>
          <dt>Last seen</dt><dd>{a.last_seen_at ? `${fmtDate(a.last_seen_at)} (${relTime(a.last_seen_at)})` : "Never"}</dd>
          <dt>Enrolled</dt><dd>{a.enrolled_at ? fmtDate(a.enrolled_at) : "Not yet"}</dd>
          <dt>Allowlist hash</dt><dd className="sys">{a.allowlist_hash || "–"}</dd>
          <dt>Created by</dt><dd>{a.created_by} · {fmtDate(a.created_at)}</dd>
          {a.revoked_at && <><dt>Revoked</dt><dd>{a.revoked_by} · {fmtDate(a.revoked_at)}</dd></>}
        </dl>
        <section>
          <h3>Using this agent</h3>
          <p className="small muted">
            Store the directory password on the agent host with <span className="sys">tessera-agent credential set</span>, then set a connection's credential reference to{" "}
            <span className="sys">{a.credential_ref_prefix}&lt;name&gt;</span>. The password never reaches Tessera. Which hosts the agent may contact is set in its own configuration file, not here.
          </p>
        </section>
      </div>
    </SidePanel>
  );
}

/** Issue an enrolment code. The code is shown once, in this dialog, and nowhere else. */
function EnrolDialog({ onClose }: { onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  const toast = useToast();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [made, setMade] = useState<AgentEnrolment | null>(null);
  useModal(ref, onClose);
  const valid = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(name.trim());
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid || busy) return;
    setBusy(true);
    setErr(null);
    try {
      setMade(await agents.enrol(name.trim()));
    } catch (x) {
      setErr((x as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(made?.code ?? "");
      toast("Enrolment code copied");
    } catch {
      toast("Could not copy. Select the code and copy it by hand.", { kind: "error" });
    }
  };
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={made ? undefined : onClose} aria-hidden />
      <div ref={ref} className="dialog" role="dialog" aria-modal="true" aria-labelledby={id}>
        {!made ? (
          <form onSubmit={submit}>
            <div className="dlg-b stack-sm">
              <h2 id={id}>Enrol a Directory Agent</h2>
              <p className="muted small">
                Name the agent after the host or site it will run on. Tessera then shows a single-use enrolment code, valid for 15 minutes, that you enter on that host.
              </p>
              <label className="field">
                Agent name
                <input className="input" data-autofocus value={name} maxLength={64} onChange={(e) => setName(e.target.value)} placeholder="e.g. Oslo datacentre" required aria-describedby={`${id}-h`} />
                <span id={`${id}-h`} className={`hint ${name && !valid ? "err" : ""}`}>Letters, digits, spaces, dots, dashes and underscores. Up to 64 characters.</span>
              </label>
              {err && <div className="callout bad" role="alert">{err}</div>}
            </div>
            <div className="dlg-f">
              <Button onClick={onClose}>Cancel</Button>
              <Button type="submit" variant="primary" disabled={!valid || busy}>{busy ? "Creating…" : "Create enrolment code"}</Button>
            </div>
          </form>
        ) : (
          <div>
            <div className="dlg-b stack-sm">
              <h2 id={id}>Enrolment code for {made.agent.name}</h2>
              <Callout tone="warn">
                This code is shown once and cannot be retrieved later; Tessera keeps only a hash of it. It works for one enrolment and expires at {fmtDate(made.expires_at)}.
              </Callout>
              <div className="row tight">
                <pre className="yaml grow" style={{ margin: 0, userSelect: "all", whiteSpace: "pre-wrap", wordBreak: "break-all" }} aria-label="Enrolment code" data-autofocus tabIndex={0}>{made.code}</pre>
                <Button icon={<Copy size={16} />} onClick={copy} label="Copy the enrolment code" />
              </div>
              <p className="small muted">
                On the agent host run <span className="sys">tessera-agent enrol -config agent.json</span> and paste the code when it waits. It is read from standard input, so it stays out of the shell history.
              </p>
            </div>
            <div className="dlg-f">
              <Button variant="primary" onClick={onClose}>Done</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
