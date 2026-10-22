import { FormEvent, useId, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Ban, Plus, ShieldOff } from "lucide-react";
import {
  McpClient, McpConsent, McpDecision, McpResource, McpToken, fmtDate, mcpAuthz, safeRedirect, useApi,
} from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Chip, Tone } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Column, DataTable } from "../../components/DataTable";
import { useConfirm } from "../../components/Dialog";
import { Callout, Loading } from "../../components/Feedback";
import { Page, Tabs } from "../../components/Page";
import { SidePanel, useSelected } from "../../components/SidePanel";
import { useToast } from "../../components/Toast";
import { useModal } from "../../components/overlay";

/**
 * Agent authorization (issue #115): the MCP authorization server's admin view. Clients are
 * identified by a client ID metadata document URL and are unusable until an administrator binds
 * them to an AI agent (the agent's permissions are the ceiling of every token it gets). Tokens are
 * short-lived and audience-bound; revoking one, or containing the agent, ends it at once. Hiding
 * a control with can() is for usability only: the API enforces agents.manage and step-up.
 */

type Tab = "clients" | "tokens" | "decisions" | "resources";
const TABS: { id: Tab; label: string }[] = [
  { id: "clients", label: "Registered clients" },
  { id: "tokens", label: "Active tokens" },
  { id: "decisions", label: "Decision log" },
  { id: "resources", label: "Resource servers" },
];

const CLIENT_TONE: Record<string, Tone> = { active: "ok", pending: "warning", disabled: "neutral" };
const TOKEN_TONE: Record<string, Tone> = { active: "ok", expired: "neutral", revoked: "critical" };

const hostOf = (u: string) => {
  try {
    return new URL(u).host;
  } catch {
    return u;
  }
};

const Scopes = ({ scopes }: { scopes: string[] }) =>
  scopes.length === 0 ? <span className="muted">none</span> : <span className="row wrap">{scopes.map((s) => <Chip key={s} mono>{s}</Chip>)}</span>;

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return <label className="field">{label}{children}{hint && <span className="hint small muted">{hint}</span>}</label>;
}

function FormDialog({ title, onClose, onSubmit, submitLabel, busy, error, children }: {
  title: string; onClose: () => void; onSubmit: () => void; submitLabel: string; busy: boolean; error: string | null; children: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useModal(ref, onClose);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSubmit();
  };
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <form onSubmit={submit}>
          <div className="dlg-b">
            <h2 id={titleId}>{title}</h2>
            {children}
            {error && <div className="mt"><Callout tone="bad">{error}</Callout></div>}
          </div>
          <div className="dlg-f">
            <Button onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={busy}>{busy ? "Working…" : submitLabel}</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- consent

/** The page an MCP client sends the user to (via /t/{slug}/mcp/oauth/authorize): approve or deny what it asked for. */
function ConsentCard({ id, onDone }: { id: string; onDone: () => void }) {
  const { data, error } = useApi<McpConsent>(`/mcp/authorizations/${encodeURIComponent(id)}`);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!data) return <Loading error={error} kind="block" />;
  const decide = async (approve: boolean) => {
    setBusy(true);
    setErr(null);
    try {
      const r = await mcpAuthz.decide(data.id, approve);
      if (!safeRedirect(r.redirect_to)) throw new Error("The client's redirect address is not allowed.");
      window.location.assign(r.redirect_to);
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  };
  const narrowed = data.requested_scope.filter((s) => !data.granted_scope.includes(s));
  const open = data.status === "pending";
  return (
    <section className="card mt" aria-labelledby="consent-h">
      <h2 id="consent-h" className="h-sm">Allow {data.client.name} to act for you?</h2>
      <p className="small muted">
        Client {" "}<Chip mono>{data.client.client_id}</Chip>{" "}will send you back to <b>{data.client.redirect_uris.map(hostOf).join(", ")}</b>.
        It acts through the agent <b>{data.agent.name}</b> on <Chip mono>{data.resource}</Chip>.
      </p>
      {data.client.loopback_redirect && (
        <Callout tone="warn">This client sends you back to an address on your own computer. Any program on your computer can claim that address, so only continue if you started this sign-in yourself.</Callout>
      )}
      <h3 className="h-sm mt">It will get</h3>
      <Scopes scopes={data.granted_scope} />
      <p className="small muted">Only what you, the agent and this request all allow. The token lasts at most 5 minutes and works only at that resource.</p>
      {narrowed.length > 0 && (
        <>
          <h3 className="h-sm mt">Asked for, but not granted</h3>
          <Scopes scopes={narrowed} />
        </>
      )}
      {err && <div className="mt"><Callout tone="bad">{err}</Callout></div>}
      {!open && <div className="mt"><Callout tone="neutral">This request is {data.status}.</Callout></div>}
      <div className="row mt">
        <Button variant="primary" disabled={!open || busy || data.granted_scope.length === 0} onClick={() => decide(true)}>Allow</Button>
        <Button disabled={!open || busy} onClick={() => decide(false)}>Deny</Button>
        <Button variant="ghost" onClick={onDone}>Close</Button>
      </div>
      <p className="small muted mt">Decision policy version {data.policy_version}. Approving needs a fresh sign-in.</p>
    </section>
  );
}

// ---------------------------------------------------------------- clients

function RegisterClientDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const c = await mcpAuthz.registerClient(url.trim());
      toast(`Fetched ${c.name}. It stays pending until you bind it to an agent and activate it.`);
      onDone();
      onClose();
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };
  return (
    <FormDialog title="Register a client" onClose={onClose} onSubmit={submit} submitLabel="Fetch and register" busy={busy} error={error}>
      <p className="muted">Enter the client's metadata document URL (its client_id). Tessera fetches it once from its own network position, checks that it names this URL, and caches it for an hour.</p>
      <Field label="Client ID metadata document URL" hint="https only, with a path, for example https://agent.example/client.json">
        <input className="input" type="url" required value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://agent.example/client.json" autoFocus />
      </Field>
    </FormDialog>
  );
}

function ClientPanel({ client, canManage, onClose, onChanged }: { client: McpClient; canManage: boolean; onClose: () => void; onChanged: () => void }) {
  const { data: agents } = useApi<{ id: number; name: string; status: string }[]>("/nhi?type=ai_agent");
  const [agent, setAgent] = useState<string>(client.agent ? String(client.agent.id) : "");
  const [status, setStatus] = useState(client.status);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const save = async () => {
    setBusy(true);
    try {
      await mcpAuthz.updateClient(client.id, { agent_identity_id: agent ? Number(agent) : null, status });
      toast("Client updated");
      onChanged();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <SidePanel title={client.name} sub={<span className="small muted">{client.client_id}</span>} onClose={onClose}>
      <p><Badge tone={CLIENT_TONE[client.status]}>{client.status}</Badge> {client.has_keys ? <Badge tone="outline">Can exchange tokens (has keys)</Badge> : <Badge tone="outline">Browser sign-in only</Badge>}</p>
      <h3 className="h-sm mt">Redirects to</h3>
      <ul className="plain-list">
        {client.redirect_uris.map((u) => <li key={u}><Chip mono>{u}</Chip></li>)}
      </ul>
      {client.loopback_redirect && <Callout tone="warn">A redirect on the user's own computer: any local program can claim it, so the client name proves nothing.</Callout>}
      <p className="small muted mt">Document fetched {fmtDate(client.fetched_at)}, trusted until {fmtDate(client.expires_at)}. A changed document sets an active client back to pending.</p>
      <h3 className="h-sm mt">Agent</h3>
      <p className="small muted">The agent's own permissions are the ceiling of every token this client gets.</p>
      {!canManage && <Callout tone="neutral">Binding clients needs the agents.manage permission (policy admins).</Callout>}
      <Field label="Bound to">
        <select className="input" value={agent} disabled={!canManage} onChange={(e) => setAgent(e.target.value)}>
          <option value="">Not bound</option>
          {(agents ?? []).map((a) => <option key={a.id} value={a.id}>{a.name}{a.status !== "active" ? ` (${a.status})` : ""}</option>)}
        </select>
      </Field>
      <Field label="Status" hint="Disabling revokes the client's tokens. Changing the agent does too.">
        <select className="input" value={status} disabled={!canManage} onChange={(e) => setStatus(e.target.value as McpClient["status"])}>
          <option value="pending">Pending</option>
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
        </select>
      </Field>
      <div className="mt"><Button variant="primary" disabled={!canManage || busy} onClick={save}>{busy ? "Saving…" : "Save"}</Button></div>
    </SidePanel>
  );
}

function Clients({ canManage }: { canManage: boolean }) {
  const { data, error, reload } = useApi<McpClient[]>("/mcp/clients");
  const [selected, setSelected] = useSelected();
  const [adding, setAdding] = useState(false);
  const cols: Column<McpClient>[] = [
    { id: "name", header: "Client", sort: (r) => r.name, cell: (r) => <><b>{r.name}</b><div className="small muted">{r.client_id}</div></> },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Badge tone={CLIENT_TONE[r.status]}>{r.status}</Badge> },
    { id: "agent", header: "Agent", sort: (r) => r.agent?.name ?? "", cell: (r) => r.agent?.name ?? <span className="muted">Not bound</span> },
    { id: "redirect", header: "Redirects to", hideNarrow: true, cell: (r) => r.redirect_uris.map(hostOf).join(", ") },
    { id: "fetched", header: "Fetched", hideNarrow: true, sort: (r) => r.fetched_at, cell: (r) => fmtDate(r.fetched_at) },
  ];
  const sel = data?.find((c) => c.id === selected) ?? null;
  return (
    <>
      <DataTable<McpClient>
        id="mcp-clients" rows={data} error={error} rowKey={(r) => r.id} columns={cols} onRefresh={reload}
        searchText={(r) => `${r.name} ${r.client_id} ${r.agent?.name ?? ""}`} searchPlaceholder="Search clients"
        filters={[{ id: "status", label: "Status", options: ["active", "pending", "disabled"].map((v) => ({ value: v, label: v })), get: (r) => r.status }]}
        rowLabel={(r) => r.name} onRowClick={(r) => setSelected(r.id)} activeKey={selected}
        commands={[canManage && { label: "Register client", icon: <Plus size={14} />, onClick: () => setAdding(true) }]}
        empty={<p className="muted">No clients yet. A client appears here the first time it asks for authorization, or when you register its metadata URL.</p>}
      />
      {sel && <ClientPanel key={sel.id + sel.status + (sel.agent?.id ?? 0)} client={sel} canManage={canManage} onClose={() => setSelected(null)} onChanged={reload} />}
      {adding && <RegisterClientDialog onClose={() => setAdding(false)} onDone={reload} />}
    </>
  );
}

// ---------------------------------------------------------------- tokens

const actChain = (t: McpToken): string => {
  const names: string[] = [];
  for (let a = t.act; a; a = a.act ?? null) names.push(a.sub.replace("identity:", "agent #"));
  return names.join(" → ") || "none";
};

function Tokens({ canManage }: { canManage: boolean }) {
  const { data, error, reload } = useApi<McpToken[]>("/mcp/tokens");
  const confirm = useConfirm();
  const toast = useToast();
  const revoke = async (rows: McpToken[]) => {
    const live = rows.filter((r) => r.state === "active");
    if (live.length === 0) return;
    const ok = await confirm({ title: `Revoke ${live.length} token${live.length === 1 ? "" : "s"}?`, body: "The holders lose access at once: resource servers see the token as inactive on their next check.", confirmLabel: "Revoke", danger: true });
    if (ok === null) return;
    try {
      for (const t of live) await mcpAuthz.revokeToken(t.jti);
      toast(`Revoked ${live.length} token${live.length === 1 ? "" : "s"}`);
      reload();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };
  const agents = [...new Set((data ?? []).map((t) => t.agent.name))].sort();
  const cols: Column<McpToken>[] = [
    { id: "agent", header: "Agent", sort: (r) => r.agent.name, cell: (r) => <b>{r.agent.name}</b> },
    { id: "user", header: "On behalf of", sort: (r) => r.subject.name, cell: (r) => r.subject.name },
    { id: "aud", header: "Resource", sort: (r) => r.audience, cell: (r) => <Chip mono>{r.audience}</Chip> },
    { id: "scope", header: "Scope", cell: (r) => <Scopes scopes={r.scope} /> },
    { id: "chain", header: "Delegation chain", hideNarrow: true, cell: (r) => actChain(r) },
    { id: "state", header: "State", sort: (r) => r.state, cell: (r) => <Badge tone={TOKEN_TONE[r.state]}>{r.state}</Badge> },
    { id: "exp", header: "Expires", hideNarrow: true, sort: (r) => r.expires_at, cell: (r) => fmtDate(r.expires_at) },
    { id: "pv", header: "Policy", hideNarrow: true, cell: (r) => <span className="small muted">{r.policy_version}</span> },
  ];
  return (
    <DataTable<McpToken>
      id="mcp-tokens" rows={data} error={error} rowKey={(r) => r.jti} columns={cols} onRefresh={reload}
      searchText={(r) => `${r.agent.name} ${r.subject.name} ${r.audience} ${r.client_id}`} searchPlaceholder="Search tokens" initialFilters={{ state: "active" }}
      filters={[
        { id: "state", label: "State", options: ["active", "expired", "revoked"].map((v) => ({ value: v, label: v })), get: (r) => r.state },
        { id: "agent", label: "Agent", options: agents.map((v) => ({ value: v, label: v })), get: (r) => r.agent.name },
      ]}
      rowLabel={(r) => `${r.agent.name} token for ${r.audience}`}
      bulkActions={canManage ? [{ label: "Revoke", icon: <Ban size={14} />, danger: true, run: revoke }] : undefined}
      empty={<p className="muted">No tokens. Tokens are issued only after a user approves a client, or when an agent exchanges one it holds.</p>}
    />
  );
}

// ---------------------------------------------------------------- decisions

function Decisions() {
  const { data, error, reload } = useApi<McpDecision[]>("/mcp/decisions?limit=500");
  const cols: Column<McpDecision>[] = [
    { id: "at", header: "When", sort: (r) => r.at, cell: (r) => fmtDate(r.at) },
    { id: "kind", header: "Kind", sort: (r) => r.kind, cell: (r) => r.kind.replace("_", " ") },
    { id: "dec", header: "Decision", sort: (r) => (r.allow ? "allow" : "deny"), cell: (r) => <Badge tone={r.allow ? "ok" : "critical"}>{r.allow ? "allow" : "deny"}</Badge> },
    { id: "agent", header: "Agent", sort: (r) => r.agent?.name ?? "", cell: (r) => r.agent?.name ?? "" },
    { id: "user", header: "On behalf of", hideNarrow: true, sort: (r) => r.subject?.name ?? "", cell: (r) => r.subject?.name ?? "" },
    { id: "what", header: "Resource / tool", cell: (r) => <>{r.resource && <Chip mono>{r.resource}</Chip>} {r.tool && <b>{r.tool}</b>}</> },
    { id: "scope", header: "Scope granted", hideNarrow: true, cell: (r) => <Scopes scopes={r.granted_scope} /> },
    { id: "why", header: "Reason", hideNarrow: true, cell: (r) => <span className="small">{r.reason}</span> },
    { id: "pv", header: "Policy version", sort: (r) => r.policy_version, cell: (r) => <span className="small muted">{r.policy_version}</span> },
  ];
  return (
    <DataTable<McpDecision>
      id="mcp-decisions" rows={data} error={error} rowKey={(r) => r.id} columns={cols} onRefresh={reload} initialSort={["at", -1]}
      searchText={(r) => `${r.kind} ${r.agent?.name ?? ""} ${r.subject?.name ?? ""} ${r.resource} ${r.tool} ${r.reason} ${r.client_id}`}
      searchPlaceholder="Search the decision log"
      filters={[
        { id: "kind", label: "Kind", options: ["issue", "exchange", "tool_call", "revoke"].map((v) => ({ value: v, label: v.replace("_", " ") })), get: (r) => r.kind },
        { id: "decision", label: "Decision", options: [{ value: "allow", label: "allow" }, { value: "deny", label: "deny" }], get: (r) => (r.allow ? "allow" : "deny") },
      ]}
      rowLabel={(r) => `${r.kind} decision ${r.id}`}
      empty={<p className="muted">No decisions yet. Every token issue, exchange, denial, revocation and tool-call decision is logged here with the policy version.</p>}
    />
  );
}

// ---------------------------------------------------------------- resource servers

function Resources({ canManage }: { canManage: boolean }) {
  const { data, error, reload } = useApi<McpResource[]>("/mcp/resources");
  const [adding, setAdding] = useState(false);
  const [uri, setUri] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [created, setCreated] = useState<McpResource | null>(null);
  const [issuer, setIssuer] = useState("");
  const [audience, setAudience] = useState("");
  const [binding, setBinding] = useState<McpResource | null>(null);
  const confirm = useConfirm();
  const toast = useToast();
  const create = async () => {
    setBusy(true);
    setErr(null);
    try {
      const bind = issuer.trim() || audience.trim() ? { issuer: issuer.trim(), audience: audience.trim() } : undefined;
      setCreated(await mcpAuthz.createResource(uri.trim(), name.trim(), bind));
      setAdding(false);
      setUri("");
      setName("");
      setIssuer("");
      setAudience("");
      reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const bind = async () => {
    if (!binding) return;
    setBusy(true);
    setErr(null);
    try {
      await mcpAuthz.bindResource(binding.id, issuer.trim(), audience.trim());
      toast(`${binding.name} is bound; its earlier tokens were revoked`);
      setBinding(null);
      reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const toggle = async (r: McpResource) => {
    const next = r.status === "active" ? "disabled" : "active";
    if (next === "disabled") {
      const ok = await confirm({ title: `Disable ${r.name}?`, body: "Its tokens are revoked and it can no longer introspect tokens.", confirmLabel: "Disable", danger: true });
      if (ok === null) return;
    }
    try {
      await mcpAuthz.updateResource(r.id, next);
      toast(`${r.name} ${next === "active" ? "enabled" : "disabled"}`);
      reload();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };
  const cols: Column<McpResource>[] = [
    { id: "name", header: "Resource server", sort: (r) => r.name, cell: (r) => <><b>{r.name}</b><div className="small muted">{r.resource}</div></> },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Badge tone={r.status === "active" ? "ok" : "neutral"}>{r.status}</Badge> },
    { id: "bind", header: "Bound to", hideNarrow: true, sort: (r) => r.issuer, cell: (r) => <><div className="small">{r.issuer}</div><div className="small muted">aud {r.audience}{!r.bound && " (default)"}</div></> },
    { id: "meta", header: "Protected resource metadata", hideNarrow: true, cell: (r) => <Chip mono>{r.metadata_path}</Chip> },
    { id: "by", header: "Registered by", hideNarrow: true, cell: (r) => `${r.created_by}, ${fmtDate(r.created_at)}` },
    { id: "act", header: "", cell: (r) => canManage ? <><Button size="sm" onClick={() => { setIssuer(r.issuer); setAudience(r.audience); setErr(null); setBinding(r); }}>Bind</Button>{" "}<Button size="sm" icon={r.status === "active" ? <ShieldOff size={14} /> : undefined} onClick={() => toggle(r)}>{r.status === "active" ? "Disable" : "Enable"}</Button></> : null },
  ];
  return (
    <>
      {created?.secret && (
        <Callout tone="warn">
          Secret for <b>{created.name}</b> (shown once, copy it now): <Chip mono>{created.secret}</Chip>. The resource server uses it with its id <Chip mono>{created.id}</Chip> as HTTP Basic credentials at the introspection and decision endpoints.{" "}
          <Button size="sm" onClick={() => setCreated(null)}>I have copied it</Button>
        </Callout>
      )}
      <DataTable<McpResource>
        id="mcp-resources" rows={data} error={error} rowKey={(r) => r.id} columns={cols} onRefresh={reload}
        searchText={(r) => `${r.name} ${r.resource}`} searchPlaceholder="Search resource servers" rowLabel={(r) => r.name}
        commands={[canManage && { label: "Register resource server", icon: <Plus size={14} />, onClick: () => setAdding(true) }]}
        empty={<p className="muted">No resource servers. A token can only be issued for a registered resource server; an unregistered one is blocked by policy. Each is bound to the authorization server and audience its tokens must carry.</p>}
      />
      {adding && (
        <FormDialog title="Register a resource server" onClose={() => setAdding(false)} onSubmit={create} submitLabel="Register" busy={busy} error={err}>
          <Field label="Name"><input className="input" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} autoFocus /></Field>
          <Field label="Resource URI" hint="The audience of its tokens (RFC 8707): an https URI without a fragment.">
            <input className="input" type="url" required value={uri} onChange={(e) => setUri(e.target.value)} placeholder="https://mcp.example.com/mcp" />
          </Field>
          <Field label="Authorization server issuer (optional)" hint="The issuer this server expects its tokens from. Empty: this tenant's MCP authorization server. Set it together with the audience.">
            <input className="input" type="url" value={issuer} onChange={(e) => setIssuer(e.target.value)} />
          </Field>
          <Field label="Token audience (optional)" hint="Empty: the resource URI.">
            <input className="input" type="url" value={audience} onChange={(e) => setAudience(e.target.value)} />
          </Field>
        </FormDialog>
      )}
      {binding && (
        <FormDialog title={`Bind ${binding.name}`} onClose={() => setBinding(null)} onSubmit={bind} submitLabel="Bind and revoke tokens" busy={busy} error={err}>
          <p className="muted">Tokens are issued for this server only by the bound authorization server, carry the bound audience, and are refused anywhere else. Changing the binding revokes its live tokens. If the issuer is not this tenant's authorization server, no token can be issued for it.</p>
          <Field label="Authorization server issuer"><input className="input" type="url" required value={issuer} onChange={(e) => setIssuer(e.target.value)} autoFocus /></Field>
          <Field label="Token audience"><input className="input" type="url" required value={audience} onChange={(e) => setAudience(e.target.value)} /></Field>
        </FormDialog>
      )}
    </>
  );
}

// ---------------------------------------------------------------- page

export function AgentAuthorization() {
  const [params, setParams] = useSearchParams();
  const { can } = useSession();
  const canManage = can("agents.manage");
  const tab = (TABS.find((t) => t.id === params.get("tab"))?.id ?? "clients") as Tab;
  const consent = params.get("consent");
  const setTab = (t: Tab) => setParams((p) => { const n = new URLSearchParams(p); n.set("tab", t); n.delete("selected"); return n; }, { replace: true });
  const closeConsent = () => setParams((p) => { const n = new URLSearchParams(p); n.delete("consent"); return n; }, { replace: true });
  return (
    <Page
      title="Agent authorization"
      crumbs={[["Protection"], ["Agent authorization"]]}
      sub="OAuth 2.1 for MCP clients. A token carries the user, the agent acting for them and the resource it is for, and only the permissions all of them have, for at most five minutes."
      tabs={<Tabs<Tab> tabs={TABS} value={tab} onChange={setTab} label="Agent authorization" />}
    >
      {consent && <ConsentCard id={consent} onDone={closeConsent} />}
      {tab === "clients" && <Clients canManage={canManage} />}
      {tab === "tokens" && <Tokens canManage={canManage} />}
      {tab === "decisions" && <Decisions />}
      {tab === "resources" && <Resources canManage={canManage} />}
    </Page>
  );
}
