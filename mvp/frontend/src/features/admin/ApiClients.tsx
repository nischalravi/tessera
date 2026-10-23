import { FormEvent, useState } from "react";
import { Ban, KeyRound, Plus } from "lucide-react";
import { ApiClient, MACHINE_ROLES, MACHINE_SCOPES, apiClients, relTime, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, DataTable, Drawer, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { Fact, errText, when } from "./common";

/**
 * API clients (design §9.5): machines and automation that call the Tessera API with short-lived,
 * sender-constrained tokens. A client holds its own private key; Tessera stores only the public key,
 * so there is no secret to leak from here. Creating, re-keying and revoking need a fresh passkey
 * sign-in and are written to the audit log. A client never gets the admin scope or an admin role.
 */
export function ApiClients() {
  const { data, error, reload } = useApi<ApiClient[]>("/admin/api-clients");
  const { can } = useSession();
  const [selected, setSelected] = useSelected();
  const [creating, setCreating] = useState(false);
  const canChange = can("admin.change.request");
  const client = data?.find((c) => c.client_id === selected) ?? null;
  return (
    <Page
      title="API clients"
      crumbs={[["Settings"], ["Admin", "/admin"], ["API clients"]]}
      sub="Machines and automation that call the Tessera API with short-lived, sender-constrained tokens. A client holds its own private key and Tessera keeps only the public key. The admin scope is never granted to a machine."
    >
      <div className="stack">
        <DataTable
          id="admin-api-clients"
          rows={data ?? null}
          error={error}
          rowKey={(c) => c.client_id}
          activeKey={selected}
          onRowClick={(c) => setSelected(c.client_id)}
          onRefresh={reload}
          rowLabel={(c) => c.name}
          commands={[canChange && { label: "New client", icon: <Plus size={14} />, onClick: () => setCreating(true) }]}
          columns={[
            { id: "name", header: "Client", sort: (c) => c.name, cell: (c) => <div><b>{c.name}</b><div className="xs faint"><code>{c.client_id}</code></div></div> },
            { id: "scopes", header: "Scopes", hideNarrow: true, cell: (c) => <span className="small">{c.allowed_scopes.map((s) => s.replace("tessera:", "")).join(", ")}</span> },
            { id: "roles", header: "Roles", hideNarrow: true, cell: (c) => <span className="small">{c.roles.length ? c.roles.join(", ") : "—"}</span> },
            { id: "keys", header: "Keys", num: true, hideNarrow: true, sort: (c) => c.keys.length, cell: (c) => c.keys.length },
            { id: "used", header: "Last used", sort: (c) => c.last_used_at ?? "", cell: (c) => <span className="small">{c.last_used_at ? relTime(c.last_used_at.replace("Z", "")) : "Never"}</span> },
            { id: "status", header: "Status", sort: (c) => c.status, cell: (c) => (c.status === "active" ? <Badge tone="ok" dot>Active</Badge> : <Badge tone="neutral" dot>Revoked</Badge>) },
          ]}
          searchText={(c) => `${c.name} ${c.client_id} ${c.allowed_scopes.join(" ")} ${c.roles.join(" ")}`}
          searchPlaceholder="Search clients…"
          empty="No API clients."
        />
        <p className="small faint" style={{ margin: 0 }}>
          A client signs a short assertion with its key to get a token that lasts 10 minutes and is bound to the key of the caller (DPoP). Revoking a client stops it from getting new tokens and ends the ones it holds.
          “Last used” is when it last got a token.
        </p>
      </div>
      {creating && <NewClient onClose={() => setCreating(false)} onCreated={(c) => { setCreating(false); setSelected(c.client_id); reload?.(); }} />}
      {client && <ClientPanel c={client} canChange={canChange} onClose={() => setSelected(null)} onChanged={() => reload?.()} />}
    </Page>
  );
}

/** Makes a key pair in the browser and returns the public JWK set and the private JWK. The private key never leaves the page. */
async function generateKeyPair(kid: string): Promise<{ jwks: { keys: JsonWebKey[] }; privateJwk: JsonWebKey }> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pub: JsonWebKey & { kid: string; alg: string; use: string } = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid, alg: "ES256", use: "sig" };
  delete pub.key_ops;
  delete pub.ext;
  const priv = { ...(await crypto.subtle.exportKey("jwk", pair.privateKey)), kid, alg: "ES256" };
  return { jwks: { keys: [pub] }, privateJwk: priv };
}

const newKid = () => `k-${new Date().toISOString().slice(0, 10)}-${Math.random().toString(36).slice(2, 6)}`;

/** The public key set field: paste a JWK set, or make a key pair here and keep the private half. */
function KeyField({ value, onChange, onPrivate }: { value: string; onChange: (v: string) => void; onPrivate: (jwk: string | null) => void }) {
  const [err, setErr] = useState<string | null>(null);
  const make = async () => {
    setErr(null);
    try {
      const { jwks, privateJwk } = await generateKeyPair(newKid());
      onChange(JSON.stringify(jwks, null, 1));
      onPrivate(JSON.stringify(privateJwk));
    } catch {
      setErr("This browser cannot make the key. Generate one on the machine that will call the API and paste its public key.");
    }
  };
  return (
    <div className="stack-sm">
      <label className="field">Public keys (JWK set)
        <textarea className="input sys" rows={6} value={value} spellCheck={false} required onChange={(e) => { onChange(e.target.value); onPrivate(null); }}
          placeholder={'{"keys":[{"kty":"EC","crv":"P-256","kid":"…","x":"…","y":"…"}]}'} />
        <span className="hint">Public keys only (EC P-256 or Ed25519, each with a unique <code>kid</code>). The client keeps the private key.</span>
      </label>
      <div className="row"><Button size="sm" onClick={make}>Make a key pair here</Button></div>
      {err && <span className="hint" role="alert">{err}</span>}
    </div>
  );
}

/** Shown once after a key pair is made in the page: the private key is not stored anywhere else. */
function PrivateKeyNotice({ jwk }: { jwk: string }) {
  return (
    <Callout tone="warn">
      <b>Copy the private key now.</b> It was made in this page and is not sent to Tessera, so it cannot be shown again. Give it only to the client.
      <textarea className="input sys" rows={4} readOnly value={jwk} onFocus={(e) => e.currentTarget.select()} aria-label="Private key (JWK)" style={{ marginTop: 6 }} />
    </Callout>
  );
}

function parseJwks(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("The keys must be a JWK set: a JSON object with a keys list.");
  }
}

function NewClient({ onClose, onCreated }: { onClose: () => void; onCreated: (c: ApiClient) => void }) {
  const toast = useToast();
  const [f, setF] = useState({ name: "", owner: "", scopes: ["tessera:read"] as string[], roles: ["viewer"] as string[], dpop: true, jwks: "" });
  const [priv, setPriv] = useState<string | null>(null);
  const [created, setCreated] = useState<ApiClient | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const toggle = (k: "scopes" | "roles", v: string) => setF((s) => ({ ...s, [k]: s[k].includes(v) ? s[k].filter((x) => x !== v) : [...s[k], v] }));
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const c = await apiClients.create({ name: f.name.trim(), owner: f.owner.trim(), scopes: f.scopes, roles: f.roles, dpop_required: f.dpop, jwks: parseJwks(f.jwks) });
      toast(`${c.name} created`);
      if (priv) setCreated(c); // keep the drawer open until the private key has been copied
      else onCreated(c);
    } catch (err) {
      setError(errText(err));
    } finally {
      setBusy(false);
    }
  };
  if (created && priv) {
    return (
      <Drawer title={`${created.name} created`} sub={<code>{created.client_id}</code>} onClose={() => onCreated(created)}>
        <div className="stack">
          <PrivateKeyNotice jwk={priv} />
          <p className="small muted">The client signs an assertion with this key (<code>iss</code> and <code>sub</code> are its client id) and sends it to the token endpoint of this tenant.</p>
          <div className="row"><Button variant="primary" onClick={() => onCreated(created)}>I have copied it</Button></div>
        </div>
      </Drawer>
    );
  }
  return (
    <Drawer title="New API client" sub="A machine that calls the API with its own key." onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Name<input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required maxLength={200} placeholder="e.g. Nightly access export" /></label>
        <label className="field">Owner (e-mail of an active user)
          <input className="input" type="email" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} required maxLength={320} />
          <span className="hint">The person accountable for this client. Every machine identity has an owner.</span>
        </label>
        <fieldset className="stack-sm">
          <legend className="small">Scopes</legend>
          {MACHINE_SCOPES.map((s) => (
            <label key={s} className="row tight small"><input type="checkbox" checked={f.scopes.includes(s)} onChange={() => toggle("scopes", s)} /> <code>{s}</code></label>
          ))}
        </fieldset>
        <fieldset className="stack-sm">
          <legend className="small">Roles</legend>
          {MACHINE_ROLES.map((r) => (
            <label key={r} className="row tight small"><input type="checkbox" checked={f.roles.includes(r)} onChange={() => toggle("roles", r)} /> {r}</label>
          ))}
          <span className="xs faint">The client acts with these roles, limited to its scopes. It cannot approve anything or change policy.</span>
        </fieldset>
        <label className="row tight small"><input type="checkbox" checked={f.dpop} onChange={(e) => setF({ ...f, dpop: e.target.checked })} /> Require DPoP (the token works only with the caller's key; leave on unless the client cannot do it)</label>
        <KeyField value={f.jwks} onChange={(v) => setF({ ...f, jwks: v })} onPrivate={setPriv} />
        {priv && <PrivateKeyNotice jwk={priv} />}
        <p className="small muted">Saving needs a recent passkey sign-in; if it asks for one, sign in and submit again.</p>
        <div aria-live="polite">{error && <Callout tone="bad">{error}</Callout>}</div>
        <div className="row"><Button type="submit" variant="primary" disabled={busy || f.scopes.length === 0 || f.roles.length === 0}>{busy ? "Creating…" : "Create client"}</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
    </Drawer>
  );
}

function ClientPanel({ c, canChange, onClose, onChanged }: { c: ApiClient; canChange: boolean; onClose: () => void; onChanged: () => void }) {
  const confirm = useConfirm();
  const toast = useToast();
  const [keys, setKeys] = useState<"add" | "replace" | null>(null);
  const machine = c.kind === "machine";
  const revoke = async () => {
    const ok = await confirm({
      title: `Revoke ${c.name}?`,
      body: "It can no longer get tokens, and the tokens it holds stop working at once. Anything that calls the API with this client will fail until it is given a new client.",
      confirmLabel: "Revoke the client",
      danger: true,
    });
    if (ok === null) return;
    try {
      await apiClients.revoke(c.client_id);
      toast(`${c.name} revoked`);
      onChanged();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };
  return (
    <SidePanel
      title={c.name}
      sub={c.status === "active" ? <Badge tone="ok" dot>Active</Badge> : <Badge tone="neutral" dot>Revoked</Badge>}
      onClose={onClose}
      commands={
        canChange && machine && c.status === "active" ? (
          <div className="cmdbar" role="toolbar" aria-label="Client actions">
            <Button size="sm" icon={<KeyRound size={13} />} onClick={() => setKeys("add")}>Add a key</Button>
            <Button size="sm" onClick={() => setKeys("replace")}>Replace keys</Button>
            <Button size="sm" variant="danger" icon={<Ban size={13} />} onClick={revoke}>Revoke</Button>
          </div>
        ) : undefined
      }
    >
      <div className="stack">
        <div className="grid g2">
          <Fact label="Client id"><code className="xs">{c.client_id}</code></Fact>
          <Fact label="Kind">{machine ? "Machine (client credentials)" : "Tessera CLI (sign-in with a person)"}</Fact>
          <Fact label="Created">{when(c.created_at)}</Fact>
          <Fact label="Last used">{c.last_used_at ? when(c.last_used_at) : "Never"}</Fact>
          <Fact label="Scopes">{c.allowed_scopes.join(", ")}</Fact>
          <Fact label="Roles">{c.roles.length ? c.roles.join(", ") : "The signed-in person's own"}</Fact>
          <Fact label="Sender-constrained (DPoP)">{c.dpop_required ? "Required" : "Not required"}</Fact>
          <Fact label="Authentication">{c.token_endpoint_auth_method === "private_key_jwt" ? "Signed assertion (private_key_jwt)" : "Public client"}</Fact>
        </div>
        <div>
          <div className="xs faint">Public keys ({c.keys.length})</div>
          {c.keys.length === 0 ? <p className="small muted" style={{ margin: 0 }}>None: this client signs in through a person.</p> : (
            <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
              {c.keys.map((k) => <li key={k.kid}><code>{k.kid}</code> · {k.alg} · <span className="xs faint" title="RFC 7638 thumbprint">{k.jkt.slice(0, 12)}…</span></li>)}
            </ul>
          )}
        </div>
        {c.status === "disabled" && <Callout tone="neutral">Revoked. It gets no new tokens and the ones it held no longer work.</Callout>}
        {!machine && <Callout tone="info">The first-party CLI client is managed by Tessera and cannot be changed here.</Callout>}
      </div>
      {keys && <KeysDrawer c={c} mode={keys} onClose={() => setKeys(null)} onDone={() => { setKeys(null); onChanged(); }} />}
    </SidePanel>
  );
}

function KeysDrawer({ c, mode, onClose, onDone }: { c: ApiClient; mode: "add" | "replace"; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [jwks, setJwks] = useState("");
  const [priv, setPriv] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiClients.keys(c.client_id, mode, parseJwks(jwks));
      toast(mode === "add" ? "Key added" : "Keys replaced");
      if (priv) setSaved(true);
      else onDone();
    } catch (err) {
      setError(errText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer
      title={mode === "add" ? `Add a key to ${c.name}` : `Replace the keys of ${c.name}`}
      sub={mode === "add" ? "Rotate without a gap: add the new key, move the client to it, then replace the set with the new key only." : "Only the keys below will work afterwards."}
      onClose={saved ? onDone : onClose}
    >
      {saved && priv ? (
        <div className="stack">
          <PrivateKeyNotice jwk={priv} />
          <div className="row"><Button variant="primary" onClick={onDone}>I have copied it</Button></div>
        </div>
      ) : (
        <form className="stack" onSubmit={submit}>
          {mode === "replace" && <Callout tone="warn">The client's other keys stop working at once. Include a key the client already uses if it must keep working.</Callout>}
          <KeyField value={jwks} onChange={setJwks} onPrivate={setPriv} />
          {priv && <PrivateKeyNotice jwk={priv} />}
          <div aria-live="polite">{error && <Callout tone="bad">{error}</Callout>}</div>
          <div className="row"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : mode === "add" ? "Add key" : "Replace keys"}</Button><Button onClick={onClose}>Cancel</Button></div>
        </form>
      )}
    </Drawer>
  );
}
