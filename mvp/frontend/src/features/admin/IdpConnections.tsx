import { FormEvent, useState } from "react";
import { Ban, Plus, Power } from "lucide-react";
import { AdminIdpConnection, adminChanges, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, DataTable, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { Fact, errText, outcome, when } from "./common";
import { FieldErrors, checkSAMLFields, serverFieldError } from "./idpFormChecks";

const TONE = { active: "ok", pending: "warning", disabled: "neutral" } as const;

/** Sign-in connections: how people sign in to Tessera. Creating or re-trusting one is an admin change. */
export function IdpConnections() {
  const { data, error, reload } = useApi<{ connections: AdminIdpConnection[] }>("/admin/idp-connections");
  const { can } = useSession();
  const [selected, setSelected] = useSelected();
  const [creating, setCreating] = useState(false);
  const rows = data?.connections ?? null;
  const current = rows?.find((c) => c.id === selected) ?? null;
  return (
    <Page
      title="Authentication"
      crumbs={[["Settings"], ["Admin", "/admin"], ["Authentication"]]}
      sub="The identity providers people use to sign in to Tessera. Tessera never stores passwords or second factors: it relies on the IdP and checks, from the sign-in itself, whether it was phishing-resistant. A new connection needs a second admin and 24 hours, then one successful test sign-in by the admin who asked for it."
    >
      <div className="stack">
        {creating && <NewConnection onDone={() => { setCreating(false); reload?.(); }} onCancel={() => setCreating(false)} />}
        <DataTable
          id="admin-idp"
          rows={rows}
          error={error}
          rowKey={(c) => c.id}
          activeKey={selected}
          onRowClick={(c) => setSelected(c.id)}
          onRefresh={reload}
          rowLabel={(c) => c.name}
          commands={[can("admin.change.request") && { label: "New connection", icon: <Plus size={14} />, onClick: () => setCreating(true) }]}
          columns={[
            { id: "name", header: "Connection", sort: (c) => c.name, cell: (c) => <div><b>{c.name}</b>{c.is_default && <> <Badge tone="outline">default</Badge></>}<div className="xs faint">{c.protocol.toUpperCase()} · {c.profile}</div></div> },
            { id: "status", header: "Status", sort: (c) => c.status, cell: (c) => <Badge tone={TONE[c.status]} dot>{c.status}</Badge> },
            { id: "issuer", header: "Issuer", hideNarrow: true, sort: (c) => c.issuer ?? "", cell: (c) => <span className="small sys truncate" style={{ display: "block", maxWidth: 320 }}>{c.issuer ?? "—"}</span> },
            { id: "domains", header: "Domains", hideNarrow: true, cell: (c) => <span className="small">{c.verified_domains.join(", ") || "—"}</span> },
            { id: "phr", header: "Phishing resistance", hideNarrow: true, cell: (c) => <span className="small">{c.assume_phishing_resistant ? <Badge tone="warning" title="Trusted without proof in the sign-in: set by a two-person change">assumed</Badge> : "proved per sign-in"}</span> },
          ]}
          searchText={(c) => `${c.name} ${c.protocol} ${c.profile} ${c.issuer ?? ""} ${c.verified_domains.join(" ")}`}
          searchPlaceholder="Search connections…"
          filters={[{ id: "status", label: "Status", options: ["active", "pending", "disabled"].map((s) => ({ value: s, label: s })), get: (c) => c.status }]}
          empty="No sign-in connections."
        />
      </div>
      {current && <ConnectionPanel c={current} canRequest={can("admin.change.request")} onClose={() => setSelected(null)} onChanged={() => reload?.()} />}
    </Page>
  );
}

function ConnectionPanel({ c, canRequest, onClose, onChanged }: { c: AdminIdpConnection; canRequest: boolean; onClose: () => void; onChanged: () => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const run = async (f: () => Promise<string>) => {
    setBusy(true);
    try {
      toast(await f());
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(false);
      onChanged();
    }
  };
  return (
    <SidePanel title={c.name} sub={<><Badge tone={TONE[c.status]} dot>{c.status}</Badge> {c.protocol.toUpperCase()} · {c.profile}</>} onClose={onClose}>
      <div className="stack">
        {c.status === "pending" && (
          <Callout tone={c.activation?.ready ? "ok" : "warn"}>
            {c.activation
              ? c.activation.ready
                ? <>The test sign-in succeeded ({when(c.activation.test_login_at)}). The admin who requested this connection can activate it.</>
                : <>Waiting for the requesting admin's successful test sign-in through this connection. The test sign-in is not yet wired into the login flow, so a connection created from here cannot be activated until it is.</>
              : <>This connection was not created by a change request; an operator activates it.</>}
          </Callout>
        )}
        <div className="grid g2">
          <Fact label="Issuer">{c.issuer ?? "—"}</Fact>
          <Fact label="Default role for new users">{c.default_role}{c.jit_provisioning ? " (just-in-time)" : " (no auto-provisioning)"}</Fact>
          <Fact label="Verified domains">{c.verified_domains.join(", ") || "—"}</Fact>
          <Fact label="Updated">{when(c.updated_at)}</Fact>
        </div>
        {canRequest && (
          <div className="row">
            {c.status === "pending" && c.activation?.ready && (
              <Button variant="primary" icon={<Power size={14} />} disabled={busy} onClick={() => run(async () => { await adminChanges.activateConnection(c.id); return "Connection activated."; })}>Activate</Button>
            )}
            {c.status !== "disabled" && (
              <Button variant="danger" icon={<Ban size={14} />} disabled={busy} onClick={async () => {
                if ((await confirm({ title: `Disable ${c.name}?`, body: "Everyone who signed in through it is signed out at once. It is refused if this is the last active connection and no break-glass key exists.", confirmLabel: "Disable", danger: true })) === null) return;
                await run(async () => outcome(await adminChanges.submit("idp_connection.disable", { connection_id: c.id })));
              }}>Disable</Button>
            )}
          </div>
        )}
        <p className="xs faint" style={{ margin: 0 }}>To change what the connection trusts (issuer, client, signing certificates, group mapping), file an <i>idp_connection.update_trust</i> request under Change requests: it needs a second admin and 24 hours, and signs out everyone who came through it.</p>
      </div>
    </SidePanel>
  );
}

/** Request a new OIDC or SAML connection. The client secret is sealed by the server and never shown again. */
function NewConnection({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const toast = useToast();
  const [protocol, setProtocol] = useState<"oidc" | "saml">("oidc");
  const [f, setF] = useState({ name: "", profile: "okta", issuer: "", client_id: "", secret: "", entra: "", domains: "", entity: "", sso: "", cert: "" });
  const [busy, setBusy] = useState(false);
  const [errs, setErrs] = useState<FieldErrors>({});
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => { setF({ ...f, [k]: e.target.value }); if (k in errs) setErrs({ ...errs, [k as keyof FieldErrors]: undefined }); };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const local = protocol === "saml" ? checkSAMLFields(f.sso, f.cert) : {};
    setErrs(local);
    if (Object.keys(local).length) return;
    const domains = f.domains.split(/[\s,]+/).filter(Boolean);
    const common = { name: f.name.trim(), protocol, ...(domains.length ? { verified_domains: domains } : {}) };
    const payload = protocol === "oidc"
      ? { ...common, profile: f.profile, issuer: f.issuer.trim(), client_id: f.client_id.trim(), ...(f.profile === "entra" ? { entra_tenant_id: f.entra.trim() } : {}) }
      : { ...common, profile: "generic_saml", idp_entity_id: f.entity.trim(), idp_sso_url: f.sso.trim(), idp_signing_certs: [f.cert.trim()] };
    setBusy(true);
    try {
      toast(outcome(await adminChanges.submit("idp_connection.create", payload, protocol === "oidc" ? f.secret : undefined)));
      onDone();
    } catch (err) {
      const msg = errText(err);
      const field = serverFieldError(msg);
      if (field) setErrs({ [field.key]: field.text });
      else toast(msg, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const inv = (k: keyof FieldErrors) => ({ "aria-invalid": !!errs[k], "aria-describedby": errs[k] ? `idp-new-${k}-err` : undefined });
  const errLine = (k: keyof FieldErrors) => errs[k] && <span id={`idp-new-${k}-err`} className="err" role="alert">{errs[k]}</span>;
  return (
    <form className="card stack-sm" onSubmit={submit} aria-label="New connection request" autoComplete="off">
      <h2>New connection request</h2>
      <div className="row">
        <label className="field grow">Name<input className="input" required value={f.name} onChange={set("name")} /></label>
        <label className="field">Protocol
          <select className="input" value={protocol} onChange={(e) => { const p = e.target.value as "oidc" | "saml"; setProtocol(p); setF({ ...f, profile: p === "saml" ? "generic_saml" : "okta" }); }}>
            <option value="oidc">OpenID Connect</option>
            <option value="saml">SAML 2.0</option>
          </select>
        </label>
      </div>
      {protocol === "oidc" ? (
        <>
          <div className="row">
            <label className="field">Profile
              <select className="input" value={f.profile} onChange={set("profile")}>
                <option value="okta">Okta</option><option value="entra">Microsoft Entra ID</option><option value="google">Google</option><option value="generic_oidc">Generic OIDC</option>
              </select>
            </label>
            <label className="field grow">Issuer<input className="input sys" required placeholder="https://acme.okta.com" value={f.issuer} onChange={set("issuer")} /></label>
          </div>
          <div className="row">
            <label className="field grow">Client ID<input className="input sys" required value={f.client_id} onChange={set("client_id")} /></label>
            <label className="field grow">Client secret<input className="input sys" type="password" required autoComplete="new-password" value={f.secret} onChange={set("secret")} /></label>
            {f.profile === "entra" && <label className="field grow">Entra tenant ID<input className="input sys" required value={f.entra} onChange={set("entra")} /></label>}
          </div>
        </>
      ) : (
        <>
          <div className="row">
            <label className="field grow">IdP entity ID<input className="input sys" required value={f.entity} onChange={set("entity")} {...inv("entity")} />{errLine("entity")}</label>
            <label className="field grow">IdP sign-in URL<input className="input sys" required placeholder="https://idp.example.com/sso" value={f.sso} onChange={set("sso")} {...inv("sso")} />{errLine("sso")}</label>
          </div>
          <label className="field">IdP signing certificate (PEM)
            <textarea className="input sys" rows={5} required value={f.cert} onChange={set("cert")} spellCheck={false} placeholder={"-----BEGIN CERTIFICATE-----\nMIIC…\n-----END CERTIFICATE-----"} {...inv("cert")} />
            {errLine("cert") || <span className="xs faint">The token-signing certificate from your IdP's SAML metadata or admin console, including the BEGIN and END lines.</span>}
          </label>
        </>
      )}
      <label className="field">Verified domains (optional, comma separated)<input className="input" placeholder="acme.example" value={f.domains} onChange={set("domains")} /></label>
      <p className="small muted" style={{ margin: 0 }}>A second admin must approve this within 72 hours, then it waits 24 hours. It starts <b>pending</b>; after you sign in through it once as a test, you activate it. Groups from the IdP can never grant admin roles.</p>
      <div className="row">
        <Button type="submit" variant="primary" disabled={busy}>{busy ? "Submitting…" : "Submit request"}</Button>
        <Button onClick={onCancel}>Close</Button>
      </div>
    </form>
  );
}
