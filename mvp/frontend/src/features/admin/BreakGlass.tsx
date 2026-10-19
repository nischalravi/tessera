import { FormEvent, useEffect, useState } from "react";
import { Ban, KeyRound, Plus, ShieldAlert, UserPlus } from "lucide-react";
import { AdminIdpConnection, AdminUser, ApiError, BreakGlassEnrolment, BreakGlassKey, BreakGlassOverview, BreakGlassUse, adminChanges, breakGlass, relTime, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, DataTable, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { inBreakGlassSession, minutesLeft, sessionNotice } from "./breakGlassState";
import { Fact, errText, outcome, when } from "./common";
import { ceremonyMessage, registerKey, webauthnSupported } from "./webauthn";

/**
 * Break-glass (design §9.6, §15.4): the hardware keys that sign in when the identity provider is down
 * or compromised, the enrolments waiting for their key, and every use. Enrolling and revoking are
 * admin changes (enrolment: two admins and 24 hours); a break-glass session itself only sees the
 * actions it may take. The API enforces all of it.
 */
export function BreakGlass() {
  const { data, error, reload } = useApi<BreakGlassOverview>("/admin/break-glass");
  const { session, can } = useSession();
  const [selected, setSelected] = useSelected();
  const [enrolling, setEnrolling] = useState(false);
  const canRequest = can("admin.change.request");
  const glass = inBreakGlassSession(session);
  const key = data?.keys.find((k) => k.id === selected) ?? null;
  const active = (data?.keys ?? []).filter((k) => !k.revoked_at);
  return (
    <Page
      title="Break-glass"
      crumbs={[["Settings"], ["Admin", "/admin"], ["Break-glass"]]}
      sub="Hardware security keys that sign in when your identity provider is down or compromised. A break-glass session lasts 60 minutes, can only take a few emergency actions, and tells every admin and security contact the moment it starts."
    >
      <div className="stack">
        {data && !data.available && (
          <Callout tone="warn">Break-glass is not configured on this server: it needs the relying party id (TESSERA_RP_ID) and the public URL. Keys cannot be registered or used until it is.</Callout>
        )}
        {data && data.available && !glass && active.length < 2 && (
          <Callout tone="warn">
            {active.length === 0 ? "No break-glass key is registered." : "Only one break-glass key is registered."} Register at least two, held by different custodians in separate places, so that losing one
            does not lock you out when the identity provider fails.
          </Callout>
        )}
        {glass && <ActionsPanel />}
        {data && data.unanswered_uses > 0 && (
          <Callout tone="bad" icon={<ShieldAlert size={16} />}>
            {data.unanswered_uses === 1 ? "A break-glass sign-in has" : `${data.unanswered_uses} break-glass sign-ins have`} not been explained. Say why {data.unanswered_uses === 1 ? "it" : "they"} happened below.
          </Callout>
        )}
        {enrolling && <Enrol onDone={() => { setEnrolling(false); reload?.(); }} onCancel={() => setEnrolling(false)} existing={active} />}
        {(data?.open_enrolments ?? []).map((e) => <Registration key={e.change_request_id} e={e} me={session.user.id} onDone={() => reload?.()} />)}
        <section className="stack-sm" aria-label="Keys">
          <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>Keys</h2>
          <DataTable
            id="break-glass-keys"
            rows={data ? data.keys : null}
            error={error}
            rowKey={(k) => k.id}
            activeKey={selected}
            onRowClick={(k) => setSelected(k.id)}
            onRefresh={reload}
            rowLabel={(k) => k.label}
            commands={[canRequest && data?.available && { label: "Enrol a key", icon: <Plus size={14} />, onClick: () => setEnrolling(true) }]}
            columns={[
              { id: "label", header: "Key", sort: (k) => k.label, cell: (k) => <div><b>{k.label}</b><div className="xs faint">Held by {k.custodian}</div></div> },
              { id: "user", header: "Break-glass user", hideNarrow: true, sort: (k) => k.user, cell: (k) => <span className="small">{k.user}</span> },
              { id: "model", header: "Model (AAGUID)", hideNarrow: true, cell: (k) => <code className="xs">{k.aaguid}</code> },
              { id: "trust", header: "Attestation", hideNarrow: true, sort: (k) => k.attestation_trust, cell: (k) => <span className="small">{k.attestation_format} · {trust(k)}</span> },
              { id: "used", header: "Last used", sort: (k) => k.last_used_at ?? "", cell: (k) => <span className="small">{k.last_used_at ? relTime(k.last_used_at.replace("Z", "")) : "Never"}</span> },
              { id: "status", header: "Status", sort: (k) => (k.revoked_at ? 1 : 0), cell: (k) => (k.revoked_at ? <Badge tone="neutral" dot>Revoked</Badge> : <Badge tone="ok" dot>Active</Badge>) },
            ]}
            searchText={(k) => `${k.label} ${k.custodian} ${k.user} ${k.aaguid}`}
            searchPlaceholder="Search keys…"
            empty="No break-glass keys yet."
          />
          {data && (
            <p className="small faint" style={{ margin: 0 }}>
              Allowed authenticator models: {data.aaguid_allowlist.length === 0 ? "any hardware key that attests its model" : data.aaguid_allowlist.join(", ")}.
              Change the list with a <i>tenant.settings.update</i> request (<code>breakglass_aaguid_allowlist</code>) under Change requests; adding models needs a second admin and 24 hours.
            </p>
          )}
        </section>
        <Uses uses={data?.uses ?? null} canExplain={canRequest} onChanged={() => reload?.()} />
      </div>
      {key && <KeyPanel k={key} canRevoke={canRequest} onClose={() => setSelected(null)} onChanged={() => reload?.()} />}
    </Page>
  );
}

const trust = (k: BreakGlassKey) => ({ basic: "certificate signed", attca: "attestation CA", mds_verified: "MDS verified" })[k.attestation_trust];

/** The notice every page shows during a break-glass session (App.tsx): time left and what it may do. */
export function BreakGlassNotice() {
  const { session } = useSession();
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(t);
  }, []);
  if (!inBreakGlassSession(session)) return null;
  return (
    <section className="callout bad" role="status" aria-label="Break-glass session" style={{ marginBottom: 12 }}>
      <ShieldAlert size={16} aria-hidden />
      <div className="grow small">{sessionNotice(session, now)} {minutesLeft(session.session.absolute_expires_at, now) <= 5 && <b>Save what you need now.</b>}</div>
    </section>
  );
}

/** The request form: a new key for a new break-glass user, or another key for an existing one. */
function Enrol({ onDone, onCancel, existing }: { onDone: () => void; onCancel: () => void; existing: BreakGlassKey[] }) {
  const [label, setLabel] = useState("");
  const [custodian, setCustodian] = useState("");
  const [userId, setUserId] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const users = [...new Map(existing.map((k) => [k.user_id, k.user])).entries()];
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      toast(outcome(await adminChanges.submit("breakglass.register", { label, custodian, ...(userId ? { user_id: userId } : {}) })));
      onDone();
    } catch (err) {
      toast(errText(err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card stack-sm" onSubmit={submit} aria-label="Enrol a break-glass key">
      <h2 style={{ margin: 0 }}>Enrol a break-glass key</h2>
      <p className="small muted" style={{ margin: 0 }}>
        A second admin approves this request and it waits 24 hours; then you have 24 hours to plug the key in and register it here. The key must be a hardware key
        that attests its model and is not a synced passkey.
      </p>
      <div className="row">
        <label className="field grow">Label
          <input className="input" required maxLength={100} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Safe A, key 1" />
        </label>
        <label className="field grow">Custodian (who holds it)
          <input className="input" required maxLength={200} value={custodian} onChange={(e) => setCustodian(e.target.value)} placeholder="Facilities safe, Building 2" />
        </label>
      </div>
      {users.length > 0 && (
        <label className="field">For
          <select className="input" value={userId} onChange={(e) => setUserId(e.target.value)}>
            <option value="">A new break-glass user</option>
            {users.map(([id, name]) => <option key={id} value={id}>Another key for {name}</option>)}
          </select>
        </label>
      )}
      <div className="row">
        <Button type="submit" variant="primary" icon={<UserPlus size={14} />} disabled={busy}>{busy ? "Submitting…" : "Submit request"}</Button>
        <Button onClick={onCancel}>Close</Button>
      </div>
    </form>
  );
}

/** An approved enrolment waiting for its key: the requester registers it within the window. */
function Registration({ e, me, onDone }: { e: BreakGlassEnrolment; me: string; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const mine = e.requested_by.id === me;
  const run = async () => {
    setBusy(true);
    try {
      const options = await breakGlass.registrationOptions(e.change_request_id);
      const credential = await registerKey(options);
      const k = await breakGlass.registrationVerify(e.change_request_id, credential);
      toast(`Registered ${k.label}.`);
      onDone();
    } catch (err) {
      toast(err instanceof ApiError ? errText(err) : ceremonyMessage(err), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="card stack-sm" role="group" aria-label={`Register ${e.label}`}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div>
          <b>Register the key “{e.label}”</b>
          <div className="small muted">Held by {e.custodian}. Approved and applied; {mine ? "plug the key in and register it" : `${e.requested_by.display_name} registers it`} before {when(e.window_closes_at)}.</div>
        </div>
        {mine && (
          <Button variant="primary" icon={<KeyRound size={14} />} onClick={run} disabled={busy || !webauthnSupported()}>
            {busy ? "Waiting for the key…" : "Register the key"}
          </Button>
        )}
      </div>
      {mine && <p className="xs faint" style={{ margin: 0 }}>Needs a fresh passkey sign-in. The key must verify you with a PIN or fingerprint, and must not be a synced passkey.</p>}
    </div>
  );
}

/** Every sign-in of the last 30 days and every one nobody has explained, with the form to explain. */
function Uses({ uses, canExplain, onChanged }: { uses: BreakGlassUse[] | null; canExplain: boolean; onChanged: () => void }) {
  const confirm = useConfirm();
  const toast = useToast();
  const explain = async (u: BreakGlassUse) => {
    const reason = await confirm({
      title: "Why was break-glass used?",
      body: <>The key “{u.key}” signed in on {when(u.used_at)}. Say what happened (an incident number, who needed access and why). This is recorded in the audit log.</>,
      confirmLabel: "Record the reason",
      reason: { label: "Reason (at least 10 characters)", required: true, placeholder: "Okta outage, ticket INC-4821: the on-call admin needed to disable the connection" },
    });
    if (reason === null) return;
    try {
      await breakGlass.attest(u.id, reason);
      toast("Recorded.");
      onChanged();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };
  return (
    <section className="stack-sm" aria-label="Uses">
      <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>Sign-ins</h2>
      <DataTable
        id="break-glass-uses"
        rows={uses}
        rowKey={(u) => u.id}
        rowLabel={(u) => `Sign-in at ${u.used_at}`}
        initialSort={["when", -1]}
        columns={[
          { id: "when", header: "When", sort: (u) => u.used_at, cell: (u) => <span className="small">{when(u.used_at)}</span> },
          { id: "key", header: "Key", sort: (u) => u.key, cell: (u) => <b>{u.key}</b> },
          { id: "ip", header: "From", hideNarrow: true, cell: (u) => <span className="small">{u.ip ?? "unknown"}</span> },
          { id: "why", header: "Why", cell: (u) => (u.answered
            ? <div className="small">{u.reason}<div className="xs faint">{u.answered_by?.display_name} · {when(u.answered_at)}</div></div>
            : <div className="row tight"><Badge tone="critical" dot>Not explained</Badge>{canExplain && <Button size="sm" onClick={() => explain(u)}>Explain</Button>}</div>) },
        ]}
        searchText={(u) => `${u.key} ${u.reason ?? ""} ${u.ip ?? ""}`}
        searchPlaceholder="Search sign-ins…"
        empty="No break-glass sign-ins in the last 30 days."
      />
    </section>
  );
}

/** The side panel of one key. */
function KeyPanel({ k, canRevoke, onClose, onChanged }: { k: BreakGlassKey; canRevoke: boolean; onClose: () => void; onChanged: () => void }) {
  const confirm = useConfirm();
  const toast = useToast();
  const revoke = async () => {
    const ok = await confirm({
      title: `Revoke ${k.label}?`,
      body: "The key can no longer sign in, and its sessions end at once. This needs only one admin and takes effect immediately. Register another key first if this is the last one.",
      confirmLabel: "Revoke the key",
      danger: true,
    });
    if (ok === null) return;
    try {
      toast(outcome(await adminChanges.submit("breakglass.revoke", { credential_id: k.id })));
      onChanged();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };
  return (
    <SidePanel
      title={k.label}
      sub={k.revoked_at ? <Badge tone="neutral" dot>Revoked</Badge> : <Badge tone="ok" dot>Active</Badge>}
      onClose={onClose}
      commands={
        <div className="cmdbar" role="toolbar" aria-label="Key actions">
          {canRevoke && !k.revoked_at && <Button size="sm" variant="danger" icon={<Ban size={13} />} onClick={revoke}>Revoke</Button>}
        </div>
      }
    >
      <div className="stack">
        <div className="grid g2">
          <Fact label="Held by">{k.custodian}</Fact>
          <Fact label="Break-glass user">{k.user}</Fact>
          <Fact label="Registered">{when(k.created_at)}</Fact>
          <Fact label="Last used">{k.last_used_at ? when(k.last_used_at) : "Never"}</Fact>
          <Fact label="Model (AAGUID)"><code className="xs">{k.aaguid}</code></Fact>
          <Fact label="Attestation">{k.attestation_format}, {trust(k)}</Fact>
          <Fact label="Transports">{k.transports.length ? k.transports.join(", ") : "Not reported"}</Fact>
          <Fact label="Backup eligible">No (synced passkeys are refused)</Fact>
        </div>
        {k.revoked_at && <Callout tone="neutral">Revoked {when(k.revoked_at)}.</Callout>}
      </div>
    </SidePanel>
  );
}

/** What a break-glass session may do (§15.4). Each change waits one hour; any admin can cancel it. */
function ActionsPanel() {
  const conns = useApi<{ connections: AdminIdpConnection[] }>("/admin/idp-connections");
  const users = useApi<{ users: AdminUser[] }>("/admin/users");
  const confirm = useConfirm();
  const toast = useToast();
  const [connection, setConnection] = useState("");
  const [user, setUser] = useState("");
  const [trustJson, setTrustJson] = useState('{\n  "assume_phishing_resistant": false\n}');
  const [busy, setBusy] = useState(false);
  const run = async (title: string, body: string, f: () => Promise<{ change_request?: { effective_at: string | null }; revoked_sessions: number }>, danger = true) => {
    if ((await confirm({ title, body, confirmLabel: "Do it", danger })) === null) return;
    setBusy(true);
    try {
      const r = await f();
      toast(r.change_request ? `Filed. It takes effect ${when(r.change_request.effective_at)}; any admin can cancel it until then.` : `Done: ${r.revoked_sessions} other session${r.revoked_sessions === 1 ? "" : "s"} ended.`);
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const connName = conns.data?.connections.find((c) => c.id === connection)?.name ?? "";
  const userName = users.data?.users.find((u) => u.id === user)?.display_name ?? "";
  return (
    <section className="card stack" aria-label="Break-glass actions">
      <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>What this session can do</h2>
      <p className="small muted" style={{ margin: 0 }}>
        Disabling a connection, changing its trust and granting tenant_admin each wait one hour before they take effect, with no second approver; every admin and security contact is told and can cancel.
        Revoking other sessions is immediate. Everything else is refused.
      </p>
      <div className="stack-sm">
        <label className="field">IdP connection
          <select className="input" value={connection} onChange={(e) => setConnection(e.target.value)}>
            <option value="">Choose a connection…</option>
            {(conns.data?.connections ?? []).map((c) => <option key={c.id} value={c.id}>{c.name} ({c.status})</option>)}
          </select>
        </label>
        <div className="row">
          <Button disabled={busy || !connection} onClick={() => run(`Disable ${connName}?`, "Everyone who signed in through it is signed out when it takes effect, in one hour.",
            () => breakGlass.action("idp_connection.disable", { connection_id: connection }))}>Disable the connection</Button>
        </div>
        <label className="field">Trust changes for the connection (JSON, for example a corrected issuer)
          <textarea className="input sys" rows={3} value={trustJson} onChange={(e) => setTrustJson(e.target.value)} spellCheck={false} />
        </label>
        <div className="row">
          <Button disabled={busy || !connection} onClick={() => {
            let payload: Record<string, unknown>;
            try { payload = { ...JSON.parse(trustJson), connection_id: connection }; } catch { toast("The trust changes are not valid JSON.", { kind: "error" }); return; }
            return run(`Change the trust settings of ${connName}?`, "It signs out everyone who came through the connection when it takes effect, in one hour.",
              () => breakGlass.action("idp_connection.update_trust", payload));
          }}>Change its trust settings</Button>
        </div>
      </div>
      <div className="stack-sm">
        <label className="field">Grant tenant_admin to
          <select className="input" value={user} onChange={(e) => setUser(e.target.value)}>
            <option value="">Choose a user…</option>
            {(users.data?.users ?? []).filter((u) => u.status === "active" && !u.is_break_glass).map((u) => <option key={u.id} value={u.id}>{u.display_name}{u.email ? ` (${u.email})` : ""}</option>)}
          </select>
        </label>
        <div className="row">
          <Button disabled={busy || !user} onClick={() => run(`Make ${userName} a tenant admin?`, "They become an admin in one hour, unless an admin cancels it.",
            () => breakGlass.action("role.grant", { user_id: user, role: "tenant_admin" }))}>Grant tenant_admin</Button>
        </div>
      </div>
      <div className="row">
        <Button variant="danger" disabled={busy} onClick={() => run("Revoke every other session?", "Everyone else is signed out at once, in every browser and the CLI. This session stays.",
          () => breakGlass.action("sessions.revoke_all"))}>Revoke all other sessions</Button>
      </div>
    </section>
  );
}
