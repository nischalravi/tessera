/**
 * Protection > OAuth apps (issue #107): the third-party apps and grants users and admins authorized in Google
 * Workspace, Microsoft Entra ID, Salesforce and GitHub, each with a scope risk score. Revoking a grant, an
 * app or every app of a breached vendor calls the provider and re-reads it; revokes that cover several grants
 * of a high-risk app need a second admin. Hiding buttons with can(...) is for usability only: the API enforces
 * the permission and a fresh phishing-resistant sign-in.
 */
import { FormEvent, useId, useRef, useState } from "react";
import { Ban, KeyRound, RefreshCw, ShieldAlert } from "lucide-react";
import { ApiError, OAuthApp, OAuthAppList, OAuthChange, OAuthCredential, OAuthGrant, OAuthRevokeReport, OAuthRevokeResult, OAuthSeverity, fmtDate, isPendingRevoke, oauthApps, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Column, DataTable, EmptyState, Page, SidePanel, Tone, useSelected, useToast } from "../../components";
import { useModal } from "../../components/overlay";

const SEV_TONE: Record<OAuthSeverity, Tone> = { critical: "critical", high: "critical", medium: "warning", low: "neutral", none: "outline" };
const PROVIDER: Record<string, string> = { google: "Google Workspace", entra: "Microsoft Entra ID", salesforce: "Salesforce", github: "GitHub" };
const FLAG: Record<string, string> = { high_risk_non_admin: "High-risk scope by a non-admin", unused: "Unused", unverified: "Unverified publisher" };
const OUTCOME: Record<string, Tone> = { revoked: "ok", failed: "critical", manual: "warning", skipped: "neutral" };

const SevBadge = ({ s }: { s: OAuthSeverity }) => <Badge tone={SEV_TONE[s]}>{s === "none" ? "None" : s[0].toUpperCase() + s.slice(1)}</Badge>;

const cols: Column<OAuthApp>[] = [
  { id: "name", header: "App", sort: (a) => a.name, cell: (a) => <span className="name-link">{a.name}</span> },
  { id: "provider", header: "Provider", sort: (a) => a.provider, cell: (a) => <span className="small">{PROVIDER[a.provider]}</span>, hideNarrow: true },
  { id: "publisher", header: "Publisher", sort: (a) => a.publisher, cell: (a) => <span className="small">{a.publisher || <span className="faint">-</span>}</span>, hideNarrow: true },
  { id: "risk", header: "Risk", sort: (a) => a.risk_score, csv: (a) => String(a.risk_score), cell: (a) => <><SevBadge s={a.severity} /> <span className="small muted">{a.risk_score}</span></> },
  { id: "grants", header: "Grants", sort: (a) => a.grants, cell: (a) => <span className="small">{a.grants}</span> },
  { id: "flags", header: "Flags", csv: (a) => a.flags.join(" "), cell: (a) => <span className="small">{a.flags.map((f) => FLAG[f]).join(", ") || <span className="faint">-</span>}</span>, hideNarrow: true },
  { id: "owner", header: "Owner", sort: (a) => a.owner?.name ?? "", cell: (a) => <span className="small">{a.owner?.name ?? <span className="faint">None</span>}</span>, hideNarrow: true },
  { id: "used", header: "Last used", sort: (a) => a.last_used ?? "", csv: (a) => a.last_used ?? "", cell: (a) => <span className="small nowrap">{a.last_used ? fmtDate(a.last_used) : <span className="faint">Unknown</span>}</span>, hideNarrow: true },
];

function ReportView({ report }: { report: OAuthRevokeReport }) {
  return (
    <div className="mt">
      <Callout tone={report.ok ? "ok" : "bad"}>
        {report.revoked} of {report.total} grants revoked and verified by a re-read at the provider.
        {report.failed > 0 && ` ${report.failed} failed.`}
        {report.manual > 0 && ` ${report.manual} need a person.`}
        {report.skipped > 0 && ` ${report.skipped} were not attempted: run the revoke again.`}
      </Callout>
      <ul className="steps mt" aria-label="Revoke results">
        {report.items.map((i) => (
          <li key={i.grant_id} className="step">
            <span className="act"><Badge tone={OUTCOME[i.outcome]}>{i.outcome}</Badge></span>
            <span className="small grow">{i.app}{i.user && ` · ${i.user}`}{i.detail && <span className="muted"> ({i.detail})</span>}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

interface RevokeTarget { title: string; blurb: string; run: (reason: string) => Promise<OAuthRevokeResult> }

/** Asks for a reason, runs the revoke and shows the report, or the pending second-admin request. */
function RevokeDialog({ target, onClose, onDone }: { target: RevokeTarget; onClose: () => void; onDone: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<OAuthRevokeResult | null>(null);
  useModal(ref, onClose);
  const ready = reason.trim().length >= 10 && !busy && !result;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await target.run(reason.trim()));
    } catch (err: any) {
      setError(String(err.message ?? err));
      if (err instanceof ApiError && err.body?.report?.items) setResult(err.body.report);
    } finally {
      setBusy(false);
      onDone();
    }
  };
  return (
    <div className="dialog-wrap">
      <div className="overlay" onClick={onClose} aria-hidden />
      <div ref={ref} className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <form onSubmit={submit}>
          <div className="dlg-b">
            <h2 id={titleId}>{target.title}</h2>
            <p className="muted">{target.blurb}</p>
            {!result && (
              <label className="field mt">
                Reason
                <textarea className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} placeholder="For example: vendor breach notice, ticket SEC-1234" />
                <span className="small muted">At least 10 characters. It goes in the audit log.</span>
              </label>
            )}
            {error && <div className="mt"><Callout tone="bad">{error}</Callout></div>}
            {result && isPendingRevoke(result) && (
              <div className="mt"><Callout tone="warn">
                Recorded. This revoke covers {result.grants} grants, so a second admin must make the same request before it runs (until {fmtDate(result.expires_at)}).
              </Callout></div>
            )}
            {result && !isPendingRevoke(result) && <ReportView report={result} />}
          </div>
          <div className="dlg-f">
            <Button onClick={onClose}>{result ? "Close" : "Cancel"}</Button>
            {!result && <Button type="submit" variant="danger-solid" disabled={!ready}>{busy ? "Revoking…" : "Revoke"}</Button>}
          </div>
        </form>
      </div>
    </div>
  );
}

function GrantRow({ g, canRevoke, onRevoke }: { g: OAuthGrant; canRevoke: boolean; onRevoke: () => void }) {
  const live = g.status === "active" || g.status === "revoke_failed";
  return (
    <li className="step">
      <span className="act"><Badge tone={g.status === "active" ? "ok" : g.status === "revoke_failed" ? "critical" : "neutral"}>{g.status.replace("_", " ")}</Badge></span>
      <span className="small grow">
        {g.identity?.name ?? (g.user || "Tenant-wide")} · {g.consent_type === "admin" ? "admin consent" : "user consent"}{g.granter_admin && " · administrator"}
        <br />
        {g.scopes.length === 0 && <span className="faint">No scopes reported</span>}
        {g.scopes.map((s) => <span key={s.scope} title={s.reason}><Badge tone={SEV_TONE[s.severity]}>{s.scope}</Badge>{" "}</span>)}
        {g.revoke_error && <><br /><span className="muted">{g.revoke_error}</span></>}
      </span>
      {live && canRevoke && <Button size="sm" variant="danger" onClick={onRevoke} aria-label={`Revoke grant of ${g.user || "tenant-wide"}`}>Revoke</Button>}
    </li>
  );
}

const CHANGE: Record<OAuthChange["kind"], string> = { credential_added: "Credential added", permission_granted: "Permission granted", owner_changed: "Owner changed" };

/** What a sync found added to the app since the last one, with the containment for each (issue #474). */
function ChangeRow({ c, canRevoke, canManage, onRemove, onRevoke, onAck }: {
  c: OAuthChange; canRevoke: boolean; canManage: boolean; onRemove: () => void; onRevoke: () => void; onAck: () => void;
}) {
  return (
    <li className="step">
      <span className="act"><Badge tone={c.status === "open" ? "critical" : "neutral"}>{CHANGE[c.kind]}</Badge></span>
      <span className="small grow">
        {c.summary}
        <br /><span className="muted">Detected {fmtDate(c.detected_at)}{c.status === "resolved" && c.resolution ? `, closed: ${c.resolution}` : ""}</span>
      </span>
      {c.status === "open" && c.credential_id && canRevoke && <Button size="sm" variant="danger" onClick={onRemove} aria-label={`Remove the credential: ${c.summary}`}>Remove credential</Button>}
      {c.status === "open" && c.grant_id && canRevoke && <Button size="sm" variant="danger" onClick={onRevoke} aria-label={`Revoke the permission: ${c.summary}`}>Revoke grant</Button>}
      {c.status === "open" && c.kind === "owner_changed" && canManage && <Button size="sm" onClick={onAck} aria-label={`Acknowledge: ${c.summary}`}>Acknowledge</Button>}
    </li>
  );
}

function AppPanel({ id, onClose, reload }: { id: string; onClose: () => void; reload: () => void }) {
  const { data, reload: reloadOne } = useApi<{ app: OAuthApp; grants: OAuthGrant[]; credentials: OAuthCredential[]; changes: OAuthChange[] }>(oauthApps.detailPath(id));
  const { can } = useSession();
  const toast = useToast();
  const canRevoke = can("oauthapps.revoke");
  const canManage = can("oauthapps.manage");
  const [dlg, setDlg] = useState<RevokeTarget | null>(null);
  const app = data?.app;
  const done = () => { reload(); reloadOne(); };
  const ack = async (c: OAuthChange) => {
    try {
      await oauthApps.resolveChange(id, c.id, "");
      toast("Change acknowledged", { kind: "ok" });
      done();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    }
  };
  const removeCredential = (credentialId: string, label: string) => setDlg({
    title: "Remove credential",
    blurb: `Removes the credential "${label}" from ${app?.name} at ${app ? PROVIDER[app.provider] : "the provider"}, then re-reads the provider to check. A certificate cannot be removed through the API and is a manual task.`,
    run: (reason) => oauthApps.removeCredential(id, credentialId, reason),
  });
  const revokeGrant = (grantId: string) => setDlg({
    title: "Revoke grant",
    blurb: `Revokes this grant of ${app?.name} at ${app ? PROVIDER[app.provider] : "the provider"}, then re-reads the provider to check.`,
    run: (reason) => oauthApps.revokeGrant(id, grantId, reason),
  });
  return (
    <SidePanel title={app?.name ?? "OAuth app"} onClose={onClose}
      sub={app && <><SevBadge s={app.severity} /><span className="small muted">{PROVIDER[app.provider]}</span></>}>
      {!app && <p className="muted">Loading…</p>}
      {app && data && (
        <>
          <dl className="kv">
            <dt>Publisher</dt><dd>{app.publisher || "Not reported"}{app.verified ? " (verified)" : " (unverified)"}</dd>
            <dt>Risk score</dt><dd>{app.risk_score} of 100</dd>
            <dt>Owner</dt><dd>{app.owner?.name ?? "No owner"}</dd>
            <dt>Client id</dt><dd className="small">{app.client_id}</dd>
            <dt>Last used</dt><dd>{app.last_used ? fmtDate(app.last_used) : "Not reported by the provider"}</dd>
            <dt>First seen</dt><dd>{fmtDate(app.first_seen)}</dd>
          </dl>
          {app.risk_reasons.length > 0 && (<><h3 className="mt">Why this score</h3><ul className="small">{app.risk_reasons.map((r) => <li key={r}>{r}</li>)}</ul></>)}
          {app.flags.length > 0 && <p className="mt">{app.flags.map((f) => <Badge key={f} tone="warning">{FLAG[f]}</Badge>)}</p>}
          {canRevoke && app.grants > 0 && (
            <p className="mt">
              <Button variant="danger" icon={<Ban size={14} />} onClick={() => setDlg({
                title: `Revoke ${app.name}`,
                blurb: `Revokes all ${app.grants} live grants of this app at ${PROVIDER[app.provider]}, then re-reads the provider to check. More than one grant of a high-risk app needs a second admin.`,
                run: (reason) => oauthApps.revokeApp(app.id, reason),
              })}>Revoke app</Button>{" "}
              <Button variant="danger" icon={<ShieldAlert size={14} />} onClick={() => setDlg({
                title: `Vendor breached: ${app.publisher || app.name}`,
                blurb: `Revokes every grant of every app published by, or named, ${app.publisher || app.name}, across all providers. It needs a second admin when any of those apps holds a high-risk scope.`,
                run: (reason) => oauthApps.revokeVendor(app.publisher || app.name, reason),
              })}>Vendor breached</Button>
            </p>
          )}
          {data.changes.length > 0 && (
            <>
              <h3 className="mt">Detected changes ({data.changes.filter((c) => c.status === "open").length} open)</h3>
              <ul className="steps" aria-label="Detected changes">
                {data.changes.map((c) => (
                  <ChangeRow key={c.id} c={c} canRevoke={canRevoke} canManage={canManage} onAck={() => ack(c)}
                    onRemove={() => c.credential_id && removeCredential(c.credential_id, c.summary)}
                    onRevoke={() => c.grant_id && revokeGrant(c.grant_id)} />
                ))}
              </ul>
            </>
          )}
          {data.credentials.some((c) => c.status === "active") && (
            <>
              <h3 className="mt">Credentials ({data.credentials.filter((c) => c.status === "active").length})</h3>
              <ul className="steps" aria-label="Credentials">
                {data.credentials.filter((c) => c.status === "active").map((c) => (
                  <li key={c.id} className="step">
                    <span className="act"><Badge tone="neutral">{c.kind}</Badge></span>
                    <span className="small grow">{c.label}{c.added_at && <span className="muted"> · added {fmtDate(c.added_at)}</span>}</span>
                    {canRevoke && <Button size="sm" variant="danger" onClick={() => removeCredential(c.id, c.label)} aria-label={`Remove credential ${c.label}`}>Remove</Button>}
                  </li>
                ))}
              </ul>
            </>
          )}
          <h3 className="mt">Grants ({data.grants.length})</h3>
          <ul className="steps" aria-label="Grants">
            {data.grants.map((g) => (
              <GrantRow key={g.id} g={g} canRevoke={canRevoke} onRevoke={() => revokeGrant(g.id)} />
            ))}
          </ul>
        </>
      )}
      {dlg && <RevokeDialog target={dlg} onClose={() => setDlg(null)} onDone={done} />}
    </SidePanel>
  );
}

export function OAuthApps() {
  const [selected, setSelected] = useSelected();
  const { data, error, reload } = useApi<OAuthAppList>(`${oauthApps.listPath}?status=all`);
  const { can } = useSession();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const sync = async () => {
    setBusy(true);
    try {
      const r = await oauthApps.sync();
      const failed = r.providers.filter((p) => p.status === "failed");
      toast(failed.length ? `Sync failed for ${failed.map((p) => PROVIDER[p.provider]).join(", ")}` : "Inventory refreshed", { kind: failed.length ? "error" : "ok" });
      reload();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  const s = data?.summary;
  return (
    <Page title="OAuth apps" crumbs={[["Protection"], ["OAuth apps"]]}
      sub="Third-party apps and the grants they hold in Google Workspace, Microsoft Entra ID, Salesforce and GitHub, scored by the scopes they were given.">
      {s && <p className="small muted">{s.apps} apps, {s.grants} live grants, {s.high_risk} high risk, {s.high_risk_non_admin} with a high-risk scope granted by a non-admin, {s.unused} unused for {data?.unused_days} days or more.</p>}
      {data?.sync.filter((x) => x.status === "failed").map((x) => <Callout key={x.provider} tone="bad">Last sync of {PROVIDER[x.provider]} failed: {x.error}. The inventory shown is from the last good sync.</Callout>)}
      {(data?.changes.length ?? 0) > 0 && (
        <Callout tone="bad">
          <KeyRound size={14} aria-hidden /> {data?.changes.length} change(s) detected since the last sync: select the app to see them and contain them.
          <ul className="small">
            {data?.changes.slice(0, 5).map((c) => <li key={c.id}><button type="button" className="linklike" onClick={() => setSelected(c.app_id)}>{c.summary}</button></li>)}
          </ul>
        </Callout>
      )}
      {(data?.pending_requests.length ?? 0) > 0 && <Callout tone="warn">{data?.pending_requests.length} revoke request(s) wait for a second admin: repeat the same revoke to approve.</Callout>}
      <DataTable
        id="oauth-apps"
        rows={data?.apps ?? null}
        error={error}
        rowKey={(a) => a.id}
        columns={cols}
        initialSort={["risk", 1]}
        searchText={(a) => `${a.name} ${a.publisher} ${a.client_id}`}
        searchPlaceholder="Search apps or publishers…"
        filters={[
          { id: "provider", label: "Provider", options: Object.entries(PROVIDER).map(([value, label]) => ({ value, label })), get: (a) => a.provider },
          { id: "severity", label: "Risk", options: ["critical", "high", "medium", "low"].map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) })), get: (a) => a.severity },
          { id: "status", label: "Status", options: [{ value: "active", label: "Active" }, { value: "revoked", label: "Revoked" }, { value: "removed", label: "Gone at the provider" }], get: (a) => a.status },
          { id: "flag", label: "Flag", options: Object.entries(FLAG).map(([value, label]) => ({ value, label })), get: (a) => a.flags.join(" ") },
        ]}
        commands={[can("oauthapps.manage") && { label: busy ? "Syncing…" : "Sync now", icon: <RefreshCw size={16} />, onClick: sync, title: "Read every connected provider now (a background job also does this hourly)" }]}
        onRefresh={reload}
        rowLabel={(a) => a.name}
        onRowClick={(a) => setSelected(a.id)}
        activeKey={selected}
        empty={<EmptyState title="No OAuth apps yet" icon={<ShieldAlert size={18} />}>Connect Google Workspace, Entra ID, Salesforce or GitHub and set a containment credential on the connection; the inventory fills on the next sync.</EmptyState>}
      />
      {selected && <AppPanel id={selected} onClose={() => setSelected(null)} reload={reload} />}
    </Page>
  );
}
