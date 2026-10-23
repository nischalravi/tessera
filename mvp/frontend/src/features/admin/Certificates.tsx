import { FormEvent, useState } from "react";
import { FileBadge, RefreshCw, Upload } from "lucide-react";
import { CertificateEntry, CertificateUpload, Connection, PURPOSE_LABEL, certificatesApi, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Drawer, EmptyState, Loading, useConfirm, useToast } from "../../components";
import { Fact, errText } from "./common";

/**
 * Certificates: every certificate and key Tessera holds (the SP key of each SAML connection, uploaded and
 * rotating certificates, signing keys, directory agent keys), with where each is used and when it expires.
 * Private keys are sealed on upload and never shown again. A SAML SP key is rotated through an overlap window:
 * a new key is published in the SP metadata beside the active one, then promoted, which retires the old one.
 * A daily job raises an alert 30 and 7 days before a certificate expires.
 */

const STATUS_TONE: Record<CertificateEntry["status"], "ok" | "info" | "neutral"> = { active: "ok", next: "info", retired: "neutral" };
const STATUS_LABEL: Record<CertificateEntry["status"], string> = { active: "Active", next: "Waiting to be promoted", retired: "Retired" };

const day = (s: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "—");

/** The expiry column: the date, and a badge when it is near or past. */
function Expiry({ c }: { c: CertificateEntry }) {
  if (!c.not_after) return <span className="faint small">No expiry recorded</span>;
  const left = c.days_left ?? 0;
  const warn = c.status !== "retired" && c.expiry_warning > 0;
  return (
    <div>
      <div className="small nowrap">{day(c.not_after)}</div>
      {warn ? (
        <Badge tone={left <= 7 ? "critical" : "warning"}>{left < 0 ? `Expired ${-left} days ago` : left === 0 ? "Expires today" : `${left} days left`}</Badge>
      ) : (
        <span className="xs faint">{c.status === "retired" ? "Retired" : `${left} days left`}</span>
      )}
    </div>
  );
}

export function Certificates() {
  const { data, error, reload } = useApi<CertificateEntry[]>("/admin/certificates");
  const { can } = useSession();
  const manage = can("connections.manage");
  const toast = useToast();
  const confirm = useConfirm();
  const [upload, setUpload] = useState<{ purpose?: CertificateUpload["purpose"]; connection?: string } | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  if (!data) return <div className="card flush"><Loading error={error} /></div>;
  const saml = data.filter((c) => c.source === "saml_connection");
  const expiring = data.filter((c) => c.status !== "retired" && c.expiry_warning > 0);
  const shown = data.find((c) => c.id === open) ?? null;

  const act = async (what: string, fn: () => Promise<unknown>) => {
    try {
      await fn();
      toast(what);
      setOpen(null);
      reload();
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };
  const rotate = async (c: CertificateEntry) => {
    if (!c.connection_id) return;
    const ok = await confirm({
      title: `Generate a new SP key for ${c.label.replace(/ SP signing$/, "")}?`,
      body: "The new certificate is published in the SP metadata beside the current one, so you can add it at the identity provider before anything changes. Sign-ins keep using the current key until you promote the new one.",
      confirmLabel: "Generate",
    });
    if (ok === null) return;
    await act("New SP key generated and published beside the active one", () => certificatesApi.generate(c.connection_id!));
  };
  const promote = async (c: CertificateEntry) => {
    const ok = await confirm({
      title: "Promote this SP certificate?",
      body: "Tessera starts signing with it and the current certificate is retired. Make sure the identity provider trusts the new certificate first: it was published in the SP metadata while it waited.",
      confirmLabel: "Promote",
    });
    if (ok === null) return;
    await act("Promoted: the old certificate is retired", () => certificatesApi.promote(c.id));
  };
  const retire = async (c: CertificateEntry) => {
    const ok = await confirm({
      title: c.status === "next" ? "Discard this waiting certificate?" : "Retire this certificate?",
      body: "Its stored private key is destroyed. The certificate stays in the list as a record.",
      confirmLabel: c.status === "next" ? "Discard" : "Retire",
      danger: true,
    });
    if (ok === null) return;
    await act("Retired", () => certificatesApi.retire(c.id));
  };

  return (
    <div className="stack">
      {manage && (
        <div className="row">
          <Button variant="primary" icon={<Upload size={15} />} onClick={() => setUpload({})}>Upload certificate</Button>
        </div>
      )}
      {expiring.length > 0 && (
        <Callout tone={expiring.some((c) => (c.days_left ?? 0) <= 7) ? "bad" : "warn"}>
          <b>{expiring.length === 1 ? "1 certificate expires" : `${expiring.length} certificates expire`} within 30 days.</b>{" "}
          {expiring.slice(0, 3).map((c) => c.label).join(", ")}{expiring.length > 3 ? ` and ${expiring.length - 3} more` : ""}. An alert is raised 30 and 7 days before expiry.
        </Callout>
      )}
      {data.length === 0 ? (
        <div className="card"><EmptyState title="No certificates" icon={<FileBadge size={18} />}>SAML service-provider keys, uploaded certificates and signing keys appear here.</EmptyState></div>
      ) : (
        <div className="card flush">
          <div className="table-scroll">
            <table>
              <caption className="sr-only">Certificates and keys Tessera holds</caption>
              <thead><tr><th scope="col">Certificate</th><th scope="col">Expires</th><th scope="col" className="hide-narrow">Used by</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {data.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <b>{c.label}</b>{" "}
                      <Badge tone={STATUS_TONE[c.status]}>{STATUS_LABEL[c.status]}</Badge>
                      <div className="xs faint">{PURPOSE_LABEL[c.purpose]} · {c.key_algorithm}</div>
                      <div className="xs faint sys truncate" title={c.fingerprint_sha256}>SHA-256 {c.fingerprint_sha256.slice(0, 16)}…</div>
                    </td>
                    <td><Expiry c={c} /></td>
                    <td className="small hide-narrow">{c.used_by}</td>
                    <td className="actions-cell"><Button size="sm" variant="ghost" onClick={() => setOpen(c.id)} aria-label={`Details of ${c.label}`}>Details</Button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <p className="small muted">
        Private keys are encrypted at rest under the platform key and are never returned by any call. An upload must be PEM, hold a key that matches the certificate, not be expired,
        use RSA of at least 2048 bits (or P-256 and up) and not be signed with SHA-1. Changes need a recent strong sign-in and are written to the audit log.
      </p>

      {shown && (
        <Drawer title={shown.label} sub={`${PURPOSE_LABEL[shown.purpose]} · ${STATUS_LABEL[shown.status]}`} onClose={() => setOpen(null)}>
          <div className="stack">
            <Fact label="Used by">{shown.used_by}</Fact>
            <Fact label="Subject">{shown.subject || "—"}</Fact>
            {shown.issuer && <Fact label="Issuer">{shown.issuer}</Fact>}
            {shown.sans.length > 0 && <Fact label="Subject alternative names">{shown.sans.join(", ")}</Fact>}
            <Fact label="Valid">{shown.not_before ? `${day(shown.not_before)} to ${day(shown.not_after)}` : "No validity period (a key, not a certificate)"}</Fact>
            <Fact label="Fingerprint (SHA-256)"><code className="sys" style={{ wordBreak: "break-all" }}>{shown.fingerprint_sha256}</code></Fact>
            <Fact label="Key">{shown.key_algorithm}{shown.signature_algorithm ? ` · signed ${shown.signature_algorithm}` : ""}</Fact>
            {shown.purpose === "mtls_client" && shown.chain_length > 0 && (
              <>
                <Fact label="Chain presented">{shown.chain_length === 1 ? "The certificate alone" : `The certificate and ${shown.chain_length - 1} intermediate${shown.chain_length === 2 ? "" : "s"}`}</Fact>
                <Fact label="Trust anchors">{shown.trust_anchors.length === 0 ? "None: the target's certificate is checked against the system roots" : shown.trust_anchors.join("; ")}</Fact>
              </>
            )}
            {manage && (
              <div className="row">
                {shown.source === "saml_connection" && shown.connection_id && (
                  <>
                    <Button icon={<RefreshCw size={14} />} onClick={() => rotate(shown)}>Generate new SP key</Button>
                    <Button onClick={() => { setOpen(null); setUpload({ purpose: "saml_sp", connection: shown.connection_id! }); }}>Upload a replacement</Button>
                  </>
                )}
                {shown.can_promote && <Button variant="primary" onClick={() => promote(shown)}>Promote</Button>}
                {shown.can_retire && <Button variant="danger" onClick={() => retire(shown)}>{shown.status === "next" ? "Discard" : "Retire"}</Button>}
              </div>
            )}
            {shown.status === "next" && <Callout tone="info">This certificate is in the SP metadata now. Add it at the identity provider, then promote it.</Callout>}
          </div>
        </Drawer>
      )}
      {upload && (
        <UploadForm
          saml={saml}
          start={upload}
          onClose={() => setUpload(null)}
          onSaved={() => { setUpload(null); toast("Certificate stored; its key is sealed"); reload(); }}
        />
      )}
    </div>
  );
}

function UploadForm({ saml, start, onClose, onSaved }: { saml: CertificateEntry[]; start: { purpose?: CertificateUpload["purpose"]; connection?: string }; onClose: () => void; onSaved: () => void }) {
  const connectors = useApi<Connection[]>("/connections");
  const [f, setF] = useState({
    purpose: (start.purpose ?? "mtls_client") as CertificateUpload["purpose"], label: "", cert: "", key: "", anchors: "",
    saml: start.connection ?? saml[0]?.connection_id ?? "", connector: "",
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const body: CertificateUpload = { purpose: f.purpose, label: f.label.trim(), certificate_pem: f.cert.trim(), private_key_pem: f.key.trim() };
    if (f.purpose === "saml_sp") body.connection_id = f.saml;
    if (f.purpose === "mtls_client" && f.connector) body.connection_id = f.connector;
    if (f.purpose === "mtls_client" && f.anchors.trim()) body.trust_anchors_pem = f.anchors.trim();
    try {
      await certificatesApi.upload(body);
      setF({ ...f, key: "" }); // the key is not kept in the form
      onSaved();
    } catch (err) {
      setError(errText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title="Upload a certificate" sub="PEM certificate with its private key." onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Used for
          <select className="input" value={f.purpose} onChange={(e) => setF({ ...f, purpose: e.target.value as CertificateUpload["purpose"] })}>
            <option value="mtls_client">Connector mutual TLS (client certificate)</option>
            <option value="saml_sp" disabled={saml.length === 0}>SAML service-provider signing (rotation)</option>
            <option value="signing">Signing</option>
            <option value="encryption">Encryption</option>
          </select>
        </label>
        {f.purpose === "saml_sp" && (
          <label className="field">SAML connection
            <select className="input" value={f.saml} onChange={(e) => setF({ ...f, saml: e.target.value })} required>
              {saml.map((c) => <option key={c.id} value={c.connection_id ?? ""}>{c.label.replace(/ SP signing$/, "")}</option>)}
            </select>
          </label>
        )}
        {f.purpose === "mtls_client" && (
          <label className="field">Hand to connection (optional)
            <select className="input" value={f.connector} onChange={(e) => setF({ ...f, connector: e.target.value })}>
              <option value="">Not assigned yet</option>
              {(connectors.data ?? []).filter((c) => c.id && !c.legacy).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
            <span className="hint">The provisioning target of that connection presents this certificate on every call. A target reached through a Directory Agent does not use it.</span>
          </label>
        )}
        <label className="field">Label<input className="input" value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })} required maxLength={100} placeholder="e.g. Workday client certificate 2027" /></label>
        <label className="field">{f.purpose === "mtls_client" ? "Certificate chain (PEM, the certificate first)" : "Certificate (PEM)"}
          <textarea className="input sys" rows={6} value={f.cert} onChange={(e) => setF({ ...f, cert: e.target.value })} required spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" />
          {f.purpose === "mtls_client" && <span className="hint">Add the intermediate certificates after it, each one signing the one before. Up to 5 certificates.</span>}
        </label>
        <label className="field">Private key (PEM, unencrypted)
          <textarea className="input sys" rows={6} value={f.key} onChange={(e) => setF({ ...f, key: e.target.value })} required spellCheck={false} autoComplete="off" placeholder="-----BEGIN PRIVATE KEY-----" />
        </label>
        {f.purpose === "mtls_client" && (
          <label className="field">Trust anchors (PEM, optional)
            <textarea className="input sys" rows={4} value={f.anchors} onChange={(e) => setF({ ...f, anchors: e.target.value })} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" />
            <span className="hint">CA certificates the target's server certificate must chain to. When given, only these are trusted for this connection; leave empty to use the system roots.</span>
          </label>
        )}
        {f.purpose === "saml_sp" && <Callout tone="info">It is published in the SP metadata beside the current certificate until you promote it. A SAML key must be RSA.</Callout>}
        <p className="small muted">The key is encrypted before it is stored and cannot be read back. Saving needs a recent strong sign-in; if it asks for one, sign in and submit again.</p>
        <div aria-live="polite">{error && <Callout tone="bad">{error}</Callout>}</div>
        <div className="row"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Storing…" : "Upload"}</Button><Button onClick={onClose}>Cancel</Button></div>
      </form>
    </Drawer>
  );
}
