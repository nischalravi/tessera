import { FormEvent, useState } from "react";
import { FileText } from "lucide-react";
import { GuestPopulationKey, TermsDocument, fmtDate, termsAdmin, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Button, Callout, Chip, Column, DataTable, EmptyState, GovernanceTabs, Page, SidePanel, useSelected, useToast } from "../../components";

/**
 * Governance → Guest terms (guest accounts design §7.4, issue #73): the terms documents guests accept at
 * step 5 of the claim, with the version in force, its SHA-256, the grace period for people who accepted an
 * earlier version, and where each applies. Publishing and assigning are the server's call (terms.manage).
 * GU-13 builds the full admin page; this is the list and the two actions.
 */
const POPULATIONS: GuestPopulationKey[] = ["visitor", "contractor", "volunteer", "partner"];

export function Terms() {
  const { can } = useSession();
  const docs = useApi<{ documents: TermsDocument[] }>("/admin/terms");
  const [selected, setSelected] = useSelected();
  const rows = docs.data?.documents ?? null;
  const current = rows?.find((d) => d.key === selected) ?? null;
  const manage = can("terms.manage");
  const cols: Column<TermsDocument>[] = [
    { id: "title", header: "Document", sort: (r) => r.title, cell: (r) => <span className="name-link">{r.title}</span> },
    { id: "key", header: "Key", sort: (r) => r.key, cell: (r) => <code className="small">{r.key}</code>, hideNarrow: true },
    { id: "version", header: "Version", num: true, sort: (r) => r.latest_version, cell: (r) => r.latest_version },
    { id: "grace", header: "Grace (days)", num: true, sort: (r) => r.grace_days, cell: (r) => r.grace_days, hideNarrow: true },
    {
      id: "applies", header: "Applies to",
      cell: (r) => (r.populations.length + r.bundles.length === 0 ? <span className="faint">nobody</span>
        : <span className="row tight wrap">{r.populations.map((p) => <Chip key={p}>{p}</Chip>)}{r.bundles.map((b) => <Chip key={b.group_id}>{b.system}:{b.name}</Chip>)}</span>),
    },
    { id: "hash", header: "SHA-256", cell: (r) => <code className="small" title={r.sha256}>{r.sha256.slice(0, 12)}…</code>, hideNarrow: true },
  ];
  return (
    <Page
      title="Guest terms"
      crumbs={[["Governance", "/governance/policies"], ["Guest terms"]]}
      sub="Terms of use guests accept before they set up a sign-in. A new version needs accepting again, within its grace period."
      tabs={<GovernanceTabs />}
    >
      {docs.error && <Callout tone="bad">{docs.error}</Callout>}
      <DataTable
        id="guest-terms"
        rows={rows}
        error={docs.error}
        rowKey={(r) => r.key}
        columns={cols}
        searchText={(r) => `${r.title} ${r.key}`}
        searchPlaceholder="Search documents…"
        onRefresh={docs.reload}
        rowLabel={(r) => r.title}
        onRowClick={(r) => setSelected(r.key)}
        activeKey={current?.key ?? null}
        empty={<EmptyState title="No terms yet" icon={<FileText size={18} />}>{manage ? "Publish a document below." : "No terms documents are published."}</EmptyState>}
      />
      {manage && <Publish onPublished={docs.reload} />}
      {current && <Panel doc={current} manage={manage} onClose={() => setSelected(null)} onChanged={docs.reload} />}
    </Page>
  );
}

function Publish({ onPublished }: { onPublished: () => void }) {
  const toast = useToast();
  const [key, setKey] = useState("");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [grace, setGrace] = useState("14");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const v = await termsAdmin.publish({ key: key.trim(), title: title.trim(), body, grace_days: Number(grace) });
      toast(`Published version ${v.version}`);
      setBody("");
      onPublished();
    } catch (x: any) {
      toast(String(x.message ?? x), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="stack" style={{ maxWidth: 640, marginTop: 16 }}>
      <h2 className="h-sm">Publish a version</h2>
      <p className="xs faint">An existing key gets the next version; guests who accepted the earlier one accept again within the grace period.</p>
      <label className="field">Key
        <input className="input" value={key} onChange={(e) => setKey(e.target.value)} placeholder="acceptable-use" required pattern="[a-z0-9][a-z0-9\-]{0,63}" />
      </label>
      <label className="field">Title
        <input className="input" value={title} onChange={(e) => setTitle(e.target.value)} required maxLength={200} />
      </label>
      <label className="field">Text
        <textarea className="input" rows={8} value={body} onChange={(e) => setBody(e.target.value)} required />
      </label>
      <label className="field">Grace period for a new version (days)
        <input className="input" type="number" min={0} max={365} value={grace} onChange={(e) => setGrace(e.target.value)} />
      </label>
      <div><Button variant="primary" type="submit" disabled={busy || !key.trim() || !title.trim() || !body.trim()}>Publish</Button></div>
    </form>
  );
}

function Panel({ doc, manage, onClose, onChanged }: { doc: TermsDocument; manage: boolean; onClose: () => void; onChanged: () => void }) {
  const toast = useToast();
  const [pops, setPops] = useState<GuestPopulationKey[]>(doc.populations);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try {
      await termsAdmin.assign(doc.key, { populations: pops, bundles: doc.bundles.map((b) => b.group_id) });
      toast("Assignment saved");
      onChanged();
    } catch (x: any) {
      toast(String(x.message ?? x), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <SidePanel title={doc.title} sub={<span className="small muted">Version {doc.latest_version}</span>} onClose={onClose}>
      <fieldset className="stack-sm" style={{ border: 0, padding: 0 }} disabled={!manage}>
        <legend className="h-sm">Applies to guests who are</legend>
        {POPULATIONS.map((p) => (
          <label key={p} className="row tight">
            <input type="checkbox" checked={pops.includes(p)} onChange={(e) => setPops(e.target.checked ? [...pops, p] : pops.filter((x) => x !== p))} /> {p}
          </label>
        ))}
        {doc.bundles.length > 0 && <p className="xs faint">Also applies to the bundles: {doc.bundles.map((b) => `${b.system}:${b.name}`).join(", ")}.</p>}
      </fieldset>
      {manage && <div><Button variant="primary" size="sm" disabled={busy} onClick={save}>Save assignment</Button></div>}
      <h3 className="h-sm">Versions</h3>
      <ul className="stack-sm" style={{ paddingLeft: 16 }}>
        {[...doc.versions].reverse().map((v) => (
          <li key={v.id} className="small">v{v.version}, {fmtDate(v.created_at)}, grace {v.grace_days} days<br /><code className="xs">{v.sha256}</code></li>
        ))}
      </ul>
    </SidePanel>
  );
}
