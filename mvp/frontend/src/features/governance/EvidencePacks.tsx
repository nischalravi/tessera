import { FormEvent, useMemo, useState } from "react";
import { Download, FileArchive } from "lucide-react";
import { EvidencePack, EvidencePackList, createEvidencePack, downloadEvidencePack, fmtDate, useApi } from "../../api";
import { Badge, Button, Chip, DataTable, EmptyState, Page, SidePanel, useSelected, useToast } from "../../components";

const day = (d: Date) => d.toISOString().slice(0, 10);
const kb = (n: number) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`);
/** Period ends are exclusive instants; show the last day that is included. */
const lastDay = (iso: string) => day(new Date(new Date(iso + "Z").getTime() - 1));

function useDownload() {
  const toast = useToast();
  return async (p: EvidencePack) => {
    try {
      const blob = await downloadEvidencePack(p.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `tessera-evidence-${p.framework}-${p.period_from.slice(0, 10)}-${lastDay(p.period_to)}.zip`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };
}

function PackPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: p, error } = useApi<EvidencePack>(`/evidence/packs/${encodeURIComponent(id)}`);
  const download = useDownload();
  const m = p?.manifest;
  return (
    <SidePanel
      title={p?.framework_name ?? "Evidence pack"}
      sub={p && <span>{p.period_from.slice(0, 10)} to {lastDay(p.period_to)}</span>}
      onClose={onClose}
      commands={p && <Button icon={<Download size={16} />} onClick={() => download(p)}>Download ZIP</Button>}
    >
      {error && <div className="small" role="alert">{error.message}</div>}
      {p && m && (
        <>
          <dl className="kv">
            <dt>Generated</dt><dd>{fmtDate(p.generated_at)} by {p.generated_by}</dd>
            <dt>Size</dt><dd className="tnum">{kb(p.size_bytes)}</dd>
            <dt>Manifest SHA-256</dt><dd className="sys" style={{ wordBreak: "break-all" }}>{p.manifest_sha256}</dd>
          </dl>
          <p className="small muted">The same hash is recorded in the audit ledger (evidence.pack_generated). Each file below has its own SHA-256 in manifest.json.</p>
          <section className="stack-sm">
            <h3 style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Controls covered</h3>
            {m.controls.map((c) => (
              <div key={c.id} className="small"><b>{c.id}</b> {c.title}<div className="row tight">{c.files.map((f) => <Chip key={f} mono>{f}</Chip>)}</div></div>
            ))}
          </section>
          <section className="stack-sm">
            <h3 style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Files</h3>
            <div className="table-scroll">
              <table>
                <thead><tr><th>File</th><th className="num">Rows</th><th className="num">Size</th></tr></thead>
                <tbody>
                  {m.files.map((f) => (
                    <tr key={f.name}><td className="sys">{f.name}</td><td className="num tnum">{f.rows < 0 ? "" : f.rows}</td><td className="num tnum">{kb(f.bytes)}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          {Object.keys(m.user_rows_by_source).length > 0 && (
            <section className="stack-sm">
              <h3 style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>User rows by source</h3>
              <div className="row tight">{Object.entries(m.user_rows_by_source).map(([s, n]) => <Chip key={s}>{s}: {n}</Chip>)}</div>
            </section>
          )}
          {m.notes.length > 0 && (
            <section className="stack-sm">
              <h3 style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Notes</h3>
              {m.notes.map((n) => <p key={n} className="small muted">{n}</p>)}
            </section>
          )}
        </>
      )}
    </SidePanel>
  );
}

export function EvidencePacks() {
  const { data, error } = useApi<EvidencePackList>("/evidence/packs");
  const toast = useToast();
  const download = useDownload();
  const [selected, setSelected] = useSelected();
  const today = useMemo(() => new Date(), []);
  const [framework, setFramework] = useState("");
  const [from, setFrom] = useState(() => day(new Date(today.getTime() - 90 * 86400000)));
  const [to, setTo] = useState(() => day(today));
  const [busy, setBusy] = useState(false);
  const fw = framework || data?.frameworks[0]?.id || "";
  const bad = !from || !to || from > to ? "The start date must not be after the end date." : null;

  const generate = async (e: FormEvent) => {
    e.preventDefault();
    if (bad || !fw) return;
    setBusy(true);
    try {
      const p = await createEvidencePack({ framework: fw, from, to });
      toast(`Generated ${p.framework_name}`);
      setSelected(p.id);
    } catch (err) {
      toast((err as Error).message, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Page
      title="Evidence packs"
      crumbs={[["Protection"], ["Evidence packs"]]}
      count={data ? `${data.packs.length} packs` : undefined}
      sub="Per framework: user listing, leaver timings, review campaigns, privileged access and revocations for a date range, with a SHA-256 manifest recorded in the audit ledger."
    >
      <form className="card stack-sm" onSubmit={generate} aria-label="Generate an evidence pack" style={{ marginBottom: 16 }}>
        <h3>Generate a pack</h3>
        <div className="row" style={{ alignItems: "flex-end", flexWrap: "wrap", gap: 12 }}>
          <label className="field">Framework
            <select className="input" value={fw} onChange={(e) => setFramework(e.target.value)}>
              {(data?.frameworks ?? []).map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
            </select>
          </label>
          <label className="field">From
            <input className="input" type="date" value={from} max={to || undefined} onChange={(e) => setFrom(e.target.value)} required />
          </label>
          <label className="field">To (included)
            <input className="input" type="date" value={to} min={from || undefined} max={day(today)} onChange={(e) => setTo(e.target.value)} required />
          </label>
          <Button type="submit" variant="primary" icon={<FileArchive size={16} />} disabled={busy || !!bad || !fw}>{busy ? "Generating…" : "Generate pack"}</Button>
        </div>
        {bad && <div className="small" role="alert">{bad}</div>}
        <p className="small muted">Grants are as they were at the end of the range (point-in-time). Identities and accounts are current records. A pack cannot be changed after it is generated.</p>
      </form>

      <DataTable<EvidencePack>
        id="evidence-packs"
        rows={data?.packs ?? null}
        error={error}
        rowKey={(p) => p.id}
        rowLabel={(p) => `${p.framework_name} ${p.period_from.slice(0, 10)}`}
        activeKey={selected}
        onRowClick={(p) => setSelected(p.id)}
        searchText={(p) => `${p.framework_name} ${p.generated_by} ${p.manifest_sha256}`}
        searchPlaceholder="Search packs"
        initialSort={["generated", -1]}
        filters={[{ id: "framework", label: "Framework", options: (data?.frameworks ?? []).map((f) => ({ value: f.id, label: f.name })), get: (p) => p.framework }]}
        columns={[
          { id: "framework", header: "Framework", sort: (p) => p.framework_name, cell: (p) => <b>{p.framework_name}</b> },
          { id: "period", header: "Period", sort: (p) => p.period_from, cell: (p) => <span className="small nowrap">{p.period_from.slice(0, 10)} to {lastDay(p.period_to)}</span> },
          { id: "generated", header: "Generated", sort: (p) => p.generated_at, cell: (p) => <span className="small nowrap">{fmtDate(p.generated_at)}</span> },
          { id: "by", header: "By", sort: (p) => p.generated_by, cell: (p) => <span className="small">{p.generated_by}</span>, hideNarrow: true },
          { id: "files", header: "Files", num: true, sort: (p) => p.files, cell: (p) => <span className="tnum">{p.files}</span>, hideNarrow: true },
          { id: "size", header: "Size", num: true, sort: (p) => p.size_bytes, cell: (p) => <span className="tnum">{kb(p.size_bytes)}</span>, hideNarrow: true },
          { id: "hash", header: "Manifest SHA-256", cell: (p) => <Badge title={p.manifest_sha256}>{p.manifest_sha256.slice(0, 12)}</Badge>, hideNarrow: true },
          { id: "dl", header: "", cell: (p) => <Button size="sm" icon={<Download size={14} />} label={`Download ${p.framework_name}`} onClick={(e) => { e.stopPropagation(); void download(p); }} /> },
        ]}
        empty={<EmptyState icon={<FileArchive />} title="No evidence packs yet">Choose a framework and a date range above, then generate one.</EmptyState>}
      />
      {selected && <PackPanel id={selected} onClose={() => setSelected(null)} />}
    </Page>
  );
}
