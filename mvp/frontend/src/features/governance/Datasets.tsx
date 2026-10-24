import { useRef, useState } from "react";
import { Database, Plus, Trash2, Upload, X } from "lucide-react";
import { Dataset, DatasetDetail, DatasetList, datasets as dsApi, datasetsPath, fmtDate, relTime, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Column, DataTable, EmptyState, GovernanceTabs, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";

/**
 * Governance → Datasets (issue #588): named lookup tables (allowed cost centers, restricted
 * systems) that workflow conditions read by name. Values are added and removed one batch at a time
 * or loaded from a CSV file (first column). Changes need catalog.manage and are audited; a dataset
 * an active workflow names cannot be renamed or deleted.
 */
export function Datasets() {
  const { can } = useSession();
  const list = useApi<DatasetList>(datasetsPath);
  const [selected, setSelected] = useSelected();
  const rows = list.data?.datasets ?? null;
  const manage = !!list.data?.can_manage && can("catalog.manage");
  const creating = selected === "new";
  const current = rows?.find((d) => d.id === selected) ?? null;
  const cols: Column<Dataset>[] = [
    { id: "name", header: "Dataset", sort: (d) => d.name, cell: (d) => <span className="name-link">{d.name}</span> },
    { id: "count", header: "Values", num: true, sort: (d) => d.count, cell: (d) => d.count },
    { id: "description", header: "Description", sort: (d) => d.description, cell: (d) => <span className="small">{d.description}</span>, hideNarrow: true },
    { id: "updated", header: "Updated", sort: (d) => d.updated_at, cell: (d) => <span className="small faint nowrap" title={fmtDate(d.updated_at)}>{relTime(d.updated_at)}</span>, hideNarrow: true },
  ];
  return (
    <Page
      tabs={<GovernanceTabs />}
      title="Datasets"
      crumbs={[["Access"], ["Access reviews", "/governance/reviews"], ["Datasets"]]}
      sub="Named lists of values that workflow conditions test an attribute against. Change a list here and every workflow that names it follows."
    >
      <div className="stack">
        {!manage && list.data && <Callout tone="neutral">Datasets are managed by people who hold catalog.manage. You can read them here.</Callout>}
        {list.error && <Callout tone="bad">{list.error.message}</Callout>}
        <DataTable
          id="datasets"
          rows={rows}
          error={list.error}
          rowKey={(d) => d.id}
          columns={cols}
          searchText={(d) => `${d.name} ${d.description}`}
          searchPlaceholder="Search datasets…"
          commands={manage ? [{ label: "New dataset", icon: <Plus size={16} />, onClick: () => setSelected("new") }] : []}
          onRefresh={list.reload}
          rowLabel={(d) => d.name}
          onRowClick={(d) => setSelected(d.id)}
          activeKey={current?.id ?? null}
          empty={<EmptyState title="No datasets yet" icon={<Database size={18} />}>Create one, add values or upload a CSV file, then name it in a workflow condition.</EmptyState>}
        />
      </div>
      {list.data && (creating || current) && (
        <Editor key={creating ? "new" : `${current!.id}-${current!.version}`} d={creating ? null : current} manage={manage} onClose={() => setSelected(null)}
          onSaved={(id) => { list.reload(); if (id) setSelected(id); }} />
      )}
    </Page>
  );
}

function Editor({ d, manage, onClose, onSaved }: { d: Dataset | null; manage: boolean; onClose: () => void; onSaved: (id?: string) => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const detail = useApi<DatasetDetail>(d ? `${datasetsPath}/${encodeURIComponent(d.id)}?limit=500` : null);
  const [name, setName] = useState(d?.name ?? "");
  const [description, setDescription] = useState(d?.description ?? "");
  const [add, setAdd] = useState("");
  const [header, setHeader] = useState(false);
  const [replace, setReplace] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const file = useRef<HTMLInputElement>(null);
  const saved = useRef<string | undefined>(d?.id);
  const readOnly = !manage;
  const run = async (fn: () => Promise<unknown>, done: string, then?: () => void) => {
    if (busy) return;
    setBusy(true);
    setErr(null);
    try {
      await fn();
      toast(done);
      (then ?? (() => onSaved(d?.id)))();
      detail.reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const changed = !d || name.trim() !== d.name || description.trim() !== d.description;
  const addValues = add.split(/\r?\n/).map((v) => v.trim()).filter(Boolean);
  const remove = async () => {
    if (!d) return;
    const ok = await confirm({ title: `Delete ${d.name}?`, body: "Its values are removed. A dataset an active workflow names cannot be deleted.", confirmLabel: "Delete", danger: true });
    if (ok == null) return;
    run(() => dsApi.remove(d.id), "Dataset deleted", () => { onClose(); onSaved(); });
  };
  return (
    <SidePanel
      title={d ? d.name : "New dataset"}
      sub={d && <span className="small muted">Version {d.version} · {d.count} value{d.count === 1 ? "" : "s"}</span>}
      onClose={onClose}
      footer={!readOnly && (
        <div className="row tight">
          <Button variant="primary" size="sm" disabled={!changed || !name.trim() || busy}
            onClick={() => run(async () => {
              const r = d ? await dsApi.update(d.id, d.version, name.trim(), description.trim()) : await dsApi.create(name.trim(), description.trim());
              saved.current = r.id;
            }, d ? "Saved" : "Dataset created", () => onSaved(saved.current))}>{d ? "Save" : "Create"}</Button>
          {d && <Button size="sm" variant="danger" icon={<Trash2 size={14} />} onClick={remove} disabled={busy}>Delete</Button>}
        </div>
      )}
    >
      <div className="stack">
        {err && <Callout tone="bad">{err}</Callout>}
        <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }} disabled={readOnly}>
          <legend><h3 className="h-sm">Details</h3></legend>
          <label className="field">Name
            <input className="input" value={name} maxLength={80} onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="field">Description (optional)
            <textarea className="input" rows={2} value={description} maxLength={500} onChange={(e) => setDescription(e.target.value)} />
          </label>
        </fieldset>
        {d && (
          <>
            <section className="stack-sm" aria-label="Values">
              <h3 className="h-sm">Values</h3>
              {detail.error && <Callout tone="bad">{detail.error.message}</Callout>}
              {detail.data && detail.data.values.length === 0 && <p className="small muted">No values yet.</p>}
              <ul className="row tight wrap" style={{ listStyle: "none", padding: 0, margin: 0 }}>
                {(detail.data?.values ?? []).map((v) => (
                  <li key={v}>
                    <Badge tone="outline">
                      {v}
                      {manage && (
                        <button type="button" className="icon-btn" aria-label={`Remove ${v}`} disabled={busy} onClick={() => run(() => dsApi.edit(d.id, [], [v]), "Value removed")}>
                          <X size={12} />
                        </button>
                      )}
                    </Badge>
                  </li>
                ))}
              </ul>
              {detail.data && d.count > detail.data.values.length && <p className="xs faint">Showing the first {detail.data.values.length} of {d.count}.</p>}
            </section>
            {manage && (
              <>
                <section className="stack-sm" aria-label="Add values">
                  <label className="field">Add values (one per line)
                    <textarea className="input" rows={3} value={add} onChange={(e) => setAdd(e.target.value)} />
                  </label>
                  <div><Button size="sm" disabled={addValues.length === 0 || busy} onClick={() => run(() => dsApi.edit(d.id, addValues, []).then(() => setAdd("")), "Values added")}>Add</Button></div>
                </section>
                <section className="stack-sm" aria-label="Upload a CSV file">
                  <h3 className="h-sm">Upload a CSV file</h3>
                  <p className="xs faint">The first column of each row is a value. Up to 1 MiB.</p>
                  <label className="row tight"><input type="checkbox" checked={header} onChange={(e) => setHeader(e.target.checked)} /> The first row is a header</label>
                  <label className="row tight"><input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} /> Replace the current values</label>
                  <input ref={file} type="file" accept=".csv,text/csv" className="sr-only" id="ds-file" aria-label="CSV file"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) run(() => dsApi.upload(d.id, f, { header, replace }), "File loaded");
                      e.target.value = "";
                    }} />
                  <div><Button size="sm" icon={<Upload size={14} />} disabled={busy} onClick={() => file.current?.click()}>Choose a file…</Button></div>
                </section>
              </>
            )}
          </>
        )}
      </div>
    </SidePanel>
  );
}
