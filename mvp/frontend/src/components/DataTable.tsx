import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Bookmark, Download, Search, Trash2, Upload, X } from "lucide-react";
import { Button } from "./Button";
import { useConfirm } from "./Dialog";
import { Loading } from "./Feedback";
import { Menu, MenuEntry } from "./Menu";
import { useToast } from "./Toast";
import { downloadCsv, parseCsv, toCsv } from "./csv";
import { store } from "../app/storage";

export interface Column<T> {
  id: string;
  header: string;
  cell: (r: T) => ReactNode;
  /** Sort key; also used for CSV export when `csv` is absent. */
  sort?: (r: T) => string | number | null | undefined;
  csv?: (r: T) => string | number | null | undefined;
  num?: boolean;
  width?: number | string;
  hideNarrow?: boolean;
}

export interface Filter<T> {
  id: string;
  label: string;
  options: { value: string; label: string }[];
  get: (r: T) => string | string[] | null | undefined;
}

export interface BulkAction<T> {
  label: string;
  icon?: ReactNode;
  danger?: boolean;
  run: (rows: T[]) => void | Promise<void>;
}

interface View { name: string; q: string; filters: Record<string, string>; sort?: [string, 1 | -1] }

export interface DataTableProps<T> {
  /** Stable id: namespaces saved views and the export filename. */
  id: string;
  rows: T[] | null;
  error?: string | null;
  rowKey: (r: T) => string | number;
  columns: Column<T>[];
  searchText: (r: T) => string;
  searchPlaceholder?: string;
  filters?: Filter<T>[];
  bulkActions?: BulkAction<T>[];
  onRowClick?: (r: T) => void;
  /** Called with parsed CSV rows. When absent, the Import button is hidden. */
  onImport?: (rows: Record<string, string>[], fileName: string) => void;
  empty?: ReactNode;
  toolbarExtra?: ReactNode;
  initialSort?: [string, 1 | -1];
  pageSize?: number;
}

export function DataTable<T>(p: DataTableProps<T>) {
  const toast = useToast();
  const confirm = useConfirm();
  const [q, setQ] = useState("");
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [sort, setSort] = useState<[string, 1 | -1] | undefined>(p.initialSort);
  const [sel, setSel] = useState<Set<string | number>>(new Set());
  const [limit, setLimit] = useState(p.pageSize ?? 100);
  const [views, setViews] = useState<View[]>(() => store.get<View[]>(`views.${p.id}`, []));
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => setSel(new Set()), [p.rows]);

  const filtered = useMemo(() => {
    let rs = p.rows ?? [];
    const needle = q.trim().toLowerCase();
    if (needle) rs = rs.filter((r) => p.searchText(r).toLowerCase().includes(needle));
    for (const f of p.filters ?? []) {
      const v = filters[f.id];
      if (!v) continue;
      rs = rs.filter((r) => {
        const got = f.get(r);
        return Array.isArray(got) ? got.includes(v) : got === v;
      });
    }
    if (sort) {
      const col = p.columns.find((c) => c.id === sort[0]);
      if (col?.sort) {
        const k = col.sort;
        rs = [...rs].sort((a, b) => {
          const x = k(a), y = k(b);
          if (x === y) return 0;
          if (x === null || x === undefined) return 1;
          if (y === null || y === undefined) return -1;
          return (x < y ? -1 : 1) * sort[1];
        });
      }
    }
    return rs;
  }, [p.rows, q, filters, sort, p.columns, p.filters, p.searchText]);

  const visible = filtered.slice(0, limit);
  const selectedRows = (p.rows ?? []).filter((r) => sel.has(p.rowKey(r)));
  const allVisibleSelected = visible.length > 0 && visible.every((r) => sel.has(p.rowKey(r)));
  const activeFilters = Object.values(filters).filter(Boolean).length + (q ? 1 : 0);

  const toggleAll = () => {
    const next = new Set(sel);
    if (allVisibleSelected) visible.forEach((r) => next.delete(p.rowKey(r)));
    else visible.forEach((r) => next.add(p.rowKey(r)));
    setSel(next);
  };
  const toggle = (k: string | number) => {
    const next = new Set(sel);
    if (next.has(k)) next.delete(k);
    else next.add(k);
    setSel(next);
  };

  const exportCsv = () => {
    const cols = p.columns.filter((c) => c.csv || c.sort);
    const csv = toCsv(cols.map((c) => c.header), filtered.map((r) => cols.map((c) => (c.csv ?? c.sort)!(r))));
    downloadCsv(`tessera-${p.id}-${new Date().toISOString().slice(0, 10)}.csv`, csv);
    toast(`Exported ${filtered.length} row${filtered.length === 1 ? "" : "s"} to CSV`);
  };

  const onFile = async (f: File | undefined) => {
    if (!f || !p.onImport) return;
    const rows = parseCsv(await f.text());
    if (!rows.length) {
      toast(`${f.name} has no data rows. The first line must be a header row.`, { kind: "error" });
      return;
    }
    p.onImport(rows, f.name);
    if (fileRef.current) fileRef.current.value = "";
  };

  const saveView = async () => {
    const name = await confirm({ title: "Save view", body: "Saves the current search, filters and sort for this list in this browser.", confirmLabel: "Save view", reason: { label: "View name", required: true, placeholder: "e.g. Engineering, privileged" } });
    if (!name) return;
    const next = [...views.filter((v) => v.name !== name), { name, q, filters, sort }];
    setViews(next);
    store.set(`views.${p.id}`, next);
    toast(`Saved view "${name}"`);
  };
  const applyView = (v: View) => {
    setQ(v.q);
    setFilters(v.filters);
    setSort(v.sort);
  };
  const deleteView = (v: View) => {
    const next = views.filter((x) => x.name !== v.name);
    setViews(next);
    store.set(`views.${p.id}`, next);
  };
  const viewItems: MenuEntry[] = [
    { heading: "Saved views" },
    ...(views.length ? views.map((v) => ({ label: v.name, onSelect: () => applyView(v) })) : [{ label: <span className="faint">No saved views yet</span> }]),
    "divider",
    { label: "Save current view…", icon: <Bookmark size={14} />, onSelect: saveView },
    ...(views.length ? (["divider", { heading: "Delete" }, ...views.map((v) => ({ label: v.name, icon: <Trash2 size={14} />, danger: true, onSelect: () => deleteView(v) }))] as MenuEntry[]) : []),
  ];

  const sortBy = (id: string) => setSort((s) => (s && s[0] === id ? [id, s[1] === 1 ? -1 : 1] : [id, 1]));
  const hasBulk = !!p.bulkActions?.length;

  return (
    <div className="card flush">
      <div className="card-h" style={{ gap: 8 }}>
        {selectedRows.length > 0 && hasBulk ? (
          <div className="row" role="toolbar" aria-label="Bulk actions">
            <b className="tnum">{selectedRows.length} selected</b>
            {p.bulkActions!.map((a) => (
              <Button key={a.label} size="sm" variant={a.danger ? "danger" : "default"} icon={a.icon} onClick={async () => { await a.run(selectedRows); setSel(new Set()); }}>
                {a.label}
              </Button>
            ))}
            <Button size="sm" variant="ghost" icon={<X size={14} />} onClick={() => setSel(new Set())}>Clear</Button>
          </div>
        ) : (
          <div className="row grow dt-filters">
            <label className="input-icon dt-search">
              <Search size={14} />
              <span className="sr-only">Search</span>
              <input className="input" style={{ width: "100%" }} value={q} onChange={(e) => setQ(e.target.value)} placeholder={p.searchPlaceholder ?? "Search…"} />
            </label>
            {(p.filters ?? []).map((f) => (
              <label key={f.id} className="row tight">
                <span className="sr-only">{f.label}</span>
                <select className="input" value={filters[f.id] ?? ""} onChange={(e) => setFilters({ ...filters, [f.id]: e.target.value })} aria-label={f.label}>
                  <option value="">{f.label}: any</option>
                  {f.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </label>
            ))}
            {activeFilters > 0 && <Button size="sm" variant="ghost" icon={<X size={14} />} onClick={() => { setQ(""); setFilters({}); }}>Reset</Button>}
          </div>
        )}
        <div className="row tight dt-tools">
          {p.toolbarExtra}
          <Menu label="Saved views" items={viewItems} trigger={(t) => <Button size="sm" variant="ghost" icon={<Bookmark size={14} />} {...t}>Views</Button>} />
          {p.onImport && (
            <>
              <input ref={fileRef} type="file" accept=".csv,text/csv" hidden onChange={(e) => onFile(e.target.files?.[0])} aria-hidden tabIndex={-1} />
              <Button size="sm" variant="ghost" icon={<Upload size={14} />} onClick={() => fileRef.current?.click()}>Import</Button>
            </>
          )}
          <Button size="sm" variant="ghost" icon={<Download size={14} />} onClick={exportCsv} disabled={!filtered.length}>Export</Button>
        </div>
      </div>
      {!p.rows ? (
        <Loading error={p.error} />
      ) : (
        <>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  {hasBulk && (
                    <th className="check">
                      <input type="checkbox" checked={allVisibleSelected} onChange={toggleAll} aria-label="Select all rows" />
                    </th>
                  )}
                  {p.columns.map((c) => (
                    <th key={c.id} className={`${c.num ? "num" : ""} ${c.hideNarrow ? "hide-narrow" : ""}`} style={{ width: c.width }} aria-sort={sort?.[0] === c.id ? (sort[1] === 1 ? "ascending" : "descending") : undefined}>
                      {c.sort ? (
                        <button className="sort" onClick={() => sortBy(c.id)}>
                          {c.header}
                          {sort?.[0] === c.id && (sort[1] === 1 ? <ArrowUp size={12} /> : <ArrowDown size={12} />)}
                        </button>
                      ) : c.header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visible.map((r) => {
                  const k = p.rowKey(r);
                  return (
                    <tr
                      key={k}
                      className={`${p.onRowClick ? "click" : ""} ${sel.has(k) ? "selected" : ""}`}
                      onClick={p.onRowClick ? () => p.onRowClick!(r) : undefined}
                      tabIndex={p.onRowClick ? 0 : undefined}
                      onKeyDown={p.onRowClick ? (e) => { if (e.key === "Enter" && e.target === e.currentTarget) p.onRowClick!(r); } : undefined}
                    >
                      {hasBulk && (
                        <td className="check" onClick={(e) => e.stopPropagation()}>
                          <input type="checkbox" checked={sel.has(k)} onChange={() => toggle(k)} aria-label="Select row" />
                        </td>
                      )}
                      {p.columns.map((c) => (
                        <td key={c.id} className={`${c.num ? "num" : ""} ${c.hideNarrow ? "hide-narrow" : ""}`}>{c.cell(r)}</td>
                      ))}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {filtered.length === 0 && (p.rows.length === 0 ? p.empty : (
            <div className="empty-state">
              <h3>No matches</h3>
              <p>Nothing matches the current search and filters. Try a broader search or reset the filters.</p>
              <div className="row mt-sm"><Button size="sm" onClick={() => { setQ(""); setFilters({}); }}>Reset filters</Button></div>
            </div>
          ))}
          <div className="spread small faint" style={{ padding: "8px 14px", borderTop: "1px solid var(--border)" }}>
            <span className="tnum">{visible.length < filtered.length ? `Showing ${visible.length} of ${filtered.length}` : `${filtered.length} row${filtered.length === 1 ? "" : "s"}`}{filtered.length !== p.rows.length && ` · filtered from ${p.rows.length}`}</span>
            {visible.length < filtered.length && <Button size="sm" variant="ghost" onClick={() => setLimit(limit + 100)}>Show more</Button>}
          </div>
        </>
      )}
    </div>
  );
}
