import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Bookmark, Check, ChevronDown, Download, FileUp, Plus, RefreshCw, Search, Trash2, X } from "lucide-react";
import { Button } from "./Button";
import { useConfirm } from "./Dialog";
import { Loading } from "./Feedback";
import { Menu, MenuEntry } from "./Menu";
import { Command, CommandBar } from "./Page";
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
  /** Row shown as selected (the one open in the side panel). */
  activeKey?: string | number | null;
  /** Commands that don't need a selection (New, Start review...). Bulk import and Refresh are added from onImport / onRefresh. */
  commands?: (Command | null | false | undefined)[];
  onRefresh?: () => void;
  /** Filter values to start with, e.g. from a deep link. */
  initialFilters?: Record<string, string>;
  /** How many filters show as chips before "+ Add filter" (default 2). */
  chips?: number;
  /** Accessible name for a row's checkbox. */
  rowLabel?: (r: T) => string;
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
  const [filters, setFilters] = useState<Record<string, string>>(() => p.initialFilters ?? {});
  const [sort, setSort] = useState<[string, 1 | -1] | undefined>(p.initialSort);
  const [sel, setSel] = useState<Set<string | number>>(new Set());
  const [limit, setLimit] = useState(p.pageSize ?? 100);
  const [views, setViews] = useState<View[]>(() => store.get<View[]>(`views.${p.id}`, []));
  const fileRef = useRef<HTMLInputElement>(null);
  const [shown, setShown] = useState<string[]>(() => [...new Set([...(p.filters ?? []).slice(0, p.chips ?? 2).map((f) => f.id), ...Object.keys(p.initialFilters ?? {})])]);

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
    setShown((xs) => [...new Set([...xs, ...Object.keys(v.filters)])]);
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
  const hasBulk = true;
  const reset = () => { setQ(""); setFilters({}); };
  const hidden = (p.filters ?? []).filter((f) => !shown.includes(f.id));
  const n = selectedRows.length;
  const cmds: (Command | null | false | undefined)[] = [
    ...(p.commands ?? []),
    p.onImport && { label: "Bulk import", icon: <FileUp size={16} />, onClick: () => fileRef.current?.click() },
    p.onRefresh && { label: "Refresh", icon: <RefreshCw size={16} />, onClick: p.onRefresh },
    ...(p.bulkActions ?? []).map((a) => ({
      label: a.label,
      icon: a.icon,
      danger: a.danger,
      disabled: n === 0,
      title: n === 0 ? "Select one or more rows first" : undefined,
      onClick: async () => { await a.run(selectedRows); setSel(new Set()); },
    })),
  ];

  return (
    <div>
      <CommandBar
        label="List commands"
        items={cmds}
        end={<>
          {n > 0 && <span className="cmd-sel tnum" role="status">{n} selected <button type="button" className="btn ghost sm" onClick={() => setSel(new Set())}>Clear</button></span>}
          {p.toolbarExtra}
          <Menu label="Saved views" items={viewItems} trigger={(t) => <button type="button" className="cmd" {...t}><Bookmark size={16} /> Views</button>} />
          <button type="button" className="cmd" onClick={exportCsv} disabled={!filtered.length}><Download size={16} /> Export</button>
        </>}
      />
      {p.onImport && <input ref={fileRef} type="file" accept=".csv,text/csv" hidden onChange={(e) => onFile(e.target.files?.[0])} aria-hidden tabIndex={-1} />}
      <div className="dt-bar" role="group" aria-label="Search and filters">
        <label className="input-icon dt-search">
          <Search size={14} />
          <span className="sr-only">Search</span>
          <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder={p.searchPlaceholder ?? "Search…"} />
        </label>
        {(p.filters ?? []).filter((f) => shown.includes(f.id)).map((f) => {
          const v = filters[f.id];
          const vLabel = f.options.find((o) => o.value === v)?.label;
          return (
            <Menu
              key={f.id}
              align="start"
              label={f.label}
              items={[
                { label: "All", icon: !v ? <Check size={14} /> : <span style={{ width: 14 }} />, checked: !v, onSelect: () => setFilters({ ...filters, [f.id]: "" }) },
                ...f.options.map((o) => ({ label: o.label, icon: v === o.value ? <Check size={14} /> : <span style={{ width: 14 }} />, checked: v === o.value, onSelect: () => setFilters({ ...filters, [f.id]: o.value }) })),
              ]}
              trigger={(t) => (
                <button type="button" className={`fchip ${v ? "on" : ""}`} aria-label={`${f.label}: ${vLabel ?? "All"}`} {...t}>
                  {f.label}: {vLabel ?? "All"} <ChevronDown size={12} aria-hidden />
                </button>
              )}
            />
          );
        })}
        {hidden.length > 0 && (
          <Menu
            align="start"
            label="Add filter"
            items={hidden.map((f) => ({ label: f.label, onSelect: () => setShown([...shown, f.id]) }))}
            trigger={(t) => <button type="button" className="fchip add" {...t}><Plus size={12} aria-hidden /> Add filter</button>}
          />
        )}
        {activeFilters > 0 && <button type="button" className="fchip add" onClick={reset}><X size={12} aria-hidden /> Reset</button>}
      </div>
      <div className="card flush">
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
                      className={`${p.onRowClick ? "click" : ""} ${sel.has(k) ? "selected" : ""} ${p.activeKey != null && String(p.activeKey) === String(k) ? "active" : ""}`}
                      aria-current={p.activeKey != null && String(p.activeKey) === String(k) ? "true" : undefined}
                      onClick={p.onRowClick ? () => p.onRowClick!(r) : undefined}
                      tabIndex={p.onRowClick ? 0 : undefined}
                      onKeyDown={p.onRowClick ? (e) => { if (e.key === "Enter" && e.target === e.currentTarget) p.onRowClick!(r); } : undefined}
                    >
                      {hasBulk && (
                        <td className="check" onClick={(e) => e.stopPropagation()}>
                          <input type="checkbox" checked={sel.has(k)} onChange={() => toggle(k)} aria-label={p.rowLabel ? `Select ${p.rowLabel(r)}` : "Select row"} />
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
              <div className="row mt-sm"><Button size="sm" onClick={reset}>Reset filters</Button></div>
            </div>
          ))}
          <div className="dt-foot">
            <span className="tnum">{visible.length < filtered.length ? `Showing ${visible.length} of ${filtered.length}` : `${filtered.length} row${filtered.length === 1 ? "" : "s"}`}{filtered.length !== p.rows.length && ` · filtered from ${p.rows.length}`}</span>
            {visible.length < filtered.length && <Button size="sm" variant="ghost" onClick={() => setLimit(limit + 100)}>Show more</Button>}
          </div>
        </>
      )}
      </div>
    </div>
  );
}
