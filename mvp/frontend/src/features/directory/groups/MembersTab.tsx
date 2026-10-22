import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Download, FileUp, GitBranch, Plus, Trash2 } from "lucide-react";
import { BatchAdd, GrpDirectMember, GrpEffectiveMember, GrpGroup, GrpList, GrpMembers, MemberFilter, groups } from "../../../api";
import { Button, Callout, CommandBar, Drawer, EmptyState, FilterChips, Loading, useToast } from "../../../components";
import { downloadCsv, parseCsv, toCsv } from "../../../components/csv";
import { ChangePreview } from "./ChangePreview";
import { IdentityPicker, fmtWhen } from "./common";
import { errText, useLoad } from "./hooks";
import { addChanges, datesProblem, idempotencyKey, parseMemberRows, removeChanges, toInstant } from "./model";
import { TraceDrawer } from "./TraceDrawer";
import { isHeld } from "../../admin/deletionGuardModel";

const PAGE = 50;
type Enabled = "all" | "true" | "false";
type Row = GrpDirectMember | GrpEffectiveMember;
const isDirect = (r: Row): r is GrpDirectMember => "type" in r;
const memberRef = (m: GrpDirectMember) => (m.type === "identity" ? String(m.identity_id) : String(m.group_id));

/** The Members tab: direct, indirect and effective members, with search, paging, add/remove (with a preview), CSV import and export. */
export function MembersTab({ g, canWrite }: { g: GrpGroup; canWrite: boolean }) {
  const toast = useToast();
  const nav = useNavigate();
  const [filter, setFilter] = useState<MemberFilter>("direct");
  const [enabled, setEnabled] = useState<Enabled>("all");
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  const [page, setPage] = useState(1);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [trace, setTrace] = useState<{ id: number; name: string } | null>(null);
  const [add, setAdd] = useState<"one" | "csv" | null>(null);
  const [removing, setRemoving] = useState<string[] | null>(null);
  const composite = g.definition !== "basic";

  // the search box applies after a pause, so every keystroke is not a request
  useEffect(() => {
    const t = setTimeout(() => {
      setTerm(q.trim());
      setPage(1);
    }, 250);
    return () => clearTimeout(t);
  }, [q]);
  useEffect(() => setPicked(new Set()), [filter, enabled, term, page, g.id]);

  const key = `members:${g.id}:${filter}:${enabled}:${term}:${page}`;
  const { data, error, reload } = useLoad<GrpMembers<Row>>(
    () => groups.members<Row>(g.id, { filter, q: term || undefined, enabled: filter === "direct" && enabled !== "all" ? enabled === "true" : undefined, page, limit: PAGE, sort: "name" }),
    key,
  );
  const rows = data?.items ?? [];
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE)) : 1;
  const direct = useMemo(() => rows.filter(isDirect), [rows]);

  const filters: { id: MemberFilter; label: string }[] = [
    { id: "direct", label: "Direct" }, { id: "indirect", label: "Indirect" }, { id: "effective", label: "Effective" },
    ...(composite ? [{ id: "composite" as MemberFilter, label: "Composite" }] : []),
  ];

  const exportAll = async () => {
    try {
      const out: (string | number)[][] = [];
      for (let p = 1; ; p++) {
        const r = await groups.members<Row>(g.id, { filter, q: term || undefined, page: p, limit: 500, sort: "name" });
        for (const m of r.items) {
          out.push(isDirect(m)
            ? [m.name, m.type, m.type === "identity" ? (m.identity_id ?? "") : (m.group_id ?? ""), m.source, m.enabled_from ?? "", m.disabled_at ?? "", m.active ? "yes" : "no"]
            : [m.name, "identity", m.identity_id, "", m.since, "", "yes"]);
        }
        if (r.items.length < 500 || p * 500 >= r.total) break;
      }
      downloadCsv(`${g.name.replace(/[^A-Za-z0-9_.-]+/g, "_")}-${filter}-members.csv`, toCsv(["name", "type", "id", "source", "from", "until", "active"], out));
    } catch (e) {
      toast(errText(e), { kind: "error" });
    }
  };

  const togglePick = (id: string) => setPicked((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const readOnly = composite; // a composite has no direct members: the API refuses them

  return (
    <div className="stack">
      <CommandBar
        label="Member actions"
        items={[
          canWrite && !readOnly && { label: "Add member", icon: <Plus size={16} />, onClick: () => setAdd("one") },
          canWrite && !readOnly && { label: "Import CSV", icon: <FileUp size={16} />, onClick: () => setAdd("csv") },
          canWrite && !readOnly && picked.size > 0 && { label: `Remove ${picked.size} selected`, icon: <Trash2 size={16} />, danger: true, onClick: () => setRemoving([...picked]) },
          { label: "Export CSV", icon: <Download size={16} />, onClick: exportAll },
        ]}
      />
      <div className="row">
        <FilterChips<MemberFilter> label="Which members" value={filter} onChange={(f) => { setFilter(f); setPage(1); }} options={filters} />
        {filter === "direct" && (
          <FilterChips<Enabled> label="Enabled" value={enabled} onChange={(v) => { setEnabled(v); setPage(1); }}
            options={[{ id: "all", label: "Any" }, { id: "true", label: "Active now" }, { id: "false", label: "Not active" }]} />
        )}
        <label className="field" style={{ minWidth: 200, flex: "1 1 200px" }}>
          <span className="sr-only">Search members</span>
          <input className="input" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search members by name or email…" />
        </label>
      </div>
      {composite && filter === "direct" && <Callout tone="neutral">A composite group has no direct members: its members come from its definition. See the Definition tab.</Callout>}
      {data?.stale && <Callout tone="warn">These members may lag: a recalculation is still running.</Callout>}
      {!data && <Loading error={error} />}
      {data && rows.length === 0 && <EmptyState title="No members">{term ? "Nothing matches that search." : "This list is empty."}</EmptyState>}
      {rows.length > 0 && (
        <div className="table-scroll">
          <table>
            <caption className="sr-only">{filter} members of {g.name}</caption>
            <thead>
              <tr>
                {canWrite && direct.length > 0 && <th scope="col" style={{ width: 32 }}><span className="sr-only">Select</span></th>}
                <th scope="col">Name</th>
                {filter === "direct" ? <><th scope="col">Source</th><th scope="col">From</th><th scope="col">Until</th><th scope="col">Now</th></> : <><th scope="col" className="num">Ways in</th><th scope="col">Member since</th></>}
                <th scope="col"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => isDirect(r) ? (
                <tr key={r.id}>
                  {canWrite && <td><input type="checkbox" aria-label={`Select ${r.name}`} checked={picked.has(memberRef(r))} onChange={() => togglePick(memberRef(r))} /></td>}
                  <td>{r.name}{r.type === "group" && <span className="faint small"> (group)</span>}{r.reason && <div className="xs faint truncate" style={{ maxWidth: 260 }}>{r.reason}</div>}</td>
                  <td>{r.source}</td>
                  <td>{fmtWhen(r.enabled_from, "Always")}</td>
                  <td>{fmtWhen(r.disabled_at)}</td>
                  <td>{r.active ? "Active" : "Not active"}</td>
                  <td className="row tight">
                    {r.type === "identity" && r.identity_id !== null && <Button size="sm" variant="ghost" icon={<GitBranch size={14} />} onClick={() => setTrace({ id: r.identity_id!, name: r.name })}>Trace</Button>}
                    {canWrite && <Button size="sm" variant="ghost" icon={<Trash2 size={14} />} label={`Remove ${r.name}`} onClick={() => setRemoving([memberRef(r)])} />}
                  </td>
                </tr>
              ) : (
                <tr key={r.identity_id}>
                  {canWrite && direct.length > 0 && <td />}
                  <td>{r.name}</td>
                  <td className="num">{r.support}</td>
                  <td>{fmtWhen(r.since)}</td>
                  <td><Button size="sm" variant="ghost" icon={<GitBranch size={14} />} onClick={() => setTrace({ id: r.identity_id, name: r.name })}>Trace</Button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && data.total > PAGE && (
        <nav className="row" aria-label="Pages">
          <Button size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</Button>
          <span className="small faint" aria-live="polite">Page {page} of {pages} · {data.total.toLocaleString("en-US")} members</span>
          <Button size="sm" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</Button>
        </nav>
      )}
      {data && data.total <= PAGE && data.total > 0 && <p className="small faint">{data.total.toLocaleString("en-US")} {data.total === 1 ? "member" : "members"}</p>}

      {trace && <TraceDrawer groupId={g.id} identity={trace.id} name={trace.name} onClose={() => setTrace(null)} />}
      {add && <AddMembers g={g} mode={add} onClose={() => setAdd(null)} onDone={reload} />}
      {removing && (
        <ChangePreview
          title={removing.length === 1 ? "Remove member" : `Remove ${removing.length} members`}
          changes={removeChanges(g.id, removing)}
          confirmLabel="Remove" danger
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            const res = await groups.batch(g.id, { remove: removing }, idempotencyKey());
            if (isHeld(res)) {
              // the deletion guard held some removals: the rest is applied, the held ones wait for a second admin
              toast(`Removed ${removing.length - res.held} of ${removing.length}: ${res.held} held for approval (threshold ${res.threshold})`, { kind: "info",
                action: { label: "Open held deletion", run: () => nav(`/admin/held-deletions?selected=${encodeURIComponent(res.hold_id)}`) } });
            } else toast(`Removed ${removing.length} ${removing.length === 1 ? "member" : "members"}`);
            setPicked(new Set());
            reload();
          }}
        />
      )}
    </div>
  );
}

/** Add one person or group, or many from a CSV (`identity` or `group`, `enabled_from`, `disabled_at`, `reason`). The preview comes before the write. */
function AddMembers({ g, mode, onClose, onDone }: { g: GrpGroup; mode: "one" | "csv"; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [kind, setKind] = useState<"identity" | "group">("identity");
  const [text, setText] = useState("");
  const [identity, setIdentity] = useState<number | null>(null);
  const [member, setMember] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [reason, setReason] = useState("");
  const [csv, setCsv] = useState<{ name: string; adds: BatchAdd[]; problems: string[] } | null>(null);
  const [preview, setPreview] = useState<BatchAdd[] | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const { data: all } = useLoad<GrpList<GrpGroup>>(kind === "group" ? () => groups.listGroups({ limit: 500 }) : null, `pick:${kind}`);
  const bad = datesProblem(from, to);
  const ready = mode === "csv" ? !!csv && csv.problems.length === 0 && csv.adds.length > 0 : !bad && (kind === "identity" ? identity !== null : !!member);

  const pickFile = async (f: File | undefined) => {
    if (!f) return;
    const parsed = parseMemberRows(parseCsv(await f.text()));
    setCsv({ name: f.name, ...parsed });
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    if (mode === "csv") return setPreview(csv!.adds);
    const a: BatchAdd = kind === "identity" ? { identity: identity! } : { group: member };
    const f = toInstant(from);
    const t = toInstant(to);
    if (f) a.enabled_from = f;
    if (t) a.disabled_at = t;
    if (reason.trim()) a.reason = reason.trim();
    setPreview([a]);
  };

  if (preview) {
    return (
      <ChangePreview
        title={preview.length === 1 ? "Add member" : `Add ${preview.length} members`}
        changes={addChanges(g.id, preview)}
        confirmLabel="Add"
        onClose={() => setPreview(null)}
        onConfirm={async () => {
          await groups.batch(g.id, { add: preview }, idempotencyKey());
          toast(`Added ${preview.length} ${preview.length === 1 ? "member" : "members"}`);
          onDone();
          onClose();
        }}
      />
    );
  }
  return (
    <Drawer title={mode === "csv" ? "Import members from CSV" : "Add a member"} sub={g.name} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="add-members" variant="primary" disabled={!ready}>Preview</Button></>}>
      <form id="add-members" className="stack" onSubmit={submit}>
        {mode === "csv" ? (
          <>
            <p className="muted small">One member per row. Columns: <code>identity</code> (an identity id) or <code>group</code> (a group id); optional <code>enabled_from</code>, <code>disabled_at</code> (dates) and <code>reason</code>. Up to 1,000 rows; the import is all or nothing.</p>
            <input ref={fileRef} type="file" accept=".csv,text/csv" aria-label="CSV file" onChange={(e) => pickFile(e.target.files?.[0])} />
            {csv && (
              <div className="small" aria-live="polite">
                <strong>{csv.name}</strong>: {csv.adds.length} {csv.adds.length === 1 ? "member" : "members"} ready
                {csv.problems.length > 0 && <Callout tone="bad"><ul style={{ margin: 0, paddingLeft: 18 }}>{csv.problems.slice(0, 8).map((p) => <li key={p}>{p}</li>)}{csv.problems.length > 8 && <li>and {csv.problems.length - 8} more</li>}</ul></Callout>}
              </div>
            )}
          </>
        ) : (
          <>
            <label className="field">
              <span>Add a</span>
              <select className="input" value={kind} onChange={(e) => setKind(e.target.value as "identity" | "group")}>
                <option value="identity">Person or account</option>
                <option value="group">Group (nesting)</option>
              </select>
            </label>
            {kind === "identity" ? (
              <IdentityPicker label="Person" text={text} onText={setText} onPick={setIdentity} autoFocus />
            ) : (
              <label className="field">
                <span>Group</span>
                <select className="input" value={member} onChange={(e) => setMember(e.target.value)} data-autofocus>
                  <option value="">Select…</option>
                  {(all?.items ?? []).filter((x) => x.id !== g.id).map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
                </select>
              </label>
            )}
            <div className="row">
              <label className="field grow"><span>Member from <span className="faint">(optional)</span></span><input className="input" type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
              <label className="field grow"><span>Member until <span className="faint">(optional)</span></span><input className="input" type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} /></label>
            </div>
            {bad && <Callout tone="bad">{bad}</Callout>}
            <label className="field"><span>Reason <span className="faint">(optional)</span></span><input className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} /></label>
          </>
        )}
      </form>
    </Drawer>
  );
}
