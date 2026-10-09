/** Searchable entities shared by the command palette and the top-bar global search. */
import { ReactNode, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { AppWindow, Bot, FileText, KeyRound, Layers, Server, Settings, UserRound } from "lucide-react";
import { ConnectorRow, Group, IdentityRow, useApi } from "../api";
import { ADMIN_SECTIONS, ROLES } from "../mocks";
import { allPages } from "./nav";
import { Match, rank } from "./fuzzy";

export interface Entry {
  id: string;
  group: string;
  label: string;
  sub?: string;
  icon: ReactNode;
  keywords?: string;
  hint?: string;
  run?: () => void;
  /** Drill-in: selecting the entry replaces the list with these entries. */
  next?: { scope: string; entries: () => Entry[] };
  identity?: IdentityRow;
}

export interface Ranked { e: Entry; m: Match }

export function useEntityEntries() {
  const nav = useNavigate();
  const { data: idents } = useApi<IdentityRow[]>("/identities");
  const { data: groups } = useApi<Group[]>("/groups");
  const { data: conns } = useApi<ConnectorRow[]>("/connectors");
  return useMemo(() => {
    const out: Entry[] = [];
    for (const i of idents ?? []) {
      const machine = i.type !== "human";
      out.push({
        id: `id-${i.id}`,
        group: machine ? "Machine identities & agents" : "Users",
        label: i.name,
        sub: [i.title, i.department, i.status !== "active" ? i.status : null].filter(Boolean).join(" · ") || (machine ? "Service account" : ""),
        icon: i.type === "ai_agent" ? <Bot size={15} /> : i.type === "service" ? <Server size={15} /> : <UserRound size={15} />,
        keywords: `${i.email ?? ""} ${i.department ?? ""} ${i.title ?? ""}`,
        run: () => nav(`/directory/${machine ? "machine" : "people"}?selected=${i.id}`),
        identity: i,
      });
    }
    for (const r of ROLES) out.push({ id: `role-${r.id}`, group: "Roles", label: r.name, sub: `Business role · ${r.members} members`, icon: <Layers size={15} />, keywords: r.entitlements.join(" "), run: () => nav(`/directory/roles?selected=${r.id}`) });
    for (const g of groups ?? []) out.push({ id: `grp-${g.id}`, group: "Entitlements", label: `${g.system}:${g.name}`, sub: [g.kind.replace(/_/g, " "), g.privileged ? "privileged" : null, g.requestable ? "JIT-eligible" : null].filter(Boolean).join(" · "), icon: <KeyRound size={15} />, keywords: g.description ?? "", run: () => nav(`/directory/entitlements?selected=${g.id}`) });
    for (const c of conns ?? []) out.push({ id: `app-${c.system}`, group: "Applications & systems", label: c.name, sub: `${c.accounts} accounts · ${c.groups} groups`, icon: <AppWindow size={15} />, keywords: c.system, run: () => nav(`/directory/apps?selected=${c.system}`) });
    for (const p of allPages()) out.push({ id: `page-${p.path}`, group: "Pages", label: p.label, sub: p.section || undefined, icon: <FileText size={15} />, keywords: `${p.section} ${p.keywords ?? ""}`, run: () => nav(p.path) });
    for (const s of ADMIN_SECTIONS) out.push({ id: `admin-${s.id}`, group: "Pages", label: s.title, sub: "Admin", icon: <Settings size={15} />, keywords: s.keywords.join(" "), run: () => nav(`/admin/${s.id}`) });
    return out;
  }, [idents, groups, conns, nav]);
}

const GROUP_ORDER = ["Actions", "Users", "Machine identities & agents", "Roles", "Entitlements", "Applications & systems", "Pages", "Settings"];

/** Rank entries and cap each group, returning them in display order. */
export function rankEntries(query: string, entries: Entry[], perGroup = 6): Ranked[] {
  const scored: Ranked[] = [];
  for (const e of entries) {
    const m = rank(query, e.label, `${e.sub ?? ""} ${e.keywords ?? ""}`);
    if (m) scored.push({ e, m });
  }
  scored.sort((a, b) => b.m.score - a.m.score);
  const byGroup = new Map<string, Ranked[]>();
  for (const r of scored) {
    const g = byGroup.get(r.e.group) ?? [];
    if (g.length < perGroup) g.push(r);
    byGroup.set(r.e.group, g);
  }
  // groups ordered by their best hit when searching, by a fixed order otherwise
  const groups = [...byGroup.keys()].sort((a, b) =>
    query.trim() ? byGroup.get(b)![0].m.score - byGroup.get(a)![0].m.score : GROUP_ORDER.indexOf(a) - GROUP_ORDER.indexOf(b),
  );
  return groups.flatMap((g) => byGroup.get(g)!);
}

export function Highlight({ text, indices }: { text: string; indices: number[] }) {
  if (!indices.length) return <>{text}</>;
  const set = new Set(indices);
  const parts: ReactNode[] = [];
  let buf = "", on = false;
  const flush = (k: number) => {
    if (buf) parts.push(on ? <mark key={k}>{buf}</mark> : buf);
    buf = "";
  };
  [...text].forEach((ch, i) => {
    const hit = set.has(i);
    if (hit !== on) {
      flush(i);
      on = hit;
    }
    buf += ch;
  });
  flush(text.length);
  return <>{parts}</>;
}

/** Grouped, keyboard-highlighted result list (listbox semantics). */
export function ResultList({ items, active, onPick, onHover, id }: { items: Ranked[]; active: number; onPick: (e: Entry) => void; onHover: (i: number) => void; id: string }) {
  let lastGroup = "";
  return (
    <div role="listbox" id={id} aria-label="Results">
      {items.map(({ e, m }, i) => {
        const header = e.group !== lastGroup ? <div className="res-group" role="presentation">{e.group}</div> : null;
        lastGroup = e.group;
        return (
          <div key={e.id}>
            {header}
            <div
              id={`${id}-${i}`}
              role="option"
              aria-selected={i === active}
              className="res"
              onMouseMove={() => i !== active && onHover(i)}
              onMouseDown={(ev) => ev.preventDefault()}
              onClick={() => onPick(e)}
            >
              <span className="res-ic" aria-hidden>{e.icon}</span>
              <span className="grow truncate">
                <Highlight text={e.label} indices={m.indices} />
                {e.sub && <span className="res-sub"> · {e.sub}</span>}
              </span>
              {(e.hint || e.next) && <span className="res-hint">{e.hint ?? "Actions"}{i === active && <kbd>↵</kbd>}</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}
