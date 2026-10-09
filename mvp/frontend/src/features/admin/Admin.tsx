import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeftRight, Bell, CircleCheck, Clock, FileBadge, Fingerprint, KeySquare, LucideIcon, Palette, Play, Plug, ScrollText, Search, Settings, UserCog,
} from "lucide-react";
import { AuditRow, api, fmtDate, relTime, useApi } from "../../api";
import { fuzzy } from "../../app/fuzzy";
import { Badge, Button, Callout, DataTable, EmptyState, Page, PreviewBadge, useToast } from "../../components";
import { ADMIN_BY_ID, ADMIN_SECTIONS, AdminSection, useMockState } from "../../mocks";

const ICONS: Record<string, LucideIcon> = { Plug, Fingerprint, UserCog, Bell, Palette, Clock, ScrollText, FileBadge, ArrowLeftRight, KeySquare };
const Icon = ({ name, size = 18 }: { name: string; size?: number }) => {
  const C = ICONS[name] ?? Settings;
  return <C size={size} aria-hidden />;
};

export function Admin() {
  const [q, setQ] = useState("");
  const nav = useNavigate();
  const shown = useMemo(() => {
    if (!q.trim()) return ADMIN_SECTIONS;
    return ADMIN_SECTIONS
      .map((s) => ({ s, m: fuzzy(q, `${s.title} ${s.summary} ${s.keywords.join(" ")} ${s.will.join(" ")}`) }))
      .filter((x) => x.m)
      .sort((a, b) => b.m!.score - a.m!.score)
      .map((x) => x.s);
  }, [q]);
  return (
    <Page title="Admin" crumbs={[["Settings"], ["Admin"]]} sub="Settings for connections, sign-in, identity rules and the platform itself. Pages marked Preview describe what they will do; the rest are live.">
      <label className="input-icon" style={{ maxWidth: 420, width: "100%", marginBottom: 16 }}>
        <Search size={14} />
        <span className="sr-only">Search settings</span>
        <input className="input" style={{ width: "100%" }} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search settings, e.g. “saml”, “smtp”, “token”" autoFocus />
      </label>
      {shown.length === 0 ? (
        <div className="card"><EmptyState title="No settings match" icon={<Search size={18} />}>Try a broader word, or press {"⌘K"} to search everything.</EmptyState></div>
      ) : (
        <div className="settings-grid">
          {shown.map((s) => (
            <Link key={s.id} to={`/admin/${s.id}`} className="card setting-card" onKeyDown={(e) => e.key === " " && nav(`/admin/${s.id}`)}>
              <span className="s-ic"><Icon name={s.icon} /></span>
              <span className="stack-sm" style={{ minWidth: 0 }}>
                <span className="row tight"><b style={{ color: "var(--text)" }}>{s.title}</b>{s.live ? <Badge tone="ok">Live</Badge> : <PreviewBadge />}</span>
                <span className="small muted">{s.summary}</span>
              </span>
            </Link>
          ))}
        </div>
      )}
    </Page>
  );
}

// ---------------------------------------------------------------- live bits
function Jobs() {
  const toast = useToast();
  const [ran, setRan] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const jobs: { id: string; name: string; schedule: string; run: () => Promise<string> }[] = [
    { id: "sync", name: "Connector sync", schedule: "On demand (demo)", run: async () => { const s = await api<Record<string, number>>("/connectors/sync", {}); return Object.entries(s).slice(0, 3).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(", "); } },
    { id: "sweep", name: "Just-in-time expiry sweeper", schedule: "Every 30 seconds", run: async () => { const r = await api<{ expired: number }>("/jit/sweep", {}); return `${r.expired} elevations expired`; } },
  ];
  const run = async (j: (typeof jobs)[number]) => {
    setBusy(j.id);
    try {
      const out = await j.run();
      setRan({ ...ran, [j.id]: new Date().toISOString() });
      toast(`${j.name}: ${out}`);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="card flush">
      <div className="table-scroll">
        <table>
          <thead><tr><th>Job</th><th>Schedule</th><th>Last run here</th><th /></tr></thead>
          <tbody>
            {jobs.map((j) => (
              <tr key={j.id}>
                <td><b>{j.name}</b></td>
                <td className="small">{j.schedule}</td>
                <td className="small">{ran[j.id] ? <span className="row tight"><CircleCheck size={13} style={{ color: "var(--ok)" }} aria-hidden /> {relTime(ran[j.id].replace("Z", ""))}</span> : <span className="faint">Not run from this page</span>}</td>
                <td className="actions-cell"><Button size="sm" icon={<Play size={13} />} disabled={busy === j.id} onClick={() => run(j)}>Run now</Button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AuditLog() {
  const { data, error } = useApi<AuditRow[]>("/audit?limit=500");
  const mock = useMockState();
  return (
    <div className="stack">
      <DataTable
        id="audit"
        rows={data}
        error={error}
        rowKey={(r) => r.id}
        initialSort={["at", -1]}
        columns={[
          { id: "at", header: "When", sort: (r) => r.at, cell: (r) => <span className="small nowrap">{fmtDate(r.at)}</span> },
          { id: "actor", header: "Actor", sort: (r) => r.actor, cell: (r) => <span className="small">{r.actor}</span> },
          { id: "action", header: "Action", sort: (r) => r.action, cell: (r) => <code className="small">{r.action}</code> },
          { id: "detail", header: "Detail", csv: (r) => JSON.stringify(r.detail), cell: (r) => <span className="xs faint sys truncate" style={{ display: "block", maxWidth: 480 }}>{JSON.stringify(r.detail)}</span>, hideNarrow: true },
        ]}
        searchText={(r) => `${r.actor} ${r.action} ${JSON.stringify(r.detail)}`}
        searchPlaceholder="Search actor, action or detail…"
        filters={[{ id: "action", label: "Action", options: [...new Set((data ?? []).map((r) => r.action))].sort().map((a) => ({ value: a, label: a })), get: (r) => r.action }]}
      />
      {mock.log.length > 0 && (
        <div className="card flush">
          <div className="card-h"><h2 className="row tight">Preview actions in this browser <PreviewBadge /></h2><span className="xs faint tnum">{mock.log.length}</span></div>
          <div className="table-scroll" style={{ maxHeight: 300 }}>
            <table>
              <tbody>
                {mock.log.slice(0, 50).map((l, i) => (
                  <tr key={i}><td className="small nowrap">{fmtDate(l.at.replace("Z", ""))}</td><td className="small">{l.actor}</td><td><code className="small">{l.action}</code></td><td className="small">{l.target}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

const LIVE: Record<string, () => JSX.Element> = { jobs: Jobs, audit: AuditLog };

export function AdminSectionPage() {
  const { section } = useParams();
  const s: AdminSection | undefined = section ? ADMIN_BY_ID[section] : undefined;
  if (!s) {
    return (
      <Page title="Setting not found" crumbs={[["Settings"], ["Admin", "/admin"], ["Not found"]]}>
        <div className="card"><EmptyState title="That settings page doesn't exist" action={<Link to="/admin">All settings</Link>}>Search the admin page for what you need.</EmptyState></div>
      </Page>
    );
  }
  const Live = LIVE[s.id];
  return (
    <Page title={s.title} badge={s.live ? undefined : <PreviewBadge />} crumbs={s.id === "connections" ? [["Settings"], [s.title]] : [["Settings"], ["Admin", "/admin"], [s.title]]} sub={s.summary}>
      <div className="stack">
        {Live && <Live />}
        <div className="card stack-sm">
          <h2 className="row tight"><Icon name={s.icon} size={16} /> {s.live ? "Coming next on this page" : "What this page will do"}</h2>
          <ul className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8 }}>
            {s.will.map((w) => <li key={w}>{w}</li>)}
          </ul>
          {!s.live && <Callout tone="neutral">This is a Preview. Nothing here is saved yet: the settings API is part of a later phase.</Callout>}
        </div>
      </div>
    </Page>
  );
}
