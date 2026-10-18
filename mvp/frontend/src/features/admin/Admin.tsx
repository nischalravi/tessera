import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Activity, ArrowLeftRight, Bell, Mail, CircleCheck, Clock, Download, FileBadge, Fingerprint, KeySquare, LucideIcon, Palette, Play, Plug, ScrollText, Search, Settings, ShieldCheck, UserCog,
} from "lucide-react";
import { AuditRow, AuditVerifyReport, api, fmtDate, useApi } from "../../api";
import { fuzzy } from "../../app/fuzzy";
import { Badge, Button, Callout, DataTable, EmptyState, Page, PreviewBadge, useToast } from "../../components";
import { EmailDelivery } from "../notifications/EmailDelivery";
import { NotificationsAdminPanel } from "../notifications/Notifications";
import { ADMIN_BY_ID, ADMIN_SECTIONS, AdminSection, useMockState } from "../../mocks";
import { Jobs } from "./Jobs";
import { Provisioning } from "./Provisioning";
import { ConfigTransfer } from "./ConfigTransfer";

const ICONS: Record<string, LucideIcon> = { Plug, Fingerprint, UserCog, Bell, Mail, Palette, Clock, ScrollText, FileBadge, ArrowLeftRight, KeySquare, Activity };
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
const OUTCOME_TONE: Record<string, "ok" | "warning" | "critical" | "neutral"> = { success: "ok", denied: "critical", failure: "warning", error: "critical" };

/** Read-only view of the tenant's hash-chained audit ledger (design §13, §17). */
function AuditLog() {
  const [withHttp, setWithHttp] = useState(false);
  const { data, error } = useApi<AuditRow[]>(`/audit?limit=500${withHttp ? "&include_http=true" : ""}`);
  const [report, setReport] = useState<AuditVerifyReport | null>(null);
  const [verifying, setVerifying] = useState(false);
  const toast = useToast();
  const mock = useMockState();
  const verify = async () => {
    setVerifying(true);
    try {
      setReport(await api<AuditVerifyReport>("/audit/verify", {}));
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setVerifying(false);
    }
  };
  const route = (r: AuditRow) => (r.http ? `${r.http.method} ${r.http.route ?? "(no route)"} → ${r.http.status}` : "");
  return (
    <div className="stack">
      <div className="card stack-sm">
        <div className="spread">
          <h2 className="row tight"><ShieldCheck size={16} aria-hidden /> Tamper-evident ledger</h2>
          <span className="row tight">
            <Button size="sm" icon={<ShieldCheck size={13} />} disabled={verifying} onClick={verify}>{verifying ? "Verifying…" : "Verify chain"}</Button>
            <a className="btn sm" href="/api/audit/export" download><Download size={13} aria-hidden /> Export (NDJSON)</a>
          </span>
        </div>
        <p className="small muted" style={{ margin: 0 }}>
          Every event is linked to the one before it by a SHA-256 hash, and the chain head is signed and anchored outside the database every few minutes. Rows cannot be edited or deleted. Every event names the signed-in user who caused it, with how they authenticated; requests without a session are recorded as <b>anonymous</b> with the reason. The browser cannot choose the actor.
        </p>
        {report && (
          <Callout tone={report.result === "ok" ? "ok" : report.result === "warning" ? "warn" : "bad"}>
            <b>{report.result === "ok" ? "Chain verified." : report.result === "warning" ? "Chain verified with warnings." : `Verification failed (exit ${report.exit_code}).`}</b>{" "}
            {report.events} events (seq {report.first_seq}–{report.last_seq}), {report.checkpoints} signed checkpoints, {report.anchored} anchored.
            {report.problems.length > 0 && (
              <ul className="small" style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                {report.problems.slice(0, 10).map((p, i) => <li key={i}><code>{p.kind}</code>{p.seq ? ` at seq ${p.seq}` : ""}: {p.detail}</li>)}
              </ul>
            )}
          </Callout>
        )}
      </div>
      <DataTable
        id="audit"
        rows={data}
        error={error}
        rowKey={(r) => r.event_id ?? r.id}
        initialSort={["seq", -1]}
        toolbarExtra={
          <label className="row tight small">
            <input type="checkbox" checked={withHttp} onChange={(e) => setWithHttp(e.target.checked)} /> Include API requests
          </label>
        }
        columns={[
          { id: "seq", header: "#", sort: (r) => r.seq ?? r.id, cell: (r) => <span className="small tnum faint">{r.seq ?? r.id}</span> },
          { id: "at", header: "When", sort: (r) => r.at, cell: (r) => <span className="small nowrap">{fmtDate(r.at)}</span> },
          {
            id: "actor", header: "Actor", sort: (r) => r.actor,
            cell: (r) => <span className="row tight small">{r.actor}{r.actor_type && r.actor_type !== "system" && r.actor !== r.actor_type && <Badge tone="outline">{r.actor_type}</Badge>}{r.actor_type === "anonymous" && r.actor === "anonymous" && <Badge tone="outline">unauthenticated</Badge>}</span>,
          },
          { id: "action", header: "Action", sort: (r) => r.action, cell: (r) => <div><code className="small">{r.action}</code>{r.http && <div className="xs faint sys">{route(r)}</div>}</div> },
          { id: "outcome", header: "Outcome", sort: (r) => r.outcome ?? "", cell: (r) => r.outcome ? <Badge tone={OUTCOME_TONE[r.outcome] ?? "neutral"}>{r.outcome}</Badge> : null, hideNarrow: true },
          { id: "target", header: "Target", csv: (r) => (r.target ? `${r.target.type}:${r.target.id}` : ""), cell: (r) => r.target ? <span className="small">{r.target.type} {r.target.id}</span> : <span className="faint xs">—</span>, hideNarrow: true },
          { id: "detail", header: "Detail", csv: (r) => JSON.stringify(r.detail), cell: (r) => <span className="xs faint sys truncate" style={{ display: "block", maxWidth: 420 }}>{JSON.stringify(r.detail)}</span>, hideNarrow: true },
          { id: "hash", header: "Hash", csv: (r) => r.hash ?? "", cell: (r) => <span className="xs faint sys" title={`hash ${r.hash}\nprev ${r.prev_hash}`}>{r.hash?.slice(0, 10)}</span>, hideNarrow: true },
        ]}
        searchText={(r) => `${r.actor} ${r.action} ${r.actor_type ?? ""} ${r.outcome ?? ""} ${route(r)} ${JSON.stringify(r.detail)} ${r.hash ?? ""}`}
        searchPlaceholder="Search actor, action, route, detail or hash…"
        filters={[
          { id: "action", label: "Action", options: [...new Set((data ?? []).map((r) => r.action))].sort().map((a) => ({ value: a, label: a })), get: (r) => r.action },
          { id: "outcome", label: "Outcome", options: ["success", "denied", "failure", "error"].map((o) => ({ value: o, label: o })), get: (r) => r.outcome ?? "" },
          { id: "actor_type", label: "Actor type", options: ["anonymous", "system", "user", "api_client", "operator"].map((o) => ({ value: o, label: o })), get: (r) => r.actor_type ?? "" },
        ]}
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

const LIVE: Record<string, () => React.JSX.Element> = { jobs: Jobs, audit: AuditLog, provisioning: Provisioning, "config-transfer": ConfigTransfer, notifications: NotificationsAdminPanel, "email-delivery": EmailDelivery };

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
