import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ArrowRight, ClipboardCheck, Inbox as InboxIcon, KeyRound, ShoppingCart, Timer, Users } from "lucide-react";
import { ActivityEvent, AuditRow, ConnectorRow, DeploymentHealth, JitRequest, Policy, ReadinessSummary, RemovalRequest, RequestLine, Violation, activityPath, relTime, removalsPath, useApi } from "../../api";
import { usePersona } from "../../app/persona";
import { useSession } from "../../app/auth";
import { Badge, Bar, Button, ButtonLink, EmptyState, Kpi, Loading, Page, Status, Tabs } from "../../components";
import { DeploymentHealthBody, ReadinessAttentionCard, ReadinessKpi } from "../insights/DeploymentHealth";
import { RiskyTable, Summary, Trend } from "../insights/RiskOverview";
import { InboxItem, useInbox, useOpenCampaigns } from "../inbox/model";
import { itemTitle } from "../inbox/Inbox";

function greeting() {
  const h = new Date().getHours();
  return h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
}

function WaitingOnYou({ items }: { items: InboxItem[] | null }) {
  const nav = useNavigate();
  return (
    <div className="card flush">
      <div className="card-h">
        <h2 className="row tight"><InboxIcon size={16} aria-hidden /> Waiting on you</h2>
        {items && items.length > 0 && <Link to="/inbox" className="small">Open inbox ({items.length})</Link>}
      </div>
      {!items ? <Loading /> : items.length === 0 ? (
        <EmptyState title="You're all caught up" icon={<ClipboardCheck size={18} />}>
          Nothing needs your decision right now. New approvals, review items and tasks will show up here.
        </EmptyState>
      ) : (
        <div>
          {items.slice(0, 6).map((it) => {
            const t = itemTitle(it);
            return (
              <div key={it.key} className="qrow" style={{ gridTemplateColumns: "28px minmax(0,1fr) auto" }} onClick={() => nav(`/inbox?item=${it.key}`)} role="link" tabIndex={0} onKeyDown={(e) => e.key === "Enter" && nav(`/inbox?item=${it.key}`)}>
                <span className="q-ic" aria-hidden>{t.icon}</span>
                <span className="grow" style={{ minWidth: 0 }}>
                  <span className="q-title truncate" style={{ display: "block" }}>{t.title}</span>
                  <span className="q-meta">{t.meta}</span>
                </span>
                <Badge tone={t.tone}>{t.kindLabel}</Badge>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function YourAccess({ id }: { id: number }) {
  const { data: d, error } = useApi<any>(`/identities/${id}`);
  const { data: jit } = useApi<JitRequest[]>("/jit/requests");
  const active = (jit ?? []).filter((r) => r.identity.id === id && r.status === "approved");
  return (
    <div className="card flush">
      <div className="card-h">
        <h2 className="row tight"><KeyRound size={16} aria-hidden /> Your access</h2>
        <Link to="/access/mine" className="small">See all</Link>
      </div>
      {!d ? <Loading error={error} kind="block" /> : (
        <div className="card-b stack">
          <div className="stat-row">
            <div className="s"><b>{d.accounts.length}</b><span>accounts</span></div>
            <div className="s"><b>{d.grants.length}</b><span>grants</span></div>
            <div className="s"><b>{d.risk?.effective ?? 0}</b><span>permissions</span></div>
            <div className="s"><b style={{ color: d.risk?.unused ? "var(--warning)" : undefined }}>{d.risk?.unused ?? 0}</b><span>unused 60 days</span></div>
          </div>
          {active.length > 0 && (
            <div className="callout ok">
              <Timer size={16} />
              <span>Active elevation: {active.map((r) => `${r.group.system}:${r.group.name}`).join(", ")}, expires {relTime(r0(active).expires_at)}.</span>
            </div>
          )}
          {(d.risk?.unused ?? 0) > 0 && (
            <div className="small muted">You hold {d.risk.unused} permissions you haven't used in 60 days. Removing them keeps you out of the next review. <Link to="/access/mine?filter=unused">Review unused access</Link></div>
          )}
          <div className="row tight">{[...new Set<string>(d.accounts.map((a: any) => a.system))].map((s) => <span key={s} className="chip sys">{s}</span>)}</div>
        </div>
      )}
    </div>
  );
}
const r0 = (xs: JitRequest[]) => xs[0];

function RequestCta() {
  const { data: groups } = useApi<any[]>("/groups?requestable=true");
  return (
    <div className="card stack-sm" style={{ background: "var(--accent-soft)", borderColor: "transparent" }}>
      <h2 className="row tight"><ShoppingCart size={16} aria-hidden /> Need access to something?</h2>
      <p className="muted">Search the catalog of roles, apps and entitlements. Tessera checks for policy conflicts before you submit, and privileged access is granted just in time.</p>
      <div className="row mt-sm">
        <ButtonLink to="/access/request" variant="primary" icon={<ArrowRight size={15} />}>Request access</ButtonLink>
        {(groups ?? []).slice(0, 3).map((g) => (
          <Link key={g.id} to={`/access/request?q=${encodeURIComponent(g.name)}`} className="chip sys">{g.system}:{g.name}</Link>
        ))}
      </div>
    </div>
  );
}

function MyRequests({ id }: { id: number }) {
  const { data: jit } = useApi<JitRequest[]>("/jit/requests");
  const { data: lines } = useApi<RequestLine[]>("/requests?scope=mine");
  const { data: removals } = useApi<RemovalRequest[]>(removalsPath("mine"));
  const mine = [
    ...(jit ?? []).filter((r) => r.identity.id === id).map((r) => ({ key: `j${r.id}`, label: `${r.group.system}:${r.group.name}`, status: r.status, at: r.requested_at, sub: `Just-in-time, ${r.duration_hours} h` })),
    ...(lines ?? []).map((l) => ({ key: l.id, label: `${l.group.system}:${l.group.name}`, status: l.status, at: l.requested_at, sub: "Catalog request" })),
    ...(removals ?? []).filter((q) => q.beneficiary.id === id).map((q) => ({ key: q.id, label: `${q.group.system}:${q.group.name}`, status: q.status, at: q.requested_at, sub: "Removal request" })),
  ].sort((a, b) => b.at.localeCompare(a.at)).slice(0, 5);
  return (
    <div className="card flush">
      <div className="card-h"><h2>Your recent requests</h2><Link to="/access/requests" className="small">History</Link></div>
      {!jit || !lines || !removals ? <Loading kind="block" /> : mine.length === 0 ? (
        <EmptyState title="No requests yet">Requests you make, and requests made for you, will show here with their status.</EmptyState>
      ) : (
        <table>
          <tbody>
            {mine.map((r) => (
              <tr key={r.key}>
                <td><b className="small">{r.label}</b><div className="xs faint">{r.sub}</div></td>
                <td className="nowrap"><Status s={r.status} /></td>
                <td className="small faint nowrap hide-narrow">{relTime(r.at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

const ACTIVITY_LABEL: Record<string, string> = {
  "request.submit": "Submitted an access request",
  "request.cancel": "Cancelled an access request",
  "request.approve": "Approved an access request",
  "request.deny": "Denied an access request",
  "request.remove": "Removed access",
  "request.draft.save": "Saved a request draft",
  "request.draft.delete": "Deleted a request draft",
  "removal.request.submit": "Asked for access to be removed",
  "removal.request.approve": "Approved a removal request",
  "removal.request.deny": "Denied a removal request",
  "removal.request.cancel": "Cancelled a removal request",
  "role.request.submit": "Requested a role",
  "identity.disable": "Disabled an identity",
  "identity.enable": "Enabled an identity",
  "containment.run": "Ran containment",
};
const activityLabel = (a: string) => ACTIVITY_LABEL[a] ?? a.replace(/[._]/g, " ").replace(/^./, (c) => c.toUpperCase());

/** Your own recent changes, from the audit ledger. It lists only what you did, never other people's activity. */
function RecentActivity() {
  const { data, error } = useApi<ActivityEvent[]>(activityPath(8));
  return (
    <div className="card flush">
      <div className="card-h"><h2>Your recent activity</h2></div>
      {!data ? <Loading error={error} kind="block" /> : data.length === 0 ? (
        <EmptyState title="Nothing yet">Changes you make, such as requests and approvals, are listed here from the audit log.</EmptyState>
      ) : (
        <table>
          <tbody>
            {data.map((e) => (
              <tr key={e.id}>
                <td><b className="small">{activityLabel(e.action)}</b></td>
                <td className="small faint nowrap">{relTime(e.occurred_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function TeamOverview({ meId }: { meId: number }) {
  const campaigns = useOpenCampaigns();
  const { data: jit } = useApi<JitRequest[]>("/jit/requests");
  const pending = (jit ?? []).filter((r) => r.status === "pending");
  const mine = (campaigns ?? []).flatMap((c) => (c.review_items ?? []).filter((i) => i.reviewer?.id === meId));
  const decided = mine.filter((i) => i.decision).length;
  const pct = mine.length ? Math.round((100 * decided) / mine.length) : 100;
  return (
    <div className="grid g2">
      <div className="card flush">
        <div className="card-h"><h2 className="row tight"><Users size={16} aria-hidden /> Team approvals</h2><Link to="/inbox?filter=approval" className="small">Approve in inbox</Link></div>
        {!jit ? <Loading kind="block" /> : pending.length === 0 ? (
          <EmptyState title="No pending approvals">When someone on your team requests access, it lands here and in your inbox.</EmptyState>
        ) : (
          <table>
            <tbody>
              {pending.map((r) => (
                <tr key={r.id}>
                  <td><b className="small">{r.identity.name}</b><div className="xs faint wrap-anywhere">{r.justification}</div></td>
                  <td className="small"><span className="sys">{r.group.system}:{r.group.name}</span>{r.group.privileged && <> <Badge tone="warning">Privileged</Badge></>}</td>
                  <td className="small faint nowrap hide-narrow">{relTime(r.requested_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="card stack-sm">
        <div className="spread"><h2 className="row tight"><ClipboardCheck size={16} aria-hidden /> Your review progress</h2><Link to="/inbox?filter=review" className="small">Continue</Link></div>
        {!campaigns ? <Loading kind="block" /> : (
          <>
            <div className="row" style={{ alignItems: "baseline" }}>
              <span style={{ fontSize: "var(--fs-3xl)", fontWeight: 600 }} className="tnum">{pct}%</span>
              <span className="muted tnum">{decided} of {mine.length} items decided</span>
            </div>
            <Bar value={decided} max={Math.max(1, mine.length)} tone="ok" />
            <p className="small muted">{campaigns.length ? `${campaigns[0].name}: ${campaigns[0].auto_certified} of ${campaigns[0].total_grants} grants were auto-certified from usage, so you only see exceptions.` : "No open campaigns."}</p>
          </>
        )}
      </div>
    </div>
  );
}

interface Attention { key: string; tone: "crit" | "warn" | "info"; title: string; sub: string; to: string }

/** "Needs attention" items for the tenant, built from live summary and violation data. */
function useAttention(): Attention[] | null {
  const { data: d } = useApi<Summary>("/summary");
  const { data: violations } = useApi<Violation[]>("/violations");
  if (!d || !violations) return null;
  const out: Attention[] = [];
  const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  [...violations].sort((a, b) => sevRank[a.severity] - sevRank[b.severity]).slice(0, 2).forEach((v) =>
    out.push({ key: v.key, tone: v.severity === "critical" ? "crit" : "warn", title: v.message, sub: `${v.policy_name} · ${v.identity_name}`, to: `/governance/policies?selected=${encodeURIComponent(v.key)}` }),
  );
  if (d.nhi.orphaned) out.push({ key: "nhi", tone: "crit", title: `${d.nhi.orphaned} machine identit${d.nhi.orphaned === 1 ? "y has" : "ies have"} no live owner`, sub: `${d.nhi.stale_secrets} stale secrets · ${d.nhi.agents_with_pii} AI agents reach PII`, to: "/directory/machine" });
  if (d.recommendations.remove) out.push({ key: "lp", tone: "warn", title: `${d.recommendations.remove} grants are safe to remove`, sub: `${d.unused_pct}% of effective permissions went unused in 60 days`, to: "/insights/least-privilege" });
  if (d.hris_pending) out.push({ key: "hris", tone: "warn", title: `${d.hris_pending} lifecycle event${d.hris_pending === 1 ? " is" : "s are"} waiting to run`, sub: "Joiner, mover and leaver plans from Workday", to: "/governance/lifecycle" });
  if (d.jit.pending) out.push({ key: "jit", tone: "info", title: `${d.jit.pending} just-in-time request${d.jit.pending === 1 ? " needs" : "s need"} approval`, sub: `${d.jit.active} elevations active now`, to: "/inbox?filter=approval" });
  if (d.reviews.open_items) out.push({ key: "rev", tone: "info", title: `${d.reviews.open_items} access review item${d.reviews.open_items === 1 ? " is" : "s are"} open`, sub: "Exception-only campaigns", to: "/governance/reviews" });
  return out;
}

function AttentionList({ items, limit }: { items: Attention[] | null; limit?: number }) {
  const nav = useNavigate();
  if (!items) return <Loading kind="block" />;
  if (!items.length) return <EmptyState title="Nothing needs attention" icon={<ClipboardCheck size={18} />}>No open violations, orphaned identities or pending work.</EmptyState>;
  return (
    <div>
      {items.slice(0, limit).map((a) => (
        <div key={a.key} className="att">
          <span className={`att-bar ${a.tone}`} aria-hidden />
          <div className="grow"><b>{a.title}</b><div className="small faint">{a.sub}</div></div>
          <Button size="sm" onClick={() => nav(a.to)} aria-label={`Review: ${a.title}`}>Review</Button>
        </div>
      ))}
    </div>
  );
}

type HomeTab = "overview" | "monitoring" | "deployment" | "recommendations";

/** Home → Deployment health: the compact dashboard, linking to Insights. */
function DeploymentTab() {
  const { data, error } = useApi<DeploymentHealth>("/insights/deployment-health");
  if (!data) return <Loading error={error} kind="page" />;
  return (
    <div className="stack">
      <DeploymentHealthBody data={data} compact />
      <Link to="/insights/deployment-health">Open Deployment health for skipped items, drift and the full connection table</Link>
    </div>
  );
}

function AdminHome() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") ?? "overview") as HomeTab;
  const setTab = (t: HomeTab) => setParams(t === "overview" ? {} : { tab: t }, { replace: true });
  const { data: d, error } = useApi<Summary>("/summary");
  const { data: conns } = useApi<ConnectorRow[]>("/connectors");
  const { data: policies } = useApi<Policy[]>("/policies");
  const { data: audit } = useApi<AuditRow[]>("/audit?limit=100");
  const { items } = useInbox("mine");
  const attention = useAttention();
  const { data: rsum, error: rerr } = useApi<{ readiness: ReadinessSummary }>("/summary?include=readiness");
  const TENANT = useSession().session.tenant.name;
  const lastSync = audit?.find((a) => /sync/i.test(a.action))?.at ?? null;
  const has = (s: string) => conns?.some((c) => c.system === s);
  const sev = d?.violations.by_severity ?? {};
  return (
    <Page
      title={TENANT}
      crumbs={false}
      sub={`Tenant overview · ${conns ? conns.length : "…"} sources · ${lastSync ? `synced ${relTime(lastSync)}` : "synced from seed data"}`}
      tabs={<Tabs<HomeTab> label="Home" value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "monitoring", label: "Monitoring" }, { id: "deployment", label: "Deployment health" }, { id: "recommendations", label: "Recommendations" }]} />}
    >
      <div role="tabpanel" className="stack">
        {!d ? (
          <>
            {tab === "overview" && <div className="grid g4"><ReadinessKpi data={rsum?.readiness} error={rerr} /></div>}
            <Loading error={error} kind="page" />
          </>
        ) : tab === "overview" ? (
          <>
            <div className="grid g4">
              <Kpi label="Identities" value={(d.identities.human + d.identities.service + d.identities.ai_agent).toLocaleString()} sub={<Badge tone="info">{d.identities.human} people · {d.identities.service} machine · {d.identities.ai_agent} agents</Badge>} to="/directory/people" />
              <Kpi label="Violations" value={d.violations.total} sub={<Badge tone="critical">{sev.critical ?? 0} critical · {sev.high ?? 0} high</Badge>} to="/governance/policies" />
              <Kpi label="Unused permissions" value={`${d.unused_pct}%`} sub={<Badge tone="warning">{d.recommendations.remove} safe to remove</Badge>} to="/insights/least-privilege" />
              <ReadinessKpi data={rsum?.readiness} error={rerr} />
            </div>
            <ReadinessAttentionCard data={rsum?.readiness} error={rerr} />
            <div className="grid g21">
              <div className="card">
                <div className="spread" style={{ marginBottom: 4 }}><h2>Recommendations</h2>{attention && attention.length > 4 && <button type="button" className="btn ghost sm" onClick={() => setTab("recommendations")}>See all {attention.length}</button>}</div>
                <AttentionList items={attention} limit={4} />
              </div>
              <div className="card">
                <h2 style={{ marginBottom: 10 }}>Basic information</h2>
                <dl className="kv">
                  <dt>Tenant</dt><dd>{TENANT}</dd>
                  <dt>Primary IdP</dt><dd>{has("okta") ? "Okta (OIDC)" : <span className="faint">Not connected</span>}</dd>
                  <dt>HR source</dt><dd>{has("workday") ? "Workday" : <span className="faint">Not connected</span>}</dd>
                  <dt>Connections</dt><dd><Link to="/admin/connections">{conns ? `${conns.length} active` : "…"}</Link></dd>
                  <dt>Accounts</dt><dd className="tnum">{d.accounts.toLocaleString()} across {d.systems} systems</dd>
                  <dt>Policies</dt><dd><Link to="/governance/policies">{policies ? `${policies.length} in Git` : "…"}</Link> · evaluated on every change</dd>
                  <dt>Environment</dt><dd><Badge>demo</Badge></dd>
                </dl>
              </div>
            </div>
          </>
        ) : tab === "monitoring" ? (
          <>
            <div className="grid g4">
              <Kpi label="Approvals waiting" value={d.jit.pending} sub={`${d.jit.active} active elevations`} to="/inbox?filter=approval" />
              <Kpi label="Review items open" value={d.reviews.open_items} sub="exception-only campaigns" to="/governance/reviews" />
              <Kpi label="Lifecycle tasks" value={d.hris_pending} sub="joiner, mover, leaver" to="/governance/lifecycle" />
              <Kpi label="Machine identity risk" value={d.nhi.orphaned} sub={`without an owner · ${d.nhi.stale_secrets} stale secrets`} to="/directory/machine" />
            </div>
            <div className="card">
              <div className="spread"><h2>Permission usage, last 90 days</h2><span className="xs faint">Daily events from connector audit logs</span></div>
              <Trend points={d.usage_trend} />
            </div>
            <div className="grid g21">
              <div className="card flush">
                <div className="card-h"><h2>Riskiest identities</h2><Link to="/insights/risk" className="small">Risk overview</Link></div>
                <RiskyTable rows={d.top_risky.slice(0, 8)} />
              </div>
              <WaitingOnYou items={items} />
            </div>
          </>
        ) : tab === "deployment" ? (
          <DeploymentTab />
        ) : (
          <div className="card">
            <h2 style={{ marginBottom: 4 }}>Recommendations</h2>
            <AttentionList items={attention} />
          </div>
        )}
      </div>
    </Page>
  );
}

export function Home() {
  const { persona, me, actor } = usePersona();
  const { items } = useInbox("mine");
  const first = actor.split(" ")[0];
  if (persona === "admin") {
    return (
      <>
        <AdminHome />
        <p className="xs faint mt">Viewing as admin & security. Switch persona in the user menu.</p>
      </>
    );
  }
  const sub = persona === "employee" ? "Here's what needs you and what you can access." : "Your team's approvals and access reviews, in one place.";
  return (
    <Page title={`${greeting()}, ${first}`} sub={sub} crumbs={false}>
      <div className="stack">
        <div className="grid g21">
          <WaitingOnYou items={items} />
          <RequestCta />
        </div>
        {persona === "manager" && me && <TeamOverview meId={me.id} />}
        {me ? (
          <div className="grid g2">
            <YourAccess id={me.id} />
            <MyRequests id={me.id} />
          </div>
        ) : <Loading kind="block" />}
        <RecentActivity />
        <p className="xs faint">Viewing as {persona}. Switch persona in the user menu.</p>
      </div>
    </Page>
  );
}
