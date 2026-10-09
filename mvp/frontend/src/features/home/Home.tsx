import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, ClipboardCheck, Inbox as InboxIcon, KeyRound, ShieldAlert, ShoppingCart, Timer, TriangleAlert, Users } from "lucide-react";
import { JitRequest, relTime, useApi } from "../../api";
import { usePersona } from "../../app/persona";
import { Badge, Bar, ButtonLink, EmptyState, Kpi, Loading, Page, Status, TypeBadge } from "../../components";
import { useMockState } from "../../mocks";
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

function MyRequests({ id, name }: { id: number; name: string }) {
  const { data: jit } = useApi<JitRequest[]>("/jit/requests");
  const mock = useMockState();
  const mine = [
    ...(jit ?? []).filter((r) => r.identity.id === id).map((r) => ({ key: `j${r.id}`, label: `${r.group.system}:${r.group.name}`, status: r.status, at: r.requested_at, sub: `Just-in-time, ${r.duration_hours} h` })),
    ...mock.requests.filter((r) => r.requester === name || r.beneficiaries.some((b) => b.id === id)).map((r) => ({ key: r.id, label: r.items.map((i) => i.name).join(", "), status: r.status, at: r.createdAt, sub: r.kind === "removal" ? "Removal request" : "Catalog request" })),
  ].slice(0, 5);
  return (
    <div className="card flush">
      <div className="card-h"><h2>Your recent requests</h2><Link to="/access/requests" className="small">History</Link></div>
      {mine.length === 0 ? (
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
                  <td><b className="small">{r.identity.name}</b><div className="xs faint">{r.justification}</div></td>
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

function AdminOverview() {
  const { data: d, error } = useApi<any>("/summary");
  const nav = useNavigate();
  if (!d) return <Loading error={error} kind="page" />;
  const sev = d.violations.by_severity;
  return (
    <div className="stack">
      <div className="grid g4">
        <Kpi label="Policy violations" icon={<TriangleAlert size={14} aria-hidden />} value={d.violations.total} tone={d.violations.total ? "critical" : undefined} sub={`${sev.critical ?? 0} critical · ${sev.high ?? 0} high`} to="/governance/policies" />
        <Kpi label="Unused permissions (60 days)" value={`${d.unused_pct}%`} sub={`${d.recommendations.remove} grants safe to remove`} to="/insights/least-privilege" />
        <Kpi label="Machine identity risk" icon={<ShieldAlert size={14} aria-hidden />} value={d.nhi.orphaned} tone={d.nhi.orphaned ? "warning" : undefined} sub={`without a live owner · ${d.nhi.stale_secrets} stale secrets`} to="/directory/machine" />
        <Kpi label="Lifecycle events pending" value={d.hris_pending} sub={`${d.jit.pending} JIT approvals · ${d.reviews.open_items} review items`} to="/governance/lifecycle" />
      </div>
      <div className="card flush">
        <div className="card-h"><h2>Riskiest identities</h2><Link to="/insights/risk" className="small">Risk overview</Link></div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Identity</th><th>Type</th><th className="num">Unused</th><th className="num hide-narrow">Privileged</th><th className="num">Violations</th><th>Risk</th></tr></thead>
            <tbody>
              {d.top_risky.slice(0, 6).map((i: any) => (
                <tr key={i.id} className="click" tabIndex={0} onClick={() => nav(`/directory/identities/${i.id}`)} onKeyDown={(e) => e.key === "Enter" && nav(`/directory/identities/${i.id}`)}>
                  <td><b>{i.name}</b><div className="xs faint">{i.title ?? i.department}</div></td>
                  <td><TypeBadge type={i.type} /></td>
                  <td className="num">{i.unused}</td>
                  <td className="num hide-narrow">{i.privileged}</td>
                  <td className="num">{i.violations ? <Badge tone="critical">{i.violations}</Badge> : 0}</td>
                  <td style={{ width: 110 }}><Bar value={i.risk} tone="risk" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export function Home() {
  const { persona, me, actor } = usePersona();
  const { items } = useInbox("mine");
  const first = actor.split(" ")[0];
  const sub =
    persona === "employee" ? "Here's what needs you and what you can access." :
    persona === "manager" ? "Your team's approvals and access reviews, in one place." :
    "Risk across every person, service account and AI agent, computed from the access graph and 90 days of usage.";
  return (
    <Page title={`${greeting()}, ${first}`} sub={sub}>
      <div className="stack">
        {persona === "admin" ? (
          <>
            <AdminOverview />
            <WaitingOnYou items={items} />
          </>
        ) : (
          <>
            <div className="grid g21">
              <WaitingOnYou items={items} />
              <RequestCta />
            </div>
            {persona === "manager" && me && <TeamOverview meId={me.id} />}
            {me ? (
              <div className="grid g2">
                <YourAccess id={me.id} />
                <MyRequests id={me.id} name={me.name} />
              </div>
            ) : <Loading kind="block" />}
          </>
        )}
        <p className="xs faint">Viewing as {persona === "admin" ? "admin & security" : persona}. Switch persona in the user menu.</p>
      </div>
    </Page>
  );
}
