/**
 * Detail side panels for the Identity lists. Each panel is a compact view of the object's full
 * page with the same actions; "Open full page" goes to the existing object page.
 */
import { ReactNode, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Ban, ClipboardCheck, ExternalLink, Network, Pencil, RefreshCw, RotateCcw, Settings, ShieldCheck, ShoppingCart, Timer, UserCheck, UserRound,
} from "lucide-react";
import { AccountRow, ConnectorRow, Group, IdentityDetail, IdentityRow, ResourceRow, Violation, ago, api, fmtDay, relTime, useApi } from "../../api";
import { useIdentityActions } from "../../app/actions";
import { usePersona } from "../../app/persona";
import {
  Avatar, Badge, Chip, CommandBar, EmptyState, IdLink, Loading, PathView, PreviewBadge, RiskPill, Sev, SidePanel, Status, Tabs, TypeBadge, TYPE_LABEL, useToast,
} from "../../components";
import { BusinessRole, ORGS, OrgUnit, mockIdentityOps, mockObjects, useMockState, useRoles } from "../../mocks";
import { PlanDrawer, RotationBadge, useRotationStatus } from "../rotation/shared";
import { RevokeDrawer } from "./IdentityPage";
import { PreviewFormDrawer } from "./shared";

const I = 16;

function useTab<T extends string>(first: T, key: unknown) {
  const [tab, setTab] = useState<T>(first);
  useEffect(() => setTab(first), [key, first]);
  return [tab, setTab] as const;
}

const Section = ({ title, children, action }: { title: ReactNode; children: ReactNode; action?: ReactNode }) => (
  <section className="stack-sm">
    <div className="spread"><h3 style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>{title}</h3>{action}</div>
    {children}
  </section>
);

// ------------------------------------------------------------- identity
type IdTab = "overview" | "access" | "groups" | "activity";

export function IdentityPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: d, error, reload } = useApi<IdentityDetail>(`/identities/${id}`);
  const acts = useIdentityActions();
  const mock = useMockState();
  const { actor } = usePersona();
  const toast = useToast();
  const [tab, setTab] = useTab<IdTab>("overview", id);
  const [edit, setEdit] = useState(false);
  const [revoke, setRevoke] = useState<number | null>(null);
  const [rotate, setRotate] = useState(false);
  const rot = useRotationStatus();

  if (!d || String(d.id) !== id) {
    return <SidePanel title={error ? "Couldn't load identity" : "Loading…"} onClose={onClose} fullHref={`/directory/identities/${id}`}><Loading error={error} kind="block" /></SidePanel>;
  }
  const human = d.type === "human";
  const status = mock.disabled[d.id] && d.status === "active" ? "disabled" : d.status;
  const lastLogin = d.accounts.map((a) => a.last_login_at).filter(Boolean).sort().pop() ?? null;
  const topRec = d.recommendations[0];
  const why = d.effective_permissions.find((p) => p.tags.length && p.unused) ?? d.effective_permissions.find((p) => p.privileged && p.unused) ?? d.effective_permissions.find((p) => p.tags.length);
  const riskLabel = (d.risk?.risk ?? 0) >= 70 ? "critical" : (d.risk?.risk ?? 0) >= 40 ? "high" : "this risk level";

  const tabs: { id: IdTab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "access", label: `Access (${d.effective_permissions.length})` },
    { id: "groups", label: `Groups (${d.grants.length})` },
    { id: "activity", label: "Activity" },
  ];

  return (
    <SidePanel
      title={d.name}
      avatar={<Avatar name={d.name} type={d.type} />}
      sub={<>{d.title ?? TYPE_LABEL[d.type]}<span aria-hidden>·</span><RiskPill score={d.risk?.risk} />{!human && <TypeBadge type={d.type} />}{status !== "active" && <Status s={status} />}</>}
      onClose={onClose}
      fullHref={`/directory/identities/${d.id}`}
      commands={
        <CommandBar
          label={`Actions for ${d.name}`}
          items={[
            { label: "Edit", icon: <Pencil size={I} />, onClick: () => setEdit(true) },
            { label: "Request access for", icon: <ShoppingCart size={I} />, disabled: status !== "active", onClick: () => acts.requestFor(d) },
            human
              ? { label: "Reset password", icon: <RotateCcw size={I} />, disabled: status !== "active", onClick: () => acts.resetPassword(d) }
              : { label: "Rotate secrets…", icon: <RotateCcw size={I} />, disabled: d.secrets.length === 0, title: d.secrets.length === 0 ? "No secrets are recorded for this identity" : "Preview the rotation of its secrets", onClick: () => setRotate(true) },
            { label: "Start review", icon: <ClipboardCheck size={I} />, onClick: () => acts.reviewAccess(d) },
            { label: "Open in graph", icon: <Network size={I} />, onClick: () => acts.openGraph(d) },
            status === "disabled"
              ? { label: "Enable", icon: <UserCheck size={I} />, onClick: async () => { await mockIdentityOps.enable(d.id, d.name, actor); toast(`${d.name} re-enabled (preview)`); } }
              : { label: "Disable", icon: <Ban size={I} />, danger: true, disabled: d.status === "terminated", onClick: () => acts.disable(d) },
          ]}
        />
      }
      tabs={<Tabs label="Identity details" tabs={tabs} value={tab} onChange={setTab} />}
    >
      {tab === "overview" && (
        <>
          <dl className="kv">
            <dt>Display name</dt><dd>{d.name}</dd>
            <dt>{human ? "Job title" : "Kind"}</dt><dd>{d.title ?? <span className="faint">-</span>}</dd>
            <dt>Department</dt><dd>{d.department ?? <span className="faint">-</span>}</dd>
            {human ? <><dt>Manager</dt><dd><IdLink i={d.manager} /></dd></> : <><dt>Owner</dt><dd>{d.owner ? <IdLink i={d.owner} /> : <Badge tone="critical">No owner</Badge>}</dd></>}
            <dt>Status</dt><dd><Status s={status} />{mock.disabled[d.id] && <> <PreviewBadge what="Disabled in this browser by a Preview action" /></>}</dd>
            {d.email && <><dt>Email</dt><dd className="truncate">{d.email}</dd></>}
            {d.hired_at && <><dt>Since</dt><dd>{fmtDay(d.hired_at)}</dd></>}
            {d.terminated_at && <><dt>Left</dt><dd>{fmtDay(d.terminated_at)}</dd></>}
            <dt>Last sign-in</dt><dd>{relTime(lastLogin)}</dd>
          </dl>
          <Section title="Risk">
            <dl className="kv">
              <dt>Risk</dt><dd><RiskPill score={d.risk?.risk} /> <span className="faint small tnum">{Math.round(d.risk?.risk ?? 0)} / 100</span></dd>
              <dt>Effective permissions</dt><dd className="tnum">{d.risk?.effective ?? 0} across {new Set(d.effective_permissions.map((p) => p.system)).size} systems</dd>
              <dt>Unused (60 days)</dt><dd className="tnum">{d.risk?.unused ?? 0}{d.risk?.effective ? ` · ${Math.round((100 * (d.risk.unused ?? 0)) / d.risk.effective)}%` : ""}</dd>
              <dt>Privileged</dt><dd className="tnum">{d.risk?.privileged ?? 0}</dd>
              <dt>Policy violations</dt><dd className="tnum">{d.violations.length ? <Badge tone="critical">{d.violations.length} open</Badge> : "0"}</dd>
              {d.owned_identities.length > 0 && <><dt>Owns</dt><dd>{d.owned_identities.length} machine identit{d.owned_identities.length === 1 ? "y" : "ies"}</dd></>}
            </dl>
          </Section>
          {why && (
            <div className="card stack-sm">
              <h3 style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Why {riskLabel}</h3>
              <div className="small muted">{why.action} on {why.resource}{why.unused ? `, unused ${ago(why.usage.days_since_used)}` : ""}{why.tags.length ? ` · ${why.tags.join(", ")}` : ""}</div>
              {why.paths[0] && <PathView steps={why.paths[0]} />}
              {topRec && (
                <div className="row mt-sm">
                  <button type="button" className="btn primary sm" onClick={() => setRevoke(topRec.edge_id)}>Preview removal</button>
                  <span className="xs faint">{topRec.target}: {topRec.unused_lost} unused permission{topRec.unused_lost === 1 ? "" : "s"}</span>
                </div>
              )}
            </div>
          )}
          <Section title="Top findings">
            {d.violations.length === 0 && d.recommendations.length === 0 ? (
              <div className="small muted row tight"><ShieldCheck size={14} aria-hidden /> Every policy passes and access matches usage.</div>
            ) : (
              <table>
                <tbody>
                  {d.violations.slice(0, 4).map((v) => (
                    <tr key={v.key}><td>{v.message}<div className="xs faint">{v.policy_name}</div></td><td className="nowrap" style={{ textAlign: "right" }}><Sev s={v.severity} /></td></tr>
                  ))}
                  {d.recommendations.slice(0, Math.max(0, 4 - d.violations.length)).map((r) => (
                    <tr key={r.edge_id}><td>{r.target}<div className="xs faint">{r.rationale}</div></td><td className="nowrap" style={{ textAlign: "right" }}><Badge tone="warning">{r.kind === "remove" ? "Unused" : "Right-size"}</Badge></td></tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>
        </>
      )}

      {tab === "access" && (
        d.effective_permissions.length === 0 ? <EmptyState title="No access">This identity holds no permissions.</EmptyState> : (
          <>
            <table>
              <thead><tr><th>Permission</th><th>Last used</th><th>Finding</th></tr></thead>
              <tbody>
                {d.effective_permissions.slice(0, 40).map((p) => {
                  const via = p.paths[0]?.find((s) => s.kind === "group")?.label;
                  return (
                    <tr key={p.perm_key}>
                      <td><span className="sys">{p.action}</span> <span className="muted">on {p.resource}</span><div className="xs faint">{p.system}{via ? ` · via ${via}` : ""}</div></td>
                      <td className="small nowrap">{ago(p.usage.days_since_used)}</td>
                      <td>{p.tags.length && p.unused ? <Badge tone="critical">{p.tags[0].toUpperCase()} · unused</Badge> : p.privileged && p.unused ? <Badge tone="warning">Standing admin</Badge> : p.unused ? <Badge tone="warning">Unused</Badge> : !p.standing ? <Badge tone="info">JIT</Badge> : <Badge tone="ok">In use</Badge>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {d.effective_permissions.length > 40 && <Link className="small" to={`/directory/identities/${d.id}?tab=access`}>All {d.effective_permissions.length} permissions on the full page</Link>}
          </>
        )
      )}

      {tab === "groups" && (
        d.grants.length === 0 ? <EmptyState title="No groups or roles">This identity holds no group or role memberships.</EmptyState> : (
          <table>
            <thead><tr><th>Group or role</th><th>Expires</th><th /></tr></thead>
            <tbody>
              {d.grants.map((g) => (
                <tr key={g.src + g.dst}>
                  <td>{g.label} {g.privileged && <Badge tone="warning">Privileged</Badge>} {g.source === "jit" && <Badge tone="info">JIT</Badge>}<div className="xs faint sys">{g.account}</div></td>
                  <td className="small nowrap">{g.expires_at ? relTime(g.expires_at) : "Standing"}</td>
                  <td className="actions-cell">{g.edge_id && <button type="button" className="btn sm danger" onClick={() => setRevoke(g.edge_id)}>Revoke…</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}

      {tab === "activity" && (
        <>
          <Section title="Accounts">
            <table>
              <tbody>
                {[...d.accounts].sort((a, b) => (b.last_login_at ?? "").localeCompare(a.last_login_at ?? "")).map((a) => (
                  <tr key={a.id}>
                    <td><Chip mono>{a.system}</Chip> <span className="small">{a.username}</span></td>
                    <td><Status s={a.status} /></td>
                    <td className="small nowrap" style={{ textAlign: "right" }}>Signed in {relTime(a.last_login_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
          <Section title="Recently used access">
            <table>
              <tbody>
                {d.effective_permissions.filter((p) => p.usage.days_since_used !== null).sort((a, b) => (a.usage.days_since_used ?? 0) - (b.usage.days_since_used ?? 0)).slice(0, 8).map((p) => (
                  <tr key={p.perm_key}>
                    <td><span className="sys">{p.action}</span> <span className="muted small">on {p.resource}</span></td>
                    <td className="small nowrap num">{p.usage.events_90d} events</td>
                    <td className="small nowrap" style={{ textAlign: "right" }}>{ago(p.usage.days_since_used)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
          {d.secrets.length > 0 && (
            <Section title="Secrets and credentials">
              <table>
                <tbody>
                  {d.secrets.map((s) => (
                    <tr key={s.id}><td className="small"><span className="sys">{s.name}</span><div className="xs faint">{s.kind.replace(/_/g, " ")}</div></td><td className="num">{s.stale ? <Badge tone="warning">{s.age_days} d old</Badge> : `${s.age_days} d old`}</td><td className="small nowrap" style={{ textAlign: "right" }}>used {ago(s.last_used_days)}</td><td><RotationBadge status={rot.get(s.id)} /></td></tr>
                  ))}
                </tbody>
              </table>
            </Section>
          )}
          {d.delegations.length > 0 && (
            <Section title="Delegations">
              {d.delegations.map((x, i) => (
                <div key={i} className="small"><IdLink i={x.agent} /> acts for <IdLink i={x.principal} /> <span className="row tight" style={{ marginTop: 4 }}>{x.scopes.map((s) => <Chip key={s} mono>{s}</Chip>)}</span></div>
              ))}
            </Section>
          )}
        </>
      )}

      {rotate && <PlanDrawer title={`Rotate ${d.name}'s secrets`} secretIds={d.secrets.map((x) => x.id)} onClose={() => setRotate(false)} />}
      {edit && (
        <PreviewFormDrawer
          title={`Edit ${d.name}`}
          kind="identity"
          verb="update"
          onClose={() => setEdit(false)}
          note={human ? "Workday is authoritative for name, department and title. Edits here are overwritten on the next sync unless the attribute is mastered in Tessera." : undefined}
          initial={{ name: d.name, title: d.title ?? "", department: d.department ?? "", email: d.email ?? "", description: d.description ?? "" }}
          fields={[
            { id: "name", label: "Display name", required: true },
            { id: "title", label: human ? "Job title" : "Kind" },
            { id: "department", label: "Department" },
            { id: "email", label: "Email" },
            { id: "description", label: "Notes", textarea: true },
          ]}
        />
      )}
      {revoke !== null && <RevokeDrawer edgeId={revoke} onClose={() => setRevoke(null)} onDone={reload} />}
    </SidePanel>
  );
}

// --------------------------------------------------------------- account
export function AccountPanel({ a, onClose }: { a: AccountRow; onClose: () => void }) {
  const nav = useNavigate();
  const toast = useToast();
  const { actor } = usePersona();
  const owner = a.identity;
  return (
    <SidePanel
      title={a.username}
      avatar={<span className="avatar" aria-hidden><UserRound size={18} /></span>}
      sub={<><Chip mono>{a.system}</Chip><Status s={a.status} /></>}
      onClose={onClose}
      fullHref={owner ? `/directory/identities/${owner.id}` : undefined}
      fullLabel={owner ? `Open ${owner.name}'s full page` : undefined}
      commands={
        <CommandBar
          label={`Actions for ${a.username}`}
          items={[
            owner && { label: "Open owner", icon: <UserRound size={I} />, onClick: () => nav(`/directory/${owner.type === "human" ? "people" : "machine"}?selected=${owner.id}`) },
            owner && { label: "Open in graph", icon: <Network size={I} />, onClick: () => nav(`/insights/graph?identity=${owner.id}`) },
            { label: "Disable account", icon: <Ban size={I} />, danger: true, onClick: async () => { await mockObjects.save("account", a.username, actor, "update"); toast(`${a.username} queued to disable (preview)`); } },
          ]}
        />
      }
    >
      <dl className="kv">
        <dt>Username</dt><dd className="sys">{a.username}</dd>
        <dt>System</dt><dd>{a.system}</dd>
        <dt>Kind</dt><dd>{a.kind.replace(/_/g, " ")}</dd>
        <dt>Status</dt><dd><Status s={a.status} /></dd>
        <dt>Belongs to</dt><dd>{owner ? <><IdLink i={owner} /> <TypeBadge type={owner.type} /></> : <Badge tone="critical">Uncorrelated</Badge>}</dd>
        <dt>Created</dt><dd>{fmtDay(a.created_at)}</dd>
        <dt>Last sign-in</dt><dd>{relTime(a.last_login_at)}</dd>
      </dl>
      {!owner && <div className="callout warn small">No person or machine identity owns this account. Correlate it in Admin, Identity rules, or disable it.</div>}
    </SidePanel>
  );
}

// ----------------------------------------------------------- entitlement
export function GroupPanel({ g, onClose }: { g: Group; onClose: () => void }) {
  const nav = useNavigate();
  const roles = useRoles();
  const [tab, setTab] = useTab<"overview" | "roles">("overview", g.id);
  const [edit, setEdit] = useState(false);
  const key = `${g.system}:${g.name}`;
  const inRoles = roles.filter((r) => r.entitlements.some((e) => e.replace(" (JIT)", "") === key));
  return (
    <SidePanel
      title={g.name}
      sub={<><Chip mono>{g.system}</Chip>{g.kind.replace(/_/g, " ")}{g.privileged && <Badge tone="warning">Privileged</Badge>}</>}
      onClose={onClose}
      fullHref={`/directory/entitlements/${g.id}`}
      commands={
        <CommandBar
          label={`Actions for ${g.name}`}
          items={[
            g.requestable
              ? { label: "Request just-in-time", icon: <Timer size={I} />, onClick: () => nav(`/access/request?add=g${g.id}`) }
              : { label: "Request access", icon: <ShoppingCart size={I} />, onClick: () => nav(`/access/request?add=g${g.id}`) },
            { label: "Edit", icon: <Pencil size={I} />, onClick: () => setEdit(true) },
            { label: "Usage and trims", icon: <Network size={I} />, onClick: () => nav("/insights/least-privilege") },
          ]}
        />
      }
      tabs={<Tabs label="Entitlement details" value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "roles", label: `Roles (${inRoles.length})` }]} />}
    >
      {tab === "overview" ? (
        <>
          <p className="muted">{g.description ?? "No description from the source system."}</p>
          <dl className="kv">
            <dt>Key</dt><dd className="sys">{g.key}</dd>
            <dt>System</dt><dd>{g.system}</dd>
            <dt>Kind</dt><dd>{g.kind.replace(/_/g, " ")}</dd>
            <dt>Privileged</dt><dd>{g.privileged ? <Badge tone="warning">Privileged</Badge> : "No"}</dd>
            <dt>Access model</dt><dd>{g.requestable ? <Badge tone="info">JIT-eligible</Badge> : "Standing access"}</dd>
            <dt>Approval</dt><dd>{g.privileged ? "Manager, resource owner and security" : "Manager"}</dd>
            <dt>Review cadence</dt><dd>{g.privileged ? "Quarterly, plus exception reviews" : "Exception reviews only"}</dd>
          </dl>
        </>
      ) : (
        <Section title={<>Part of these roles <PreviewBadge /></>}>
          {inRoles.length === 0 ? <div className="small muted">Not bundled in any business role. People request it directly.</div> :
            inRoles.map((r) => <div key={r.id} className="small"><Link to={`/directory/roles?selected=${r.id}`}>{r.name}</Link> <span className="faint">· {r.members} members</span></div>)}
        </Section>
      )}
      {edit && (
        <PreviewFormDrawer title={`Edit ${g.name}`} kind="entitlement" verb="update" onClose={() => setEdit(false)}
          initial={{ name: g.name, description: g.description ?? "" }}
          fields={[{ id: "name", label: "Name", required: true }, { id: "description", label: "Description", textarea: true }]}
        />
      )}
    </SidePanel>
  );
}

// ------------------------------------------------------------------ app
export function AppPanel({ c, onClose }: { c: ConnectorRow; onClose: () => void }) {
  const { data: resources, error } = useApi<ResourceRow[]>("/resources");
  const nav = useNavigate();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useTab<"overview" | "resources">("overview", c.system);
  const res = (resources ?? []).filter((r) => r.system === c.system);
  const sync = async () => {
    setBusy(true);
    try {
      const s = await api<Record<string, number>>("/connectors/sync", {});
      toast(`Sync finished: ${Object.entries(s).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).slice(0, 3).join(", ")}`);
    } catch (e) {
      toast(`Sync failed: ${(e as Error).message}`, { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <SidePanel
      title={c.name}
      sub={<><Chip mono>{c.system}</Chip><Status s="active" /><span>Connector {c.type}</span></>}
      onClose={onClose}
      fullHref={`/directory/apps/${c.system}`}
      commands={
        <CommandBar
          label={`Actions for ${c.name}`}
          items={[
            { label: busy ? "Syncing…" : "Sync now", icon: <RefreshCw size={I} />, disabled: busy, onClick: sync },
            { label: "Accounts", icon: <UserRound size={I} />, onClick: () => nav("/directory/accounts") },
            { label: "Connection settings", icon: <Settings size={I} />, onClick: () => nav("/admin/connections") },
          ]}
        />
      }
      tabs={<Tabs label="Application details" value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "resources", label: `Resources (${c.resources})` }]} />}
    >
      {tab === "overview" ? (
        <dl className="kv">
          <dt>System</dt><dd className="sys">{c.system}</dd>
          <dt>Connector</dt><dd>{c.type}</dd>
          <dt>Accounts</dt><dd className="tnum">{c.accounts}</dd>
          <dt>Groups & roles</dt><dd className="tnum">{c.groups}</dd>
          <dt>Resources</dt><dd className="tnum">{c.resources}</dd>
          <dt>Permissions</dt><dd className="tnum">{c.permissions}</dd>
          <dt>Sensitive resources</dt><dd className="tnum">{resources ? res.filter((r) => r.tags.length).length : "…"}</dd>
        </dl>
      ) : !resources ? <Loading error={error} /> : res.length === 0 ? <EmptyState title="No resources">This connector reports none.</EmptyState> : (
        <table>
          <thead><tr><th>Resource</th><th className="num">Who can access</th></tr></thead>
          <tbody>
            {res.map((r) => (
              <tr key={r.id} className="click" tabIndex={0} onClick={() => nav(`/insights/graph?resource=${r.id}`)} onKeyDown={(e) => e.key === "Enter" && nav(`/insights/graph?resource=${r.id}`)}>
                <td><span className="sys">{r.name}</span><div className="row tight" style={{ marginTop: 2 }}>{r.environment && <Chip>{r.environment}</Chip>}{r.tags.map((t) => <Chip key={t}>{t}</Chip>)}</div></td>
                <td className="num">{r.identities_with_access}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </SidePanel>
  );
}

// ----------------------------------------------------------------- role
export function RolePanel({ role, onClose }: { role: BusinessRole; onClose: () => void }) {
  const nav = useNavigate();
  const acts = useIdentityActions();
  const { data: groups } = useApi<Group[]>("/groups");
  const [tab, setTab] = useTab<"overview" | "ents">("overview", role.id);
  const [edit, setEdit] = useState(false);
  const tone = role.risk === "high" ? "critical" : role.risk === "medium" ? "warning" : "ok";
  return (
    <SidePanel
      title={role.name}
      sub={<><PreviewBadge /><Badge tone={tone}>{role.risk[0].toUpperCase() + role.risk.slice(1)} risk</Badge></>}
      onClose={onClose}
      fullHref={`/directory/roles/${role.id}`}
      commands={
        <CommandBar
          label={`Actions for ${role.name}`}
          items={[
            { label: "Request this role", icon: <ShoppingCart size={I} />, onClick: () => nav(`/access/request?add=${role.id}`) },
            { label: "Edit", icon: <Pencil size={I} />, onClick: () => setEdit(true) },
            { label: "Start review", icon: <ClipboardCheck size={I} />, onClick: () => acts.startCampaign() },
          ]}
        />
      }
      tabs={<Tabs label="Role details" value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "ents", label: `Entitlements (${role.entitlements.length})` }]} />}
    >
      {tab === "overview" ? (
        <>
          <p className="muted">{role.description}</p>
          <dl className="kv">
            <dt>Owner</dt><dd>{role.owner}</dd>
            <dt>Birthright for</dt><dd>{role.birthright ?? <span className="faint">Nobody (request only)</span>}</dd>
            <dt>Members</dt><dd className="tnum">{role.members}</dd>
            <dt>Updated</dt><dd>{role.updated}</dd>
          </dl>
        </>
      ) : (
        <table>
          <tbody>
            {role.entitlements.map((e) => {
              const k = e.replace(" (JIT)", "");
              const g = (groups ?? []).find((x) => `${x.system}:${x.name}` === k);
              return (
                <tr key={e}>
                  <td>{g ? <Link className="sys" to={`/directory/entitlements?selected=${g.id}`}>{k}</Link> : <span className="sys">{k}</span>}</td>
                  <td style={{ textAlign: "right" }}>{e.endsWith(" (JIT)") && <Badge tone="info">JIT only</Badge>} {g?.privileged && <Badge tone="warning">Privileged</Badge>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {edit && (
        <PreviewFormDrawer title={`Edit ${role.name}`} kind="role" verb="update" onClose={() => setEdit(false)}
          initial={{ name: role.name, description: role.description, owner: role.owner }}
          fields={[{ id: "name", label: "Name", required: true }, { id: "description", label: "Description", textarea: true }, { id: "owner", label: "Owner" }]}
        />
      )}
    </SidePanel>
  );
}

// ------------------------------------------------------------------ org
export function OrgPanel({ org, onClose }: { org: OrgUnit; onClose: () => void }) {
  const { data: people, error } = useApi<IdentityRow[]>("/identities?type=human");
  const nav = useNavigate();
  const [tab, setTab] = useTab<"overview" | "people">("overview", org.id);
  const members = (people ?? []).filter((p) => !org.department || p.department === org.department);
  const active = members.filter((m) => m.status === "active");
  const parent = ORGS.find((o) => o.id === org.parent);
  return (
    <SidePanel
      title={org.name}
      sub={<><PreviewBadge /><span>{org.costCenter}</span></>}
      onClose={onClose}
      fullHref={`/directory/orgs/${org.id}`}
      commands={
        <CommandBar
          label={`Actions for ${org.name}`}
          items={[{ label: "Request access for everyone", icon: <ShoppingCart size={I} />, disabled: !active.length, onClick: () => nav(`/access/request?for=${active.map((m) => m.id).join(",")}`) }]}
        />
      }
      tabs={<Tabs label="Organization details" value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "people", label: `People (${people ? members.length : "…"})` }]} />}
    >
      {tab === "overview" ? (
        <dl className="kv">
          <dt>Owner</dt><dd>{org.owner}</dd>
          <dt>Cost center</dt><dd className="sys">{org.costCenter}</dd>
          <dt>Part of</dt><dd>{parent ? parent.name : "Top level"}</dd>
          <dt>Workday department</dt><dd>{org.department ?? "Everyone"}</dd>
          <dt>Active people</dt><dd className="tnum">{people ? active.length : "…"}</dd>
        </dl>
      ) : !people ? <Loading error={error} /> : (
        <table>
          <tbody>
            {members.map((m) => (
              <tr key={m.id} className="click" tabIndex={0} onClick={() => nav(`/directory/people?selected=${m.id}`)} onKeyDown={(e) => e.key === "Enter" && nav(`/directory/people?selected=${m.id}`)}>
                <td>{m.name}<div className="xs faint">{m.title}</div></td>
                <td><Status s={m.status} /></td>
                <td style={{ textAlign: "right" }}><RiskPill score={m.risk} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </SidePanel>
  );
}

// ------------------------------------------------------------- violation
export function ViolationPanel({ v, description, onClose }: { v: Violation; description?: string; onClose: () => void }) {
  const nav = useNavigate();
  return (
    <SidePanel
      title={v.identity_name}
      sub={<><Sev s={v.severity} /><span className="truncate">{v.policy_name}</span></>}
      onClose={onClose}
      fullHref={v.identity_id ? `/directory/identities/${v.identity_id}?tab=violations` : undefined}
      commands={
        <CommandBar
          label="Actions for this violation"
          items={v.identity_id ? [
            { label: "Open identity", icon: <ExternalLink size={I} />, onClick: () => nav(`/directory/people?selected=${v.identity_id}`) },
            { label: "Start review", icon: <ClipboardCheck size={I} />, onClick: () => nav(`/governance/reviews?identity=${v.identity_id}`) },
            { label: "Open in graph", icon: <Network size={I} />, onClick: () => nav(`/insights/graph?identity=${v.identity_id}`) },
          ] : []}
        />
      }
    >
      <Section title="Finding"><p>{v.message}</p></Section>
      {v.evidence.length > 0 && (
        <Section title="Evidence">
          {v.evidence.map((e, i) => <div key={i} className="small sys muted">{e}</div>)}
        </Section>
      )}
      <Section title="Policy">
        <dl className="kv">
          <dt>Name</dt><dd>{v.policy_name}</dd>
          <dt>Severity</dt><dd><Sev s={v.severity} /></dd>
          <dt>Policy id</dt><dd className="sys">{v.policy_id}</dd>
        </dl>
        {description && <p className="small muted">{description}</p>}
      </Section>
      <div className="small faint">Fix it by removing one side of the access, then the policy re-evaluates. Use the what-if simulation on this page to check the blast radius first.</div>
    </SidePanel>
  );
}
