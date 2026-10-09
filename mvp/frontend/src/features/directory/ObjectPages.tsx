/** Object pages for roles, entitlements, applications and organizations. */
import { ReactNode, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ClipboardCheck, Network, Pencil, RefreshCw, Settings, ShoppingCart, Timer } from "lucide-react";
import { AccountRow, ConnectorRow, Group, IdentityRow, ResourceRow, api, relTime, useApi } from "../../api";
import { useIdentityActions } from "../../app/actions";
import { Badge, Bar, Button, Callout, Chip, EmptyState, IdLink, Loading, Page, PreviewBadge, Status, TypeBadge, useToast } from "../../components";
import { ORGS, useRoles } from "../../mocks";
import { PreviewFormDrawer } from "./shared";

function ObjectHead({ icon, meta, actions }: { icon?: ReactNode; meta: ReactNode; actions: ReactNode }) {
  return (
    <div className="object-head card">
      <div className="row" style={{ flexWrap: "nowrap", alignItems: "flex-start", minWidth: 0 }}>
        {icon && <span className="avatar lg" aria-hidden>{icon}</span>}
        <div className="small muted" style={{ minWidth: 0 }}>{meta}</div>
      </div>
      <div className="row tight object-actions" role="toolbar" aria-label="Actions">{actions}</div>
    </div>
  );
}

function NotFound({ what, back }: { what: string; back: [string, string] }) {
  return (
    <Page title={`${what} not found`} crumbs={[["Directory", "/directory"], back]}>
      <div className="card"><EmptyState title={`That ${what.toLowerCase()} doesn't exist`} action={<Link to={back[1]}>Back to {back[0].toLowerCase()}</Link>}>It may have been removed, or the link is wrong.</EmptyState></div>
    </Page>
  );
}

// ------------------------------------------------------------------- role
export function RolePage() {
  const { id } = useParams();
  const role = useRoles().find((r) => r.id === id);
  const { data: groups } = useApi<Group[]>("/groups");
  const { data: people } = useApi<IdentityRow[]>("/identities?type=human&status=active");
  const nav = useNavigate();
  const acts = useIdentityActions();
  const [edit, setEdit] = useState(false);
  if (!role) return <NotFound what="Role" back={["Roles", "/directory/roles"]} />;
  const birthright = (people ?? []).filter((p) => role.birthright && p.department === role.birthright);
  return (
    <Page title={role.name} badge={<PreviewBadge />} crumbs={[["Directory", "/directory"], ["Roles", "/directory/roles"], [role.name]]}>
      <ObjectHead
        meta={<>
          <div style={{ color: "var(--text)" }}>{role.description}</div>
          <div className="row" style={{ marginTop: 6 }}>
            <span>Owner {role.owner}</span>
            {role.birthright && <span>Birthright for {role.birthright}</span>}
            <span>Updated {role.updated}</span>
            <Badge tone={role.risk === "high" ? "critical" : role.risk === "medium" ? "warning" : "ok"} dot>{role.risk} risk</Badge>
          </div>
        </>}
        actions={<>
          <Button size="sm" variant="primary" icon={<ShoppingCart size={14} />} onClick={() => nav(`/access/request?add=${role.id}`)}>Request this role</Button>
          <Button size="sm" icon={<Pencil size={14} />} onClick={() => setEdit(true)}>Edit</Button>
          <Button size="sm" icon={<ClipboardCheck size={14} />} onClick={() => acts.startCampaign()}>Start review</Button>
        </>}
      />
      <div className="grid g21 mt">
        <div className="card flush">
          <div className="card-h"><h2>Entitlements in this role</h2><span className="small faint tnum">{role.entitlements.length}</span></div>
          <div className="table-scroll">
            <table>
              <thead><tr><th>Entitlement</th><th>Kind</th><th>Privileged</th></tr></thead>
              <tbody>
                {role.entitlements.map((e) => {
                  const jit = e.endsWith(" (JIT)");
                  const key = e.replace(" (JIT)", "");
                  const g = (groups ?? []).find((x) => `${x.system}:${x.name}` === key);
                  return (
                    <tr key={e}>
                      <td>{g ? <Link to={`/directory/entitlements/${g.id}`} className="sys">{key}</Link> : <span className="sys">{key}</span>}{jit && <> <Badge tone="info">JIT only</Badge></>}</td>
                      <td className="small">{g?.kind.replace(/_/g, " ") ?? <span className="faint">not discovered</span>}</td>
                      <td>{g?.privileged ? <Badge tone="warning">Privileged</Badge> : <span className="faint">No</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
        <div className="card stack-sm">
          <h2>Who gets it automatically</h2>
          {role.birthright ? (
            <>
              <div className="small muted">Everyone in {role.birthright} receives this role on their first day. {people ? `${birthright.length} people today.` : ""}</div>
              {birthright.slice(0, 8).map((p) => <div key={p.id} className="small"><IdLink i={p} /> <span className="faint">{p.title}</span></div>)}
              {birthright.length > 8 && <Link className="small" to="/directory/people">and {birthright.length - 8} more</Link>}
            </>
          ) : <div className="small muted">Nobody. This role is granted only by request and approval.</div>}
        </div>
      </div>
      {edit && (
        <PreviewFormDrawer title={`Edit ${role.name}`} kind="role" verb="update" onClose={() => setEdit(false)}
          initial={{ name: role.name, description: role.description, owner: role.owner }}
          fields={[{ id: "name", label: "Name", required: true }, { id: "description", label: "Description", textarea: true }, { id: "owner", label: "Owner" }]}
        />
      )}
    </Page>
  );
}

// ------------------------------------------------------------ entitlement
export function EntitlementPage() {
  const { id } = useParams();
  const { data: groups, error } = useApi<Group[]>("/groups");
  const roles = useRoles();
  const nav = useNavigate();
  const [edit, setEdit] = useState(false);
  if (!groups) return <Page title="Entitlement" crumbs={[["Directory", "/directory"], ["Entitlements", "/directory/entitlements"]]}><Loading error={error} kind="page" /></Page>;
  const g = groups.find((x) => String(x.id) === id);
  if (!g) return <NotFound what="Entitlement" back={["Entitlements", "/directory/entitlements"]} />;
  const key = `${g.system}:${g.name}`;
  const inRoles = roles.filter((r) => r.entitlements.some((e) => e.replace(" (JIT)", "") === key));
  return (
    <Page title={g.name} crumbs={[["Directory", "/directory"], ["Entitlements", "/directory/entitlements"], [g.name]]}>
      <ObjectHead
        meta={<>
          <div style={{ color: "var(--text)" }}>{g.description ?? "No description from the source system."}</div>
          <div className="row" style={{ marginTop: 6 }}>
            <Chip mono>{g.system}</Chip>
            <span>{g.kind.replace(/_/g, " ")}</span>
            {g.privileged && <Badge tone="warning">Privileged</Badge>}
            {g.requestable ? <Badge tone="info">JIT-eligible</Badge> : <span>Standing access</span>}
          </div>
        </>}
        actions={<>
          {g.requestable ? (
            <Button size="sm" variant="primary" icon={<Timer size={14} />} onClick={() => nav(`/access/request?add=g${g.id}`)}>Request just-in-time</Button>
          ) : (
            <Button size="sm" variant="primary" icon={<ShoppingCart size={14} />} onClick={() => nav(`/access/request?add=g${g.id}`)}>Request access</Button>
          )}
          <Button size="sm" icon={<Pencil size={14} />} onClick={() => setEdit(true)}>Edit</Button>
          <Button size="sm" icon={<Network size={14} />} onClick={() => nav(`/insights/least-privilege`)}>Usage and trims</Button>
        </>}
      />
      <div className="grid g2 mt">
        <div className="card stack-sm">
          <h2>Part of these roles <PreviewBadge /></h2>
          {inRoles.length === 0 ? <div className="small muted">Not bundled in any business role. People request it directly.</div> :
            inRoles.map((r) => <div key={r.id} className="small"><Link to={`/directory/roles/${r.id}`}>{r.name}</Link> <span className="faint">· {r.members} members</span></div>)}
        </div>
        <div className="card stack-sm">
          <h2>Governance</h2>
          <dl className="kv">
            <dt>Key</dt><dd className="sys">{g.key}</dd>
            <dt>Approval</dt><dd>{g.privileged ? "Manager, resource owner and security" : "Manager"}</dd>
            <dt>Review cadence</dt><dd>{g.privileged ? "Quarterly, plus exception reviews" : "Exception reviews only"}</dd>
          </dl>
        </div>
      </div>
      {edit && (
        <PreviewFormDrawer title={`Edit ${g.name}`} kind="entitlement" verb="update" onClose={() => setEdit(false)}
          note={`Name and membership are owned by ${g.system}. Tessera stores the description, owner and risk labels.`}
          initial={{ name: g.name, description: g.description ?? "", privileged: g.privileged ? "Yes" : "No" }}
          fields={[{ id: "name", label: "Name", required: true }, { id: "description", label: "Description", textarea: true }, { id: "privileged", label: "Privileged", options: ["No", "Yes"] }, { id: "owner", label: "Owner" }]}
        />
      )}
    </Page>
  );
}

// -------------------------------------------------------------------- app
export function AppPage() {
  const { system } = useParams();
  const { data: conns, error } = useApi<ConnectorRow[]>("/connectors");
  const { data: resources } = useApi<ResourceRow[]>("/resources");
  const { data: accounts, error: accErr } = useApi<AccountRow[]>(`/accounts?system=${system}`);
  const nav = useNavigate();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  if (!conns) return <Page title="Application" crumbs={[["Directory", "/directory"], ["Applications & systems", "/directory/apps"]]}><Loading error={error} kind="page" /></Page>;
  const c = conns.find((x) => x.system === system);
  if (!c) return <NotFound what="Application" back={["Applications & systems", "/directory/apps"]} />;
  const res = (resources ?? []).filter((r) => r.system === system);
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
    <Page title={c.name} crumbs={[["Directory", "/directory"], ["Applications & systems", "/directory/apps"], [c.name]]}>
      <ObjectHead
        meta={<div className="row"><Chip mono>{c.system}</Chip><Status s="active" /><span>Connector {c.type}</span></div>}
        actions={<>
          <Button size="sm" variant="primary" icon={<RefreshCw size={14} />} disabled={busy} onClick={sync}>{busy ? "Syncing…" : "Sync now"}</Button>
          <Button size="sm" icon={<Settings size={14} />} onClick={() => nav("/admin/connections")}>Connection settings</Button>
        </>}
      />
      <div className="card mt">
        <div className="stat-row">
          <div className="s"><b className="tnum">{c.accounts}</b><span>accounts</span></div>
          <div className="s"><b className="tnum">{c.groups}</b><span>groups and roles</span></div>
          <div className="s"><b className="tnum">{c.resources}</b><span>resources</span></div>
          <div className="s"><b className="tnum">{c.permissions}</b><span>permissions</span></div>
        </div>
      </div>
      <div className="grid g2 mt">
        <div className="card flush">
          <div className="card-h"><h2>Resources</h2></div>
          {!resources ? <Loading /> : res.length === 0 ? <EmptyState title="No resources">This connector reports none.</EmptyState> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Resource</th><th>Labels</th><th className="num">Who can access</th></tr></thead>
                <tbody>
                  {res.map((r) => (
                    <tr key={r.id} className="click" tabIndex={0} onClick={() => nav(`/insights/graph?resource=${r.id}`)} onKeyDown={(e) => e.key === "Enter" && nav(`/insights/graph?resource=${r.id}`)}>
                      <td><b className="sys">{r.name}</b><div className="xs faint">{r.kind}</div></td>
                      <td><div className="row tight">{r.environment && <Chip>{r.environment}</Chip>}{r.tags.map((t) => <Chip key={t}>{t}</Chip>)}</div></td>
                      <td className="num">{r.identities_with_access}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <div className="card flush">
          <div className="card-h"><h2>Accounts</h2><Link className="small" to="/directory/accounts">All accounts</Link></div>
          {!accounts ? <Loading error={accErr} /> : (
            <div className="table-scroll" style={{ maxHeight: 420 }}>
              <table>
                <thead><tr><th>Account</th><th>Belongs to</th><th>Last login</th></tr></thead>
                <tbody>
                  {accounts.slice(0, 50).map((a) => (
                    <tr key={a.id}>
                      <td className="small sys">{a.username}</td>
                      <td className="small">{a.identity ? <IdLink i={a.identity} /> : <Badge tone="critical">Uncorrelated</Badge>}</td>
                      <td className="small nowrap">{relTime(a.last_login_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </Page>
  );
}

// -------------------------------------------------------------------- org
export function OrgPage() {
  const { id } = useParams();
  const org = ORGS.find((o) => o.id === id);
  const { data: people, error } = useApi<IdentityRow[]>("/identities?type=human");
  const nav = useNavigate();
  const [edit, setEdit] = useState(false);
  if (!org) return <NotFound what="Organization" back={["Organizations", "/directory/orgs"]} />;
  const members = (people ?? []).filter((p) => !org.department || p.department === org.department);
  const children = ORGS.filter((o) => o.parent === org.id);
  const parent = ORGS.find((o) => o.id === org.parent);
  const active = members.filter((m) => m.status === "active");
  return (
    <Page title={org.name} badge={<PreviewBadge />} crumbs={[["Directory", "/directory"], ["Organizations", "/directory/orgs"], [org.name]]}>
      <ObjectHead
        meta={<div className="row"><span>Owner {org.owner}</span><span className="sys">{org.costCenter}</span>{parent && <span>Part of <Link to={`/directory/orgs/${parent.id}`}>{parent.name}</Link></span>}</div>}
        actions={<>
          <Button size="sm" variant="primary" icon={<ShoppingCart size={14} />} disabled={!active.length} onClick={() => nav(`/access/request?for=${active.map((m) => m.id).join(",")}`)}>Request access for everyone</Button>
          <Button size="sm" icon={<Pencil size={14} />} onClick={() => setEdit(true)}>Edit</Button>
        </>}
      />
      {children.length > 0 && (
        <div className="row mt">{children.map((c) => <Link key={c.id} to={`/directory/orgs/${c.id}`} className="btn sm">{c.name}</Link>)}</div>
      )}
      <div className="card flush mt">
        <div className="card-h"><h2>People</h2><span className="small faint tnum">{members.length}</span></div>
        {!people ? <Loading error={error} /> : members.length === 0 ? <EmptyState title="No members">Nobody is in this organization yet.</EmptyState> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Name</th><th>Title</th><th>Status</th><th className="num hide-narrow">Violations</th><th>Risk</th></tr></thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.id} className="click" tabIndex={0} onClick={() => nav(`/directory/identities/${m.id}`)} onKeyDown={(e) => e.key === "Enter" && nav(`/directory/identities/${m.id}`)}>
                    <td><b>{m.name}</b> <span className="hide-narrow"><TypeBadge type={m.type} /></span></td>
                    <td className="small">{m.title}</td>
                    <td><Status s={m.status} /></td>
                    <td className="num hide-narrow">{m.violations ?? 0}</td>
                    <td style={{ width: 100 }}><Bar value={m.risk ?? 0} tone="risk" /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {!org.department && <div className="mt"><Callout tone="neutral">The top-level organization lists everyone.</Callout></div>}
      {edit && (
        <PreviewFormDrawer title={`Edit ${org.name}`} kind="org" verb="update" onClose={() => setEdit(false)}
          initial={{ name: org.name, owner: org.owner, costCenter: org.costCenter }}
          fields={[{ id: "name", label: "Name", required: true }, { id: "owner", label: "Owner" }, { id: "costCenter", label: "Cost center" }]}
        />
      )}
    </Page>
  );
}
