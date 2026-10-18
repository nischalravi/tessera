/** Object pages for roles, entitlements, applications and organizations. */
import { ReactNode, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Network, Pencil, RefreshCw, Settings, ShoppingCart, Timer } from "lucide-react";
import { AccountRow, ConnectorRow, Group, OrgDetail, ResourceRow, RolesView, api, orgPath, relTime, useApi } from "../../api";
import { Badge, Button, Callout, Chip, EmptyState, IdLink, Loading, Page, Status, useToast } from "../../components";
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
    <Page title={`${what} not found`} crumbs={[["Identity"], back]}>
      <div className="card"><EmptyState title={`That ${what.toLowerCase()} doesn't exist`} action={<Link to={back[1]}>Back to {back[0].toLowerCase()}</Link>}>It may have been removed, or the link is wrong.</EmptyState></div>
    </Page>
  );
}

// ------------------------------------------------------------ entitlement
export function EntitlementPage() {
  const { id } = useParams();
  const { data: groups, error } = useApi<Group[]>("/groups");
  const { data: rv } = useApi<RolesView>("/roles");
  const nav = useNavigate();
  const [edit, setEdit] = useState(false);
  if (!groups) return <Page title="Entitlement" crumbs={[["Identity"], ["Entitlements", "/directory/entitlements"]]}><Loading error={error} kind="page" /></Page>;
  const g = groups.find((x) => String(x.id) === id);
  if (!g) return <NotFound what="Entitlement" back={["Entitlements", "/directory/entitlements"]} />;
  const inRoles = (rv?.roles ?? []).filter((r) => r.status === "active" && r.entitlements.some((e) => e.id === g.id));
  return (
    <Page title={g.name} crumbs={[["Identity"], ["Entitlements", "/directory/entitlements"], [g.name]]}>
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
          <h2>Part of these roles</h2>
          {inRoles.length === 0 ? <div className="small muted">Not bundled in any business role. People request it directly.</div> :
            inRoles.map((r) => <div key={r.id} className="small"><Link to={`/directory/roles/${r.id}`}>{r.name}</Link> <span className="faint">· {r.member_count} members</span></div>)}
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
  if (!conns) return <Page title="Application" crumbs={[["Identity"], ["Applications", "/directory/apps"]]}><Loading error={error} kind="page" /></Page>;
  const c = conns.find((x) => x.system === system);
  if (!c) return <NotFound what="Application" back={["Applications", "/directory/apps"]} />;
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
    <Page title={c.name} crumbs={[["Identity"], ["Applications", "/directory/apps"], [c.name]]}>
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
  const { data: org, error, reload } = useApi<OrgDetail>(id ? orgPath(id) : null);
  const nav = useNavigate();
  if (error?.kind === "not_found") return <NotFound what="Organization" back={["Organizations", "/directory/orgs"]} />;
  if (!org) return <Page title="Organization" crumbs={[["Identity"], ["Organizations", "/directory/orgs"], ["…"]]}><Loading error={error} what="organization" kind="page" onRetry={reload} /></Page>;
  const active = org.people.filter((m) => m.status === "active");
  return (
    <Page title={org.name} crumbs={[["Identity"], ["Organizations", "/directory/orgs"], [org.name]]}>
      <ObjectHead
        meta={<div className="row"><span>Owners {org.owners.length ? org.owners.map((o) => o.name).join(", ") : "none found"}</span>{org.parent && <span>Part of <Link to={`/directory/orgs/${org.parent.id}`}>{org.parent.name}</Link></span>}</div>}
        actions={
          <Button size="sm" variant="primary" icon={<ShoppingCart size={14} />} disabled={!active.length} onClick={() => nav(`/access/request?for=${active.map((m) => m.id).join(",")}`)}>Request access for everyone</Button>
        }
      />
      {org.child_orgs.length > 0 && (
        <div className="row mt">{org.child_orgs.map((c) => <Link key={c.id} to={`/directory/orgs/${c.id}`} className="btn sm">{c.name}</Link>)}</div>
      )}
      <div className="card flush mt">
        <div className="card-h"><h2>People</h2><span className="small faint tnum">{org.people.length}</span></div>
        {org.people.length === 0 ? <EmptyState title="No members">{org.kind === "tenant" ? "The people are in the departments below." : "Nobody is in this organization."}</EmptyState> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Name</th><th>Title</th><th className="hide-narrow">Manager</th><th>Status</th></tr></thead>
              <tbody>
                {org.people.map((m) => (
                  <tr key={m.id} className="click" tabIndex={0} onClick={() => nav(`/directory/identities/${m.id}`)} onKeyDown={(e) => e.key === "Enter" && nav(`/directory/identities/${m.id}`)}>
                    <td><b>{m.name}</b></td>
                    <td className="small">{m.title}</td>
                    <td className="small hide-narrow">{m.manager?.name ?? <span className="faint">-</span>}</td>
                    <td><Status s={m.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div className="mt"><Callout tone="neutral">Organizations are derived from the HR source's departments and managers. They are read-only here.</Callout></div>
    </Page>
  );
}
