import { Fragment, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Ban, ChevronDown, ChevronRight, ClipboardCheck, Ellipsis, GitMerge, Link2, ShieldAlert, Network, Pencil, RotateCcw, ShieldCheck, ShoppingCart, UserCheck } from "lucide-react";
import { IdentityDetail, SimResult, ago, api, fmtDate, fmtDay, invalidLink, isNumericId, sodRemediate, useApi } from "../../api";
import { useIdentityActions } from "../../app/actions";
import { usePersona } from "../../app/persona";
import {
  Avatar, Badge, Button, Callout, Chip, Drawer, EmptyState, IdLink, Loading, Menu, Page, PathView, Segmented, Sev, SimulationView, Status, Tabs, TypeBadge, useToast,
} from "../../components";
import { mockObjects } from "../../mocks";
import { useSession } from "../../app/auth";
import { AffiliationsSection, IdentifiersSection } from "./affiliations";
import { MergeDialog } from "./correlation";
import { ContainDialog } from "./containment";
import { PreviewFormDrawer } from "./shared";
import { LifecycleSection } from "../lifecycle/parts";

/** Dry-run first, then apply: shows the blast radius of removing one grant before anything changes. */
export function RevokeDrawer({ edgeId, via, onClose, onDone }: { edgeId: number; via?: { riskId: string; identityId: number }; onClose: () => void; onDone?: () => void }) {
  const toast = useToast();
  const [res, setRes] = useState<SimResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    (via ? sodRemediate.revoke(via.riskId, via.identityId, edgeId, true) : api<SimResult>("/least-privilege/revoke", { edge_id: edgeId, dry_run: true }))
      .then((r) => alive && setRes(r))
      .catch((e) => alive && setErr(e.message));
    return () => {
      alive = false;
    };
  }, [edgeId]);
  const apply = async () => {
    setBusy(true);
    try {
      const r = await (via ? sodRemediate.revoke(via.riskId, via.identityId, edgeId, false) : api<SimResult>("/least-privilege/revoke", { edge_id: edgeId, dry_run: false }));
      setRes(r);
      toast("Grant revoked. An audit record was written.");
      onDone?.();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer
      wide
      title={res?.applied ? "Grant revoked" : "Revoke grant: dry run"}
      sub={res?.grant?.label}
      onClose={onClose}
      footer={res && !res.applied ? (
        <><Button onClick={onClose}>Cancel</Button><Button variant="danger-solid" disabled={busy} onClick={apply}>Revoke grant</Button></>
      ) : <Button onClick={onClose}>Close</Button>}
    >
      {err && <Callout tone="bad">{err}</Callout>}
      {res?.applied && <div style={{ marginBottom: 12 }}><Callout tone="ok">Applied. The grant was removed and an audit record written.</Callout></div>}
      {res ? <SimulationView r={res} /> : !err && <Loading kind="block" />}
    </Drawer>
  );
}

type Tab = "access" | "grants" | "violations" | "recs" | "accounts" | "affiliations" | "delegation" | "lifecycle";

function Header({ d }: { d: IdentityDetail }) {
  const acts = useIdentityActions();
  const { actor } = usePersona();
  const toast = useToast();
  const [edit, setEdit] = useState(false);
  const [merging, setMerging] = useState(false);
  const [containing, setContaining] = useState(false);
  const { can } = useSession();
  const nav = useNavigate();
  const human = d.type === "human";
  const status = d.status;
  return (
    <>
      <div className="object-head card">
        <div className="row" style={{ flexWrap: "nowrap", alignItems: "flex-start", minWidth: 0 }}>
          <Avatar name={d.name} type={d.type} lg />
          <div style={{ minWidth: 0 }}>
            <div className="row tight">
              <TypeBadge type={d.type} />
              <Status s={status} />
              {!human && !d.owner && <Badge tone="critical">No owner</Badge>}
            </div>
            <div className="small muted" style={{ marginTop: 6 }}>
              {[d.title, d.department, d.email].filter(Boolean).join(" · ")}
            </div>
            <div className="small muted row" style={{ marginTop: 4 }}>
              {d.manager && <span>Manager <IdLink i={d.manager} /></span>}
              {d.owner && <span>Owner <IdLink i={d.owner} /></span>}
              {d.hired_at && <span>Since {fmtDay(d.hired_at)}</span>}
              {d.terminated_at && <span>Left {fmtDay(d.terminated_at)}</span>}
            </div>
          </div>
        </div>
        <div className="row tight object-actions" role="toolbar" aria-label="Actions">
          {status === "disabled" ? (
            <Button size="sm" icon={<UserCheck size={14} />} disabled={!can("identities.contain")} title={can("identities.contain") ? undefined : "Needs the identities.contain permission"} onClick={() => acts.enable(d)}>Enable</Button>
          ) : (
            <Button size="sm" variant="danger" icon={<Ban size={14} />} disabled={d.status !== "active" || !can("identities.contain")} title={can("identities.contain") ? undefined : "Needs the identities.contain permission"} onClick={() => acts.disable(d)}>Disable</Button>
          )}
          {human ? (
            <Button size="sm" icon={<RotateCcw size={14} />} disabled={status !== "active"} onClick={() => acts.resetPassword(d)}>Reset password</Button>
          ) : (
            <Button size="sm" icon={<RotateCcw size={14} />} onClick={async () => { await mockObjects.save("secret", d.name, actor, "update"); toast(`Secret rotation requested for ${d.name} (preview)`); }}>Rotate secret</Button>
          )}
          <Button size="sm" icon={<Pencil size={14} />} onClick={() => setEdit(true)}>Edit</Button>
          <Button size="sm" icon={<ShoppingCart size={14} />} disabled={status !== "active"} onClick={() => acts.requestFor(d)}>Request access for</Button>
          <Button size="sm" icon={<ClipboardCheck size={14} />} onClick={() => acts.reviewAccess(d)}>Start review</Button>
          <Menu
            label="More actions"
            items={[
              { label: "Open in access graph", icon: <Network size={14} />, onSelect: () => acts.openGraph(d) },
              ...(can("identities.contain") && d.status !== "merged"
                ? [{ label: "Contain identity…", icon: <ShieldAlert size={14} />, onSelect: () => setContaining(true) }]
                : []),
              ...(can("identities.merge") && d.status !== "merged"
                ? [{ label: "Merge into…", icon: <GitMerge size={14} />, onSelect: () => setMerging(true) }]
                : []),
              { label: "Copy link", icon: <Link2 size={14} />, onSelect: () => { navigator.clipboard?.writeText(window.location.href).then(() => toast("Link copied"), () => toast("Couldn't copy the link", { kind: "error" })); } },
            ]}
            trigger={(t) => <Button size="sm" variant="ghost" icon={<Ellipsis size={16} />} label="More actions" {...t} />}
          />
        </div>
      </div>
      {d.status === "merged" && (
        <div className="mt">
          <Callout tone="warn">
            This identity was merged into another one. Its accounts and ownership moved there; its history stays here.{" "}
            <Link to="/directory/matches?tab=merges">See merges</Link> to undo it.
          </Callout>
        </div>
      )}
      {containing && <ContainDialog identity={{ id: d.id, name: d.name }} onClose={() => setContaining(false)} />}
      {merging && (
        <MergeDialog
          merged={d}
          onClose={() => setMerging(false)}
          onMerged={(survivor) => {
            setMerging(false);
            toast(`${d.name} merged`);
            nav(`/directory/identities/${survivor}`);
          }}
        />
      )}
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
    </>
  );
}

export function IdentityPage() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const validId = isNumericId(id);
  const { data: d, error: loadError, reload } = useApi<IdentityDetail>(validId ? `/identities/${id}` : null);
  const error = validId ? loadError : invalidLink();
  const [open, setOpen] = useState<string | null>(null);
  const [filter, setFilter] = useState<"" | "unused" | "privileged" | "sensitive">("");
  const [revoke, setRevoke] = useState<number | null>(null);
  const tab = (params.get("tab") ?? "access") as Tab;
  const setTab = (t: Tab) => setParams({ tab: t }, { replace: true });

  if (!d) return <Page title="Identity" crumbs={[["Identity"], ["…"]]}><Loading error={error} what="identity" kind="page" onRetry={reload} /></Page>;

  const machine = d.type !== "human";
  const crumbs: [string, string?][] = [["Identity"], machine ? ["Machine identities & agents", "/directory/machine"] : ["Users", "/directory/people"], [d.name]];
  const perms = d.effective_permissions.filter((p) => !filter || (filter === "unused" ? p.unused : filter === "privileged" ? p.privileged : p.tags.length > 0));
  const tabs: { id: Tab; label: string }[] = [
    { id: "access", label: `Access (${d.effective_permissions.length})` },
    { id: "grants", label: `Grants (${d.grants.length})` },
    { id: "violations", label: `Violations (${d.violations.length})` },
    { id: "recs", label: `Recommendations (${d.recommendations.length})` },
    { id: "accounts", label: `Accounts (${d.accounts.length})` },
  ];
  if (!machine) tabs.push({ id: "affiliations", label: "Affiliations & identifiers" });
  if (d.delegations.length || d.owned_identities.length) tabs.push({ id: "delegation", label: "Delegation & ownership" });
  if (!machine) tabs.push({ id: "lifecycle", label: "Worker type & dates" });

  return (
    <Page title={d.name} crumbs={crumbs}>
      <Header d={d} />
      {d.description && <div className="mt"><Callout tone="neutral">{d.description}</Callout></div>}
      <div className="card mt">
        <div className="stat-row">
          <div className="s"><b className="tnum">{d.risk?.effective ?? 0}</b><span>effective permissions</span></div>
          <div className="s"><b className="tnum">{d.risk?.unused ?? 0}</b><span>unused 60 days</span></div>
          <div className="s"><b className="tnum">{d.risk?.privileged ?? 0}</b><span>privileged</span></div>
          <div className="s"><b className="tnum">{d.risk?.sensitive ?? 0}</b><span>on sensitive data</span></div>
          <div className="s"><b className="tnum" style={{ color: d.violations.length ? "var(--critical)" : undefined }}>{d.violations.length}</b><span>violations</span></div>
          <div className="s"><b className="tnum">{d.risk?.risk ?? 0}</b><span>risk score</span></div>
        </div>
      </div>
      <div className="mt">
        <Tabs label="Identity sections" tabs={tabs} value={tab} onChange={setTab} />
      </div>

      {tab === "lifecycle" && !machine && <div className="card"><LifecycleSection id={d.id} /></div>}
      {tab === "access" && (
        <div className="card flush">
          <div className="card-h">
            <span className="small muted">Select a permission to see every path that grants it.</span>
            <Segmented label="Filter permissions" value={filter} onChange={setFilter} options={[["", "All"], ["unused", "Unused"], ["privileged", "Privileged"], ["sensitive", "Sensitive"]]} />
          </div>
          {perms.length === 0 ? <EmptyState title="Nothing matches">No permissions match this filter.</EmptyState> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Permission</th><th>Resource</th><th>System</th><th>Last used</th><th className="num hide-narrow">Events 90d</th><th className="num">Paths</th></tr></thead>
                <tbody>
                  {perms.map((p) => (
                    <Fragment key={p.perm_key}>
                      <tr className="click" onClick={() => setOpen(open === p.perm_key ? null : p.perm_key)}>
                        <td><button type="button" className="linklike" aria-expanded={open === p.perm_key} onClick={(e) => { e.stopPropagation(); setOpen(open === p.perm_key ? null : p.perm_key); }}><b>{p.action}</b></button> {p.privileged && <Badge tone="warning">Privileged</Badge>} {!p.standing && <Badge tone="info">JIT</Badge>}</td>
                        <td>{p.resource} {p.environment && <Chip>{p.environment}</Chip>} {p.tags.map((t) => <Chip key={t}>{t}</Chip>)}</td>
                        <td className="sys">{p.system}</td>
                        <td className="nowrap">{p.unused ? <Badge tone="warning">{ago(p.usage.days_since_used)}</Badge> : <span className="small">{ago(p.usage.days_since_used)}</span>}</td>
                        <td className="num hide-narrow">{p.usage.events_90d}</td>
                        <td className="num small muted">{p.paths.length} {open === p.perm_key ? <ChevronDown size={12} aria-hidden /> : <ChevronRight size={12} aria-hidden />}</td>
                      </tr>
                      {open === p.perm_key && (
                        <tr>
                          <td colSpan={6} style={{ background: "var(--surface-2)" }}>
                            <div className="stack-sm">
                              {p.paths.map((path, i) => <PathView key={i} steps={path} />)}
                              <Link className="small" to={`/insights/graph?identity=${d.id}&perm=${encodeURIComponent(p.perm_key)}`}>Show in access graph</Link>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === "grants" && (
        <div className="card flush">
          {d.grants.length === 0 ? <EmptyState title="No grants">This identity holds no group or role memberships.</EmptyState> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Granted</th><th>Account</th><th>Type</th><th>Expires</th><th><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {d.grants.map((g) => (
                    <tr key={g.src + g.dst}>
                      <td><b>{g.label}</b> {g.privileged && <Badge tone="warning">Privileged</Badge>}</td>
                      <td className="sys small">{g.account}</td>
                      <td>{g.source === "jit" ? <Badge tone="info">JIT</Badge> : <span className="muted small">{g.relation.replace(/_/g, " ")}</span>}</td>
                      <td className="small nowrap">{g.expires_at ? fmtDate(g.expires_at) : "Standing"}</td>
                      <td className="actions-cell">{g.edge_id && <Button size="sm" variant="danger" onClick={() => setRevoke(g.edge_id)}>Revoke…</Button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === "affiliations" && !machine && (
        <div className="grid g2">
          <div className="card"><AffiliationsSection identityId={d.id} name={d.name} human /></div>
          <div className="card"><IdentifiersSection identityId={d.id} /></div>
        </div>
      )}

      {tab === "violations" && (
        <div className="stack">
          {d.violations.length === 0 && <div className="card"><EmptyState title="No policy violations" icon={<ShieldCheck size={18} />}>Every policy passes for this identity.</EmptyState></div>}
          {d.violations.map((v) => (
            <div key={v.key} className="card stack-sm">
              <div className="row"><Sev s={v.severity} /><b>{v.policy_name}</b></div>
              <div>{v.message}</div>
              {v.evidence.map((e, i) => <div key={i} className="small muted sys">{e}</div>)}
            </div>
          ))}
        </div>
      )}

      {tab === "recs" && (
        <div className="card flush">
          {d.recommendations.length === 0 ? <EmptyState title="No recommendations">Access matches usage. Nothing to trim.</EmptyState> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Grant</th><th>Recommendation</th><th className="num">Unused / lost</th><th>Last used</th><th><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {d.recommendations.map((r) => (
                    <tr key={r.edge_id}>
                      <td><b>{r.target}</b><div className="xs faint">{r.unused_examples.slice(0, 3).join(", ")}</div></td>
                      <td style={{ maxWidth: 360 }}><Badge tone={r.kind === "remove" ? "critical" : "warning"}>{r.kind === "remove" ? "Remove" : "Right-size"}</Badge><div className="small muted">{r.rationale}</div></td>
                      <td className="num">{r.unused_lost} / {r.permissions_lost}</td>
                      <td className="small nowrap">{ago(r.days_since_used)}</td>
                      <td className="actions-cell"><Button size="sm" onClick={() => setRevoke(r.edge_id)}>Dry-run revoke</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === "accounts" && (
        <div className="grid g2">
          <div className="card flush">
            <div className="card-h"><h2>Accounts</h2></div>
            <div className="table-scroll">
              <table>
                <thead><tr><th>System</th><th>Username</th><th>Status</th><th>Last login</th></tr></thead>
                <tbody>
                  {d.accounts.map((a) => (
                    <tr key={a.id}>
                      <td><Chip mono>{a.system}</Chip></td>
                      <td className="small">{a.username}<div className="xs faint">{a.kind.replace(/_/g, " ")}</div></td>
                      <td><Status s={a.status} /></td>
                      <td className="small nowrap">{fmtDay(a.last_login_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="card flush">
            <div className="card-h"><h2>Secrets and credentials</h2></div>
            {d.secrets.length === 0 ? <EmptyState title="No machine credentials">Only service accounts and agents hold API keys or tokens.</EmptyState> : (
              <div className="table-scroll">
                <table>
                  <thead><tr><th>Secret</th><th className="num">Age</th><th>Last used</th></tr></thead>
                  <tbody>
                    {d.secrets.map((s) => (
                      <tr key={s.id}>
                        <td className="small"><span className="sys">{s.name}</span><div className="xs faint">{s.kind.replace(/_/g, " ")}</div></td>
                        <td className="num">{s.stale ? <Badge tone="warning">{s.age_days} d</Badge> : `${s.age_days} d`}</td>
                        <td className="small nowrap">{ago(s.last_used_days)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {tab === "delegation" && (
        <div className="grid g2">
          <div className="card stack-sm">
            <h2>Delegations</h2>
            {d.delegations.length === 0 && <div className="muted small">None</div>}
            {d.delegations.map((x, i) => (
              <div key={i} className="stack-sm">
                <div className="small"><IdLink i={x.agent} /> acts on behalf of <IdLink i={x.principal} /></div>
                <div className="row tight">{x.scopes.map((s) => <Chip key={s} mono>{s}</Chip>)}</div>
              </div>
            ))}
          </div>
          <div className="card stack-sm">
            <h2>Owns</h2>
            {d.owned_identities.length === 0 && <div className="muted small">Nothing</div>}
            {d.owned_identities.map((o) => (
              <div key={o.id} className="row small"><TypeBadge type={o.type} /><IdLink i={o} /><span className="faint">{o.title}</span></div>
            ))}
          </div>
        </div>
      )}
      {revoke !== null && <RevokeDrawer edgeId={revoke} onClose={() => setRevoke(null)} onDone={reload} />}
    </Page>
  );
}
