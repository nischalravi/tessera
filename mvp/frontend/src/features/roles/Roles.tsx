/**
 * Business roles (issue #161): a role bundles entitlements from several systems, with an owner,
 * a risk and an optional birthright rule. Every change (create, edit, assign, remove, reconcile,
 * retire) is previewed as a plan first: the grants Tessera adds, the role grants it removes and
 * the grants it keeps because something else grants them.
 */
import { FormEvent, ReactNode, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Archive, ClipboardCheck, History, Pencil, Plus, RefreshCw, ShoppingCart, UserMinus, UserPlus } from "lucide-react";
import {
  AbacList, BusinessRole, Group, IdentityRow, PersonRef, PlanStep, RoleChange, RoleDrift, RolePlan, RoleRule, RoleSpec, RoleVersion, RolesView,
  fmtDate, relTime, abacPaths, rolePaths, roles as roleApi, useApi,
} from "../../api";
import { useIdentityActions } from "../../app/actions";
import {
  Badge, Button, Callout, CommandBar, DataTable, Drawer, EmptyState, Loading, Page, SidePanel, Status, Tabs, useSelected, useToast,
} from "../../components";

const I = 16;
const riskTone = (r: string) => (r === "high" ? "critical" : r === "medium" ? "warning" : "ok");
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);
const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const gname = (g: { system: string; name: string }) => `${g.system}:${g.name}`;

/** A short label for lists: "Engineering · 2 titles" (the full rule is in ruleText). */
export function ruleShort(r: RoleRule | null): string | null {
  if (!r) return null;
  const parts = [r.department.join(", "), r.type.length ? `${r.type.length} type${r.type.length === 1 ? "" : "s"}` : "", r.title.length ? `${r.title.length} title${r.title.length === 1 ? "" : "s"}` : "", r.policy ? "attribute policy" : ""];
  return parts.filter(Boolean).join(" · ") || null;
}

/** "Engineering; titles: Frontend Engineer" (null: no rule). */
export function ruleText(r: RoleRule | null): string | null {
  if (!r) return null;
  const parts = [r.department.join(", "), r.type.length ? `types: ${r.type.join(", ")}` : "", r.title.length ? `titles: ${r.title.join(", ")}` : "", r.policy ? "an attribute policy" : ""];
  return parts.filter(Boolean).join("; ") || null;
}

const sourceLabel: Record<string, string> = { rule: "Birthright rule", request: "Request", manual: "Assigned" };

// ------------------------------------------------------------------- list
export function Roles() {
  const { data: view, error, reload } = useApi<RolesView>(rolePaths.list);
  const nav = useNavigate();
  const acts = useIdentityActions();
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useSelected();
  const newOpen = params.get("new") === "1";
  const setNew = (v: boolean) => {
    const next = new URLSearchParams(params);
    if (v) next.set("new", "1");
    else next.delete("new");
    setParams(next, { replace: true });
  };
  const rows = view?.roles ?? null;
  const open = rows?.find((r) => r.id === selected);
  return (
    <Page title="Roles" count={rows ? plural(rows.length, "role") : null} crumbs={[["Identity"], ["Roles"]]}
      sub="Business roles bundle entitlements from several systems, so people request one thing and reviewers certify one thing.">
      <DataTable
        id="roles"
        rows={rows}
        error={error}
        rowKey={(r) => r.id}
        columns={[
          { id: "name", header: "Role", sort: (r) => r.name, cell: (r) => <div><span className="name-link">{r.name}</span><div className="xs faint truncate" style={{ maxWidth: 420 }}>{r.description}</div></div> },
          { id: "owner", header: "Owner", sort: (r) => r.owner?.name ?? "", cell: (r) => <span className="small">{r.owner?.name ?? <span className="faint">No owner</span>}</span>, hideNarrow: true },
          { id: "ents", header: "Entitlements", num: true, sort: (r) => r.entitlements.length, cell: (r) => r.entitlements.length },
          { id: "birth", header: "Birthright for", sort: (r) => ruleText(r.birthright) ?? "", cell: (r) => (r.birthright ? <Badge tone="outline" title={ruleText(r.birthright) ?? undefined}>{ruleShort(r.birthright)}</Badge> : <span className="faint">-</span>), hideNarrow: true },
          { id: "members", header: "Members", num: true, sort: (r) => r.member_count, cell: (r) => r.member_count },
          { id: "risk", header: "Risk", sort: (r) => ["low", "medium", "high"].indexOf(r.risk), csv: (r) => r.risk, cell: (r) => <Badge tone={riskTone(r.risk)} dot>{cap(r.risk)}</Badge> },
          { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => (r.status === "retired" ? <Badge>Retired</Badge> : r.requestable ? <Badge tone="info">Requestable</Badge> : <span className="small faint">Active</span>) },
          { id: "updated", header: "Updated", sort: (r) => r.updated_at, cell: (r) => <span className="small nowrap" title={fmtDate(r.updated_at)}>{relTime(r.updated_at)}</span>, hideNarrow: true },
        ]}
        searchText={(r) => `${r.name} ${r.description} ${r.owner?.name ?? ""} ${r.entitlements.map(gname).join(" ")}`}
        searchPlaceholder="Search roles or the entitlements in them…"
        filters={[
          { id: "risk", label: "Risk", options: ["low", "medium", "high"].map((v) => ({ value: v, label: cap(v) })), get: (r) => r.risk },
          { id: "status", label: "Status", options: [{ value: "active", label: "Active" }, { value: "retired", label: "Retired" }], get: (r) => r.status },
          { id: "birth", label: "Assigned by", options: [{ value: "rule", label: "Birthright rule" }, { value: "none", label: "Request or by hand" }], get: (r) => (r.birthright ? "rule" : "none") },
        ]}
        commands={[
          view?.can_manage && { label: "New role", icon: <Plus size={I} />, onClick: () => setNew(true) },
          { label: "Start review", icon: <ClipboardCheck size={I} />, onClick: () => acts.startCampaign() },
        ]}
        bulkActions={[{ label: "Request", icon: <ShoppingCart size={I} />, run: (rs) => nav(`/access/request?add=${rs.filter((r) => r.requestable && r.status === "active").map((r) => r.id).join(",")}`) }]}
        onRefresh={reload}
        rowLabel={(r) => r.name}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        empty={<EmptyState title="No business roles yet">{view?.can_manage ? "Create one to bundle entitlements people usually get together." : "Policy admins create roles here."}</EmptyState>}
      />
      {open && view && <RolePanel id={open.id} view={view} onClose={() => setSelected(null)} />}
      {newOpen && <RoleEditor onClose={() => setNew(false)} onSaved={(r) => setSelected(r.id)} />}
    </Page>
  );
}

// ------------------------------------------------------------------- detail
type RoleTab = "overview" | "ents" | "members" | "drift" | "history";

function useRoleCommands(role: BusinessRole | null, view: RolesView | null) {
  const nav = useNavigate();
  const [drawer, setDrawer] = useState<null | "edit" | "assign" | "reconcile" | "retire" | { remove: PersonRef }>(null);
  const manage = !!view?.can_manage && role?.status === "active";
  const items = role ? [
    role.requestable && role.status === "active" && !role.held && { label: role.pending ? "Requested" : "Request this role", icon: <ShoppingCart size={I} />, disabled: role.pending, onClick: () => nav(`/access/request?add=${role.id}`) },
    manage && { label: "Edit", icon: <Pencil size={I} />, onClick: () => setDrawer("edit") },
    manage && { label: "Assign", icon: <UserPlus size={I} />, onClick: () => setDrawer("assign") },
    manage && { label: "Reconcile", icon: <RefreshCw size={I} />, onClick: () => setDrawer("reconcile"), title: "Bring rule members and grants in step" },
    manage && { label: "Retire", icon: <Archive size={I} />, danger: true, onClick: () => setDrawer("retire") },
  ] : [];
  const drawers = role && drawer && (
    drawer === "edit" ? <RoleEditor role={role} onClose={() => setDrawer(null)} />
      : drawer === "assign" ? <AssignDrawer role={role} onClose={() => setDrawer(null)} />
        : drawer === "reconcile" ? (
          <PlanDrawer title={`Reconcile ${role.name}`} intro="Adds people the birthright rule now matches, removes rule members it no longer matches, and restores grants members are missing."
            run={(d) => roleApi.reconcile(role.id, d)} applyLabel="Apply" done="Role reconciled" onClose={() => setDrawer(null)} />
        ) : drawer === "retire" ? (
          <PlanDrawer title={`Retire ${role.name}`} intro="Every member loses the role and the grants only it gave them. Pending requests are denied. The role stays in the history."
            reason="required" danger run={(d, why) => roleApi.retire(role.id, why, d)} applyLabel="Retire role" done="Role retired" onClose={() => setDrawer(null)} />
        ) : (
          <PlanDrawer title={`Remove ${drawer.remove.name} from ${role.name}`} intro="They lose the role and the grants only it gave them. Grants they have another way stay."
            reason="required" danger run={(d, why) => roleApi.unassign(role.id, drawer.remove.id, why, d)} applyLabel="Remove" done="Removed from the role" onClose={() => setDrawer(null)} />
        )
  );
  return { items, drawers, remove: manage ? (p: PersonRef) => setDrawer({ remove: p }) : undefined };
}

function RoleBody({ role, tab, onRemove }: { role: BusinessRole; tab: RoleTab; onRemove?: (p: PersonRef) => void }) {
  switch (tab) {
    case "overview":
      return (
        <>
          {role.status === "retired" && <Callout tone="neutral">This role is retired: nobody holds it and it cannot be requested.</Callout>}
          <p className="muted">{role.description || <span className="faint">No description</span>}</p>
          <dl className="kv">
            <dt>Owner</dt><dd>{role.owner ? <Link to={`/directory/identities/${role.owner.id}`}>{role.owner.name}</Link> : <span className="faint">No owner</span>}</dd>
            <dt>Birthright for</dt><dd>{ruleText(role.birthright) ?? <span className="faint">Nobody (request or assign)</span>}</dd>
            <dt>Requestable</dt><dd>{role.requestable ? "Yes, in the catalog" : "No"}</dd>
            <dt>Members</dt><dd className="tnum">{role.member_count}</dd>
            <dt>Version</dt><dd className="tnum">{role.version}</dd>
            <dt>Updated</dt><dd>{fmtDate(role.updated_at)}{role.updated_by && ` by ${role.updated_by.display_name}`}</dd>
          </dl>
        </>
      );
    case "ents":
      return (
        <table>
          <thead><tr><th>Entitlement</th><th>Kind</th><th><span className="sr-only">Flags</span></th></tr></thead>
          <tbody>
            {role.entitlements.map((g) => (
              <tr key={g.id}>
                <td><Link className="sys" to={`/directory/entitlements/${g.id}`}>{gname(g)}</Link></td>
                <td className="small">{g.kind.replace(/_/g, " ")}</td>
                <td style={{ textAlign: "right" }}>{g.privileged && <Badge tone="warning">Privileged</Badge>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      );
    case "members":
      return !role.members?.length ? <EmptyState title="Nobody holds this role">{role.birthright ? "Reconcile to assign the people its rule matches." : "Assign people, or let them request it."}</EmptyState> : (
        <table>
          <thead><tr><th>Person</th><th>How</th><th>Since</th><th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {role.members.map((m) => (
              <tr key={m.person.id}>
                <td><Link to={`/directory/identities/${m.person.id}`}>{m.person.name}</Link>{m.person.status !== "active" && <> <Status s={m.person.status} /></>}</td>
                <td className="small">{sourceLabel[m.source]}{m.assigned_by && <div className="xs faint">by {m.assigned_by.display_name}</div>}</td>
                <td className="small faint nowrap" title={fmtDate(m.assigned_at)}>{relTime(m.assigned_at)}</td>
                <td style={{ textAlign: "right" }}>
                  {onRemove && m.source !== "rule" && <Button size="sm" variant="danger" icon={<UserMinus size={14} />} onClick={() => onRemove(m.person)} aria-label={`Remove ${m.person.name}`}>Remove</Button>}
                  {m.source === "rule" && <span className="xs faint">Change the rule to remove</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      );
    case "drift":
      return <DriftView id={role.id} />;
    case "history":
      return <VersionsView id={role.id} />;
  }
}

function DriftView({ id }: { id: string }) {
  const { data, error } = useApi<RoleDrift>(rolePaths.drift(id));
  if (!data) return <Loading error={error} kind="block" />;
  return (
    <div className="stack">
      <section className="stack-sm" aria-labelledby="drift-missing">
        <h3 id="drift-missing">Members missing entitlements ({data.missing.length})</h3>
        {data.missing.length === 0 ? <p className="small muted">Every member holds everything in the role.</p> : (
          <>
            <p className="small muted">A grant was removed elsewhere, or the person has no account in that system. Reconcile restores what it can.</p>
            <ul className="stack-sm">{data.missing.map((m) => <li key={m.person.id}><Link to={`/directory/identities/${m.person.id}`}>{m.person.name}</Link>: <span className="sys small">{m.missing.map(gname).join(", ")}</span></li>)}</ul>
          </>
        )}
      </section>
      <section className="stack-sm" aria-labelledby="drift-holders">
        <h3 id="drift-holders">Hold the entitlements without the role ({data.holders.length})</h3>
        {data.holders.length === 0 ? <p className="small muted">Nobody else holds most of this role's entitlements.</p> : (
          <>
            <p className="small muted">Candidates to assign the role to, or access to review.</p>
            <ul className="stack-sm">
              {data.holders.slice(0, 100).map((h) => (
                <li key={h.person.id}><Link to={`/directory/identities/${h.person.id}`}>{h.person.name}</Link>{" "}
                  {h.holds_all ? <Badge tone="info">Holds all</Badge> : <span className="small faint">{h.held.length} of them</span>}</li>
              ))}
            </ul>
          </>
        )}
      </section>
    </div>
  );
}

function VersionsView({ id }: { id: string }) {
  const { data, error } = useApi<RoleVersion[]>(rolePaths.versions(id));
  if (!data) return <Loading error={error} kind="block" />;
  return (
    <ol className="timeline">
      {data.map((v) => {
        const s = v.snapshot as { status?: string; entitlements?: number[]; name?: string };
        return (
          <li key={v.version}>
            <b>Version {v.version}</b> by {v.actor} <span className="faint" title={fmtDate(v.changed_at)}>{relTime(v.changed_at)}</span>
            <div className="small muted">{s.name}{s.entitlements ? `, ${plural(s.entitlements.length, "entitlement")}` : ""}{s.status === "retired" ? ", retired" : ""}</div>
            {v.note && <div className="small">{v.note}</div>}
          </li>
        );
      })}
    </ol>
  );
}

function roleTabs(role: BusinessRole | null, canRead: boolean): { id: RoleTab; label: ReactNode }[] {
  return [
    { id: "overview", label: "Overview" },
    { id: "ents", label: `Entitlements (${role?.entitlements.length ?? "…"})` },
    ...(canRead ? [
      { id: "members" as RoleTab, label: `Members (${role?.member_count ?? "…"})` },
      { id: "drift" as RoleTab, label: "Drift" },
      { id: "history" as RoleTab, label: <><History size={13} aria-hidden /> History</> },
    ] : []),
  ];
}

export function RolePanel({ id, view, onClose }: { id: string; view: RolesView; onClose: () => void }) {
  const summary = view.roles.find((r) => r.id === id) ?? null;
  const { data: detail, error } = useApi<BusinessRole>(view.can_read_members ? rolePaths.one(id) : null);
  const role = detail ? { ...detail, held: summary?.held ?? false, pending: summary?.pending ?? false } : summary;
  const [tab, setTab] = useState<RoleTab>("overview");
  useEffect(() => setTab("overview"), [id]);
  const cmds = useRoleCommands(role, view);
  if (!role) return null;
  // drawers sit beside the panel, not inside it (the panel's transform would trap them)
  return (
    <>
    <SidePanel
      title={role.name}
      sub={<><Badge tone={riskTone(role.risk)}>{cap(role.risk)} risk</Badge>{role.status === "retired" && <Badge>Retired</Badge>}</>}
      onClose={onClose}
      fullHref={`/directory/roles/${role.id}`}
      commands={<CommandBar label={`Actions for ${role.name}`} items={cmds.items} />}
      tabs={<Tabs label="Role details" value={tab} onChange={setTab} tabs={roleTabs(role, view.can_read_members)} />}
    >
      {error && tab !== "overview" && tab !== "ents" ? <Loading error={error} kind="block" /> : <RoleBody role={role} tab={tab} onRemove={cmds.remove} />}
    </SidePanel>
    {cmds.drawers}
    </>
  );
}

export function RolePage() {
  const { id = "" } = useParams();
  const { data: view } = useApi<RolesView>(rolePaths.list);
  const { data: detail, error } = useApi<BusinessRole>(rolePaths.one(id));
  const summary = view?.roles.find((r) => r.id === id) ?? null;
  const role = detail ? { ...detail, held: summary?.held ?? false, pending: summary?.pending ?? false } : summary;
  const [tab, setTab] = useState<RoleTab>("overview");
  const cmds = useRoleCommands(role, view);
  if (!role) {
    return error ? (
      <Page title="Role not found" crumbs={[["Identity"], ["Roles", "/directory/roles"]]}>
        <div className="card"><EmptyState title="That role doesn't exist" action={<Link to="/directory/roles">Back to roles</Link>}>It may have been removed, or the link is wrong.</EmptyState></div>
      </Page>
    ) : <Loading kind="page" />;
  }
  return (
    <Page title={role.name} crumbs={[["Identity"], ["Roles", "/directory/roles"], [role.name]]}
      badge={<><Badge tone={riskTone(role.risk)} dot>{cap(role.risk)} risk</Badge>{role.status === "retired" && <Badge>Retired</Badge>}</>}
      commands={<CommandBar label={`Actions for ${role.name}`} items={cmds.items} />}>
      <Tabs label="Role details" value={tab} onChange={setTab} tabs={roleTabs(role, view?.can_read_members ?? true)} />
      <div className="card mt"><RoleBody role={role} tab={tab} onRemove={cmds.remove} /></div>
      {cmds.drawers}
    </Page>
  );
}

// ------------------------------------------------------------------- plans
const ACTION: Record<PlanStep["action"], { label: string; tone: "ok" | "critical" | "info" | "warning" | "neutral" }> = {
  add_member: { label: "Gets the role", tone: "info" },
  remove_member: { label: "Loses the role", tone: "warning" },
  add_grant: { label: "Grant", tone: "ok" },
  remove_grant: { label: "Remove grant", tone: "critical" },
  keep_grant: { label: "Keeps", tone: "neutral" },
  no_account: { label: "No account", tone: "warning" },
};

export function PlanView({ plan }: { plan: RolePlan }) {
  const shown = plan.steps.slice(0, 300);
  return (
    <div className="stack-sm" aria-live="polite">
      <div className="row tight" role="list" aria-label="Plan summary">
        <span role="listitem"><Badge tone="info">{plural(plan.members_added, "person", "people")} gain the role</Badge></span>
        <span role="listitem"><Badge tone="warning">{plural(plan.members_removed, "person", "people")} lose it</Badge></span>
        <span role="listitem"><Badge tone="ok">{plural(plan.grants_added, "grant")} added</Badge></span>
        <span role="listitem"><Badge tone="critical">{plural(plan.grants_removed, "grant")} removed</Badge></span>
        {plan.no_account > 0 && <span role="listitem"><Badge tone="warning">{plan.no_account} without an account</Badge></span>}
      </div>
      {plan.steps.length === 0 ? <p className="small muted">Nothing to change.</p> : (
        <div className="table-scroll" style={{ maxHeight: 360 }}>
          <table>
            <thead><tr><th>Person</th><th>Change</th><th>What</th><th>Why</th></tr></thead>
            <tbody>
              {shown.map((s, i) => (
                <tr key={i}>
                  <td className="small">{s.identity}</td>
                  <td><Badge tone={ACTION[s.action].tone}>{ACTION[s.action].label}</Badge></td>
                  <td className="small sys">{s.group ?? s.role ?? ""}</td>
                  <td className="xs muted">{s.reason ?? (s.source ? sourceLabel[s.source] : "")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {plan.steps.length > shown.length && <p className="xs faint">and {plan.steps.length - shown.length} more steps</p>}
    </div>
  );
}

/** A change previewed as a plan (dry run), then applied. */
function PlanDrawer({ title, intro, reason, danger, run, applyLabel, done, onClose, children, ready = true, deps = "" }: {
  title: string; intro: ReactNode; reason?: "required" | "optional"; danger?: boolean;
  run: (dryRun: boolean, reason: string) => Promise<RoleChange>; applyLabel: string; done: string; onClose: () => void;
  children?: ReactNode; ready?: boolean; deps?: string;
}) {
  const toast = useToast();
  const [why, setWhy] = useState("");
  const [plan, setPlan] = useState<RolePlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setPlan(null), [why, deps]);
  const blocked = !ready || (reason === "required" && !why.trim());
  const go = async (dry: boolean) => {
    setBusy(true);
    setErr(null);
    try {
      const res = await run(dry, why.trim());
      if (dry) setPlan(res.plan);
      else {
        toast(`${done}: ${plural(res.plan.grants_added, "grant")} added, ${plural(res.plan.grants_removed, "grant")} removed`);
        onClose();
      }
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={title} onClose={onClose} wide
      footer={<>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={() => go(true)} disabled={blocked || busy}>{plan ? "Preview again" : "Preview plan"}</Button>
        <Button variant={danger ? "danger-solid" : "primary"} onClick={() => go(false)} disabled={blocked || busy || !plan}>{applyLabel}</Button>
      </>}>
      <div className="stack">
        <p className="muted">{intro}</p>
        {children}
        {reason && (
          <label className="field">{reason === "required" ? "Reason (kept in the audit log)" : "Note (optional)"}
            <textarea className="input" value={why} onChange={(e) => setWhy(e.target.value)} />
          </label>
        )}
        {err && <Callout tone="bad">{err}</Callout>}
        {plan ? <PlanView plan={plan} /> : <p className="small faint">Preview the plan to see what changes before you apply it.</p>}
      </div>
    </Drawer>
  );
}

function AssignDrawer({ role, onClose }: { role: BusinessRole; onClose: () => void }) {
  const { data: people } = useApi<IdentityRow[]>("/identities?status=active");
  const [pid, setPid] = useState<number | "">("");
  const [q, setQ] = useState("");
  const taken = new Set((role.members ?? []).map((m) => m.person.id));
  const shown = (people ?? []).filter((p) => !taken.has(p.id) && p.name.toLowerCase().includes(q.toLowerCase())).slice(0, 200);
  return (
    <PlanDrawer title={`Assign ${role.name}`} intro="The person gets the role and every entitlement in it they don't already hold." reason="optional"
      ready={pid !== ""} deps={String(pid)} run={(d, why) => roleApi.assign(role.id, Number(pid), why, d)} applyLabel="Assign" done="Role assigned" onClose={onClose}>
      <label className="field">Find a person<input className="input" data-autofocus value={q} onChange={(e) => setQ(e.target.value)} placeholder="Name" /></label>
      <label className="field">Person
        <select className="input" value={pid} onChange={(e) => setPid(e.target.value ? Number(e.target.value) : "")}>
          <option value="">Choose…</option>
          {shown.map((p) => <option key={p.id} value={p.id}>{p.name}{p.department ? ` (${p.department})` : ""}</option>)}
        </select>
      </label>
    </PlanDrawer>
  );
}

// ------------------------------------------------------------------- editor
const TYPES: [string, string][] = [["human", "People"], ["service", "Service accounts"], ["ai_agent", "AI agents"]];

function toSpec(role?: BusinessRole): RoleSpec {
  return {
    name: role?.name ?? "", description: role?.description ?? "", owner_identity_id: role?.owner?.id ?? null, risk: role?.risk ?? "low",
    requestable: role?.requestable ?? false, birthright: role?.birthright ?? null, entitlement_group_ids: role?.entitlements.map((g) => g.id) ?? [], note: "",
  };
}

export function RoleEditor({ role, onClose, onSaved }: { role?: BusinessRole; onClose: () => void; onSaved?: (r: BusinessRole) => void }) {
  const { data: groups } = useApi<Group[]>("/groups");
  const { data: people } = useApi<IdentityRow[]>("/identities?status=active");
  const { data: abacView } = useApi<AbacList>(abacPaths.list);
  const toast = useToast();
  const [spec, setSpec] = useState<RoleSpec>(() => toSpec(role));
  const [useRule, setUseRule] = useState(!!role?.birthright);
  const [titles, setTitles] = useState((role?.birthright?.title ?? []).join(", "));
  const [q, setQ] = useState("");
  const [plan, setPlan] = useState<RolePlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const depts = useMemo(() => [...new Set((people ?? []).map((p) => p.department).filter((d): d is string => !!d))].sort(), [people]);
  const owners = useMemo(() => (people ?? []).filter((p) => p.type === "human"), [people]);
  const rule: RoleRule | null = useRule
    ? { department: spec.birthright?.department ?? [], type: spec.birthright?.type ?? [], title: titles.split(",").map((t) => t.trim()).filter(Boolean), policy: spec.birthright?.policy ?? "" }
    : null;
  const body: RoleSpec = { ...spec, birthright: rule };
  const sig = JSON.stringify(body);
  useEffect(() => setPlan(null), [sig]);
  const set = (p: Partial<RoleSpec>) => setSpec((s) => ({ ...s, ...p }));
  const setRule = (p: Partial<RoleRule>) => setSpec((s) => ({ ...s, birthright: { department: [], type: [], title: [], ...s.birthright, ...p } }));
  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  const picked = new Set(spec.entitlement_group_ids);
  const shown = (groups ?? []).filter((g) => gname(g).toLowerCase().includes(q.toLowerCase()));
  const ruleEmpty = useRule && !rule!.department.length && !rule!.type.length && !rule!.title.length && !rule!.policy;
  const ready = spec.name.trim() !== "" && picked.size > 0 && !ruleEmpty;
  const go = async (dry: boolean) => {
    setBusy(true);
    setErr(null);
    try {
      const res = role ? await roleApi.update(role.id, role.version, body, dry) : await roleApi.create(body, dry);
      if (dry) setPlan(res.plan);
      else {
        toast(`Role “${res.role.name}” saved: ${plural(res.plan.members_added, "member")} added, ${plural(res.plan.grants_added, "grant")} added, ${plural(res.plan.grants_removed, "grant")} removed`);
        onSaved?.(res.role);
        onClose();
      }
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (ready && !busy) void go(!plan);
  };
  return (
    <Drawer title={role ? `Edit ${role.name}` : "New role"} onClose={onClose} wide
      footer={<>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={() => go(true)} disabled={!ready || busy}>{plan ? "Preview again" : "Preview plan"}</Button>
        <Button type="submit" form="role-form" variant="primary" disabled={!ready || busy || !plan}>{role ? "Save changes" : "Create role"}</Button>
      </>}>
      <form id="role-form" className="stack" onSubmit={submit}>
        <label className="field">Name<input className="input" data-autofocus value={spec.name} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. Payments engineer" maxLength={120} /></label>
        <label className="field">Description<textarea className="input" value={spec.description} onChange={(e) => set({ description: e.target.value })} placeholder="Who should have it and why" /></label>
        <div className="grid g2">
          <label className="field">Owner
            <select className="input" value={spec.owner_identity_id ?? ""} onChange={(e) => set({ owner_identity_id: e.target.value ? Number(e.target.value) : null })}>
              <option value="">No owner</option>
              {owners.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </label>
          <label className="field">Risk
            <select className="input" value={spec.risk} onChange={(e) => set({ risk: e.target.value as RoleSpec["risk"] })}>
              <option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option>
            </select>
          </label>
        </div>
        <label className="row tight"><input type="checkbox" checked={spec.requestable} onChange={(e) => set({ requestable: e.target.checked })} /> People can request it in the catalog</label>
        <fieldset className="field stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend>Birthright rule</legend>
          <label className="row tight"><input type="checkbox" checked={useRule} onChange={(e) => setUseRule(e.target.checked)} /> Assign it automatically to the active people who match</label>
          {useRule && (
            <div className="stack-sm card" style={{ padding: 12 }}>
              <div><div className="small">Departments</div>
                <div className="row tight">{depts.map((d) => <label key={d} className="row tight small"><input type="checkbox" checked={!!spec.birthright?.department.includes(d)} onChange={() => setRule({ department: toggle(spec.birthright?.department ?? [], d) })} /> {d}</label>)}</div>
              </div>
              <div><div className="small">Identity types</div>
                <div className="row tight">{TYPES.map(([v, l]) => <label key={v} className="row tight small"><input type="checkbox" checked={!!spec.birthright?.type.includes(v)} onChange={() => setRule({ type: toggle(spec.birthright?.type ?? [], v) })} /> {l}</label>)}</div>
              </div>
              <label className="field small">Job titles (comma separated, exact)<input className="input" value={titles} onChange={(e) => setTitles(e.target.value)} placeholder="e.g. Frontend Engineer, Engineering Manager, Frontend" /></label>
              <label className="field small">Attribute policy (optional, must also hold)
                <select className="input" value={spec.birthright?.policy ?? ""} onChange={(e) => setRule({ policy: e.target.value })}>
                  <option value="">None</option>
                  {(abacView?.policies ?? []).filter((p) => p.status === "active" || p.id === spec.birthright?.policy).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </label>
              {ruleEmpty && <p className="xs faint">Pick at least one department, type, title or attribute policy.</p>}
            </div>
          )}
        </fieldset>
        <fieldset className="field stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend>Entitlements ({picked.size})</legend>
          <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter entitlements…" aria-label="Filter entitlements" />
          <div className="card flush" style={{ maxHeight: 240, overflow: "auto" }}>
            {!groups ? <Loading kind="block" /> : shown.map((g) => (
              <label key={g.id} className="row small" style={{ padding: "6px 12px", borderBottom: "1px solid var(--border)", flexWrap: "nowrap" }}>
                <input type="checkbox" checked={picked.has(g.id)} onChange={(e) => set({ entitlement_group_ids: e.target.checked ? [...spec.entitlement_group_ids, g.id] : spec.entitlement_group_ids.filter((x) => x !== g.id) })} />
                <span className="sys grow">{gname(g)}</span>
                {g.privileged && <Badge tone="warning">Privileged</Badge>}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="field">Why this change (kept with the version)<input className="input" value={spec.note} onChange={(e) => set({ note: e.target.value })} maxLength={500} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
        {plan ? <PlanView plan={plan} /> : <p className="small faint">Preview the plan to see who gains or loses access before you save.</p>}
      </form>
    </Drawer>
  );
}
