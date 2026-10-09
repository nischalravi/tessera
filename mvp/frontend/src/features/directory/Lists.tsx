import { FormEvent, useMemo, useState } from "react";
import { Outlet, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { Ban, ClipboardCheck, KeyRound, Plus, RotateCcw, ShoppingCart, Users } from "lucide-react";
import { AccountRow, ConnectorRow, Group, HrisEvent, IdentityRow, NhiRow, ResourceRow, api, fmtDay, relTime, useApi } from "../../api";
import { useIdentityActions } from "../../app/actions";
import { usePersona } from "../../app/persona";
import {
  Avatar, Badge, Bar, Button, Callout, Chip, Column, DataTable, Drawer, EmptyState, Flag, IdLink, LinkTabs, Page, PreviewBadge, Status, TypeBadge, useToast,
} from "../../components";
import { ORGS, mockObjects, mockRoles, useMockState, useRoles } from "../../mocks";
import { AgentCard } from "./AgentCards";
import { ImportDrawer, PreviewFormDrawer, opts, uniq } from "./shared";

const TABS = [
  { to: "/directory/people", label: "People" },
  { to: "/directory/machine", label: "Machine identities & agents" },
  { to: "/directory/accounts", label: "Accounts" },
  { to: "/directory/roles", label: "Roles" },
  { to: "/directory/entitlements", label: "Entitlements" },
  { to: "/directory/apps", label: "Applications & systems" },
  { to: "/directory/orgs", label: "Organizations" },
  { to: "/directory/groups", label: "Groups" },
];

export function DirectoryLayout() {
  const { pathname } = useLocation();
  const current = TABS.find((t) => pathname.startsWith(t.to));
  return (
    <Page title="Directory" crumbs={[["Directory", "/directory"], [current?.label ?? ""]]} sub="Everyone and everything that holds access, and the things access is made of. Open any row for its full picture and actions.">
      <LinkTabs label="Directory sections" tabs={TABS} />
      <Outlet />
    </Page>
  );
}

/** `?new=1` / `?import=1` deep links (from the command palette) open the matching drawer. */
function useDrawerParam(name: "new" | "import") {
  const [params, setParams] = useSearchParams();
  const open = params.get(name) === "1";
  const set = (v: boolean) => {
    const next = new URLSearchParams(params);
    if (v) next.set(name, "1");
    else next.delete(name);
    setParams(next, { replace: true });
  };
  return [open, set] as const;
}

function useImport() {
  const [open, setOpen] = useDrawerParam("import");
  const [file, setFile] = useState<{ rows: Record<string, string>[]; name: string } | null>(null);
  return {
    open: open || !!file,
    file,
    start: () => setOpen(true),
    onImport: (rows: Record<string, string>[], name: string) => setFile({ rows, name }),
    close: () => {
      setFile(null);
      setOpen(false);
    },
  };
}

const NewButton = ({ label, onClick, preview }: { label: string; onClick: () => void; preview?: boolean }) => (
  <Button size="sm" variant="primary" icon={<Plus size={14} />} onClick={onClick} title={preview ? "Preview: saved in this browser only" : undefined}>{label}</Button>
);

// ------------------------------------------------------------------ people
const TEAMS = ["backend", "frontend", "platform", "data", "security", "finance", "sales", "support", "people", "exec"];
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);

/** "New person" emits a real HRIS joiner event; the joiner plan then provisions birthright access. */
function NewPersonDrawer({ onClose }: { onClose: () => void }) {
  const nav = useNavigate();
  const toast = useToast();
  const [f, setF] = useState({ name: "", title: "", team: "backend" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const ev = await api<HrisEvent>("/hris/events", {
        type: "joiner",
        identity_id: null,
        payload: { name: f.name.trim(), email: `${f.name.trim().toLowerCase().replace(/\s+/g, ".")}@larkspur.example`, team: f.team, department: cap(f.team), title: f.title.trim() || "New hire" },
      });
      toast(`Joiner created for ${f.name}. Review the provisioning plan.`, { action: { label: "Open plan", run: () => nav(`/governance/lifecycle?event=${ev.id}`) } });
      onClose();
    } catch (x) {
      setErr((x as Error).message);
      setBusy(false);
    }
  };
  return (
    <Drawer title="Onboard a new person" sub="Creates a joiner event, the same as one arriving from Workday. Nothing is provisioned until you execute the plan." onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="new-person" variant="primary" disabled={busy || !f.name.trim()}>Create joiner</Button></>}
    >
      <form id="new-person" className="stack" onSubmit={submit}>
        <label className="field">Full name<input className="input" data-autofocus value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="e.g. Juniper Halloway" /></label>
        <label className="field">Job title<input className="input" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} placeholder="New hire" /></label>
        <label className="field">Team
          <select className="input" value={f.team} onChange={(e) => setF({ ...f, team: e.target.value })}>{TEAMS.map((t) => <option key={t} value={t}>{cap(t)}</option>)}</select>
          <span className="hint">Decides birthright access: the team's role and groups.</span>
        </label>
        {err && <Callout tone="bad">{err}</Callout>}
      </form>
    </Drawer>
  );
}

function identityColumns(): Column<IdentityRow>[] {
  return [
    {
      id: "name", header: "Name", sort: (r) => r.name.toLowerCase(), csv: (r) => r.name,
      cell: (r) => (
        <div className="row" style={{ flexWrap: "nowrap" }}>
          <Avatar name={r.name} type={r.type} />
          <div style={{ minWidth: 0 }}>
            <b>{r.name}</b>
            <div className="xs faint truncate">{r.email ?? ""}</div>
          </div>
        </div>
      ),
    },
    { id: "dept", header: "Department", sort: (r) => r.department ?? "", cell: (r) => <span className="small">{r.department}<div className="xs faint">{r.title}</div></span>, hideNarrow: true },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Status s={r.status} /> },
    { id: "systems", header: "Systems", csv: (r) => r.systems.join(" "), cell: (r) => <div className="row tight">{r.systems.map((s) => <Chip key={s} mono>{s}</Chip>)}</div>, hideNarrow: true },
    { id: "eff", header: "Permissions", num: true, sort: (r) => r.effective ?? 0, cell: (r) => r.effective ?? 0, hideNarrow: true },
    { id: "unused", header: "Unused", num: true, sort: (r) => r.unused ?? 0, cell: (r) => r.unused ?? 0, hideNarrow: true },
    { id: "viol", header: "Violations", num: true, sort: (r) => r.violations ?? 0, cell: (r) => (r.violations ? <Badge tone="critical">{r.violations}</Badge> : <span className="faint">0</span>) },
    { id: "last", header: "Last active", sort: (r) => r.last_activity ?? "", cell: (r) => <span className="small nowrap">{relTime(r.last_activity)}</span>, hideNarrow: true },
    { id: "risk", header: "Risk", sort: (r) => r.risk ?? 0, width: 110, cell: (r) => <Bar value={r.risk ?? 0} tone="risk" /> },
  ];
}

export function People() {
  const { data, error } = useApi<IdentityRow[]>("/identities?type=human");
  const acts = useIdentityActions();
  const nav = useNavigate();
  const mock = useMockState();
  const [newOpen, setNew] = useDrawerParam("new");
  const imp = useImport();
  const rows = useMemo(() => data?.map((r) => (mock.disabled[r.id] && r.status === "active" ? { ...r, status: "disabled" } : r)) ?? null, [data, mock.disabled]);
  const cols = useMemo(identityColumns, []);
  return (
    <>
      <DataTable
        id="people"
        rows={rows}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        initialSort={["risk", -1]}
        searchText={(r) => `${r.name} ${r.email ?? ""} ${r.department ?? ""} ${r.title ?? ""}`}
        searchPlaceholder="Search name, email, team…"
        filters={[
          { id: "dept", label: "Department", options: opts(uniq((data ?? []).map((r) => r.department))), get: (r) => r.department },
          { id: "status", label: "Status", options: opts(["active", "disabled", "terminated"]), get: (r) => r.status },
          { id: "system", label: "System", options: opts(uniq((data ?? []).flatMap((r) => r.systems))), get: (r) => r.systems },
        ]}
        bulkActions={[
          { label: "Request access for", icon: <ShoppingCart size={14} />, run: (rs) => nav(`/access/request?for=${rs.map((r) => r.id).join(",")}`) },
          { label: "Start review", icon: <ClipboardCheck size={14} />, run: () => acts.startCampaign() },
          { label: "Disable…", icon: <Ban size={14} />, danger: true, run: (rs) => acts.disableMany(rs) },
        ]}
        onRowClick={(r) => nav(`/directory/identities/${r.id}`)}
        onImport={imp.onImport}
        toolbarExtra={<NewButton label="New person" onClick={() => setNew(true)} />}
        empty={<EmptyState title="No people yet" icon={<Users size={18} />}>Connect Workday or import a CSV to populate the directory.</EmptyState>}
      />
      {newOpen && <NewPersonDrawer onClose={() => setNew(false)} />}
      {imp.open && <ImportDrawer kind="people" label="people" columns={["email", "name", "department", "title", "manager_email"]} rows={imp.file?.rows} fileName={imp.file?.name} onClose={imp.close} />}
    </>
  );
}

// -------------------------------------------------------- machine identities
export function Machine() {
  const { data, error } = useApi<NhiRow[]>("/nhi");
  const nav = useNavigate();
  const acts = useIdentityActions();
  const toast = useToast();
  const [newOpen, setNew] = useDrawerParam("new");
  const { data: people } = useApi<IdentityRow[]>("/identities?type=human&status=active");
  const agents = (data ?? []).filter((x) => x.type === "ai_agent");
  const [showAgents, setShowAgents] = useState(true);
  const cols: Column<NhiRow>[] = [
    { id: "name", header: "Name", sort: (r) => r.name.toLowerCase(), csv: (r) => r.name, cell: (r) => <div className="row" style={{ flexWrap: "nowrap" }}><Avatar name={r.name} type={r.type} /><div style={{ minWidth: 0 }}><b>{r.name}</b><div className="xs faint truncate">{r.kind}</div></div></div> },
    { id: "type", header: "Type", sort: (r) => r.type, cell: (r) => <TypeBadge type={r.type} />, hideNarrow: true },
    { id: "owner", header: "Owner", sort: (r) => r.owner?.name ?? "", cell: (r) => (r.owner ? <span className="small"><IdLink i={r.owner} /></span> : <Badge tone="critical">No owner</Badge>) },
    { id: "systems", header: "Systems", csv: (r) => r.systems.join(" "), cell: (r) => <div className="row tight">{r.systems.map((s) => <Chip key={s} mono>{s}</Chip>)}</div>, hideNarrow: true },
    { id: "secret", header: "Oldest secret", num: true, sort: (r) => r.oldest_secret_days ?? -1, cell: (r) => (r.oldest_secret_days == null ? <span className="faint">-</span> : r.oldest_secret_days > 90 ? <Badge tone="warning">{r.oldest_secret_days} d</Badge> : `${r.oldest_secret_days} d`) },
    { id: "last", header: "Last active", sort: (r) => r.days_since_activity ?? 9999, cell: (r) => <span className="small nowrap">{r.days_since_activity == null ? "never" : r.days_since_activity === 0 ? "today" : `${r.days_since_activity} d ago`}</span>, hideNarrow: true },
    { id: "flags", header: "Flags", csv: (r) => r.flags.join(" "), cell: (r) => <div className="row tight">{r.flags.map((f) => <Flag key={f} f={f} />)}</div> },
    { id: "risk", header: "Risk", sort: (r) => r.risk, width: 100, cell: (r) => <Bar value={r.risk} tone="risk" /> },
  ];
  return (
    <div className="stack">
      {agents.length > 0 && (
        <div className="stack-sm">
          <div className="spread">
            <h2>AI agents and who they act for</h2>
            <Button size="sm" variant="ghost" onClick={() => setShowAgents(!showAgents)} aria-expanded={showAgents}>{showAgents ? "Hide" : `Show ${agents.length}`}</Button>
          </div>
          {showAgents && <div className="grid g2">{agents.map((a) => <AgentCard key={a.id} a={a} />)}</div>}
        </div>
      )}
      <DataTable
        id="machine"
        rows={data}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        initialSort={["risk", -1]}
        searchText={(r) => `${r.name} ${r.kind} ${r.description ?? ""} ${r.owner?.name ?? ""} ${r.systems.join(" ")}`}
        searchPlaceholder="Search service accounts, keys, agents…"
        filters={[
          { id: "type", label: "Type", options: [{ value: "service", label: "Service account" }, { value: "ai_agent", label: "AI agent" }], get: (r) => r.type },
          { id: "flag", label: "Flag", options: [["orphaned", "No owner"], ["owner_left", "Owner left"], ["stale_secret", "Stale secret"], ["dormant", "Dormant"], ["privileged", "Privileged"], ["pii_access", "PII access"]].map(([value, label]) => ({ value, label })), get: (r) => r.flags },
          { id: "system", label: "System", options: opts(uniq((data ?? []).flatMap((r) => r.systems))), get: (r) => r.systems },
        ]}
        bulkActions={[
          { label: "Rotate secrets", icon: <RotateCcw size={14} />, run: async (rs) => { await mockObjects.save("secret", `${rs.length} identities`, "bulk", "update"); toast(`Rotation requested for ${rs.length} identities (preview)`); } },
          { label: "Disable…", icon: <Ban size={14} />, danger: true, run: (rs) => acts.disableMany(rs) },
        ]}
        onRowClick={(r) => nav(`/directory/identities/${r.id}`)}
        toolbarExtra={<NewButton label="Register" preview onClick={() => setNew(true)} />}
      />
      {newOpen && (
        <PreviewFormDrawer
          title="Register a machine identity"
          kind="machine_identity"
          onClose={() => setNew(false)}
          note="Every machine identity needs a human owner. Tessera alerts when the owner leaves or the secret is older than 90 days."
          fields={[
            { id: "name", label: "Name", required: true, placeholder: "e.g. billing-sync-bot" },
            { id: "type", label: "Type", required: true, options: ["Service account", "API key", "AI agent", "Integration user"] },
            { id: "owner", label: "Owner", required: true, options: (people ?? []).map((p) => p.name).sort() },
            { id: "system", label: "System", options: ["aws", "github", "okta", "snowflake", "workday"] },
            { id: "purpose", label: "Purpose", textarea: true, placeholder: "What it does and why it needs access" },
          ]}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- accounts
export function Accounts() {
  const { data, error } = useApi<AccountRow[]>("/accounts");
  const nav = useNavigate();
  const toast = useToast();
  const { actor } = usePersona();
  const [newOpen, setNew] = useDrawerParam("new");
  const imp = useImport();
  const cols: Column<AccountRow>[] = [
    { id: "user", header: "Account", sort: (r) => r.username.toLowerCase(), cell: (r) => <b className="sys">{r.username}</b> },
    { id: "system", header: "System", sort: (r) => r.system, cell: (r) => <Chip mono>{r.system}</Chip> },
    { id: "kind", header: "Kind", sort: (r) => r.kind, cell: (r) => <span className="small">{r.kind.replace(/_/g, " ")}</span>, hideNarrow: true },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Status s={r.status} /> },
    { id: "owner", header: "Belongs to", sort: (r) => r.identity?.name ?? "", cell: (r) => (r.identity ? <span className="small"><IdLink i={r.identity} /></span> : <Badge tone="critical">Uncorrelated</Badge>) },
    { id: "login", header: "Last login", sort: (r) => r.last_login_at ?? "", cell: (r) => <span className="small nowrap">{relTime(r.last_login_at)}</span> },
    { id: "created", header: "Created", sort: (r) => r.created_at ?? "", cell: (r) => <span className="small nowrap">{fmtDay(r.created_at)}</span>, hideNarrow: true },
  ];
  return (
    <>
      <DataTable
        id="accounts"
        rows={data}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        searchText={(r) => `${r.username} ${r.system} ${r.identity?.name ?? ""}`}
        searchPlaceholder="Search usernames or owners…"
        filters={[
          { id: "system", label: "System", options: opts(uniq((data ?? []).map((r) => r.system))), get: (r) => r.system },
          { id: "kind", label: "Kind", options: opts(uniq((data ?? []).map((r) => r.kind))), get: (r) => r.kind },
          { id: "status", label: "Status", options: opts(uniq((data ?? []).map((r) => r.status))), get: (r) => r.status },
          { id: "corr", label: "Correlation", options: [{ value: "yes", label: "Correlated" }, { value: "no", label: "Uncorrelated" }], get: (r) => (r.identity ? "yes" : "no") },
        ]}
        bulkActions={[
          { label: "Disable accounts…", icon: <Ban size={14} />, danger: true, run: async (rs) => { await mockObjects.save("account", `${rs.length} accounts`, actor, "update"); toast(`${rs.length} accounts queued to disable (preview)`); } },
        ]}
        onRowClick={(r) => r.identity && nav(`/directory/identities/${r.identity.id}`)}
        onImport={imp.onImport}
        toolbarExtra={<NewButton label="New account" preview onClick={() => setNew(true)} />}
        empty={<EmptyState title="No accounts" icon={<KeyRound size={18} />}>Accounts appear after a connector sync.</EmptyState>}
      />
      {newOpen && (
        <PreviewFormDrawer title="New account" kind="account" onClose={() => setNew(false)}
          note="Most accounts are created by provisioning when access is granted. Use this for a one-off account in a system without a connector."
          fields={[
            { id: "username", label: "Username", required: true },
            { id: "system", label: "System", required: true, options: uniq((data ?? []).map((r) => r.system)) },
            { id: "kind", label: "Kind", options: uniq((data ?? []).map((r) => r.kind)) },
            { id: "owner", label: "Belongs to (email)", placeholder: "name@larkspur.example" },
          ]}
        />
      )}
      {imp.open && <ImportDrawer kind="accounts" label="accounts" columns={["username", "system", "kind", "owner_email", "status"]} rows={imp.file?.rows} fileName={imp.file?.name} onClose={imp.close} />}
    </>
  );
}

// ------------------------------------------------------------------- roles
export function Roles() {
  const roles = useRoles();
  const nav = useNavigate();
  const [newOpen, setNew] = useDrawerParam("new");
  const imp = useImport();
  return (
    <>
      <div className="row mt-sm" style={{ marginBottom: 12 }}>
        <PreviewBadge what="Business roles have no backend yet. They bundle real groups and roles from your connected systems." />
        <span className="small muted">Business roles bundle entitlements from several systems so people request one thing.</span>
      </div>
      <DataTable
        id="roles"
        rows={roles}
        rowKey={(r) => r.id}
        columns={[
          { id: "name", header: "Role", sort: (r) => r.name, cell: (r) => <div><b>{r.name}</b><div className="xs faint truncate" style={{ maxWidth: 420 }}>{r.description}</div></div> },
          { id: "owner", header: "Owner", sort: (r) => r.owner, cell: (r) => <span className="small">{r.owner}</span>, hideNarrow: true },
          { id: "ents", header: "Entitlements", num: true, sort: (r) => r.entitlements.length, cell: (r) => r.entitlements.length },
          { id: "birth", header: "Birthright for", sort: (r) => r.birthright ?? "", cell: (r) => (r.birthright ? <Badge tone="outline">{r.birthright}</Badge> : <span className="faint">-</span>), hideNarrow: true },
          { id: "members", header: "Members", num: true, sort: (r) => r.members, cell: (r) => r.members },
          { id: "risk", header: "Risk", sort: (r) => ["low", "medium", "high"].indexOf(r.risk), csv: (r) => r.risk, cell: (r) => <Badge tone={r.risk === "high" ? "critical" : r.risk === "medium" ? "warning" : "ok"} dot>{cap(r.risk)}</Badge> },
          { id: "updated", header: "Updated", sort: (r) => r.updated, cell: (r) => <span className="small nowrap">{r.updated}</span>, hideNarrow: true },
        ]}
        searchText={(r) => `${r.name} ${r.description} ${r.owner} ${r.entitlements.join(" ")}`}
        searchPlaceholder="Search roles or the entitlements in them…"
        filters={[
          { id: "risk", label: "Risk", options: opts(["low", "medium", "high"]), get: (r) => r.risk },
          { id: "birth", label: "Birthright", options: opts(uniq(roles.map((r) => r.birthright))), get: (r) => r.birthright },
        ]}
        bulkActions={[{ label: "Request", icon: <ShoppingCart size={14} />, run: (rs) => nav(`/access/request?add=${rs.map((r) => r.id).join(",")}`) }]}
        onRowClick={(r) => nav(`/directory/roles/${r.id}`)}
        onImport={imp.onImport}
        toolbarExtra={<NewButton label="New role" preview onClick={() => setNew(true)} />}
      />
      {newOpen && <NewRoleDrawer onClose={() => setNew(false)} />}
      {imp.open && <ImportDrawer kind="roles" label="roles" columns={["name", "description", "owner", "entitlements", "birthright"]} rows={imp.file?.rows} fileName={imp.file?.name} onClose={imp.close} />}
    </>
  );
}

function NewRoleDrawer({ onClose }: { onClose: () => void }) {
  const { data: groups } = useApi<Group[]>("/groups");
  const { actor } = usePersona();
  const toast = useToast();
  const nav = useNavigate();
  const [f, setF] = useState({ name: "", description: "", owner: actor, birthright: "" });
  const [picked, setPicked] = useState<string[]>([]);
  const [q, setQ] = useState("");
  const shown = (groups ?? []).filter((g) => `${g.system}:${g.name}`.toLowerCase().includes(q.toLowerCase()));
  const risk = picked.some((p) => (groups ?? []).find((g) => `${g.system}:${g.name}` === p)?.privileged) ? "high" : picked.length > 3 ? "medium" : "low";
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await mockRoles.create({ name: f.name.trim(), description: f.description.trim(), owner: f.owner, birthright: f.birthright || undefined, entitlements: picked, risk }, actor);
    toast(`Role “${r.name}” created (preview)`, { action: { label: "Open", run: () => nav(`/directory/roles/${r.id}`) } });
    onClose();
  };
  return (
    <Drawer title="New role" sub={<PreviewBadge />} onClose={onClose} wide
      footer={<><Button onClick={onClose}>Cancel</Button><Button type="submit" form="new-role" variant="primary" disabled={!f.name.trim() || !picked.length}>Create role</Button></>}
    >
      <form id="new-role" className="stack" onSubmit={submit}>
        <label className="field">Name<input className="input" data-autofocus value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="e.g. Payments engineer" /></label>
        <label className="field">Description<textarea className="input" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} placeholder="Who should have it and why" /></label>
        <div className="grid g2">
          <label className="field">Owner<input className="input" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} /></label>
          <label className="field">Birthright for
            <select className="input" value={f.birthright} onChange={(e) => setF({ ...f, birthright: e.target.value })}>
              <option value="">Nobody (request only)</option>
              {ORGS.filter((o) => o.department).map((o) => <option key={o.id}>{o.department}</option>)}
            </select>
          </label>
        </div>
        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="spread" style={{ width: "100%" }}><span>Entitlements ({picked.length})</span><span className="xs faint">Risk if created: <b>{risk}</b></span></legend>
          <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter entitlements…" aria-label="Filter entitlements" />
          <div className="card flush" style={{ maxHeight: 260, overflow: "auto" }}>
            {shown.map((g) => {
              const k = `${g.system}:${g.name}`;
              return (
                <label key={g.id} className="row small" style={{ padding: "6px 12px", borderBottom: "1px solid var(--border)", flexWrap: "nowrap" }}>
                  <input type="checkbox" checked={picked.includes(k)} onChange={(e) => setPicked(e.target.checked ? [...picked, k] : picked.filter((x) => x !== k))} />
                  <span className="sys grow">{k}</span>
                  {g.privileged && <Badge tone="warning">Privileged</Badge>}
                </label>
              );
            })}
          </div>
        </fieldset>
      </form>
    </Drawer>
  );
}

// ------------------------------------------------------------ entitlements
const KIND_LABEL: Record<string, string> = { group: "Group", role: "Role", team: "Team", security_group: "Security group" };

function groupColumns(): Column<Group>[] {
  return [
    { id: "name", header: "Name", sort: (r) => r.name.toLowerCase(), csv: (r) => `${r.system}:${r.name}`, cell: (r) => <div><b className="sys">{r.name}</b><div className="xs faint truncate" style={{ maxWidth: 420 }}>{r.description}</div></div> },
    { id: "system", header: "System", sort: (r) => r.system, cell: (r) => <Chip mono>{r.system}</Chip> },
    { id: "kind", header: "Kind", sort: (r) => r.kind, cell: (r) => <span className="small">{KIND_LABEL[r.kind] ?? r.kind}</span> },
    { id: "priv", header: "Privileged", sort: (r) => (r.privileged ? 1 : 0), cell: (r) => (r.privileged ? <Badge tone="warning">Privileged</Badge> : <span className="faint">No</span>) },
    { id: "jit", header: "Just-in-time", sort: (r) => (r.requestable ? 1 : 0), cell: (r) => (r.requestable ? <Badge tone="info">JIT-eligible</Badge> : <span className="faint">Standing</span>), hideNarrow: true },
  ];
}

function GroupList({ id, kinds, newLabel }: { id: string; kinds?: string[]; newLabel: string }) {
  const { data, error } = useApi<Group[]>("/groups");
  const nav = useNavigate();
  const [newOpen, setNew] = useDrawerParam("new");
  const imp = useImport();
  const rows = useMemo(() => (data ? data.filter((g) => !kinds || kinds.includes(g.kind)) : null), [data, kinds]);
  const cols = useMemo(groupColumns, []);
  return (
    <>
      <DataTable
        id={id}
        rows={rows}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        searchText={(r) => `${r.system}:${r.name} ${r.description ?? ""}`}
        searchPlaceholder="Search by name, system or description…"
        filters={[
          { id: "system", label: "System", options: opts(uniq((rows ?? []).map((r) => r.system))), get: (r) => r.system },
          { id: "kind", label: "Kind", options: uniq((rows ?? []).map((r) => r.kind)).map((k) => ({ value: k, label: KIND_LABEL[k] ?? k })), get: (r) => r.kind },
          { id: "priv", label: "Privileged", options: [{ value: "yes", label: "Privileged" }, { value: "no", label: "Not privileged" }], get: (r) => (r.privileged ? "yes" : "no") },
        ]}
        bulkActions={[{ label: "Request access", icon: <ShoppingCart size={14} />, run: (rs) => nav(`/access/request?add=${rs.map((r) => `g${r.id}`).join(",")}`) }]}
        onRowClick={(r) => nav(`/directory/entitlements/${r.id}`)}
        onImport={imp.onImport}
        toolbarExtra={<NewButton label={newLabel} preview onClick={() => setNew(true)} />}
      />
      {newOpen && (
        <PreviewFormDrawer title={newLabel} kind={id} onClose={() => setNew(false)}
          note="Entitlements are normally discovered by connector sync. Create one here to manage a system without a connector."
          fields={[
            { id: "name", label: "Name", required: true },
            { id: "system", label: "System", required: true, options: uniq((data ?? []).map((r) => r.system)) },
            { id: "kind", label: "Kind", options: Object.values(KIND_LABEL) },
            { id: "privileged", label: "Privileged", options: ["No", "Yes"] },
            { id: "description", label: "Description", textarea: true },
          ]}
        />
      )}
      {imp.open && <ImportDrawer kind={id} label={id} columns={["name", "system", "kind", "privileged", "description"]} rows={imp.file?.rows} fileName={imp.file?.name} onClose={imp.close} />}
    </>
  );
}

export const Entitlements = () => <GroupList id="entitlements" newLabel="New entitlement" />;
const GROUP_KINDS = ["group", "team", "security_group"];
export const Groups = () => <GroupList id="groups" kinds={GROUP_KINDS} newLabel="New group" />;

// -------------------------------------------------------------------- apps
export function Apps() {
  const { data, error } = useApi<ConnectorRow[]>("/connectors");
  const { data: resources } = useApi<ResourceRow[]>("/resources");
  const nav = useNavigate();
  const sensitive = (sys: string) => (resources ?? []).filter((r) => r.system === sys && r.tags.length).length;
  return (
    <DataTable
      id="apps"
      rows={data}
      error={error}
      rowKey={(r) => r.system}
      columns={[
        { id: "name", header: "Application", sort: (r) => r.name, cell: (r) => <div><b>{r.name}</b><div className="xs faint sys">{r.system}</div></div> },
        { id: "status", header: "Connection", cell: () => <Status s="active" />, csv: () => "connected" },
        { id: "accounts", header: "Accounts", num: true, sort: (r) => r.accounts, cell: (r) => r.accounts },
        { id: "groups", header: "Groups & roles", num: true, sort: (r) => r.groups, cell: (r) => r.groups },
        { id: "resources", header: "Resources", num: true, sort: (r) => r.resources, cell: (r) => r.resources, hideNarrow: true },
        { id: "sens", header: "Sensitive", num: true, sort: (r) => sensitive(r.system), cell: (r) => (sensitive(r.system) ? <Badge tone="warning">{sensitive(r.system)}</Badge> : <span className="faint">0</span>), hideNarrow: true },
        { id: "perms", header: "Permissions", num: true, sort: (r) => r.permissions, cell: (r) => r.permissions, hideNarrow: true },
      ]}
      searchText={(r) => `${r.name} ${r.system}`}
      searchPlaceholder="Search applications…"
      onRowClick={(r) => nav(`/directory/apps/${r.system}`)}
      toolbarExtra={<NewButton label="Add connection" onClick={() => nav("/admin/connections")} />}
    />
  );
}

// -------------------------------------------------------------------- orgs
export function Orgs() {
  const { data: idents } = useApi<IdentityRow[]>("/identities?type=human");
  const nav = useNavigate();
  const [newOpen, setNew] = useDrawerParam("new");
  const imp = useImport();
  const count = (dept: string | null) => (idents ?? []).filter((i) => (dept ? i.department === dept : true) && i.status === "active").length;
  return (
    <>
      <div className="row mt-sm" style={{ marginBottom: 12 }}>
        <PreviewBadge what="Org units come from the mock layer. Member counts are real, matched on department." />
        <span className="small muted">Org units mirror Workday departments. Owners approve requests and reviews by default.</span>
      </div>
      <DataTable
        id="orgs"
        rows={ORGS}
        rowKey={(r) => r.id}
        columns={[
          { id: "name", header: "Organization", sort: (r) => r.name, cell: (r) => <div><b>{r.name}</b><div className="xs faint">{r.parent ? `in ${ORGS.find((o) => o.id === r.parent)?.name}` : "Top level"}</div></div> },
          { id: "owner", header: "Owner", sort: (r) => r.owner, cell: (r) => <span className="small">{r.owner}</span> },
          { id: "cc", header: "Cost center", sort: (r) => r.costCenter, cell: (r) => <span className="small sys">{r.costCenter}</span>, hideNarrow: true },
          { id: "members", header: "Active people", num: true, sort: (r) => count(r.department), cell: (r) => (idents ? count(r.department) : "…") },
        ]}
        searchText={(r) => `${r.name} ${r.owner} ${r.costCenter}`}
        searchPlaceholder="Search organizations…"
        onRowClick={(r) => nav(`/directory/orgs/${r.id}`)}
        onImport={imp.onImport}
        toolbarExtra={<NewButton label="New organization" preview onClick={() => setNew(true)} />}
      />
      {newOpen && (
        <PreviewFormDrawer title="New organization" kind="org" onClose={() => setNew(false)}
          fields={[
            { id: "name", label: "Name", required: true },
            { id: "parent", label: "Parent", options: ORGS.map((o) => o.name) },
            { id: "owner", label: "Owner", required: true, options: (idents ?? []).map((i) => i.name).sort() },
            { id: "costCenter", label: "Cost center", placeholder: "CC-0000" },
          ]}
        />
      )}
      {imp.open && <ImportDrawer kind="orgs" label="organizations" columns={["name", "parent", "owner_email", "cost_center"]} rows={imp.file?.rows} fileName={imp.file?.name} onClose={imp.close} />}
    </>
  );
}
