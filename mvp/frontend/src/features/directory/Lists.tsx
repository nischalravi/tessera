import { FormEvent, useMemo, useState } from "react";
import { Outlet, useNavigate, useSearchParams } from "react-router-dom";
import { Ban, ClipboardCheck, KeyRound, Plus, RotateCcw, ShoppingCart, UserCheck, Users } from "lucide-react";
import { AccountRow, AffiliationSummaryRow, ConnectorRow, Group, HrisEvent, IdentityRow, NhiRow, OrgRow, ResourceRow, api, fmtDay, relTime, useAIAgents, useApi, LifecycleList, orgsPath } from "../../api";
import { useIdentityActions } from "../../app/actions";
import { useSession } from "../../app/auth";
import { usePersona } from "../../app/persona";
import {
  Avatar, Badge, Button, Callout, Chip, Column, Command, DataTable, Drawer, EmptyState, Flag, GroupTabs, IdLink, Page, RiskPill, Status, Tabs, TypeBadge, useSelected, useToast,
} from "../../components";
import { mockObjects } from "../../mocks";
import { identityRotation, SECRET_STATUS_LABEL, SECRET_STATUS_TONE } from "../rotation/model";
import { PlanDrawer, useRotationStatus } from "../rotation/shared";
import { AgentCard } from "./AgentCards";
import { McpFindings, SponsorCell, sourceLabel } from "./AgentFindings";
import { StateBadge, WORKER_LABEL } from "../lifecycle/parts";
import { AccountPanel, AppPanel, GroupPanel, IdentityPanel, OrgPanel } from "./Panels";
import { BulkOwnerDrawer } from "./owners";
import { ViewToggle } from "./groups/ViewToggle";
import { ImportDrawer, PreviewFormDrawer, opts, uniq } from "./shared";
import { HierarchySourceCard } from "./orgSettings";
import { AFFILIATION_LABEL, STATE_LABEL as PERSON_STATE_LABEL } from "./affiliationModel";

/** Identity lists each render their own page header; the layout only hosts them. */
export function DirectoryLayout() {
  return <Outlet />;
}

const IDENTITY: [string] = ["Identity"];
const plural = (n: number | undefined | null, one: string, many = `${one}s`) => (n == null ? null : `${n.toLocaleString()} ${n === 1 ? one : many}`);

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

const newCmd = (label: string, onClick: () => void, preview?: boolean): Command => ({ label, icon: <Plus size={16} />, onClick, title: preview ? "Preview: saved in this browser only" : undefined });

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
            <span className="name-link">{r.name}</span>
            <div className="xs faint truncate">{r.title ?? r.email ?? ""}</div>
          </div>
        </div>
      ),
    },
    { id: "type", header: "Type", sort: (r) => r.type, cell: (r) => <TypeBadge type={r.type} />, hideNarrow: true },
    { id: "dept", header: "Department", sort: (r) => r.department ?? "", cell: (r) => r.department, hideNarrow: true },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Status s={r.status} /> },
    { id: "systems", header: "Systems", csv: (r) => r.systems.join(" "), cell: (r) => <div className="row tight" style={{ flexWrap: "nowrap" }}>{r.systems.map((s) => <Chip key={s} mono>{s}</Chip>)}</div>, hideNarrow: true },
    { id: "eff", header: "Permissions", num: true, sort: (r) => r.effective ?? 0, cell: (r) => r.effective ?? 0, hideNarrow: true },
    { id: "unused", header: "Unused", num: true, sort: (r) => r.unused ?? 0, cell: (r) => r.unused ?? 0, hideNarrow: true },
    { id: "viol", header: "Violations", num: true, sort: (r) => r.violations ?? 0, cell: (r) => (r.violations ? <Badge tone="critical">{r.violations}</Badge> : <span className="faint">0</span>) },
    { id: "last", header: "Last active", sort: (r) => r.last_activity ?? "", cell: (r) => <span className="small nowrap">{relTime(r.last_activity)}</span>, hideNarrow: true },
    { id: "risk", header: "Risk", sort: (r) => r.risk ?? 0, csv: (r) => r.risk ?? 0, cell: (r) => <RiskPill score={r.risk} /> },
  ];
}

export function People() {
  const { data, error, reload } = useApi<IdentityRow[]>("/identities?type=human");
  const { data: lc } = useApi<LifecycleList>("/lifecycle");
  const worker = useMemo(() => new Map((lc?.rows ?? []).map((l) => [l.person.id, l])), [lc]);
  const { data: aff } = useApi<{ people: AffiliationSummaryRow[] }>("/affiliation-summary");
  const affOf = useMemo(() => new Map((aff?.people ?? []).map((a) => [a.identity_id, a])), [aff]);
  const [selected, setSelected] = useSelected();
  const acts = useIdentityActions();
  const nav = useNavigate();
  const [newOpen, setNew] = useDrawerParam("new");
  const imp = useImport();
  const rows = data;
  const cols = useMemo(() => {
    const c = identityColumns();
    c.splice(2, 0, { id: "worker", header: "Worker type", sort: (r) => worker.get(r.id)?.worker_type ?? "employee",
      cell: (r) => { const l = worker.get(r.id); return l && l.worker_type !== "employee" ? <span className="small">{WORKER_LABEL[l.worker_type]}{l.state === "ending" && <> <StateBadge l={l} /></>}</span> : <span className="small faint">Employee</span>; }, hideNarrow: true });
    return c;
  }, [worker]);
  return (
    <Page title="Users" count={plural(rows?.length, "identity", "identities")} crumbs={[IDENTITY, ["Users"]]}>
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
          { id: "worker", label: "Worker type", options: Object.entries(WORKER_LABEL).map(([value, label]) => ({ value, label })), get: (r) => worker.get(r.id)?.worker_type ?? "employee" },
          { id: "status", label: "Status", options: opts(["active", "disabled", "terminated"]), get: (r) => r.status },
          { id: "affiliation", label: "Affiliation", options: Object.entries(AFFILIATION_LABEL).map(([value, label]) => ({ value, label })), get: (r) => affOf.get(r.id)?.types ?? [] },
          { id: "lifecycle", label: "Lifecycle state", options: Object.entries(PERSON_STATE_LABEL).map(([value, label]) => ({ value, label })), get: (r) => affOf.get(r.id)?.lifecycle_state ?? "" },
          { id: "system", label: "System", options: opts(uniq((data ?? []).flatMap((r) => r.systems))), get: (r) => r.systems },
        ]}
        commands={[
          newCmd("New user", () => setNew(true)),
          { label: "Start review", icon: <ClipboardCheck size={16} />, onClick: () => acts.startCampaign() },
        ]}
        onRefresh={reload}
        bulkActions={[
          { label: "Request access for", icon: <ShoppingCart size={16} />, run: (rs) => nav(`/access/request?for=${rs.map((r) => r.id).join(",")}`) },
          { label: "Disable", icon: <Ban size={16} />, danger: true, run: (rs) => acts.disableMany(rs) },
        ]}
        rowLabel={(r) => r.name}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        onImport={imp.onImport}
        empty={<EmptyState title="No people yet" icon={<Users size={18} />}>Connect Workday or import a CSV to populate the directory.</EmptyState>}
      />
      {selected && <IdentityPanel id={selected} onClose={() => setSelected(null)} />}
      {newOpen && <NewPersonDrawer onClose={() => setNew(false)} />}
      {imp.open && <ImportDrawer kind="people" label="people" columns={["email", "name", "department", "title", "manager_email"]} rows={imp.file?.rows} fileName={imp.file?.name} onClose={imp.close} />}
    </Page>
  );
}

// -------------------------------------------------------- machine identities
export function Machine() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "mcp" ? "mcp" : "inventory";
  const setTab = (t: "inventory" | "mcp") => {
    const next = new URLSearchParams(params);
    if (t === "mcp") next.set("tab", "mcp");
    else next.delete("tab");
    next.delete("selected");
    setParams(next, { replace: true });
  };
  const { data, error, reload } = useApi<NhiRow[]>("/nhi");
  const { data: agentRows } = useAIAgents();
  const agentOf = useMemo(() => new Map((agentRows ?? []).map((a) => [a.id, a])), [agentRows]);
  const [selected, setSelected] = useSelected();
  const acts = useIdentityActions();
  const toast = useToast();
  const [newOpen, setNew] = useDrawerParam("new");
  const { data: people } = useApi<IdentityRow[]>("/identities?type=human&status=active");
  const agents = (data ?? []).filter((x) => x.type === "ai_agent");
  const { can } = useSession();
  const [assign, setAssign] = useState<NhiRow[] | null>(null);
  const [showAgents, setShowAgents] = useState(false);
  const [rotate, setRotate] = useState<{ title: string; ids: number[] } | null>(null);
  const rot = useRotationStatus();
  const rotationOf = (r: NhiRow) => identityRotation(r.secrets.map((s) => rot.get(s.id)).filter((x): x is NonNullable<typeof x> => !!x));
  const cols: Column<NhiRow>[] = [
    { id: "name", header: "Name", sort: (r) => r.name.toLowerCase(), csv: (r) => r.name, cell: (r) => <div className="row" style={{ flexWrap: "nowrap" }}><Avatar name={r.name} type={r.type} /><div style={{ minWidth: 0 }}><span className="name-link">{r.name}</span><div className="xs faint truncate">{r.kind}</div></div></div> },
    { id: "type", header: "Type", sort: (r) => r.type, cell: (r) => <TypeBadge type={r.type} />, hideNarrow: true },
    { id: "owner", header: "Owner", sort: (r) => r.owner?.name ?? "", cell: (r) => (r.owner ? <span className="small nowrap"><IdLink i={r.owner} /></span> : <Badge tone="critical">No owner</Badge>) },
    // where an AI agent was discovered, and who created it (issue #116); other machine identities have none
    {
      id: "source", header: "Source", sort: (r) => agentOf.get(r.id)?.source ?? "", csv: (r) => agentOf.get(r.id)?.source ?? "",
      cell: (r) => {
        const a = agentOf.get(r.id);
        return a ? <div><Chip mono>{sourceLabel(a.source)}</Chip>{a.creator && <div className="xs faint truncate">created by {a.creator}</div>}</div> : <span className="faint">-</span>;
      },
      hideNarrow: true,
    },
    // the sponsor is the owner the nhi-ownership policy checks, so "No sponsor" here is a violation there
    {
      id: "sponsor", header: "Sponsor", sort: (r) => agentOf.get(r.id)?.sponsor_status ?? "", csv: (r) => agentOf.get(r.id)?.sponsor_status ?? "",
      cell: (r) => { const a = agentOf.get(r.id); return a ? <SponsorCell a={a} /> : <span className="faint">-</span>; },
    },
    { id: "systems", header: "Systems", csv: (r) => r.systems.join(" "), cell: (r) => <div className="row tight" style={{ flexWrap: "nowrap" }}>{r.systems.map((s) => <Chip key={s} mono>{s}</Chip>)}</div>, hideNarrow: true },
    { id: "secret", header: "Oldest secret", num: true, sort: (r) => r.oldest_secret_days ?? -1, cell: (r) => (r.oldest_secret_days == null ? <span className="faint">-</span> : r.oldest_secret_days > 90 ? <Badge tone="warning">{r.oldest_secret_days} d</Badge> : `${r.oldest_secret_days} d`) },
    { id: "rotation", header: "Rotation", sort: (r) => rotationOf(r)?.key ?? "", csv: (r) => { const x = rotationOf(r); return x ? SECRET_STATUS_LABEL[x.key] : ""; }, cell: (r) => { const x = rotationOf(r); return x ? <Badge tone={SECRET_STATUS_TONE[x.key]} dot>{SECRET_STATUS_LABEL[x.key]}{x.count > 1 ? ` (${x.count})` : ""}</Badge> : <span className="faint">-</span>; }, hideNarrow: true },
    { id: "last", header: "Last active", sort: (r) => r.days_since_activity ?? 9999, cell: (r) => <span className="small nowrap">{r.days_since_activity == null ? "never" : r.days_since_activity === 0 ? "today" : `${r.days_since_activity} d ago`}</span>, hideNarrow: true },
    { id: "flags", header: "Flags", csv: (r) => r.flags.join(" "), cell: (r) => <div className="row tight">{r.flags.map((f) => <Flag key={f} f={f} />)}</div> },
    { id: "risk", header: "Risk", sort: (r) => r.risk, csv: (r) => r.risk, cell: (r) => <RiskPill score={r.risk} /> },
  ];
  return (
    <Page title="Machine identities & agents" count={plural(data?.length, "identity", "identities")} crumbs={[IDENTITY, ["Machine identities & agents"]]}>
      <Tabs
        label="Machine identities and agents"
        value={tab}
        onChange={setTab}
        tabs={[{ id: "inventory", label: "Inventory" }, { id: "mcp", label: "MCP config findings" }]}
      />
      {tab === "mcp" ? <McpFindings /> : <>
      <DataTable
        id="machine"
        rows={data}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        initialSort={["risk", -1]}
        searchText={(r) => `${r.name} ${r.kind} ${r.description ?? ""} ${r.owner?.name ?? ""} ${r.systems.join(" ")} ${agentOf.get(r.id)?.source ?? ""} ${agentOf.get(r.id)?.creator ?? ""}`}
        searchPlaceholder="Search service accounts, keys, agents…"
        filters={[
          { id: "type", label: "Type", options: [{ value: "service", label: "Service account" }, { value: "ai_agent", label: "AI agent" }], get: (r) => r.type },
          { id: "flag", label: "Flag", options: [["orphaned", "No owner"], ["owner_left", "Owner left"], ["stale_secret", "Stale secret"], ["dormant", "Dormant"], ["privileged", "Privileged"], ["pii_access", "PII access"]].map(([value, label]) => ({ value, label })), get: (r) => r.flags },
          { id: "system", label: "System", options: opts(uniq((data ?? []).flatMap((r) => r.systems))), get: (r) => r.systems },
          { id: "source", label: "Source", options: opts(uniq((agentRows ?? []).map((a) => a.source))).map((o) => ({ ...o, label: sourceLabel(o.value) })), get: (r) => agentOf.get(r.id)?.source },
          { id: "sponsor", label: "Sponsor", options: [["active", "Active"], ["inactive", "Inactive"], ["none", "No sponsor"]].map(([value, label]) => ({ value, label })), get: (r) => agentOf.get(r.id)?.sponsor_status },
        ]}
        commands={[newCmd("Register", () => setNew(true), true)]}
        onRefresh={reload}
        bulkActions={[
          ...(can("ownership.manage") ? [{ label: "Assign owner", icon: <UserCheck size={16} />, run: (rs: NhiRow[]) => setAssign(rs) }] : []),
          { label: "Rotate secrets…", icon: <RotateCcw size={16} />, run: (rs) => {
            const ids = rs.flatMap((r) => r.secrets.map((s) => s.id));
            if (ids.length === 0) toast("None of the selected identities has a recorded secret", { kind: "info" });
            else setRotate({ title: `Rotate the secrets of ${rs.length} identit${rs.length === 1 ? "y" : "ies"}`, ids });
          } },
          { label: "Disable", icon: <Ban size={16} />, danger: true, run: (rs) => acts.disableMany(rs) },
        ]}
        rowLabel={(r) => r.name}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
      />
      {agents.length > 0 && (
        <div className="stack-sm mt">
          <div className="spread">
            <h2>AI agents and who they act for</h2>
            <Button size="sm" variant="ghost" onClick={() => setShowAgents(!showAgents)} aria-expanded={showAgents}>{showAgents ? "Hide" : `Show ${agents.length}`}</Button>
          </div>
          {showAgents && <div className="grid g2">{agents.map((a) => <AgentCard key={a.id} a={a} />)}</div>}
        </div>
      )}
      </>}
      {selected && tab === "inventory" && <IdentityPanel id={selected} onClose={() => setSelected(null)} />}
      {rotate && <PlanDrawer title={rotate.title} secretIds={rotate.ids} onClose={() => { setRotate(null); reload(); }} />}
      {assign && <BulkOwnerDrawer objects={assign.map((r) => ({ kind: "identity", key: String(r.id), label: r.name }))} onClose={() => setAssign(null)} onDone={reload} />}
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
    </Page>
  );
}

// ---------------------------------------------------------------- accounts
export function Accounts() {
  const { data, error, reload } = useApi<AccountRow[]>("/accounts");
  const [selected, setSelected] = useSelected();
  const open = data?.find((a) => String(a.id) === selected);
  const toast = useToast();
  const { actor } = usePersona();
  const [newOpen, setNew] = useDrawerParam("new");
  const imp = useImport();
  const cols: Column<AccountRow>[] = [
    { id: "user", header: "Account", sort: (r) => r.username.toLowerCase(), cell: (r) => <span className="sys name-link">{r.username}</span> },
    { id: "system", header: "System", sort: (r) => r.system, cell: (r) => <Chip mono>{r.system}</Chip> },
    { id: "kind", header: "Kind", sort: (r) => r.kind, cell: (r) => <span className="small">{r.kind.replace(/_/g, " ")}</span>, hideNarrow: true },
    { id: "status", header: "Status", sort: (r) => r.status, cell: (r) => <Status s={r.status} /> },
    { id: "owner", header: "Belongs to", sort: (r) => r.identity?.name ?? "", cell: (r) => (r.identity ? <span className="small nowrap"><IdLink i={r.identity} /></span> : <Badge tone="critical">Uncorrelated</Badge>) },
    { id: "login", header: "Last login", sort: (r) => r.last_login_at ?? "", cell: (r) => <span className="small nowrap">{relTime(r.last_login_at)}</span> },
    { id: "created", header: "Created", sort: (r) => r.created_at ?? "", cell: (r) => <span className="small nowrap">{fmtDay(r.created_at)}</span>, hideNarrow: true },
  ];
  return (
    <Page title="Accounts" count={plural(data?.length, "account")} crumbs={[IDENTITY, ["Accounts"]]}>
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
        commands={[newCmd("New account", () => setNew(true), true)]}
        onRefresh={reload}
        bulkActions={[
          { label: "Disable", icon: <Ban size={16} />, danger: true, run: async (rs) => { await mockObjects.save("account", `${rs.length} accounts`, actor, "update"); toast(`${rs.length} accounts queued to disable (preview)`); } },
        ]}
        rowLabel={(r) => r.username}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        onImport={imp.onImport}
        empty={<EmptyState title="No accounts" icon={<KeyRound size={18} />}>Accounts appear after a connector sync.</EmptyState>}
      />
      {open && <AccountPanel a={open} onClose={() => setSelected(null)} />}
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
    </Page>
  );
}

// ------------------------------------------------------------ entitlements
const KIND_LABEL: Record<string, string> = { group: "Group", role: "Role", team: "Team", security_group: "Security group" };

function groupColumns(): Column<Group>[] {
  return [
    { id: "name", header: "Name", sort: (r) => r.name.toLowerCase(), csv: (r) => `${r.system}:${r.name}`, cell: (r) => <div><span className="sys name-link">{r.name}</span><div className="xs faint truncate" style={{ maxWidth: 420 }}>{r.description}</div></div> },
    { id: "system", header: "System", sort: (r) => r.system, cell: (r) => <Chip mono>{r.system}</Chip> },
    { id: "kind", header: "Kind", sort: (r) => r.kind, cell: (r) => <span className="small">{KIND_LABEL[r.kind] ?? r.kind}</span> },
    { id: "priv", header: "Privileged", sort: (r) => (r.privileged ? 1 : 0), cell: (r) => (r.privileged ? <Badge tone="warning">Privileged</Badge> : <span className="faint">No</span>) },
    { id: "jit", header: "Just-in-time", sort: (r) => (r.requestable ? 1 : 0), cell: (r) => (r.requestable ? <Badge tone="info">JIT-eligible</Badge> : <span className="faint">Standing</span>), hideNarrow: true },
  ];
}

function GroupList({ id, kinds, newLabel, title, toggle }: { id: string; kinds?: string[]; newLabel: string; title: string; toggle?: boolean }) {
  const { data, error, reload } = useApi<Group[]>("/groups");
  const nav = useNavigate();
  const [selected, setSelected] = useSelected();
  const [newOpen, setNew] = useDrawerParam("new");
  const imp = useImport();
  const rows = useMemo(() => (data ? data.filter((g) => !kinds || kinds.includes(g.kind)) : null), [data, kinds]);
  const cols = useMemo(groupColumns, []);
  const open = rows?.find((g) => String(g.id) === selected);
  return (
    <Page title={title} count={plural(rows?.length, id === "groups" ? "group" : "entitlement")} crumbs={[IDENTITY, [title]]} tabs={<GroupTabs />}>
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
        commands={[newCmd(newLabel, () => setNew(true), true)]}
        onRefresh={reload}
        bulkActions={[{ label: "Request access", icon: <ShoppingCart size={16} />, run: (rs) => nav(`/access/request?add=${rs.map((r) => `g${r.id}`).join(",")}`) }]}
        rowLabel={(r) => `${r.system}:${r.name}`}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
        onImport={imp.onImport}
        toolbarExtra={toggle ? <ViewToggle /> : undefined}
      />
      {open && <GroupPanel g={open} onClose={() => setSelected(null)} />}
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
    </Page>
  );
}

export const Entitlements = () => <GroupList id="entitlements" title="Entitlements" newLabel="New entitlement" />;
const GROUP_KINDS = ["group", "team", "security_group"];
/** Connected groups: the groups of the connected systems. The managed (native) groups are in `groups/`. */
export const ConnectedGroups = () => <GroupList id="groups" title="Groups" kinds={GROUP_KINDS} newLabel="New group" toggle />;

// -------------------------------------------------------------------- apps
export function Apps() {
  const { data, error, reload } = useApi<ConnectorRow[]>("/connectors");
  const { data: resources } = useApi<ResourceRow[]>("/resources");
  const nav = useNavigate();
  const [selected, setSelected] = useSelected();
  const open = data?.find((c) => c.system === selected);
  const sensitive = (sys: string) => (resources ?? []).filter((r) => r.system === sys && r.tags.length).length;
  return (
    <Page title="Applications" count={plural(data?.length, "application")} crumbs={[IDENTITY, ["Applications"]]}>
    <DataTable
      id="apps"
      rows={data}
      error={error}
      rowKey={(r) => r.system}
      columns={[
        { id: "name", header: "Application", sort: (r) => r.name, cell: (r) => <div className="nowrap"><span className="name-link">{r.name}</span><div className="xs faint sys">{r.system}</div></div> },
        { id: "status", header: "Connection", cell: () => <Status s="active" />, csv: () => "connected" },
        { id: "accounts", header: "Accounts", num: true, sort: (r) => r.accounts, cell: (r) => r.accounts },
        { id: "groups", header: "Groups & roles", num: true, sort: (r) => r.groups, cell: (r) => r.groups },
        { id: "resources", header: "Resources", num: true, sort: (r) => r.resources, cell: (r) => r.resources, hideNarrow: true },
        { id: "sens", header: "Sensitive", num: true, sort: (r) => sensitive(r.system), cell: (r) => (sensitive(r.system) ? <Badge tone="warning">{sensitive(r.system)}</Badge> : <span className="faint">0</span>), hideNarrow: true },
        { id: "perms", header: "Permissions", num: true, sort: (r) => r.permissions, cell: (r) => r.permissions, hideNarrow: true },
      ]}
      searchText={(r) => `${r.name} ${r.system}`}
      searchPlaceholder="Search applications…"
      commands={[newCmd("Add connection", () => nav("/admin/connections"))]}
      onRefresh={reload}
      rowLabel={(r) => r.name}
      onRowClick={(r) => setSelected(r.system)}
      activeKey={selected}
    />
    {open && <AppPanel c={open} onClose={() => setSelected(null)} />}
    </Page>
  );
}

// -------------------------------------------------------------------- orgs
export function Orgs() {
  const { data, error, reload } = useApi<OrgRow[]>(orgsPath);
  const [selected, setSelected] = useSelected();
  const byId = useMemo(() => new Map((data ?? []).map((o) => [o.id, o])), [data]);
  return (
    <Page title="Organizations" count={data ? plural(data.length, "organization") : undefined} crumbs={[IDENTITY, ["Organizations"]]}
      sub="One organization per department in your HR source, under one root for the company. Owners are named on the organization, else the people at the top of the department's reporting lines. Departments and managers come from the HR source.">
      <DataTable
        id="orgs"
        rows={data}
        error={error}
        onRefresh={reload}
        rowKey={(r) => r.id}
        columns={[
          { id: "name", header: "Organization", sort: (r) => r.name, cell: (r) => <div><span className="name-link">{r.name}</span><div className="xs faint">{r.parent_id ? `in ${byId.get(r.parent_id)?.name ?? "the company"}` : "Top level"}</div></div> },
          { id: "owner", header: "Owner", sort: (r) => r.owner?.name ?? "", cell: (r) => r.owner ? <span className="small">{r.owner.name}</span> : <span className="small faint">None found</span> },
          { id: "members", header: "Active people", num: true, sort: (r) => r.active, cell: (r) => r.active },
          { id: "total", header: "All people", num: true, sort: (r) => r.members, cell: (r) => r.members, hideNarrow: true },
        ]}
        searchText={(r) => `${r.name} ${r.owner?.name ?? ""}`}
        searchPlaceholder="Search organizations…"
        rowLabel={(r) => r.name}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={selected}
      />
      {selected && byId.has(selected) && <OrgPanel id={selected} onClose={() => setSelected(null)} />}
      <HierarchySourceCard onSaved={reload} />
    </Page>
  );
}
