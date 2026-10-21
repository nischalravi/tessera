import { ComponentProps, useState } from "react";
import { Link } from "react-router-dom";
import { Scale } from "lucide-react";
import { AlertTriangle, ShieldCheck as Shield, Undo2, UserX, Scale as ScaleIcon } from "lucide-react";
import { IdentityDetail, SodMitigationList, SodViolation, SodViewKey, SodViewView, sodControlPaths, sodPaths, sodViewPath, useApi } from "../../api";
import { Badge, Button, Callout, CommandBar, DataTable, EmptyState, InsightsTabs, Page, Sev, SidePanel, useSelected } from "../../components";
import { EndEarlyDrawer, EscalateDrawer, MitigateDrawer, Target } from "../governance/MitigateDrawers";
import { RevokeDrawer } from "../directory/IdentityPage";
import { ALL_VISIBLE, visible } from "./sodViewModel";
import { PRIORITIES, describeOptions, distinct, escalationLabel, offers, openCount, sortViolations, statusLabel } from "../governance/sodModel";

type Col = ComponentProps<typeof DataTable<SodViolation>>["columns"][number];
type Flt = NonNullable<ComponentProps<typeof DataTable<SodViolation>>["filters"]>[number];
const opts = (vs: SodViolation[], get: (v: SodViolation) => string | string[]) => distinct(vs, get).map((value) => ({ value, label: value }));

/** One conflict: both halves with the paths that grant them, and a dry-run revoke of either. */
function ConflictPanel({ v, onClose, onChanged }: { v: SodViolation; onClose: () => void; onChanged: () => void }) {
  const { data: d, reload } = useApi<IdentityDetail>(`/identities/${v.identity_id}`);
  const { data: mits, reload: reloadMits } = useApi<SodMitigationList>(sodControlPaths.mitigations());
  const [revoke, setRevoke] = useState<number | null>(null);
  const [drawer, setDrawer] = useState<null | "mitigate" | "accept" | "escalate" | "end">(null);
  const grants = v.edges.map(([src, dst]) => d?.grants.find((g) => g.src === src && g.dst === dst)).filter((g) => !!g);
  const target: Target = { riskId: v.risk_id, riskName: v.risk_name, identityId: v.identity_id, identityName: v.identity_name };
  const covered = !!v.mitigation && v.status !== "open";
  const canRequest = !!mits?.can_request && v.status === "open";
  const live = mits?.mitigations.find((m) => m.id === v.mitigation?.mitigation_id);
  const done = () => { reload(); reloadMits(); onChanged(); };
  return (
    <>
      <SidePanel title={v.identity_name} sub={<><Sev s={v.priority} /> <Badge tone={v.status === "open" ? "critical" : v.status === "mitigation_pending" ? "warning" : "ok"}>{v.mitigation?.label ?? statusLabel(v.status)}</Badge></>} onClose={onClose} fullHref={`/directory/identities/${v.identity_id}`} fullLabel="Open person"
        commands={<CommandBar label={`Actions for ${v.identity_name}`} items={[
          canRequest && offers(v, "mitigate") && { label: "Mitigate…", icon: <Shield size={16} />, onClick: () => setDrawer("mitigate") },
          canRequest && offers(v, "accept") && { label: "Accept…", icon: <ScaleIcon size={16} />, onClick: () => setDrawer("accept") },
          canRequest && offers(v, "escalate") && { label: "Escalate…", icon: <AlertTriangle size={16} />, onClick: () => setDrawer("escalate") },
          covered && live?.status === "active" && { label: "End early…", icon: <Undo2 size={16} />, danger: true, onClick: () => setDrawer("end") },
          ...(v.status === "open" || v.status === "mitigation_pending" ? grants.filter(() => offers(v, "revoke")).map((g) => g.edge_id ? { label: `Revoke ${g.label}…`, icon: <UserX size={16} />, onClick: () => setRevoke(g.edge_id) } : null) : []),
        ]} />}>
        <div className="stack">
          <div><b>{v.risk_name}</b><div className="small muted">{v.ruleset.name}{v.business_process ? ` · ${v.business_process}` : ""}</div></div>
          {covered && v.mitigation && (
            <Callout tone="ok">{v.mitigation.label}{v.mitigation.control ? ` by ${v.mitigation.control}` : ""}. It is left out of the open counts and stays in reports. When it ends the violation opens again.</Callout>
          )}
          {v.status === "mitigation_pending" && <Callout tone="warn">A request is waiting for a second person to approve it. Until then the violation is open.</Callout>}
          <p>{v.message}</p>
          {v.sides.map((side, i) => (
            <section key={i} className="stack-sm" aria-label={`Side ${i + 1}: ${side.function.name}`}>
              <h3>{i + 1}. {side.function.name}</h3>
              {side.grants.map((g) => (
                <div key={g.perm_key} className="card stack-sm">
                  <div className="small"><b className="sys">{g.action}</b> on {g.resource} <span className="faint">({g.system})</span></div>
                  {g.paths.map((p, j) => <div key={j} className="small muted sys">{p}</div>)}
                </div>
              ))}
            </section>
          ))}
          <p className="xs faint">Options this risk offers: {describeOptions(v.remediation)}. {v.remediation.includes("escalate") && <>Escalations go to {escalationLabel(v.escalate_to)}. </>}Resolve by removing either side, or cover it with a control another person approves.</p>
        </div>
      </SidePanel>
      {revoke !== null && <RevokeDrawer edgeId={revoke} via={{ riskId: v.risk_id, identityId: v.identity_id }} onClose={() => setRevoke(null)} onDone={done} />}
      {(drawer === "mitigate" || drawer === "accept") && <MitigateDrawer target={target} kind={drawer === "accept" ? "accept" : "control"} offerControl={drawer === "mitigate"} offerAccept={drawer === "accept"} onClose={() => setDrawer(null)} onDone={done} />}
      {drawer === "end" && live && <EndEarlyDrawer mitigationId={live.id} label={`${v.identity_name}: ${v.risk_name}`} onClose={() => setDrawer(null)} onDone={done} />}
      {drawer === "escalate" && <EscalateDrawer target={target} routeTo={v.escalate_to?.name} onClose={() => setDrawer(null)} onDone={done} />}
    </>
  );
}

export function SodConflicts() {
  const { data, error, reload } = useApi<{ total: number; violations: SodViolation[] }>(sodPaths.violations());
  const [selected, setSelected] = useSelected();
  // the tenant's choice of columns and filters (Admin > SoD page); everything until it loads or when it cannot
  const { data: cfg } = useApi<SodViewView>(sodViewPath);
  const shown = cfg ?? ALL_VISIBLE;
  const rows = data ? sortViolations(data.violations) : null;
  const open = rows?.find((v) => v.key === selected);
  const all = rows ?? [];
  const crumbs: [string, string?][] = [["Protection"], ["Insights", "/insights"], ["SoD conflicts"]];
  return (
    <Page tabs={<InsightsTabs />} title="Separation-of-duties conflicts" count={rows ? `${openCount(rows)} open of ${rows.length} conflict${rows.length === 1 ? "" : "s"}` : undefined} crumbs={crumbs}
      sub={<>People and machine identities who hold an entitlement of each of two conflicting functions, through any combination of groups, roles and systems. Define the rules under <Link to="/governance/policies?view=risks">Policies & SoD</Link>.</>}>
      <DataTable
        id="sod-conflicts"
        rows={rows}
        error={error}
        rowKey={(v) => v.key}
        columns={visible<{ key?: SodViewKey; col: Col }>([
          { key: "risk", col: { id: "risk", header: "Risk", sort: (v) => v.risk_name, cell: (v) => <div><span className="name-link">{v.risk_name}</span><div className="xs faint">{v.identity_name}</div></div> } },
          { col: { id: "priority", header: "Priority", sort: (v) => PRIORITIES.indexOf(v.priority) * -1, csv: (v) => v.priority, cell: (v) => <Sev s={v.priority} /> } },
          { key: "function", col: { id: "f1", header: "Function 1", sort: (v) => v.function1.name, cell: (v) => v.function1.name, hideNarrow: true } },
          { key: "function", col: { id: "f2", header: "Function 2", sort: (v) => v.function2.name, cell: (v) => v.function2.name, hideNarrow: true } },
          { key: "entitlement", col: { id: "ent", header: "Entitlement", sort: (v) => v.entitlement, cell: (v) => <span className="sys small">{v.entitlement}</span>, hideNarrow: true } },
          { col: { id: "sys", header: "System", sort: (v) => v.systems.join(), csv: (v) => v.systems.join(" "), cell: (v) => v.systems.join(", "), hideNarrow: true } },
          { key: "ruleset", col: { id: "ruleset", header: "Ruleset", sort: (v) => v.ruleset.name, cell: (v) => v.ruleset.name, hideNarrow: true } },
          { key: "mitigating_control", col: { id: "control", header: "Mitigating control", sort: (v) => v.mitigation?.control ?? "", csv: (v) => v.mitigation?.control ?? "", cell: (v) => v.mitigation?.control || <span className="faint">-</span>, hideNarrow: true } },
          { key: "business_process", col: { id: "process", header: "Business process", sort: (v) => v.business_process, cell: (v) => v.business_process || <span className="faint">-</span>, hideNarrow: true } },
          { col: { id: "status", header: "Status", sort: (v) => v.status, cell: (v) => <Badge tone={v.status === "open" ? "critical" : v.status === "mitigation_pending" ? "warning" : "ok"}>{v.mitigation?.label ?? statusLabel(v.status)}</Badge> } },
        ], shown.columns).map((c) => c.col)}
        initialSort={["priority", 1]}
        searchText={(v) => `${v.identity_name} ${v.risk_name} ${v.function1.name} ${v.function2.name} ${v.entitlement} ${v.message}`}
        searchPlaceholder="Search conflicts, people or entitlements…"
        filters={visible<{ key?: SodViewKey; f: Flt }>([
          { f: { id: "priority", label: "Priority", options: PRIORITIES.map((p) => ({ value: p, label: p[0].toUpperCase() + p.slice(1) })), get: (v) => v.priority } },
          { key: "risk", f: { id: "risk", label: "Risk", options: opts(all, (v) => v.risk_name), get: (v) => v.risk_name } },
          { key: "function", f: { id: "function", label: "Function", options: opts(all, (v) => [v.function1.name, v.function2.name]), get: (v) => [v.function1.name, v.function2.name] } },
          { key: "entitlement", f: { id: "entitlement", label: "Entitlement", options: opts(all, (v) => v.entitlement), get: (v) => v.entitlement } },
          { key: "ruleset", f: { id: "ruleset", label: "Ruleset", options: opts(all, (v) => v.ruleset.name), get: (v) => v.ruleset.name } },
          { f: { id: "system", label: "System", options: opts(all, (v) => v.systems), get: (v) => v.systems } },
          { key: "mitigating_control", f: { id: "control", label: "Mitigating control", options: opts(all, (v) => v.mitigation?.control ?? ""), get: (v) => v.mitigation?.control ?? "" } },
          { key: "business_process", f: { id: "process", label: "Business process", options: opts(all, (v) => v.business_process), get: (v) => v.business_process } },
          { f: { id: "status", label: "Status", options: opts(all, (v) => v.status).map((o) => ({ ...o, label: statusLabel(o.value) })), get: (v) => v.status } },
        ], shown.filters).map((c) => c.f)}
        onRefresh={reload}
        rowLabel={(v) => `${v.identity_name}: ${v.risk_name}`}
        onRowClick={(v) => setSelected(v.key)}
        activeKey={selected}
        empty={<EmptyState title="No conflicts" icon={<Scale size={18} />} action={<Link to="/governance/policies?view=risks"><Button>Review the risks</Button></Link>}>Nobody holds both halves of any enabled risk.</EmptyState>}
      />
      {open && <ConflictPanel v={open} onClose={() => setSelected(null)} onChanged={reload} />}
    </Page>
  );
}
