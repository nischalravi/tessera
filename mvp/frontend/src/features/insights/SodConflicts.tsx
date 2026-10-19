import { useState } from "react";
import { Link } from "react-router-dom";
import { Scale } from "lucide-react";
import { IdentityDetail, SodViolation, sodPaths, useApi } from "../../api";
import { Badge, Button, CommandBar, DataTable, EmptyState, InsightsTabs, Page, Sev, SidePanel, useSelected } from "../../components";
import { RevokeDrawer } from "../directory/IdentityPage";
import { PRIORITIES, distinct, sortViolations, statusLabel } from "../governance/sodModel";

const opts = (vs: SodViolation[], get: (v: SodViolation) => string | string[]) => distinct(vs, get).map((value) => ({ value, label: value }));

/** One conflict: both halves with the paths that grant them, and a dry-run revoke of either. */
function ConflictPanel({ v, onClose }: { v: SodViolation; onClose: () => void }) {
  const { data: d, reload } = useApi<IdentityDetail>(`/identities/${v.identity_id}`);
  const [revoke, setRevoke] = useState<number | null>(null);
  const grants = v.edges.map(([src, dst]) => d?.grants.find((g) => g.src === src && g.dst === dst)).filter((g) => !!g);
  return (
    <>
      <SidePanel title={v.identity_name} sub={<><Sev s={v.priority} /> <Badge>{statusLabel(v.status)}</Badge></>} onClose={onClose} fullHref={`/directory/identities/${v.identity_id}`} fullLabel="Open person"
        commands={<CommandBar label={`Actions for ${v.identity_name}`} items={grants.map((g) => g.edge_id ? { label: `Remove ${g.label}…`, onClick: () => setRevoke(g.edge_id) } : null)} />}>
        <div className="stack">
          <div><b>{v.risk_name}</b><div className="small muted">{v.ruleset.name}{v.business_process ? ` · ${v.business_process}` : ""}</div></div>
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
          <p className="xs faint">Open conflicts count toward risk reports. Resolve one by removing either side, or ask a risk owner about a mitigating control.</p>
        </div>
      </SidePanel>
      {revoke !== null && <RevokeDrawer edgeId={revoke} onClose={() => setRevoke(null)} onDone={reload} />}
    </>
  );
}

export function SodConflicts() {
  const { data, error, reload } = useApi<{ total: number; violations: SodViolation[] }>(sodPaths.violations());
  const [selected, setSelected] = useSelected();
  const rows = data ? sortViolations(data.violations) : null;
  const open = rows?.find((v) => v.key === selected);
  const all = rows ?? [];
  const crumbs: [string, string?][] = [["Protection"], ["Insights", "/insights"], ["SoD conflicts"]];
  return (
    <Page tabs={<InsightsTabs />} title="Separation-of-duties conflicts" count={rows ? `${rows.length} conflict${rows.length === 1 ? "" : "s"}` : undefined} crumbs={crumbs}
      sub={<>People and machine identities who hold an entitlement of each of two conflicting functions, through any combination of groups, roles and systems. Define the rules under <Link to="/governance/policies?view=risks">Policies & SoD</Link>.</>}>
      <DataTable
        id="sod-conflicts"
        rows={rows}
        error={error}
        rowKey={(v) => v.key}
        columns={[
          { id: "risk", header: "Risk", sort: (v) => v.risk_name, cell: (v) => <div><span className="name-link">{v.risk_name}</span><div className="xs faint">{v.identity_name}</div></div> },
          { id: "priority", header: "Priority", sort: (v) => PRIORITIES.indexOf(v.priority) * -1, csv: (v) => v.priority, cell: (v) => <Sev s={v.priority} /> },
          { id: "f1", header: "Function 1", sort: (v) => v.function1.name, cell: (v) => v.function1.name, hideNarrow: true },
          { id: "f2", header: "Function 2", sort: (v) => v.function2.name, cell: (v) => v.function2.name, hideNarrow: true },
          { id: "ent", header: "Entitlement", sort: (v) => v.entitlement, cell: (v) => <span className="sys small">{v.entitlement}</span>, hideNarrow: true },
          { id: "sys", header: "System", sort: (v) => v.systems.join(), csv: (v) => v.systems.join(" "), cell: (v) => v.systems.join(", "), hideNarrow: true },
          { id: "ruleset", header: "Ruleset", sort: (v) => v.ruleset.name, cell: (v) => v.ruleset.name, hideNarrow: true },
          { id: "process", header: "Business process", sort: (v) => v.business_process, cell: (v) => v.business_process || <span className="faint">-</span>, hideNarrow: true },
          { id: "status", header: "Status", sort: (v) => v.status, cell: (v) => <Badge tone={v.status === "open" ? "critical" : "ok"}>{statusLabel(v.status)}</Badge> },
        ]}
        initialSort={["priority", 1]}
        searchText={(v) => `${v.identity_name} ${v.risk_name} ${v.function1.name} ${v.function2.name} ${v.entitlement} ${v.message}`}
        searchPlaceholder="Search conflicts, people or entitlements…"
        filters={[
          { id: "priority", label: "Priority", options: PRIORITIES.map((p) => ({ value: p, label: p[0].toUpperCase() + p.slice(1) })), get: (v) => v.priority },
          { id: "risk", label: "Risk", options: opts(all, (v) => v.risk_name), get: (v) => v.risk_name },
          { id: "ruleset", label: "Ruleset", options: opts(all, (v) => v.ruleset.name), get: (v) => v.ruleset.name },
          { id: "system", label: "System", options: opts(all, (v) => v.systems), get: (v) => v.systems },
          { id: "process", label: "Business process", options: opts(all, (v) => v.business_process), get: (v) => v.business_process },
          { id: "status", label: "Status", options: opts(all, (v) => v.status).map((o) => ({ ...o, label: statusLabel(o.value) })), get: (v) => v.status },
        ]}
        onRefresh={reload}
        rowLabel={(v) => `${v.identity_name}: ${v.risk_name}`}
        onRowClick={(v) => setSelected(v.key)}
        activeKey={selected}
        empty={<EmptyState title="No conflicts" icon={<Scale size={18} />} action={<Link to="/governance/policies?view=risks"><Button>Review the risks</Button></Link>}>Nobody holds both halves of any enabled risk.</EmptyState>}
      />
      {open && <ConflictPanel v={open} onClose={() => setSelected(null)} />}
    </Page>
  );
}
