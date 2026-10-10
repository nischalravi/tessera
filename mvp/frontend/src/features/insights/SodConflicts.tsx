import { useState } from "react";
import { Link } from "react-router-dom";
import { Scale } from "lucide-react";
import { IdentityDetail, Policy, Violation, useApi } from "../../api";
import { Button, Callout, EmptyState, Loading, Page, Sev, InsightsTabs } from "../../components";
import { RevokeDrawer } from "../directory/IdentityPage";

/** Pull the two permission sets out of a separation_of_duties policy's YAML for display. */
function conflictSides(src: string): [string, string] | null {
  const a = src.match(/^\s*a:\s*\[(.*)\]/m)?.[1];
  const b = src.match(/^\s*b:\s*\[(.*)\]/m)?.[1];
  const clean = (s: string) => s.replace(/["']/g, "").split(",").map((x) => x.trim()).join(", ");
  return a && b ? [clean(a), clean(b)] : null;
}

/** One conflict: shows both toxic paths and lets you dry-run removing either side. */
function Conflict({ v }: { v: Violation & { edges?: [string, string][] } }) {
  const { data: d, reload } = useApi<IdentityDetail>(v.identity_id ? `/identities/${v.identity_id}` : null);
  const [revoke, setRevoke] = useState<number | null>(null);
  const sides = (v.edges ?? []).map(([src, dst]) => d?.grants.find((g) => g.src === src && g.dst === dst)).filter((g) => !!g);
  return (
    <div className="card stack-sm">
      <div className="spread">
        <div className="row"><Sev s={v.severity} />{v.identity_id ? <Link to={`/directory/identities/${v.identity_id}`}><b>{v.identity_name}</b></Link> : <b>{v.identity_name}</b>}</div>
        <span className="xs faint">{v.policy_name}</span>
      </div>
      <div>{v.message}</div>
      {v.evidence.map((e, i) => <div key={i} className="small muted sys">{e}</div>)}
      {sides.length > 0 && (
        <div className="row mt-sm">
          <span className="small muted">Resolve by removing</span>
          {sides.map((g) => g.edge_id && <Button key={g.edge_id} size="sm" onClick={() => setRevoke(g.edge_id)}>{g.label}…</Button>)}
        </div>
      )}
      {revoke !== null && <RevokeDrawer edgeId={revoke} onClose={() => setRevoke(null)} onDone={reload} />}
    </div>
  );
}

export function SodConflicts() {
  const { data: policies, error } = useApi<Policy[]>("/policies");
  const { data: violations } = useApi<(Violation & { edges?: [string, string][] })[]>("/violations");
  const crumbs: [string, string?][] = [["Protection"], ["Insights", "/insights"], ["SoD conflicts"]];
  if (!policies) return <Page tabs={<InsightsTabs />} title="SoD conflicts" crumbs={crumbs}><Loading error={error} kind="page" /></Page>;
  const sod = policies.filter((p) => p.type === "separation_of_duties");
  const ids = new Set(sod.map((p) => p.id));
  const conflicts = (violations ?? []).filter((v) => ids.has(v.policy_id));
  return (
    <Page tabs={<InsightsTabs />} title="Separation-of-duties conflicts" crumbs={crumbs} sub="People and machine identities who can complete both halves of a sensitive process, through any combination of groups, roles and systems. Checked against effective permissions, not role names.">
      <div className="grid g12">
        <div className="stack">
          <h2>Rules</h2>
          {sod.length === 0 && <div className="card"><EmptyState title="No SoD rules">Add a policy of type <code>separation_of_duties</code> in <code>server/policies/</code>.</EmptyState></div>}
          {sod.map((p) => {
            const s = conflictSides(p.source);
            return (
              <div key={p.id} className="card stack-sm">
                <div className="spread"><Sev s={p.severity} /><span className="xs faint tnum">{p.violations} conflict{p.violations === 1 ? "" : "s"}</span></div>
                <b>{p.name}</b>
                <div className="small muted">{p.description}</div>
                {s && (
                  <dl className="kv">
                    <dt>Side A</dt><dd className="sys small">{s[0]}</dd>
                    <dt>Side B</dt><dd className="sys small">{s[1]}</dd>
                  </dl>
                )}
              </div>
            );
          })}
          <Callout tone="neutral">Access requests are checked against these rules before they are submitted. A request that would create a conflict needs an SoD exception.</Callout>
        </div>
        <div className="stack">
          <h2>Current conflicts <span className="faint tnum">({violations ? conflicts.length : "…"})</span></h2>
          {!violations ? <div className="card"><Loading kind="block" /></div> : conflicts.length === 0 ? (
            <div className="card"><EmptyState title="No conflicts" icon={<Scale size={18} />}>Nobody can both create and approve under the current rules.</EmptyState></div>
          ) : conflicts.map((v) => <Conflict key={v.key} v={v} />)}
        </div>
      </div>
    </Page>
  );
}
