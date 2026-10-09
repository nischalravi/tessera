import { useState } from "react";
import { Link } from "react-router-dom";
import { Scissors } from "lucide-react";
import { Recommendation, ago, useApi } from "../../api";
import { Badge, Button, Callout, Chip, EmptyState, FilterChips, Loading, Page, Segmented, TypeBadge } from "../../components";
import { RevokeDrawer } from "../directory/IdentityPage";

const KIND: Record<string, [string, "critical" | "info" | "warning"]> = { remove: ["Remove", "critical"], role_trim: ["Role trim", "info"], right_size: ["Right-size", "warning"] };

export function LeastPrivilege() {
  const [days, setDays] = useState<"30" | "60" | "90">("60");
  const [kind, setKind] = useState<"remove" | "role_trim" | "right_size" | "">("remove");
  const [itype, setItype] = useState<"" | "human" | "service" | "ai_agent">("");
  const { data, error, reload } = useApi<Recommendation[]>(`/least-privilege/recommendations?unused_days=${days}${kind ? `&kind=${kind}` : ""}${itype ? `&identity_type=${itype}` : ""}`);
  const [revoke, setRevoke] = useState<number | null>(null);
  const totalUnused = (data ?? []).reduce((a, r) => a + r.unused_lost, 0);
  return (
    <Page
      title="Least privilege"
      crumbs={[["Insights", "/insights"], ["Least privilege"]]}
      sub="Grants whose permissions have gone unused, from per-identity usage events. Every revoke shows its blast radius before anything changes."
      actions={<Segmented label="Unused for" value={days} onChange={setDays} options={[["30", "30 days"], ["60", "60 days"], ["90", "90 days"]]} />}
    >
      <div className="spread" style={{ marginBottom: 12 }}>
        <FilterChips label="Recommendation type" value={kind} onChange={setKind} options={[{ id: "remove", label: "Safe to remove" }, { id: "role_trim", label: "Role trims" }, { id: "right_size", label: "Right-size" }, { id: "", label: "All" }]} />
        <FilterChips label="Identity type" value={itype} onChange={setItype} options={[{ id: "", label: "Everyone" }, { id: "human", label: "People" }, { id: "service", label: "Service" }, { id: "ai_agent", label: "Agents" }]} />
      </div>
      {!data ? <div className="card flush"><Loading error={error} /></div> : (
        <div className="stack">
          <Callout>
            {data.length} recommendation{data.length === 1 ? "" : "s"} would remove <b className="tnum">{totalUnused}</b> unused permissions. <i>Safe to remove</i>: nothing the grant uniquely provides was used in {days} days. <i>Role trim</i>: a permission inside a role that none of its holders used. <i>Right-size</i>: most of a grant was unused.
          </Callout>
          <div className="card flush">
            {data.length === 0 ? <EmptyState title="Nothing to trim" icon={<Scissors size={18} />}>No recommendations for this filter. Try a shorter unused window or another type.</EmptyState> : (
              <div className="table-scroll">
                <table>
                  <thead><tr><th>Who</th><th>Grant</th><th className="hide-narrow">Why</th><th className="num">Unused / lost</th><th>Last used</th><th /></tr></thead>
                  <tbody>
                    {data.map((r) => (
                      <tr key={String(r.id ?? r.edge_id)}>
                        {r.kind === "role_trim" ? (
                          <td style={{ maxWidth: 220 }}><b>{r.identity_name}</b><div className="xs faint">{r.holders?.slice(0, 4).join(", ")}{(r.holders?.length ?? 0) > 4 ? " …" : ""}</div></td>
                        ) : (
                          <td>
                            <Link to={`/directory/identities/${r.identity_id}`}><b>{r.identity_name}</b></Link>
                            <div className="row tight" style={{ marginTop: 3 }}>{r.identity_type && <TypeBadge type={r.identity_type} />}<span className="xs faint">{r.department}</span></div>
                          </td>
                        )}
                        <td>
                          <b>{r.target}</b> {r.target_privileged && <Badge tone="warning">Privileged</Badge>}
                          <div className="xs faint sys">{r.grant}</div>
                          {r.sensitive_tags.length > 0 && <div className="row tight" style={{ marginTop: 3 }}>{r.sensitive_tags.map((t) => <Chip key={t}>{t}</Chip>)}</div>}
                        </td>
                        <td className="small hide-narrow" style={{ maxWidth: 340 }}>
                          <Badge tone={KIND[r.kind][1]}>{KIND[r.kind][0]}</Badge> {r.rationale}
                          {r.used_examples.length > 0 && <div className="xs faint" style={{ marginTop: 3 }}>Still used: {r.used_examples.slice(0, 2).join("; ")}</div>}
                        </td>
                        <td className="num">{r.unused_lost} / {r.permissions_lost}{(r.privileged_unused ?? 0) > 0 && <div className="xs faint">{r.privileged_unused} privileged</div>}</td>
                        <td className="small nowrap">{ago(r.days_since_used)}</td>
                        <td className="actions-cell"><Button size="sm" onClick={() => setRevoke(r.edge_id)}>Dry-run revoke</Button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
      {revoke !== null && <RevokeDrawer edgeId={revoke} onClose={() => setRevoke(null)} onDone={reload} />}
    </Page>
  );
}
