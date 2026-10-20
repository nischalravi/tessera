import { Suspense, lazy } from "react";
import { Link } from "react-router-dom";
import { IdentityRules as Rules, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Callout, Loading } from "../../components";

// the editor is the one the Identity matches page uses; load it only for a person who may change settings
const MatchingSettingsForm = lazy(async () => ({ default: (await import("../directory/IdentityMatches")).MatchingSettingsForm }));

const TIER_TONE = { A: "ok", B: "info", C: "warning", D: "neutral" } as const;

/**
 * Identity rules: what the identity engines apply today, in one place. The matching and correlation rules
 * (how an incoming person or account is matched to an existing one), the group naming rules and the dormancy
 * threshold are read from the engines themselves, so this page cannot drift from them. The matching settings can
 * be changed here by someone who holds identity.matching.configure.
 */
export function IdentityRules() {
  const { data, error } = useApi<Rules>("/admin/identity-rules");
  const { can } = useSession();
  if (!data) return <div className="card flush"><Loading error={error} /></div>;
  const m = data.matching;
  return (
    <div className="stack">
      <div className="card stack-sm">
        <h2>Matching and correlation</h2>
        <p className="small muted" style={{ margin: 0 }}>
          When a person arrives from a source (HR, a campus system, an invitation, a sign-in), Tessera looks for an existing person. Rules fire at a tier: <b>A</b> is exact, <b>B</b> strong, <b>C</b> possible. {m.self_asserted}
        </p>
        <div className="table-scroll">
          <table>
            <caption className="sr-only">Matching rules</caption>
            <thead><tr><th scope="col">Rule</th><th scope="col">Tier</th><th scope="col">What it compares</th></tr></thead>
            <tbody>
              {m.rules.map((r) => (
                <tr key={r.name}>
                  <td><b>{r.name.replace(/_/g, " ")}</b><div className="xs faint sys">{r.name}</div></td>
                  <td><Badge tone={TIER_TONE[r.tier]}>Tier {r.tier}</Badge></td>
                  <td className="small">{r.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="small muted" style={{ margin: 0 }}>
          Names match as similar at {m.name_strong} (strong) and {m.name_possible} (possible). For a connector account that has no person yet, Tessera proposes one by{" "}
          {data.correlation.proposals.map((p) => p.description.replace(/\.$/, "").toLowerCase()).join(", or when ")}. {data.correlation.decisions}{" "}
          Reviewers work the queues on <Link to="/directory/identity-matches">Identity matches</Link> and <Link to="/directory/matches">Account matches</Link>.
        </p>
      </div>

      <div className="card stack-sm">
        <h2>Matching settings</h2>
        {can("matching.configure") ? (
          <Suspense fallback={<p role="status">Loading…</p>}><MatchingSettingsForm /></Suspense>
        ) : (
          <ul className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8 }}>
            <li>Strong (Tier B) matches between authoritative sources link {m.settings.auto_link_tier_b ? "automatically" : "after review"}.</li>
            <li>Exact (Tier A) matches {m.settings.require_review_tier_a ? "are also sent to review" : "link without review"}.</li>
            <li>A merge can be undone for {m.settings.unmerge_window_days} days.</li>
            <li className="faint">Changing these needs the <code>{m.changeable_with}</code> permission (policy admin).</li>
          </ul>
        )}
      </div>

      <div className="card stack-sm">
        <h2>Group naming</h2>
        <ul className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8 }}>
          <li>A group or folder name is a path of segments separated by <code>{data.group_naming.separator}</code>, for example <code>apps:payroll:admins</code>.</li>
          <li>Each segment uses {data.group_naming.allowed}, up to {data.group_naming.max_segment} characters; a whole name is at most {data.group_naming.max_name} and {data.group_naming.max_depth} levels deep.</li>
          <li>Names are unique ignoring case, and an old name is kept as an alias after a rename or move. Display names are up to {data.group_naming.max_display} characters.</li>
        </ul>
      </div>

      <div className="card stack-sm">
        <h2>Dormancy</h2>
        <ul className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8 }}>
          {data.dormancy.map((d) => <li key={d.identity_type}><b>{d.identity_type}</b>: dormant after {d.days} days without use. {d.effect}</li>)}
        </ul>
      </div>

      <Callout tone="neutral">
        <b>Not configurable yet.</b>
        <ul className="small" style={{ margin: "6px 0 0", paddingLeft: 18 }}>{data.not_configurable.map((n) => <li key={n}>{n}</li>)}</ul>
      </Callout>
    </div>
  );
}
