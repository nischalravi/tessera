import { FormEvent, Suspense, lazy, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowDown, ArrowUp } from "lucide-react";
import { IdentityRules as Rules, identityRulesApi, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Loading, useToast } from "../../components";
import { errText } from "./common";

// the editor is the one the Identity matches page uses; load it only for a person who may change settings
const MatchingSettingsForm = lazy(async () => ({ default: (await import("../directory/IdentityMatches")).MatchingSettingsForm }));

const KEY_LABEL: Record<string, string> = { external_id: "External ID", email: "Email address" };
const ATTR_LABEL: Record<string, string> = { name: "Name", email: "Email address", department: "Department", title: "Job title" };

/**
 * The rules the tenant tunes: the order the connector resolver correlates a reference to a person, the authoritative
 * system of each person attribute, and the dormancy days of service identities and AI agents. The server checks every
 * value again and refuses an unknown system or a stale version.
 */
function RulesEditor({ data, onSaved }: { data: Rules; onSaved: () => void }) {
  const r = data.rules;
  const toast = useToast();
  const [order, setOrder] = useState(r.correlation_order);
  const [auth, setAuth] = useState(r.authoritative);
  const [svc, setSvc] = useState(String(r.dormant_service_days));
  const [agent, setAgent] = useState(String(r.dormant_ai_agent_days));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setOrder(r.correlation_order);
    setAuth(r.authoritative);
    setSvc(String(r.dormant_service_days));
    setAgent(String(r.dormant_ai_agent_days));
  }, [r.version]); // eslint-disable-line react-hooks/exhaustive-deps

  const can = r.can_manage;
  const days = (v: string) => (/^\d+$/.test(v.trim()) ? Number(v) : NaN);
  const daysOk = (n: number) => n >= r.min_days && n <= r.max_days;
  const problem = order.length === 0 ? "Keep at least one correlation key." : !daysOk(days(svc)) || !daysOk(days(agent)) ? `Dormancy is ${r.min_days} to ${r.max_days} days.` : null;
  const unused = r.correlation_keys.filter((k) => !order.includes(k));
  const move = (i: number, d: number) => setOrder((o) => { const n = [...o]; [n[i], n[i + d]] = [n[i + d], n[i]]; return n; });
  const changed = JSON.stringify(order) !== JSON.stringify(r.correlation_order) || JSON.stringify(auth) !== JSON.stringify(r.authoritative) ||
    days(svc) !== r.dormant_service_days || days(agent) !== r.dormant_ai_agent_days;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problem || !changed || busy || !can) return;
    setBusy(true);
    setErr(null);
    try {
      await identityRulesApi.save({ version: r.version, correlation_order: order, authoritative: auth, dormant_service_days: days(svc), dormant_ai_agent_days: days(agent) });
      toast("Identity rules saved");
      onSaved();
    } catch (x) {
      setErr(errText(x));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card stack" onSubmit={submit} aria-label="Identity rules">
      <h2>Correlation, sources and dormancy</h2>
      {!can && <Callout tone="neutral">You can read these rules. A policy admin changes them.</Callout>}
      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h3>Correlation order</h3></legend>
        <p className="small muted" style={{ margin: 0 }}>When a connector names a person (a manager, an owner, the person behind an account), Tessera tries these keys in order and takes the first match. A reviewer's pinned decision always wins.</p>
        <ol className="small" style={{ margin: 0, paddingLeft: 20, lineHeight: 2.2 }}>
          {order.map((k, i) => (
            <li key={k}>
              <span className="row tight">
                <b>{KEY_LABEL[k] ?? k}</b>
                <Button size="sm" variant="ghost" icon={<ArrowUp size={14} />} label={`Move ${KEY_LABEL[k] ?? k} up`} disabled={i === 0 || !can} onClick={() => move(i, -1)} />
                <Button size="sm" variant="ghost" icon={<ArrowDown size={14} />} label={`Move ${KEY_LABEL[k] ?? k} down`} disabled={i === order.length - 1 || !can} onClick={() => move(i, 1)} />
                <Button size="sm" variant="ghost" disabled={!can || order.length === 1} onClick={() => setOrder((o) => o.filter((x) => x !== k))}>Don't use</Button>
              </span>
            </li>
          ))}
        </ol>
        {unused.length > 0 && (
          <div className="row small">
            <span className="faint">Not used:</span>
            {unused.map((k) => <Button key={k} size="sm" disabled={!can} onClick={() => setOrder((o) => [...o, k])}>Use {KEY_LABEL[k] ?? k}</Button>)}
          </div>
        )}
      </fieldset>

      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h3>Authoritative source per attribute</h3></legend>
        <p className="small muted" style={{ margin: 0 }}>When another system reports a person Tessera already knows, the value from this system is kept. A person seen for the first time takes the first source's value until the authoritative system reports.</p>
        {r.systems.length === 0 && <p className="small faint" style={{ margin: 0 }}>No connection yet: add one under Connections to name it here.</p>}
        <div className="grid g2">
          {r.attributes.map((a) => (
            <label key={a} className="field">{ATTR_LABEL[a] ?? a}
              <select className="input" value={auth[a] ?? ""} onChange={(e) => setAuth((m) => { const n = { ...m }; if (e.target.value) n[a] = e.target.value; else delete n[a]; return n; })}>
                <option value="">Any source (last write wins)</option>
                {/* a saved source whose connection is gone stays visible so it can be changed */}
                {[...new Set([...r.systems, ...(auth[a] ? [auth[a]] : [])])].map((sys) => <option key={sys} value={sys}>{sys}</option>)}
              </select>
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }} disabled={!can}>
        <legend><h3>Dormancy</h3></legend>
        <p className="small muted" style={{ margin: 0 }}>A machine identity unused for this many days is flagged dormant in the machine-identity inventory and counts in its risk score. {data.not_configurable.join(" ")}</p>
        <div className="grid g2">
          <label className="field">Service identities (days)
            <input className="input" inputMode="numeric" value={svc} onChange={(e) => setSvc(e.target.value)} aria-invalid={!daysOk(days(svc))} style={{ maxWidth: 140 }} />
          </label>
          <label className="field">AI agents (days)
            <input className="input" inputMode="numeric" value={agent} onChange={(e) => setAgent(e.target.value)} aria-invalid={!daysOk(days(agent))} style={{ maxWidth: 140 }} />
          </label>
        </div>
      </fieldset>

      {problem && changed && <p className="small" role="alert">{problem}</p>}
      {err && <Callout tone="bad">{err}</Callout>}
      {can && <div className="row" style={{ justifyContent: "flex-end" }}><Button type="submit" variant="primary" disabled={!!problem || !changed || busy}>{busy ? "Saving…" : "Save rules"}</Button></div>}
    </form>
  );
}

const TIER_TONE = { A: "ok", B: "info", C: "warning", D: "neutral" } as const;

/**
 * Identity rules: what the identity engines apply today, in one place. The matching and correlation rules
 * (how an incoming person or account is matched to an existing one), the group naming rules and the dormancy
 * threshold are read from the engines themselves, so this page cannot drift from them. The matching settings can
 * be changed here by someone who holds matching.configure, and so can the correlation order, the authoritative source of
 * each attribute and the dormancy thresholds (the editor below).
 */
export function IdentityRules() {
  const { data, error, reload } = useApi<Rules>("/admin/identity-rules");
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

      <RulesEditor data={data} onSaved={() => reload?.()} />
    </div>
  );
}
