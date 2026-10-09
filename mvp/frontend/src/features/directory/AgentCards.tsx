import { Link } from "react-router-dom";
import { NhiRow, ago } from "../../api";
import { Avatar, Bar, Callout, Chip, Flag } from "../../components";

/** An AI agent with its owner -> agent -> on-behalf-of chain and the tool scopes it was delegated. */
export function AgentCard({ a }: { a: NhiRow }) {
  return (
    <div className="card stack-sm">
      <div className="spread" style={{ alignItems: "flex-start", flexWrap: "nowrap" }}>
        <div className="row" style={{ flexWrap: "nowrap", minWidth: 0 }}>
          <Avatar name={a.name} type={a.type} />
          <div style={{ minWidth: 0 }}>
            <Link to={`/directory/identities/${a.id}`}><b>{a.name}</b></Link>
            <div className="xs faint truncate">{a.description}</div>
          </div>
        </div>
        <div style={{ width: 80, flex: "none" }} title={`Risk ${a.risk}`}><Bar value={a.risk} tone="risk" /></div>
      </div>
      {a.flags.length > 0 && <div className="row tight">{a.flags.map((f) => <Flag key={f} f={f} />)}</div>}
      {a.delegations.length === 0 && <div className="small muted">No delegations recorded.</div>}
      {a.delegations.map((d, i) => (
        <div key={i} className="stack-sm">
          <div className="chain" aria-label="Delegation chain">
            {d.chain.map((c, j) => (
              <span key={j} className="row tight">
                {j > 0 && <span className="faint" aria-hidden>→</span>}
                <span className={`lnk ${c.status !== "active" ? "bad" : ""}`}>
                  <small>{c.role.replace(/_/g, " ")}</small>
                  {c.name}
                  {c.status !== "active" && <span className="xs" style={{ marginLeft: 4, color: "var(--critical)" }}>(left)</span>}
                </span>
              </span>
            ))}
          </div>
          <div className="row tight"><span className="xs faint">Scopes</span>{d.scopes.map((s) => <Chip key={s} mono>{s}</Chip>)}</div>
          {d.exceeds_principal.length > 0 && (
            <Callout tone="warn">Holds {d.exceeds_principal.length} permission{d.exceeds_principal.length > 1 ? "s" : ""} its principal does not, for example {d.exceeds_principal.slice(0, 2).join("; ")}.</Callout>
          )}
        </div>
      ))}
      <div className="xs faint">
        {a.effective_permissions} permissions · {a.privileged_permissions} privileged · {a.systems.join(", ")} · last active {ago(a.days_since_activity)}
      </div>
    </div>
  );
}
