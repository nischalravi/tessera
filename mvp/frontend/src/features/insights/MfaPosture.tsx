/**
 * Insights → MFA posture: how strongly each person can authenticate (the strongest method
 * registered in Okta and Entra), coverage per department and per privileged group, passkey
 * enrolment over time, and app and data-platform accounts that bypass SSO or MFA.
 *
 * Every number comes from GET /api/mfa/posture. A system whose methods could not be read
 * (for example a missing Graph scope) is listed as a data gap and its people are "Unknown",
 * never counted as having no MFA.
 */
import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Fingerprint, ShieldAlert } from "lucide-react";
import { MfaAppFinding, MfaClass, MfaCounts, MfaGroup, MfaIdentity, MfaPosture as Posture, fmtDay, mfaPosturePath, useApi } from "../../api";
import { Badge, Callout, DataTable, EmptyState, FilterChips, InsightsTabs, Kpi, Loading, Page, SidePanel, useSelected } from "../../components";
import type { Tone } from "../../components";

const CLASS_LABEL: Record<MfaClass, string> = {
  phishing_resistant: "Phishing-resistant", push_number_match: "Push with number match", push: "Push (no number match)", otp: "OTP",
  sms_voice: "SMS, voice or e-mail", none: "No MFA", unknown: "Unknown",
};
const CLASS_TONE: Record<MfaClass, Tone> = {
  phishing_resistant: "ok", push_number_match: "info", push: "neutral", otp: "warning", sms_voice: "critical", none: "critical", unknown: "outline",
};
const CLASS_RANK: Record<MfaClass, number> = { phishing_resistant: 5, push_number_match: 4, push: 3, otp: 2, sms_voice: 1, none: 0, unknown: -1 };
const ISSUE_LABEL = { local_password: "Local password", no_mfa: "No MFA", sso_not_enforced: "SSO not enforced" } as const;
const KIND_LABEL: Record<string, string> = {
  passkey: "Passkey (FIDO2)", security_key: "Security key", windows_hello: "Windows Hello", certificate: "Certificate", fastpass: "Okta FastPass",
  app_push: "Authenticator push", totp: "Authenticator code", hardware_otp: "Hardware token", sms: "SMS", voice: "Voice call", email: "E-mail code",
};

const ClassBadge = ({ c }: { c: MfaClass }) => <Badge tone={CLASS_TONE[c]}>{CLASS_LABEL[c]}</Badge>;
const pct = (n: number, of: number) => (of > 0 ? `${Math.round((100 * n) / of)}%` : "–");

/** Counts of one group by class, as numbers (never colour alone) with a proportional bar. */
function CoverageTable({ title, rows, empty }: { title: string; rows: MfaGroup[]; empty: string }) {
  const cols: [keyof MfaCounts, string][] = [
    ["phishing_resistant", "Phishing-resistant"], ["push_number_match", "Push + number"], ["push", "Push"], ["otp", "OTP"],
    ["sms_voice", "SMS / voice"], ["no_mfa", "No MFA"], ["unknown", "Unknown"],
  ];
  return (
    <div className="card flush">
      <div className="card-h"><h2>{title}</h2></div>
      {rows.length === 0 ? <EmptyState title="Nothing to show">{empty}</EmptyState> : (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Group</th><th className="num">People</th>{cols.map(([k, l]) => <th key={k} className="num">{l}</th>)}<th>Phishing-resistant share</th></tr></thead>
            <tbody>
              {rows.map((g) => (
                <tr key={g.key}>
                  <td><b>{g.key}</b></td>
                  <td className="num">{g.total}</td>
                  {cols.map(([k]) => <td key={k} className="num">{g[k] || <span className="faint">0</span>}</td>)}
                  <td>
                    <div className="row tight">
                      <div className="bar ok" role="meter" aria-label={`${g.key}: ${pct(g.phishing_resistant, g.total - g.unknown)} phishing-resistant`}
                        aria-valuenow={g.phishing_resistant} aria-valuemin={0} aria-valuemax={Math.max(1, g.total - g.unknown)} style={{ width: 80 }}>
                        <i style={{ width: `${(100 * g.phishing_resistant) / Math.max(1, g.total - g.unknown)}%` }} />
                      </div>
                      <span className="small tnum">{pct(g.phishing_resistant, g.total - g.unknown)}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** Passkey enrolment over time: the daily snapshots as a line, with the first and last value in text. */
function PasskeyTrend({ trend }: { trend: Posture["trend"] }) {
  if (trend.length < 2) {
    return <div className="card"><h2>Passkey enrolment</h2><p className="small muted mt-sm">The trend appears after two daily snapshots. One is stored at each sync that reads authentication methods.</p></div>;
  }
  const W = 560, H = 120, P = 6;
  const max = Math.max(1, ...trend.map((t) => t.passkey_enrolled), ...trend.map((t) => t.total));
  const x = (i: number) => P + (i * (W - 2 * P)) / (trend.length - 1);
  const y = (v: number) => H - P - (v * (H - 2 * P)) / max;
  const line = (f: (t: Posture["trend"][number]) => number) => trend.map((t, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(f(t)).toFixed(1)}`).join(" ");
  const first = trend[0], last = trend[trend.length - 1];
  return (
    <div className="card">
      <div className="spread"><h2>Passkey enrolment</h2><span className="small faint">{fmtDay(first.date)} to {fmtDay(last.date)}</span></div>
      <p className="small mt-sm">
        <b className="tnum">{last.passkey_enrolled}</b> of <span className="tnum">{last.total}</span> people have a passkey or security key
        {" "}(<span className="tnum">{first.passkey_enrolled}</span> on {fmtDay(first.date)}); <b className="tnum">{last.phishing_resistant}</b> have a phishing-resistant method.
      </p>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} role="img" aria-label={`Passkey enrolment rose from ${first.passkey_enrolled} to ${last.passkey_enrolled} people between ${first.date} and ${last.date}`}>
        <path d={line((t) => t.total)} fill="none" stroke="var(--border-strong)" strokeWidth="1.5" strokeDasharray="4 3" />
        <path d={line((t) => t.passkey_enrolled)} fill="none" stroke="var(--accent-line)" strokeWidth="2" />
      </svg>
      <div className="xs faint row tight"><span><b style={{ color: "var(--accent-text)" }}>—</b> with a passkey</span><span>- - everyone</span></div>
    </div>
  );
}

function IdentityPanel({ i, onClose }: { i: MfaIdentity; onClose: () => void }) {
  return (
    <SidePanel title={i.name} sub={<>{i.department}{i.title && ` · ${i.title}`}</>} onClose={onClose} fullHref={`/directory/identities/${i.id}`} fullLabel="Open identity">
      <div className="stack">
        <div className="row"><ClassBadge c={i.best} />{i.privileged && <Badge tone="warning">Privileged</Badge>}{i.passkey && <Badge tone="ok">Passkey enrolled</Badge>}</div>
        {i.best === "unknown" && <Callout tone="neutral">None of this person&apos;s accounts is in a system whose authentication methods Tessera could read, so their MFA is unknown. Check the data sources above.</Callout>}
        {i.best === "none" && <Callout tone="warn">The identity provider reports no registered authentication method for this person.</Callout>}
        {i.privileged && i.best !== "phishing_resistant" && i.best !== "unknown" && <Callout tone="warn">Privileged access without a phishing-resistant method. A policy of type <code>mfa_required</code> turns this into a violation.</Callout>}
        {i.privileged && (
          <section>
            <h3>Why privileged</h3>
            <ul className="small">{i.privileged_via.map((v) => <li key={v}>{v}</li>)}</ul>
          </section>
        )}
        <section>
          <h3>Registered methods <span className="faint tnum">({i.methods.length})</span></h3>
          {i.methods.length === 0 ? <p className="small muted">None.</p> : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Method</th><th>Class</th><th>System</th><th>Enrolled</th></tr></thead>
                <tbody>
                  {i.methods.map((m, k) => (
                    <tr key={k}>
                      <td>{KIND_LABEL[m.kind] ?? m.kind}{m.label && <div className="xs faint">{m.label}</div>}</td>
                      <td><ClassBadge c={m.strength} /></td>
                      <td className="small sys">{m.system}</td>
                      <td className="small nowrap">{m.enrolled_at ? fmtDay(m.enrolled_at) : "–"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section>
          <h3>Read from</h3>
          <p className="small">{i.systems.length ? i.systems.join(", ") : "No connected identity provider."}</p>
        </section>
      </div>
    </SidePanel>
  );
}

function AppFindings({ findings, systems }: { findings: MfaAppFinding[]; systems: Posture["app_systems"] }) {
  const silent = systems.filter((s) => s.with_signals === 0);
  return (
    <div className="card flush">
      <div className="card-h"><h2>Apps and data platforms that bypass SSO or MFA</h2><span className="small faint">Only what each connector reports is judged</span></div>
      {systems.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead><tr><th>System</th><th className="num">Active accounts</th><th className="num">With sign-in facts</th><th className="num">Flagged</th></tr></thead>
            <tbody>
              {systems.map((s) => (
                <tr key={s.system}>
                  <td className="sys">{s.system}</td><td className="num">{s.accounts}</td>
                  <td className="num">{s.with_signals || <span className="faint">0, not reported</span>}</td><td className="num">{s.flagged}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {silent.length > 0 && <div style={{ padding: "var(--s-3)" }}><Callout tone="neutral">{silent.map((s) => s.system).join(", ")} report no password, MFA or SSO facts yet, so nothing can be said about them. This is a data gap, not a clean result.</Callout></div>}
      {findings.length === 0 ? <EmptyState title="No bypass found">No account that reported its sign-in facts has a local password, no MFA or SSO not enforced.</EmptyState> : (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Account</th><th>Person</th><th>Finding</th></tr></thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.account_id}>
                  <td><span className="sys">{f.username}</span><div className="xs faint">{f.system}</div></td>
                  <td>{f.identity_id ? <Link to={`/directory/identities/${f.identity_id}`}>{f.identity_name || `Identity ${f.identity_id}`}</Link> : <span className="faint">Unmatched</span>}{f.privileged && <> <Badge tone="warning">Privileged</Badge></>}</td>
                  <td><div className="row tight">{f.issues.map((x) => <Badge key={x} tone={x === "no_mfa" ? "critical" : "warning"}>{ISSUE_LABEL[x]}</Badge>)}</div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function MfaPosture() {
  const [params, setParams] = useSearchParams();
  const department = params.get("department") ?? "";
  const privRaw = params.get("privileged");
  const privileged = privRaw === "true" || privRaw === "false" ? privRaw : "";
  const setFilter = (k: string, v: string) =>
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (v) next.set(k, v);
      else next.delete(k);
      next.delete("selected");
      return next;
    }, { replace: true });
  const { data, error } = useApi<Posture>(mfaPosturePath(department, privileged));
  const [selected, setSelected] = useSelected();
  const sel = useMemo(() => data?.identities.find((i) => String(i.id) === selected) ?? null, [data, selected]);
  const crumbs: [string, string?][] = [["Protection"], ["Insights", "/insights"], ["MFA posture"]];
  const sub = "The strongest authentication method each person has registered in Okta and Entra, by department and privileged group. Phishing-resistant means a passkey, security key, Windows Hello, certificate or Okta FastPass.";
  if (!data) return <Page tabs={<InsightsTabs />} title="MFA posture" crumbs={crumbs} sub={sub}><Loading error={error} kind="page" /></Page>;

  const t = data.summary.totals;
  const covered = t.total - t.unknown;
  const priv = data.summary.privileged_totals;
  const privWeak = priv.total - priv.unknown - priv.phishing_resistant;
  const unavailable = data.sources.filter((s) => s.status !== "ok");
  return (
    <Page tabs={<InsightsTabs />} title="MFA posture" crumbs={crumbs} sub={sub} count={`${t.total} people`}>
      <div className="stack">
        {data.sources.length === 0 && <Callout tone="warn">No connected identity provider has reported authentication methods yet. Connect Okta or Entra, or turn on <code>TESSERA_OKTA_AUTH_METHODS</code> / <code>TESSERA_ENTRA_AUTH_METHODS</code>; until then every person is Unknown.</Callout>}
        {unavailable.map((s) => <Callout key={s.system} tone="warn"><b>{s.system}</b>: authentication methods could not be read. {s.detail} People in this system show as Unknown until a sync succeeds.</Callout>)}
        <div className="stack-sm">
          <FilterChips label="Department" value={department} onChange={(v) => setFilter("department", v)}
            options={[{ id: "", label: "All departments" }, ...data.departments.map((d) => ({ id: d, label: d }))]} />
          <FilterChips label="Privileged" value={privileged} onChange={(v) => setFilter("privileged", v)}
            options={[{ id: "", label: "Everyone" }, { id: "true", label: "Privileged" }, { id: "false", label: "Not privileged" }]} />
        </div>
        <div className="grid g4">
          <Kpi label="Phishing-resistant" icon={<Fingerprint size={14} aria-hidden />} value={pct(t.phishing_resistant, covered)} sub={`${t.phishing_resistant} of ${covered} people with known MFA`} />
          <Kpi label="Passkey enrolled" value={t.passkey_enrolled} sub={`${pct(t.passkey_enrolled, covered)} of people with known MFA`} />
          <Kpi label="No MFA registered" value={t.no_mfa} tone={t.no_mfa ? "critical" : undefined} sub={t.unknown ? `${t.unknown} more are unknown` : "Every person is covered"} />
          <Kpi label="Privileged without phishing-resistant" icon={<ShieldAlert size={14} aria-hidden />} value={privWeak} tone={privWeak ? "warning" : undefined} sub={`of ${priv.total - priv.unknown} privileged people with known MFA`} />
        </div>
        <div className="grid g2">
          <CoverageTable title="By department" rows={data.summary.by_department} empty="No people match the filters." />
          <CoverageTable title="By privileged group" rows={data.summary.by_privileged_group} empty="Nobody in the selection is in a privileged group." />
        </div>
        <PasskeyTrend trend={data.trend} />
        <DataTable<MfaIdentity>
          id="mfa-identities"
          rows={data.identities}
          rowKey={(r) => r.id}
          activeKey={selected}
          onRowClick={(r) => setSelected(r.id)}
          rowLabel={(r) => r.name}
          initialSort={["best", 1]}
          columns={[
            { id: "name", header: "Person", sort: (r) => r.name, cell: (r) => <div><b className="name-link">{r.name}</b><div className="xs faint">{r.title}</div></div> },
            { id: "dept", header: "Department", sort: (r) => r.department, cell: (r) => r.department, hideNarrow: true },
            { id: "priv", header: "Privileged", sort: (r) => (r.privileged ? 0 : 1), csv: (r) => (r.privileged ? "yes" : "no"), cell: (r) => (r.privileged ? <Badge tone="warning">Privileged</Badge> : <span className="faint">–</span>) },
            { id: "best", header: "Strongest method", sort: (r) => CLASS_RANK[r.best], csv: (r) => CLASS_LABEL[r.best], cell: (r) => <ClassBadge c={r.best} /> },
            { id: "passkey", header: "Passkey", sort: (r) => (r.passkey ? 0 : 1), csv: (r) => (r.passkey ? "yes" : "no"), cell: (r) => (r.passkey ? <Badge tone="ok">Yes</Badge> : <span className="faint">No</span>), hideNarrow: true },
            { id: "methods", header: "Methods", num: true, sort: (r) => r.methods.length, cell: (r) => r.methods.length, hideNarrow: true },
          ]}
          filters={[
            { id: "best", label: "Strongest method", options: (Object.keys(CLASS_LABEL) as MfaClass[]).map((c) => ({ value: c, label: CLASS_LABEL[c] })), get: (r) => r.best },
          ]}
          chips={1}
          searchText={(r) => `${r.name} ${r.department} ${r.title} ${r.privileged_groups.join(" ")}`}
          searchPlaceholder="Search people, departments, groups"
          empty={<EmptyState title="No people match">Change the department or privileged filter.</EmptyState>}
        />
        <AppFindings findings={data.app_findings} systems={data.app_systems} />
        <p className="xs faint">As of {fmtDay(data.as_of)}.</p>
      </div>
      {sel && <IdentityPanel i={sel} onClose={() => setSelected(null)} />}
    </Page>
  );
}
