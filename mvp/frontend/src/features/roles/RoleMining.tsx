/**
 * Role mining (issue #298): business roles suggested from the access people hold. A run clusters
 * people by the entitlements they hold, deterministically, and lists candidate roles with who holds
 * all of it, who holds extra, the attribute that best predicts membership (a suggested birthright
 * rule) and a confidence. Accepting a candidate creates a draft role (no members, no rule, not
 * requestable): it grants and removes nothing, and assignment follows the usual role flows.
 */
import { ReactNode, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Check, Pencil, Play, X } from "lucide-react";
import {
  IdentityRow, MiningCandidate, MiningParams, MiningRun, MiningRunDetail, MiningRunsView, Risk,
  fmtDate, miningPaths, relTime, roleMining, useApi,
} from "../../api";
import { confidenceTone, ruleLabel } from "./miningModel";
import {
  Badge, Button, Callout, CommandBar, DataTable, Drawer, EmptyState, Loading, Page, RoleTabs, SidePanel, Tabs, useSelected, useToast,
} from "../../components";

const I = 16;
const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const gname = (g: { system: string; name: string }) => `${g.system}:${g.name}`;
const TYPES: [string, string][] = [["human", "People"], ["service", "Service accounts"], ["ai_agent", "AI agents"]];

const STATUS_LABEL: Record<MiningCandidate["status"], string> = { open: "Open", accepted: "Accepted", dismissed: "Dismissed" };
const statusTone = (s: MiningCandidate["status"]) => (s === "accepted" ? "ok" : s === "dismissed" ? "neutral" : "info");
const RUN_TONE: Record<MiningRun["status"], "ok" | "info" | "critical"> = { queued: "info", running: "info", succeeded: "ok", failed: "critical" };

function toggle<T>(list: T[], v: T): T[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
}

// ------------------------------------------------------------------- page
export function RoleMining() {
  const { data: view, error, reload: reloadRuns } = useApi<MiningRunsView>(miningPaths.runs);
  const [picked, setPicked] = useState<string | null>(null);
  const [selected, setSelected] = useSelected();
  const runId = picked ?? view?.runs[0]?.id ?? null;
  const { data: detail, error: detailError, reload } = useApi<MiningRunDetail>(runId ? miningPaths.run(runId) : null);
  const status = detail?.run.status;
  // a queued run is computed by the job queue: look again until it finishes
  useEffect(() => {
    if (status !== "queued" && status !== "running") return;
    const t = setInterval(() => {
      reload();
      reloadRuns();
    }, 2500);
    return () => clearInterval(t);
  }, [status, reload, reloadRuns]);
  const rows = detail?.run.status === "succeeded" ? detail.candidates : detail ? [] : null;
  const open = rows?.find((c) => c.id === selected);
  const refresh = () => {
    reload();
    reloadRuns();
  };
  return (
    <Page title="Role mining" count={rows ? plural(rows.length, "candidate") : null} crumbs={[["Identity"], ["Roles", "/directory/roles"], ["Mining"]]} tabs={<RoleTabs />}
      sub="Suggests business roles from the access people hold today. Accepting a candidate creates a draft role; it never grants or removes access.">
      <div className="stack">
        {view && <RunForm view={view} busy={status === "queued" || status === "running"} onStarted={(r) => { setPicked(r.id); setSelected(null); reloadRuns(); }} />}
        {detail && <RunSummary detail={detail} runs={view?.runs ?? []} picked={runId} onPick={(id) => { setPicked(id); setSelected(null); }} />}
        <DataTable
          id="role-mining"
          rows={rows}
          error={error ?? detailError}
          rowKey={(c) => c.id}
          columns={[
            { id: "name", header: "Candidate", sort: (c) => c.rank, cell: (c) => <div><span className="name-link">{c.name}</span><div className="xs faint">#{c.rank}{c.similar_role && <> · {c.similarity}% like {c.similar_role.name}</>}</div></div> },
            { id: "coverage", header: "Coverage", num: true, sort: (c) => c.coverage, csv: (c) => String(c.coverage), cell: (c) => <span title={`${c.outlier_count} with extra access`}>{c.coverage}{c.outlier_count > 0 && <span className="xs faint"> · {c.outlier_count} extra</span>}</span> },
            { id: "ents", header: "Entitlements", sort: (c) => c.entitlements.length, csv: (c) => c.entitlements.map(gname).join("; "), cell: (c) => <div className="small"><b>{c.entitlements.length}</b><div className="xs faint truncate" style={{ maxWidth: 280 }}>{c.entitlements.map(gname).join(", ")}</div></div>, hideNarrow: true },
            { id: "rule", header: "Suggested rule", sort: (c) => ruleLabel(c.rule) ?? "", csv: (c) => ruleLabel(c.rule) ?? "", cell: (c) => (c.rule ? <Badge tone="outline" title={`${c.rule.precision}% of people with it hold the role; ${c.rule.recall}% of holders match`}>{ruleLabel(c.rule)}</Badge> : <span className="faint">None fits</span>), hideNarrow: true },
            { id: "conf", header: "Confidence", num: true, sort: (c) => c.confidence, csv: (c) => String(c.confidence), cell: (c) => <Badge tone={confidenceTone(c.confidence)} dot>{c.confidence}%</Badge> },
            { id: "status", header: "Decision", sort: (c) => c.status, csv: (c) => c.status, cell: (c) => <Badge tone={statusTone(c.status)}>{STATUS_LABEL[c.status]}</Badge> },
          ]}
          searchText={(c) => `${c.name} ${c.entitlements.map(gname).join(" ")} ${ruleLabel(c.rule) ?? ""}`}
          searchPlaceholder="Search candidates or their entitlements…"
          filters={[{ id: "status", label: "Decision", options: (["open", "accepted", "dismissed"] as const).map((v) => ({ value: v, label: STATUS_LABEL[v] })), get: (c) => c.status }]}
          onRefresh={refresh}
          rowLabel={(c) => c.name}
          onRowClick={(c) => setSelected(c.id)}
          activeKey={selected}
          empty={<EmptyState title={detail ? (detail.run.status === "succeeded" ? "No candidates" : "No results yet") : "No runs yet"}>
            {detail ? (detail.run.status === "succeeded" ? "Nothing met the settings. Lower the minimum members or similarity, or widen the filters." : "The run has not finished.") : "Run mining to see suggested roles."}
          </EmptyState>}
        />
      </div>
      {open && view && <CandidatePanel id={open.id} canManage={view.can_manage} onClose={() => setSelected(null)} onChanged={refresh} />}
    </Page>
  );
}

// ------------------------------------------------------------------- run
function RunForm({ view, busy, onStarted }: { view: MiningRunsView; busy: boolean; onStarted: (r: MiningRun) => void }) {
  const { data: people } = useApi<IdentityRow[]>("/identities?status=active");
  const toast = useToast();
  const [p, setP] = useState<MiningParams>(view.defaults);
  const [titles, setTitles] = useState("");
  const [working, setWorking] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const depts = useMemo(() => [...new Set((people ?? []).map((x) => x.department).filter((d): d is string => !!d))].sort(), [people]);
  const num = (k: keyof MiningParams) => (e: { target: { value: string } }) => setP((s) => ({ ...s, [k]: Number(e.target.value) }));
  const run = async () => {
    setWorking(true);
    setErr(null);
    try {
      const r = await roleMining.start({ ...p, title: titles.split(",").map((t) => t.trim()).filter(Boolean) });
      toast(r.status === "succeeded" ? `Found ${plural(r.candidates, "candidate")}` : "Run queued");
      onStarted(r);
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setWorking(false);
    }
  };
  return (
    <section className="card stack" aria-labelledby="mining-params">
      <h2 id="mining-params" className="h3">Run settings</h2>
      <div className="grid g2">
        <fieldset className="field stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="small">Departments (none: everyone)</legend>
          <div className="row tight">{depts.map((d) => <label key={d} className="row tight small"><input type="checkbox" checked={p.department.includes(d)} onChange={() => setP((s) => ({ ...s, department: toggle(s.department, d) }))} /> {d}</label>)}</div>
        </fieldset>
        <fieldset className="field stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="small">Identity types (none: all)</legend>
          <div className="row tight">{TYPES.map(([v, l]) => <label key={v} className="row tight small"><input type="checkbox" checked={p.type.includes(v)} onChange={() => setP((s) => ({ ...s, type: toggle(s.type, v) }))} /> {l}</label>)}</div>
        </fieldset>
      </div>
      <label className="field small">Job titles (comma separated, exact; none: all)<input className="input" value={titles} onChange={(e) => setTitles(e.target.value)} placeholder="e.g. Software Engineer, Senior Software Engineer" /></label>
      <div className="grid g2">
        <label className="field small">Minimum people holding it<input className="input" type="number" min={2} max={1000} value={p.min_members} onChange={num("min_members")} /></label>
        <label className="field small">Minimum entitlements in a role<input className="input" type="number" min={2} max={50} value={p.min_entitlements} onChange={num("min_entitlements")} /></label>
        <label className="field small">Similarity to group people (%)<input className="input" type="number" min={30} max={100} value={p.min_similarity} onChange={num("min_similarity")} /></label>
        <label className="field small">Most candidates to list<input className="input" type="number" min={1} max={100} value={p.max_candidates} onChange={num("max_candidates")} /></label>
      </div>
      {err && <Callout tone="bad">{err}</Callout>}
      <div className="row">
        <Button variant="primary" icon={<Play size={I} />} onClick={run} disabled={!view.can_manage || busy || working}>{busy ? "Run in progress…" : "Run mining"}</Button>
        {!view.can_manage && <span className="xs faint">Policy admins run mining.</span>}
        <span className="xs faint">Same data and settings always give the same candidates. Large tenants run as a background job.</span>
      </div>
    </section>
  );
}

function RunSummary({ detail, runs, picked, onPick }: { detail: MiningRunDetail; runs: MiningRun[]; picked: string | null; onPick: (id: string) => void }) {
  const r = detail.run;
  const p = r.params;
  const filters = [p.department.length && `departments: ${p.department.join(", ")}`, p.title.length && `titles: ${p.title.join(", ")}`, p.type.length && `types: ${p.type.join(", ")}`].filter(Boolean).join("; ");
  return (
    <section className="card stack-sm" aria-label="Latest run">
      <div className="row">
        <Badge tone={RUN_TONE[r.status]} dot>{r.status[0].toUpperCase() + r.status.slice(1)}</Badge>
        <span className="small" title={fmtDate(r.created_at)}>{relTime(r.created_at)} by {r.requested_by}</span>
        {runs.length > 1 && (
          <label className="row tight small">Run
            <select className="input" value={picked ?? ""} onChange={(e) => onPick(e.target.value)}>
              {runs.map((x) => <option key={x.id} value={x.id}>{fmtDate(x.created_at)} · {x.status === "succeeded" ? plural(x.candidates, "candidate") : x.status}</option>)}
            </select>
          </label>
        )}
      </div>
      <dl className="kv">
        <dt>Mined</dt><dd>{plural(r.people, "person", "people")}, {plural(r.entitlements, "entitlement")}{filters ? `; ${filters}` : ""}</dd>
        <dt>Settings</dt><dd className="small">at least {p.min_members} people, {p.min_entitlements} entitlements, {p.min_similarity}% similar, up to {p.max_candidates} candidates</dd>
        <dt>Snapshot</dt><dd className="small"><code title={r.snapshot_hash}>{r.snapshot_hash ? r.snapshot_hash.slice(0, 16) : "pending"}</code> <span className="xs faint">({r.algorithm})</span></dd>
      </dl>
      {r.truncated && <Callout tone="warn">This run hit its size or time bound and looked at part of the data. Narrow it with a filter for a complete result.</Callout>}
      {r.skipped_existing > 0 && <p className="xs faint">{plural(r.skipped_existing, "pattern")} already match an existing role and are not listed.</p>}
      {r.status === "failed" && <Callout tone="bad">{r.error || "The run failed."}</Callout>}
      {(r.status === "queued" || r.status === "running") && <p className="small" role="status">The run is {r.status}. This page updates when it finishes.</p>}
    </section>
  );
}

// ------------------------------------------------------------------- panel
type PanelTab = "overview" | "members" | "outliers";

function CandidatePanel({ id, canManage, onClose, onChanged }: { id: string; canManage: boolean; onClose: () => void; onChanged: () => void }) {
  const { data: c, error, reload } = useApi<MiningCandidate>(miningPaths.candidate(id));
  const [tab, setTab] = useState<PanelTab>("overview");
  const [drawer, setDrawer] = useState<null | "accept" | "edit" | "dismiss">(null);
  useEffect(() => setTab("overview"), [id]);
  if (!c) return error ? <SidePanel title="Candidate" onClose={onClose}><Loading error={error} kind="block" /></SidePanel> : null;
  const decide = !!canManage && c.status === "open";
  const done = () => {
    setDrawer(null);
    reload();
    onChanged();
  };
  return (
    <>
      <SidePanel
        title={c.name}
        sub={<><Badge tone={confidenceTone(c.confidence)} dot>{c.confidence}% confidence</Badge><Badge tone={statusTone(c.status)}>{STATUS_LABEL[c.status]}</Badge></>}
        onClose={onClose}
        commands={<CommandBar label={`Actions for ${c.name}`} items={[
          decide && { label: "Accept", icon: <Check size={I} />, onClick: () => setDrawer("accept"), title: "Create a draft role from this candidate" },
          decide && { label: "Edit and accept", icon: <Pencil size={I} />, onClick: () => setDrawer("edit") },
          decide && { label: "Dismiss", icon: <X size={I} />, danger: true, onClick: () => setDrawer("dismiss") },
        ]} />}
        tabs={<Tabs label="Candidate details" value={tab} onChange={setTab} tabs={[
          { id: "overview", label: "Overview" },
          { id: "members", label: `Members (${c.coverage})` },
          { id: "outliers", label: `Extra access (${c.outlier_count})` },
        ]} />}
      >
        <CandidateBody c={c} tab={tab} />
      </SidePanel>
      {(drawer === "accept" || drawer === "edit") && <AcceptDrawer c={c} edit={drawer === "edit"} onClose={() => setDrawer(null)} onDone={done} />}
      {drawer === "dismiss" && <DismissDrawer c={c} onClose={() => setDrawer(null)} onDone={done} />}
    </>
  );
}

function CandidateBody({ c, tab }: { c: MiningCandidate; tab: PanelTab }): ReactNode {
  if (tab === "members") {
    return !c.members ? <Loading kind="block" /> : (
      <table>
        <thead><tr><th>Person</th><th>Type</th></tr></thead>
        <tbody>{c.members.map((m) => <tr key={m.id}><td><Link to={`/directory/identities/${m.id}`}>{m.name}</Link></td><td className="small">{m.type.replace(/_/g, " ")}</td></tr>)}</tbody>
      </table>
    );
  }
  if (tab === "outliers") {
    return !c.outliers ? <Loading kind="block" /> : c.outliers.length === 0 ? (
      <EmptyState title="No extra access">Everyone who holds this set holds little beyond it.</EmptyState>
    ) : (
      <div className="stack-sm">
        <p className="small muted">These people hold the whole set and also entitlements few of the others have. Review them before assigning the role.</p>
        <table>
          <thead><tr><th>Person</th><th>Also holds</th></tr></thead>
          <tbody>{c.outliers.map((o) => <tr key={o.person.id}><td><Link to={`/directory/identities/${o.person.id}`}>{o.person.name}</Link></td><td className="small sys">{o.extra.map(gname).join(", ")}</td></tr>)}</tbody>
        </table>
      </div>
    );
  }
  return (
    <div className="stack">
      <dl className="kv">
        <dt>Held by</dt><dd>{plural(c.coverage, "person", "people")}, {c.outlier_count} with extra access</dd>
        <dt>Suggested rule</dt>
        <dd>{c.rule ? <>{ruleLabel(c.rule)} <span className="xs faint">({c.rule.precision}% of people with it hold the set; {c.rule.recall}% of holders match)</span></> : <span className="faint">No attribute predicts it well; assign by request or by hand.</span>}</dd>
        <dt>Confidence</dt><dd><Badge tone={confidenceTone(c.confidence)}>{c.confidence}%</Badge> <span className="xs faint">how well the rule predicts members, how alike the members are ({c.cohesion}%), how many there are</span></dd>
        {c.similar_role && <><dt>Similar role</dt><dd><Link to={`/directory/roles/${c.similar_role.id}`}>{c.similar_role.name}</Link> <span className="xs faint">({c.similarity}% overlap)</span></dd></>}
        {c.status !== "open" && <><dt>Decision</dt><dd>{STATUS_LABEL[c.status]}{c.decided_by && ` by ${c.decided_by}`}{c.decided_at && <> <span className="faint" title={fmtDate(c.decided_at)}>{relTime(c.decided_at)}</span></>}</dd></>}
        {c.decision_reason && <><dt>Reason</dt><dd>{c.decision_reason}</dd></>}
        {c.role_id && <><dt>Role</dt><dd><Link to={`/directory/roles/${c.role_id}`}>Open the draft role</Link></dd></>}
      </dl>
      <section aria-labelledby="cand-ents" className="stack-sm">
        <h3 id="cand-ents">Entitlements ({c.entitlements.length})</h3>
        <ul className="stack-sm">
          {c.entitlements.map((g) => <li key={g.id}><Link className="sys" to={`/directory/entitlements/${g.id}`}>{gname(g)}</Link>{g.privileged && <> <Badge tone="warning">Privileged</Badge></>}</li>)}
        </ul>
      </section>
    </div>
  );
}

// ------------------------------------------------------------------- decisions
function AcceptDrawer({ c, edit, onClose, onDone }: { c: MiningCandidate; edit: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [name, setName] = useState(c.name);
  const [description, setDescription] = useState("");
  const [risk, setRisk] = useState<Risk | "">("");
  const [picked, setPicked] = useState<number[]>(c.entitlements.map((g) => g.id));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const ready = name.trim() !== "" && picked.length > 0;
  const go = async () => {
    setBusy(true);
    setErr(null);
    try {
      const body = edit ? { name: name.trim(), description: description.trim() || undefined, risk: risk || undefined, entitlement_group_ids: picked } : {};
      const res = await roleMining.accept(c.id, body);
      toast(`Draft role “${res.role.name}” created. Nobody has it yet.`);
      onDone();
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={edit ? `Edit and accept ${c.name}` : `Accept ${c.name}`} onClose={onClose} wide
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" onClick={go} disabled={!ready || busy}>Create draft role</Button></>}>
      <div className="stack">
        <Callout tone="info">This creates a business role with no members, no birthright rule and not requestable. It grants and removes no access. Assign people, add the rule or publish it from Roles; those steps follow the usual approval rules.</Callout>
        {edit ? (
          <>
            <label className="field">Name<input className="input" data-autofocus value={name} onChange={(e) => setName(e.target.value)} maxLength={120} /></label>
            <label className="field">Description (optional)<textarea className="input" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Leave empty for a description of how it was mined" /></label>
            <label className="field">Risk
              <select className="input" value={risk} onChange={(e) => setRisk(e.target.value as Risk | "")}>
                <option value="">Automatic (high when it holds a privileged entitlement)</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option>
              </select>
            </label>
            <fieldset className="field stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
              <legend>Entitlements ({picked.length} of {c.entitlements.length})</legend>
              <div className="card flush">
                {c.entitlements.map((g) => (
                  <label key={g.id} className="row small" style={{ padding: "6px 12px", borderBottom: "1px solid var(--border)", flexWrap: "nowrap" }}>
                    <input type="checkbox" checked={picked.includes(g.id)} onChange={() => setPicked((s) => toggle(s, g.id))} />
                    <span className="sys grow">{gname(g)}</span>
                    {g.privileged && <Badge tone="warning">Privileged</Badge>}
                  </label>
                ))}
              </div>
              <p className="xs faint">You can drop entitlements here; add more by editing the role afterwards.</p>
            </fieldset>
          </>
        ) : (
          <dl className="kv">
            <dt>Name</dt><dd>{c.name}</dd>
            <dt>Entitlements</dt><dd>{plural(c.entitlements.length, "entitlement")}</dd>
            <dt>Held by</dt><dd>{plural(c.coverage, "person", "people")} today</dd>
            {c.rule && <><dt>Suggested rule</dt><dd>{ruleLabel(c.rule)} (not applied)</dd></>}
          </dl>
        )}
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}

function DismissDrawer({ c, onClose, onDone }: { c: MiningCandidate; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [why, setWhy] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const go = async () => {
    setBusy(true);
    setErr(null);
    try {
      await roleMining.dismiss(c.id, why.trim());
      toast("Candidate dismissed");
      onDone();
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer title={`Dismiss ${c.name}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="danger-solid" onClick={go} disabled={!why.trim() || busy}>Dismiss</Button></>}>
      <div className="stack">
        <p className="muted">The candidate stays in this run as dismissed, with your reason, and is recorded in the audit log.</p>
        <label className="field">Reason (kept in the audit log)<textarea className="input" data-autofocus value={why} onChange={(e) => setWhy(e.target.value)} maxLength={500} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}
