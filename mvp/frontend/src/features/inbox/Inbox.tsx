import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Check, ClipboardCheck, Keyboard, KeyRound, ListChecks, Plug, Search, ShoppingCart, X } from "lucide-react";
import { HrisEvent, JitRequest, SimResult, ago, approveRequest, denyRequest, fmtDate, hrisExecute, jitDecide, relTime, reviewDecide, simulate, useApi } from "../../api";
import { usePersona } from "../../app/persona";
import {
  Badge, Button, Callout, EmptyState, FilterChips, Flag, IdLink, Loading, Page, Tone, TypeBadge, useConfirm, useToast,
} from "../../components";
import { isTyping, modalOpen } from "../../components/overlay";
import { STAGE_LABEL, Stages } from "../access/stages";
import { InboxItem, InboxKind, useInbox } from "./model";

const KIND_LABEL: Record<InboxKind, string> = { approval: "Approval", review: "Review", task: "Task", connection: "Connection" };

export function itemTitle(it: InboxItem): { icon: ReactNode; title: string; meta: ReactNode; tone: Tone; kindLabel: string } {
  switch (it.kind) {
    case "approval":
      if (it.source === "jit") {
        const r = it.jit;
        return { icon: <KeyRound size={15} />, title: `${r.identity.name} requests ${r.group.system}:${r.group.name}`, meta: <>{r.duration_hours} h just-in-time · {r.group.privileged && <Badge tone="warning">Privileged</Badge>} {relTime(r.requested_at)}</>, tone: "info", kindLabel: KIND_LABEL.approval };
      }
      {
        const a = it.item, l = a.line;
        return {
          icon: <ShoppingCart size={15} />, title: `${l.beneficiary.name} needs ${l.group.system}:${l.group.name}`, tone: "info", kindLabel: KIND_LABEL.approval,
          meta: <>{STAGE_LABEL[a.kind]} approval{a.on_behalf_of && ` for ${a.on_behalf_of.display_name}`} · asked by {l.requested_by.display_name} {relTime(l.requested_at)}{a.escalated && <> <Badge tone="warning">Escalated</Badge></>}{l.group.privileged && <> <Badge tone="warning">Privileged</Badge></>}</>,
        };
      }
    case "review": {
      const i = it.item;
      return { icon: <ClipboardCheck size={15} />, title: `${i.identity.name}: ${i.grant.split(" → ")[1] ?? i.grant}`, meta: <>{i.reasons.slice(0, 2).map((r) => <Flag key={r} f={r} />)} <span>last used {ago(i.context.days_since_used)}</span></>, tone: "accent", kindLabel: KIND_LABEL.review };
    }
    case "task": {
      const e = it.event;
      const who = e.identity?.name ?? e.payload.name;
      return { icon: <ListChecks size={15} />, title: `${e.type[0].toUpperCase() + e.type.slice(1)}: ${who}`, meta: <>HRIS event {e.external_id} · effective {fmtDate(e.effective_at)}</>, tone: e.type === "leaver" ? "critical" : "neutral", kindLabel: KIND_LABEL.task };
    }
    case "connection":
      return { icon: <Plug size={15} />, title: `${it.conn.name} is degraded`, meta: <>Readiness {it.conn.score} · write-back stopped, reads continue</>, tone: "warning", kindLabel: KIND_LABEL.connection };
  }
}

// --------------------------------------------------------------- detail
function JitDetail({ r }: { r: JitRequest }) {
  const { data: d } = useApi<any>(`/identities/${r.identity.id}`);
  const { data: all } = useApi<JitRequest[]>("/jit/requests");
  const [sim, setSim] = useState<SimResult | null>(null);
  const [simErr, setSimErr] = useState<string | null>(null);
  const acct = d?.accounts.find((a: any) => `${a.system}:${a.username}` === r.account);
  useEffect(() => {
    if (!acct) return;
    let alive = true;
    simulate({ add_edges: [{ src: `account:${acct.id}`, dst: `group:${r.group.id}` }] })
      .then((x) => alive && setSim(x))
      .catch((e) => alive && setSimErr(e.message));
    return () => {
      alive = false;
    };
  }, [acct?.id, r.group.id]);
  const prior = (all ?? []).filter((x) => x.identity.id === r.identity.id && x.group.id === r.group.id && x.id !== r.id);
  return (
    <div className="stack">
      <dl className="kv">
        <dt>Requester</dt><dd><IdLink i={r.identity} /> <TypeBadge type={r.identity.type} /></dd>
        <dt>Access</dt><dd><span className="sys">{r.group.system}:{r.group.name}</span> {r.group.privileged && <Badge tone="warning">Privileged</Badge>}</dd>
        <dt>Duration</dt><dd>{r.duration_hours} hours, removed automatically</dd>
        <dt>Account</dt><dd className="sys">{r.account}</dd>
        <dt>Justification</dt><dd>{r.justification}</dd>
        <dt>Requested</dt><dd>{fmtDate(r.requested_at)}</dd>
      </dl>
      <div>
        <h3 style={{ marginBottom: 8 }}>Usage context</h3>
        {!d ? <Loading kind="block" /> : (
          <div className="stack-sm small">
            <div className="stat-row">
              <div className="s"><b>{d.risk?.effective ?? 0}</b><span>permissions today</span></div>
              <div className="s"><b>{d.risk?.unused ?? 0}</b><span>unused 60 days</span></div>
              <div className="s"><b style={{ color: d.violations.length ? "var(--critical)" : undefined }}>{d.violations.length}</b><span>violations</span></div>
            </div>
            <div className="muted">{prior.length ? `Requested this ${prior.length} time(s) before: ${prior.map((p) => p.status).join(", ")}.` : "First time requesting this access."}</div>
          </div>
        )}
      </div>
      <div>
        <h3 style={{ marginBottom: 8 }}>If approved</h3>
        {simErr ? <div className="err">{simErr}</div> : !sim ? <Loading kind="block" /> : (
          sim.summary.violations_introduced ? (
            <Callout tone="bad">Approving adds {sim.summary.permissions_added} permissions and introduces {sim.summary.violations_introduced} policy violation(s): {sim.violations.introduced.map((v) => v.policy_name).join(", ")}.</Callout>
          ) : (
            <Callout tone="ok">Adds {sim.summary.permissions_added} permission(s) for {r.duration_hours} h. No policy violations introduced.</Callout>
          )
        )}
      </div>
    </div>
  );
}

function ReviewDetail({ it }: { it: Extract<InboxItem, { kind: "review" }> }) {
  const i = it.item, c = i.context;
  return (
    <div className="stack">
      <dl className="kv">
        <dt>Identity</dt><dd><IdLink i={i.identity} /> <TypeBadge type={i.identity.type} /></dd>
        <dt>Access</dt><dd><b>{i.grant.split(" → ")[1]}</b><div className="xs faint sys">via {i.grant.split(" → ")[0]}</div></dd>
        <dt>Why you're seeing it</dt><dd className="row tight">{i.reasons.map((r) => <Flag key={r} f={r} />)}</dd>
        <dt>Reviewer</dt><dd><IdLink i={i.reviewer} /></dd>
        <dt>Campaign</dt><dd>{it.campaign.name}</dd>
      </dl>
      <div>
        <h3 style={{ marginBottom: 8 }}>Usage context</h3>
        <div className="stat-row">
          <div className="s"><b>{c.permissions_used}/{c.permissions}</b><span>permissions used</span></div>
          <div className="s"><b>{c.events_90d}</b><span>events in 90 days</span></div>
          <div className="s"><b>{ago(c.days_since_used)}</b><span>last used</span></div>
          {c.peer_coverage !== null && <div className="s"><b>{Math.round(c.peer_coverage * 100)}%</b><span>of peers hold it</span></div>}
        </div>
      </div>
      {c.violations.length > 0 && <Callout tone="bad">Violates: {c.violations.join("; ")}</Callout>}
      {c.sample_permissions.length > 0 && (
        <div>
          <h3 style={{ marginBottom: 6 }}>Includes</h3>
          {c.sample_permissions.map((p) => <div key={p} className="small sys">{p}</div>)}
        </div>
      )}
      <div className="small muted">
        {c.days_since_used === null || c.days_since_used > 60
          ? "Suggestion: revoke. It hasn't been used recently and can be re-requested if needed."
          : c.violations.length ? "Suggestion: revoke or move to just-in-time access. It's in use but breaks policy." : "Suggestion: keep. It's actively used."}
      </div>
    </div>
  );
}

function TaskDetail({ e }: { e: HrisEvent }) {
  const { data, error } = useApi<any>(`/hris/events/${e.id}/plan`);
  if (!data) return <Loading error={error} kind="block" />;
  const plan = data.plan;
  if (!plan) return <Callout tone="ok">Already executed.</Callout>;
  return (
    <div className="stack">
      {plan.impact && (
        <div className="stat-row">
          <div className="s"><b>{plan.impact.permissions_removed}</b><span>permissions removed</span></div>
          <div className="s"><b>{plan.impact.systems.length}</b><span>systems</span></div>
          <div className="s"><b>{plan.impact.owned_nhis}</b><span>machine identities to re-own</span></div>
        </div>
      )}
      <div>
        <h3 style={{ marginBottom: 8 }}>Plan ({plan.steps.length} steps)</h3>
        <ul className="steps">
          {plan.steps.slice(0, 12).map((s: any, i: number) => (
            <li key={i} className="step"><span className="small grow">{s.detail}</span><span className="chip sys">{s.system}</span></li>
          ))}
        </ul>
        {plan.steps.length > 12 && <Link className="small" to="/governance/lifecycle">See all {plan.steps.length} steps in Lifecycle</Link>}
      </div>
    </div>
  );
}

function Detail({ it }: { it: InboxItem }) {
  const t = itemTitle(it);
  return (
    <div className="card side-panel" aria-live="polite">
      <div className="stack">
        <div>
          <Badge tone={t.tone}>{t.kindLabel}</Badge>
          <h2 style={{ marginTop: 8, fontSize: "var(--fs-lg)" }}>{t.title}</h2>
        </div>
        {it.kind === "approval" && it.source === "jit" && <JitDetail r={it.jit} />}
        {it.kind === "approval" && it.source === "request" && (
          <>
            <dl className="kv">
              <dt>For</dt><dd><Link to={`/directory/identities/${it.item.line.beneficiary.id}`}>{it.item.line.beneficiary.name}</Link></dd>
              <dt>Access</dt><dd className="sys small">{it.item.line.group.system}:{it.item.line.group.name}</dd>
              <dt>Account</dt><dd className="sys small">{it.item.line.account.system}:{it.item.line.account.username}</dd>
              <dt>Requested by</dt><dd>{it.item.line.requested_by.display_name}</dd>
              <dt>Duration</dt><dd>{it.item.line.duration_hours ? `${it.item.line.duration_hours} hours` : "Until removed"}</dd>
              <dt>Justification</dt><dd>{it.item.line.justification}</dd>
              {it.item.on_behalf_of && <><dt>You decide for</dt><dd>{it.item.on_behalf_of.display_name} (delegation)</dd></>}
            </dl>
            <h3>Approval stages</h3>
            <Stages stages={it.item.line.stages} />
          </>
        )}
        {it.kind === "review" && <ReviewDetail it={it} />}
        {it.kind === "task" && <TaskDetail e={it.event} />}
        {it.kind === "connection" && (
          <div className="stack-sm">
            <p className="small muted">A scheduled check failed twice, a credential is close to expiry or sync has failed. Reads continue and data is labelled as coming from a degraded connection; write-back has stopped.</p>
            <Link className="btn" to={`/admin/connections/${it.conn.id}`}>Open the connection</Link>
          </div>
        )}
      </div>
    </div>
  );
}

// -------------------------------------------------------------- actions
type Verb = "approve" | "deny" | "keep" | "revoke" | "run";
const VERBS: Record<InboxKind, { primary: Verb; secondary: Verb }> = {
  approval: { primary: "approve", secondary: "deny" },
  review: { primary: "keep", secondary: "revoke" },
  task: { primary: "run", secondary: "run" },
  connection: { primary: "run", secondary: "run" },
};
const VERB_LABEL: Record<Verb, string> = { approve: "Approve", deny: "Deny", keep: "Keep", revoke: "Revoke", run: "Run plan" };

function useInboxActions() {
  const { me } = usePersona();
  const confirm = useConfirm();
  const toast = useToast();
  const selfRequest = (it: InboxItem) => it.kind === "approval" && it.source === "jit" && it.jit.identity.id === me?.id;

  async function act(it: InboxItem, verb: Verb, opts: { quiet?: boolean; skipConfirm?: boolean } = {}): Promise<boolean> {
    try {
      if (it.kind === "approval") {
        if (selfRequest(it)) {
          toast("You can't approve your own request. Someone else needs to decide.", { kind: "error" });
          return false;
        }
        if (it.source === "jit") await jitDecide(it.jit.id, verb === "approve" ? "approve" : "deny");
        else if (verb === "approve") await approveRequest(it.item.line.id);
        else {
          const reason = await confirm({ title: "Deny this request?", body: itemTitle(it).title, confirmLabel: "Deny", danger: true, reason: { label: "Reason (the requester sees it)", required: true } });
          if (reason === null) return false;
          await denyRequest(it.item.line.id, reason);
        }
        if (!opts.quiet) toast(`${verb === "approve" ? "Approved" : "Denied"}: ${itemTitle(it).title}`);
      } else if (it.kind === "review") {
        let comment: string | undefined;
        if (verb === "revoke" && !opts.skipConfirm) {
          const ok = await confirm({ title: "Revoke this access?", body: `Removes ${it.item.grant} from ${it.item.identity.name}'s effective access now and writes an audit record.`, confirmLabel: "Revoke", danger: true });
          if (ok === null) return false;
        }
        if (verb === "keep" && it.item.context.privileged && !opts.skipConfirm) {
          const reason = await confirm({ title: "Keep privileged access?", body: "Certifying privileged access needs a reason for the audit trail.", confirmLabel: "Keep access", reason: { label: "Reason", required: true, placeholder: "e.g. On-call for payments; usage expected next sprint" } });
          if (reason === null) return false;
          comment = reason;
        }
        await reviewDecide(it.item.id, verb === "revoke" ? "revoke" : "keep", comment);
        if (!opts.quiet) toast(`${verb === "revoke" ? "Revoked" : "Kept"}: ${itemTitle(it).title}`);
      } else if (it.kind === "task") {
        const ok = await confirm({ title: `Run the ${it.event.type} plan?`, body: "Executes every step in the plan against Tessera's graph and writes an audit record. Nothing is written back to source systems yet.", confirmLabel: "Run plan", danger: it.event.type === "leaver" });
        if (ok === null) return false;
        await hrisExecute(it.event.id);
        toast(`Plan executed: ${itemTitle(it).title}`);
      } else if (it.kind === "connection") {
        return false; // opened from its row
      }
      return true;
    } catch (e: any) {
      toast(`Couldn't ${VERB_LABEL[verb].toLowerCase()}: ${e.message}`, { kind: "error" });
      return false;
    }
  }
  return { act, selfRequest };
}

// ----------------------------------------------------------------- page
const FILTERS: { id: "all" | InboxKind; label: string }[] = [
  { id: "all", label: "All" }, { id: "approval", label: "Approvals" }, { id: "review", label: "Reviews" }, { id: "task", label: "Tasks" }, { id: "connection", label: "Connections" },
];

export function Inbox() {
  const { persona } = usePersona();
  const [params, setParams] = useSearchParams();
  const filter = (params.get("filter") ?? "all") as "all" | InboxKind;
  const [scope, setScope] = useState<"mine" | "all">(persona === "admin" ? "all" : "mine");
  const { items, error } = useInbox(scope);
  const [q, setQ] = useState("");
  const [selKey, setSelKey] = useState<string | null>(params.get("item"));
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [help, setHelp] = useState(false);
  const { act, selfRequest } = useInboxActions();
  const confirm = useConfirm();
  const toast = useToast();
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => setScope(persona === "admin" ? "all" : "mine"), [persona]);

  const visible = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (items ?? []).filter((i) => (filter === "all" || i.kind === filter) && (!needle || itemTitle(i).title.toLowerCase().includes(needle)));
  }, [items, filter, q]);
  const counts = useMemo(() => {
    const c: Record<string, number> = { all: items?.length ?? 0 };
    (items ?? []).forEach((i) => (c[i.kind] = (c[i.kind] ?? 0) + 1));
    return c;
  }, [items]);

  const idx = Math.max(0, visible.findIndex((i) => i.key === selKey));
  const current = visible[idx] ?? null;

  useEffect(() => {
    if (visible.length && !visible.some((i) => i.key === selKey)) setSelKey(visible[Math.min(idx, visible.length - 1)].key);
  }, [visible, selKey, idx]);
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
  }, [selKey]);

  const run = async (it: InboxItem, verb: Verb) => {
    if (busy) return;
    const next = visible[idx + 1]?.key ?? visible[idx - 1]?.key ?? null;
    setBusy(true);
    const ok = await act(it, verb);
    setBusy(false);
    if (ok) setSelKey(next);
  };

  const bulk = async (primary: boolean) => {
    const chosen = visible.filter((i) => checked.has(i.key) && i.kind !== "task" && i.kind !== "connection" && !selfRequest(i));
    if (!chosen.length) return;
    const destructive = !primary && chosen.some((i) => i.kind === "review");
    const ok = await confirm({
      title: primary ? `Approve or keep ${chosen.length} items?` : `Deny or revoke ${chosen.length} items?`,
      body: primary ? "Approvals are granted and review items certified. Privileged review items still need individual reasons and are skipped." : "Requests are denied and review items revoked immediately.",
      confirmLabel: primary ? "Apply to all" : "Deny / revoke all",
      danger: destructive,
    });
    if (ok === null) return;
    setBusy(true);
    let n = 0;
    for (const it of chosen) {
      if (primary && it.kind === "review" && it.item.context.privileged) continue;
      if (await act(it, primary ? VERBS[it.kind].primary : VERBS[it.kind].secondary, { quiet: true, skipConfirm: true })) n++;
    }
    setBusy(false);
    setChecked(new Set());
    toast(`${n} item${n === 1 ? "" : "s"} done`);
  };

  // keyboard: j/k or arrows move, a approve/keep, d deny/decline, r revoke, x select, ? help
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isTyping(e) || modalOpen() || e.metaKey || e.ctrlKey || e.altKey) return;
      const k = e.key;
      if (k === "j" || k === "ArrowDown") { e.preventDefault(); const n = visible[Math.min(visible.length - 1, idx + 1)]; if (n) setSelKey(n.key); }
      else if (k === "k" || k === "ArrowUp") { e.preventDefault(); const n = visible[Math.max(0, idx - 1)]; if (n) setSelKey(n.key); }
      else if (k === "?") setHelp((h) => !h);
      else if (!current) return;
      else if (k === "x") setChecked((s) => { const n = new Set(s); if (n.has(current.key)) n.delete(current.key); else n.add(current.key); return n; });
      else if (k === "a") run(current, VERBS[current.kind].primary);
      else if (k === "d" && current.kind === "approval") run(current, VERBS[current.kind].secondary);
      else if (k === "r" && current.kind === "review") run(current, "revoke");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const checkedCount = visible.filter((i) => checked.has(i.key)).length;

  return (
    <Page
      title="Inbox"
      sub="Approvals routed to you (including as a delegate), access reviews and lifecycle tasks in one queue. Decide with the buttons or the keyboard."
      actions={<Button variant="ghost" icon={<Keyboard size={15} />} onClick={() => setHelp(!help)} aria-expanded={help}>Shortcuts</Button>}
    >
      {help && (
        <div className="card small" style={{ marginBottom: 16 }}>
          <div className="row" style={{ gap: 18 }}>
            <span><kbd>J</kbd> <kbd>K</kbd> or <kbd>↑</kbd> <kbd>↓</kbd> move</span>
            <span><kbd>A</kbd> approve / keep / accept / run</span>
            <span><kbd>D</kbd> deny / decline</span>
            <span><kbd>R</kbd> revoke (reviews)</span>
            <span><kbd>X</kbd> select for bulk</span>
            <span><kbd>/</kbd> search</span>
            <span><kbd>?</kbd> toggle this</span>
          </div>
        </div>
      )}
      <div className="spread" style={{ marginBottom: 12, flexWrap: "wrap" }}>
        <FilterChips label="Filter inbox" value={filter} onChange={(v) => setParams(v === "all" ? {} : { filter: v })} options={FILTERS.map((f) => ({ ...f, count: counts[f.id] ?? 0 }))} />
        <div className="row">
          <label className="input-icon">
            <Search size={14} />
            <span className="sr-only">Filter items</span>
            <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter items…" style={{ width: 200 }} />
          </label>
          <select className="input" value={scope} onChange={(e) => setScope(e.target.value as "mine" | "all")} aria-label="Whose items">
            <option value="mine">Assigned to me</option>
            <option value="all">Everyone's</option>
          </select>
        </div>
      </div>

      <div className="split">
        <div className="card flush">
          {checkedCount > 0 && (
            <div className="card-h" role="toolbar" aria-label="Bulk actions">
              <b className="tnum">{checkedCount} selected</b>
              <div className="row tight">
                <Button size="sm" variant="primary" icon={<Check size={14} />} disabled={busy} onClick={() => bulk(true)}>Approve / keep</Button>
                <Button size="sm" variant="danger" icon={<X size={14} />} disabled={busy} onClick={() => bulk(false)}>Deny / revoke</Button>
                <Button size="sm" variant="ghost" onClick={() => setChecked(new Set())}>Clear</Button>
              </div>
            </div>
          )}
          {!items ? <Loading error={error} /> : visible.length === 0 ? (
            <EmptyState title={items.length ? "Nothing matches this filter" : "Inbox zero"} icon={<Check size={18} />} action={scope === "mine" && persona !== "admin" ? <Button size="sm" onClick={() => setScope("all")}>Show everyone's items</Button> : <Link to="/access/request" className="btn sm">Request access</Link>}>
              {items.length ? "Try another filter or clear the search." : scope === "mine" ? "Nothing is assigned to you. Approvals, review items and tasks for you will appear here." : "No open approvals, reviews or tasks. Start an access review from Governance when you're ready."}
            </EmptyState>
          ) : (
            <div ref={listRef} role="listbox" aria-label="Inbox items" aria-activedescendant={current ? `ib-${current.key}` : undefined} tabIndex={0}>
              {visible.map((it) => {
                const t = itemTitle(it);
                const v = VERBS[it.kind];
                const self = selfRequest(it);
                return (
                  <div key={it.key} id={`ib-${it.key}`} role="option" aria-selected={it.key === current?.key} className="qrow" onClick={() => setSelKey(it.key)}>
                    <input type="checkbox" checked={checked.has(it.key)} onClick={(e) => e.stopPropagation()} onChange={() => setChecked((s) => { const n = new Set(s); if (n.has(it.key)) n.delete(it.key); else n.add(it.key); return n; })} aria-label={`Select ${t.title}`} />
                    <span className="q-ic" aria-hidden>{t.icon}</span>
                    <span style={{ minWidth: 0 }}>
                      <span className="q-title truncate" style={{ display: "block" }}>{t.title}</span>
                      <span className="q-meta"><Badge tone={t.tone}>{t.kindLabel}</Badge> {t.meta}</span>
                    </span>
                    <span className="q-actions" onClick={(e) => e.stopPropagation()}>
                      {it.kind === "connection" ? (
                        <Link className="btn sm" to={`/admin/connections/${it.conn.id}`}>Open</Link>
                      ) : it.kind === "task" ? (
                        <Button size="sm" disabled={busy} onClick={() => run(it, "run")} kbd={it.key === current?.key ? "A" : undefined}>Run plan</Button>
                      ) : (
                        <>
                          <Button size="sm" variant="primary" disabled={busy || self} title={self ? "You can't approve your own request" : undefined} onClick={() => run(it, v.primary)} kbd={it.key === current?.key ? "A" : undefined}>{VERB_LABEL[v.primary]}</Button>
                          <Button size="sm" variant={v.secondary === "revoke" ? "danger" : "default"} disabled={busy} onClick={() => run(it, v.secondary)} kbd={it.key === current?.key ? (v.secondary === "revoke" ? "R" : "D") : undefined}>{VERB_LABEL[v.secondary]}</Button>
                        </>
                      )}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
        {current ? <Detail key={current.key} it={current} /> : <div className="card side-panel hide-narrow"><EmptyState title="Select an item">Its details and usage context show here.</EmptyState></div>}
      </div>
    </Page>
  );
}
