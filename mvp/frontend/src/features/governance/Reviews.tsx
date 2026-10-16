import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Ban, Check, ClipboardCheck, Network, Plus, UserRound, X } from "lucide-react";
import { ReviewSchedules } from "./ReviewSchedules";
import { Campaign as CampaignT, IdentityRow, ReviewItem, RuleAction, ago, fmtDate, reviewDecide, useApi } from "../../api";
import { useIdentityActions } from "../../app/actions";
import { Badge, Bar, Button, CommandBar, DataTable, EmptyState, FilterChips, Flag, IdLink, Loading, Page, Segmented, SidePanel, Tabs, TypeBadge, flagLabel, useConfirm, useConfirmChoice, useSelected, useToast, GovernanceTabs } from "../../components";

const SOURCE_LABEL = { rule: "Birthright rule", request: "Approved request", manual: "Assigned by hand" } as const;

/** What an item is about: a grant (account, target), or a business-role membership (role, source). */
function accessOf(it: ReviewItem): { title: string; sub: string; membership: boolean } {
  if (it.kind === "membership" && it.role) {
    const n = it.context.membership?.grants.length ?? 0;
    return { title: `${it.role.name} (role)`, sub: `${SOURCE_LABEL[it.member_source ?? "manual"]} · ${n} grant${n === 1 ? "" : "s"}`, membership: true };
  }
  const [a, g] = it.grant.split(" → ");
  return { title: g ?? it.grant, sub: a ?? "", membership: false };
}

function useDecide() {
  const toast = useToast();
  const confirm = useConfirm();
  const choose = useConfirmChoice();
  return async (it: ReviewItem, decision: "keep" | "revoke") => {
    const { title: grant, membership } = accessOf(it);
    let comment: string | undefined;
    let action: RuleAction | undefined;
    if (decision === "revoke" && membership && it.member_source === "rule") {
      // the rule still matches them: removing the membership alone would be undone, so the reviewer chooses
      const r = await choose({
        title: `Revoke ${grant} for ${it.identity.name}?`,
        body: `A birthright rule assigns this role and still matches ${it.identity.name}. Choose what your decision does.`,
        confirmLabel: "Revoke", danger: true,
        choice: { label: "Rule member", options: [
          { value: "exclude", label: "Exclude from the rule", hint: "Removes the role and the grants only it justifies. The rule skips them from now on; the exclusion list is versioned and audited." },
          { value: "flag", label: "Flag the rule to the role owner", hint: "Nothing is removed. The owner is told the rule gives this person access you do not accept." },
        ] },
        reason: { label: "Comment (optional)", placeholder: "Why it should go" },
      });
      if (r === null) return false;
      comment = r.reason;
      action = r.choice as RuleAction;
    } else if (decision === "revoke") {
      const body = membership
        ? `Removes the role from ${it.identity.name} as soon as you confirm, with the grants only it justified. The change is recorded with your name.`
        : `Removes it from ${it.identity.name} as soon as you confirm. The change is recorded with your name.`;
      const r = await confirm({ title: `Revoke ${grant}?`, body, confirmLabel: "Revoke", danger: true, reason: { label: "Comment (optional)", placeholder: "Why it should go" } });
      if (r === null) return false;
      comment = r;
    }
    try {
      await reviewDecide(it.id, decision, comment, action);
      toast(decision === "keep" ? `Kept ${grant} for ${it.identity.name}` : action === "flag" ? `Flagged the rule for ${grant} to its owner` : `Revoked ${grant} from ${it.identity.name}`);
      return true;
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
      return false;
    }
  };
}

function ItemPanel({ it, onClose }: { it: ReviewItem; onClose: () => void }) {
  const decide = useDecide();
  const nav = useNavigate();
  const { title: grant, sub: acct, membership } = accessOf(it);
  const c = it.context;
  const m = c.membership;
  return (
    <SidePanel
      title={grant}
      sub={<><span>{it.identity.name}</span><TypeBadge type={it.identity.type} />{it.decision && <Badge tone={it.decision === "revoke" ? "critical" : "ok"}>{it.decision === "revoke" ? (it.resolution === "flag" ? "Flagged" : "Revoked") : "Kept"}</Badge>}</>}
      onClose={onClose}
      fullHref={`/directory/identities/${it.identity.id}`}
      fullLabel={`Open ${it.identity.name}'s full page`}
      commands={
        <CommandBar
          label="Decision"
          items={[
            { label: "Keep", icon: <Check size={16} />, disabled: !!it.decision, onClick: () => decide(it, "keep") },
            { label: "Revoke", icon: <Ban size={16} />, danger: true, disabled: !!it.decision, onClick: () => decide(it, "revoke") },
            { label: "Open identity", icon: <UserRound size={16} />, onClick: () => nav(`/directory/${it.identity.type === "human" ? "people" : "machine"}?selected=${it.identity.id}`) },
            { label: "Open in graph", icon: <Network size={16} />, onClick: () => nav(`/insights/graph?identity=${it.identity.id}`) },
          ]}
        />
      }
    >
      <section className="stack-sm">
        <h3 style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Why it's here</h3>
        <div className="row tight">{it.reasons.map((r) => <Flag key={r} f={r} />)}</div>
        {c.violations.length > 0 && <div className="small muted">{c.violations.join("; ")}</div>}
      </section>
      <dl className="kv">
        {membership ? <><dt>Role</dt><dd>{it.role?.name}</dd><dt>Assigned by</dt><dd>{SOURCE_LABEL[it.member_source ?? "manual"]}</dd></> : <><dt>Granted through</dt><dd className="sys">{acct}</dd></>}
        <dt>Permissions used</dt><dd className="tnum">{c.permissions_used} of {c.permissions}</dd>
        <dt>Last used</dt><dd>{ago(c.days_since_used)}</dd>
        <dt>Events (90 days)</dt><dd className="tnum">{c.events_90d}</dd>
        <dt>Privileged</dt><dd>{c.privileged ? <Badge tone="warning">Privileged</Badge> : "No"}</dd>
        {c.sensitive.length > 0 && <><dt>Sensitive data</dt><dd>{c.sensitive.map((t) => <Badge key={t} tone="critical">{t}</Badge>)}</dd></>}
        <dt>Peers holding it</dt><dd>{c.peer_coverage === null ? <span className="faint">No peer group</span> : `${Math.round(c.peer_coverage * 100)}%`}</dd>
        <dt>Reviewer</dt><dd><IdLink i={it.reviewer} /></dd>
        {it.decided_at && <><dt>Decided</dt><dd>{fmtDate(it.decided_at)}{it.comment ? ` · “${it.comment}”` : ""}</dd></>}
      </dl>
      {m && (
        <section className="stack-sm">
          <h3 style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Grants this role made</h3>
          {m.grants.length === 0 ? <div className="small muted">None yet: {it.identity.name} has no account that received them.</div> : (
            <ul className="small">{m.grants.map((g) => <li key={g} className="sys">{g}</li>)}</ul>
          )}
          {m.source === "rule" && <div className="xs faint">A birthright rule assigns this role. Revoking it means excluding {it.identity.name} from the rule, or flagging the rule to the role owner.</div>}
        </section>
      )}
      {c.sample_permissions.length > 0 && (
        <section className="stack-sm">
          <h3 style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Sample permissions</h3>
          <div className="row tight">{c.sample_permissions.map((x) => <span key={x} className="chip sys">{x}</span>)}</div>
        </section>
      )}
    </SidePanel>
  );
}

function Campaign({ id, identity, onRefresh, onStart }: { id: number; identity: number | null; onRefresh: () => void; onStart: () => void }) {
  const { data, error, reload } = useApi<CampaignT>(`/reviews/campaigns/${id}`);
  const decide = useDecide();
  const [selected, setSelected] = useSelected("item");
  if (!data) return <div className="card flush"><Loading error={error} /></div>;
  const all = (data.review_items ?? []).filter((i) => identity === null || i.identity.id === identity);
  const open = all.find((i) => String(i.id) === selected);
  const pctAuto = data.total_grants ? Math.round((100 * data.auto_certified) / data.total_grants) : 0;
  return (
    <div className="stack">
      <div className="card stack-sm">
        <div className="stat-row">
          <div className="s"><b className="tnum">{data.total_grants}</b><span>grants in scope</span></div>
          <div className="s"><b className="tnum" style={{ color: "var(--ok)" }}>{data.auto_certified}</b><span>auto-certified ({pctAuto}%)</span></div>
          <div className="s"><b className="tnum">{data.items}</b><span>need a person</span></div>
          <div className="s"><b className="tnum">{data.decided}</b><span>decided</span></div>
          <div className="s"><b className="tnum">{data.revoked}</b><span>revoked</span></div>
        </div>
        <Bar value={data.decided} max={Math.max(1, data.items)} tone="ok" />
        <div className="xs faint">Only exceptions go to reviewers: grants unused for {data.unused_days}+ days, in a policy violation, held by leavers or orphaned machine identities, or privileged and idle. Everything else was auto-certified from usage evidence.</div>
      </div>
      <DataTable
        id="review-items"
        rows={all}
        rowKey={(it) => it.id}
        columns={[
          { id: "who", header: "Identity", sort: (it) => it.identity.name, csv: (it) => it.identity.name, cell: (it) => <div><span className="name-link">{it.identity.name}</span><div style={{ marginTop: 3 }}><TypeBadge type={it.identity.type} /></div></div> },
          { id: "grant", header: "Access", sort: (it) => it.grant, csv: (it) => it.grant, cell: (it) => { const a = accessOf(it); return <div style={{ maxWidth: 280 }}><span className="small">{a.title}</span><div className="xs faint sys">{a.sub}</div></div>; } },
          { id: "why", header: "Why it's here", csv: (it) => it.reasons.join(" "), cell: (it) => <div className="row tight">{it.reasons.map((r) => <Flag key={r} f={r} />)}</div>, hideNarrow: true },
          { id: "usage", header: "Usage", sort: (it) => it.context.days_since_used ?? 9999, csv: (it) => `${it.context.permissions_used}/${it.context.permissions}`, cell: (it) => <span className="small nowrap"><span className="tnum">{it.context.permissions_used}/{it.context.permissions}</span> used · {ago(it.context.days_since_used)}</span>, hideNarrow: true },
          { id: "reviewer", header: "Reviewer", sort: (it) => it.reviewer?.name ?? "", csv: (it) => it.reviewer?.name ?? "", cell: (it) => <span className="small">{it.reviewer?.name ?? <span className="faint">None</span>}</span>, hideNarrow: true },
          {
            id: "decision", header: "Decision", sort: (it) => it.decision ?? "", csv: (it) => it.decision ?? "open",
            cell: (it) => it.decision ? <Badge tone={it.decision === "revoke" ? "critical" : "ok"}>{it.decision === "revoke" ? (it.resolution === "flag" ? "Flagged" : "Revoked") : "Kept"}</Badge> : (
              <div className="row tight" style={{ flexWrap: "nowrap" }} onClick={(e) => e.stopPropagation()}>
                <Button size="sm" onClick={() => decide(it, "keep")}>Keep</Button>
                <Button size="sm" variant="danger" onClick={() => decide(it, "revoke")}>Revoke</Button>
              </div>
            ),
          },
        ]}
        initialFilters={{ status: "open" }}
        searchText={(it) => `${it.identity.name} ${it.grant} ${it.reviewer?.name ?? ""}`}
        searchPlaceholder="Search people or access…"
        filters={[
          { id: "status", label: "Status", options: [{ value: "open", label: "Needs decision" }, { value: "decided", label: "Decided" }], get: (it) => (it.decision ? "decided" : "open") },
          { id: "reason", label: "Reason", options: Object.keys(data.reasons).map((r) => ({ value: r, label: flagLabel(r) })), get: (it) => it.reasons },
          { id: "type", label: "Identity type", options: [{ value: "human", label: "Person" }, { value: "service", label: "Service account" }, { value: "ai_agent", label: "AI agent" }], get: (it) => it.identity.type },
        ]}
        commands={[{ label: "Start review", icon: <Plus size={16} />, onClick: onStart }]}
        onRefresh={() => { reload(); onRefresh(); }}
        bulkActions={[
          { label: "Keep", icon: <Check size={16} />, run: async (rs) => { for (const it of rs.filter((x) => !x.decision)) await decide(it, "keep"); } },
        ]}
        rowLabel={(it) => `${it.identity.name}, ${it.grant}`}
        onRowClick={(it) => setSelected(it.id)}
        activeKey={selected}
        empty={<EmptyState title="Nothing to review here" icon={<ClipboardCheck size={18} />}>This campaign has no items for this view.</EmptyState>}
      />
      {open && <ItemPanel it={open} onClose={() => setSelected(null)} />}
      <div className="xs faint">Tip: the Inbox shows your review items one at a time with keyboard shortcuts: A keeps, R revokes, J and K move.</div>
    </div>
  );
}

export function Reviews() {
  const { data, error, reload } = useApi<CampaignT[]>("/reviews/campaigns");
  const [params, setParams] = useSearchParams();
  const acts = useIdentityActions();
  const [days, setDays] = useState<"30" | "60" | "90">("60");
  const identity = params.get("identity") ? Number(params.get("identity")) : null;
  const { data: idents } = useApi<IdentityRow[]>(identity ? "/identities" : null);
  const who = idents?.find((i) => i.id === identity);
  const sel = params.get("campaign") ? Number(params.get("campaign")) : data?.[0]?.id ?? null;
  const setSel = (id: number) => {
    const next = new URLSearchParams(params);
    next.set("campaign", String(id));
    setParams(next, { replace: true });
  };
  const crumbs: [string, string?][] = [["Access"], ["Access reviews"]];
  const view = params.get("view") === "schedules" ? "schedules" : "campaigns";
  const setView = (v: string) => setParams(v === "schedules" ? { view: v } : {}, { replace: true });
  const viewTabs = <Tabs label="Access review views" value={view} onChange={setView} tabs={[{ id: "campaigns", label: "Campaigns" }, { id: "schedules", label: "Schedules" }]} />;
  return (
    <Page tabs={<GovernanceTabs />}
      title="Access reviews"
      count={data ? `${data.length} campaign${data.length === 1 ? "" : "s"}` : undefined}
      crumbs={crumbs}
      sub="Exception-only certification. Reviewers see only risky or unused access, with usage and peer context for each decision. Revokes apply to the graph immediately."
      actions={<>
        <span className="small faint">New reviews flag access unused for</span>
        <Segmented label="Unused threshold for new reviews" value={days} onChange={setDays} options={[["30", "30 d"], ["60", "60 d"], ["90", "90 d"]]} />
      </>}
    >
      {viewTabs}
      {view === "schedules" ? <ReviewSchedules onLaunched={(id) => { reload(); setParams({ campaign: String(id) }, { replace: true }); }} /> :
      !data ? <div className="card flush"><Loading error={error} /></div> : data.length === 0 ? (
        <div className="card"><EmptyState title="No reviews yet" icon={<ClipboardCheck size={18} />} action={<Button variant="primary" onClick={() => acts.startCampaign(Number(days))}>Start your first review</Button>}>
          A review collects only the access that needs a human decision. Everything with recent usage is auto-certified.
        </EmptyState></div>
      ) : (
        <div className="stack">
          {identity !== null && (
            <div className="callout spread">
              <span>Showing items for <b>{who?.name ?? `identity ${identity}`}</b> only.</span>
              <Button size="sm" variant="ghost" icon={<X size={14} />} onClick={() => { const n = new URLSearchParams(params); n.delete("identity"); setParams(n, { replace: true }); }}>Show everyone</Button>
            </div>
          )}
          <FilterChips
            label="Campaign"
            value={String(sel)}
            onChange={(v) => setSel(Number(v))}
            options={data.map((c) => ({ id: String(c.id), label: c.name, count: c.items - c.decided }))}
          />
          {sel !== null && <Campaign key={sel} id={sel} identity={identity} onRefresh={reload} onStart={() => acts.startCampaign(Number(days))} />}
          {data[0] && <div className="xs faint">Latest campaign started {fmtDate(data[0].created_at)}. <Link to="/inbox?filter=review">Review in the inbox</Link></div>}
        </div>
      )}
    </Page>
  );
}
