import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ClipboardCheck, Plus, X } from "lucide-react";
import { Campaign as CampaignT, IdentityRow, ago, fmtDate, reviewDecide, useApi } from "../../api";
import { useIdentityActions } from "../../app/actions";
import { usePersona } from "../../app/persona";
import { Badge, Bar, Button, EmptyState, FilterChips, Flag, IdLink, Loading, Page, Segmented, TypeBadge, flagLabel, useConfirm, useToast } from "../../components";

function Campaign({ id, identity }: { id: number; identity: number | null }) {
  const { data, error } = useApi<CampaignT>(`/reviews/campaigns/${id}`);
  const { actor } = usePersona();
  const toast = useToast();
  const confirm = useConfirm();
  const [reason, setReason] = useState("");
  const [showDone, setShowDone] = useState(false);
  if (!data) return <div className="card flush"><Loading error={error} /></div>;
  const decide = async (itemId: number, name: string, grant: string, decision: "keep" | "revoke") => {
    let comment: string | undefined;
    if (decision === "revoke") {
      const r = await confirm({ title: `Revoke ${grant}?`, body: `Removes it from ${name} as soon as you confirm. The change is recorded with your name.`, confirmLabel: "Revoke", danger: true, reason: { label: "Comment (optional)", placeholder: "Why it should go" } });
      if (r === null) return;
      comment = r;
    }
    try {
      await reviewDecide(itemId, decision, actor, comment);
      toast(decision === "keep" ? `Kept ${grant} for ${name}` : `Revoked ${grant} from ${name}`);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };
  const all = data.review_items ?? [];
  const items = all.filter((i) => (!reason || i.reasons.includes(reason)) && (showDone || !i.decision) && (identity === null || i.identity.id === identity));
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
      <div className="spread">
        <FilterChips label="Reason" value={reason} onChange={setReason} options={[{ id: "", label: "All reasons" }, ...Object.entries(data.reasons).map(([r, n]) => ({ id: r, label: flagLabel(r), count: n }))]} />
        <label className="row tight small muted"><input type="checkbox" checked={showDone} onChange={(e) => setShowDone(e.target.checked)} /> Show decided</label>
      </div>
      <div className="card flush">
        {items.length === 0 ? (
          <EmptyState title={showDone ? "Nothing matches" : "Nothing left to review here"} icon={<ClipboardCheck size={18} />}>
            {showDone ? "Try another reason." : "Every item in this view has a decision. Turn on “Show decided” to see them."}
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Identity</th><th>Access</th><th className="hide-narrow">Why it's here</th><th className="hide-narrow">Usage</th><th className="hide-narrow">Reviewer</th><th>Decision</th></tr></thead>
              <tbody>
                {items.map((it) => {
                  const [acct, grant] = it.grant.split(" → ");
                  return (
                    <tr key={it.id}>
                      <td><IdLink i={it.identity} /><div style={{ marginTop: 3 }}><TypeBadge type={it.identity.type} /></div></td>
                      <td style={{ maxWidth: 260 }}>
                        <b className="small">{grant ?? it.grant}</b>
                        <div className="xs faint sys">{acct}</div>
                      </td>
                      <td className="hide-narrow">
                        <div className="row tight">{it.reasons.map((r) => <Flag key={r} f={r} />)}</div>
                        {it.context.violations.length > 0 && <div className="xs faint" style={{ marginTop: 4 }}>{it.context.violations.join("; ")}</div>}
                      </td>
                      <td className="small hide-narrow">
                        <span className="tnum">{it.context.permissions_used}/{it.context.permissions}</span> used · last {ago(it.context.days_since_used)}
                        {it.context.peer_coverage !== null && <div className="xs faint">{Math.round(it.context.peer_coverage * 100)}% of peers hold this</div>}
                      </td>
                      <td className="small hide-narrow"><IdLink i={it.reviewer} /></td>
                      <td className="nowrap">
                        {it.decision ? <Badge tone={it.decision === "revoke" ? "critical" : "ok"}>{it.decision === "revoke" ? "Revoked" : "Kept"}</Badge> : (
                          <div className="row tight">
                            <Button size="sm" onClick={() => decide(it.id, it.identity.name, grant ?? it.grant, "keep")}>Keep</Button>
                            <Button size="sm" variant="danger" onClick={() => decide(it.id, it.identity.name, grant ?? it.grant, "revoke")}>Revoke</Button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div className="xs faint">Tip: the Inbox shows your review items one at a time with keyboard shortcuts: A keeps, R revokes, J and K move.</div>
    </div>
  );
}

export function Reviews() {
  const { data, error } = useApi<CampaignT[]>("/reviews/campaigns");
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
  const crumbs: [string, string?][] = [["Governance", "/governance"], ["Access reviews"]];
  return (
    <Page
      title="Access reviews"
      crumbs={crumbs}
      sub="Exception-only certification. Reviewers see only risky or unused access, with usage and peer context for each decision. Revokes apply to the graph immediately."
      actions={<>
        <Segmented label="Unused threshold" value={days} onChange={setDays} options={[["30", "30 d"], ["60", "60 d"], ["90", "90 d"]]} />
        <Button variant="primary" icon={<Plus size={15} />} onClick={() => acts.startCampaign(Number(days))}>Start review</Button>
      </>}
    >
      {!data ? <div className="card flush"><Loading error={error} /></div> : data.length === 0 ? (
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
          {sel !== null && <Campaign key={sel} id={sel} identity={identity} />}
          {data[0] && <div className="xs faint">Latest campaign started {fmtDate(data[0].created_at)}. <Link to="/inbox?filter=review">Review in the inbox</Link></div>}
        </div>
      )}
    </Page>
  );
}
