import { ReactNode, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Check, GitMerge, ShieldAlert, UserCheck, UserPlus, X } from "lucide-react";
import {
  IdentityMatchCandidate,
  IdentityMatchItem,
  IdentityMatchList,
  MatchDecision,
  MatchingSettings,
  MergeRequest,
  MergeRisk,
  approveMergeRequest,
  decideIdentityMatch,
  fmtDate,
  putMatchingSettings,
  rejectMergeRequest,
  relTime,
  useApi,
} from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Chip } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Column, DataTable } from "../../components/DataTable";
import { useConfirm } from "../../components/Dialog";
import { Callout, EmptyState } from "../../components/Feedback";
import { Page, Tabs } from "../../components/Page";
import { SidePanel, useSelected } from "../../components/SidePanel";
import { useToast } from "../../components/Toast";

/**
 * Identity matches (guest accounts design §5.6, issue #68): invitations and intake records that
 * might be someone Tessera already knows. The matcher never links a self-asserted intake itself;
 * a reviewer decides, with a reason, and a link into a person who holds privileged access, has
 * IAL 2 or more or is an employee needs a second reviewer. Attributes are masked: the page shows
 * enough to decide (a name's first letters, an address's domain), never the full values.
 */
type Tab = "review" | "requests" | "reverification" | "decided" | "settings";

export const RULE_LABEL: Record<string, string> = {
  signed_in_as_candidate: "Signed in as the person",
  source_record_linked: "Same source record",
  authoritative_identifier: "Same authoritative ID",
  federated_binding: "Same federated sign-in",
  verified_email_dob_name: "Verified email, date of birth and name",
  name_dob: "Similar name and date of birth",
  verified_email: "Verified email",
  verified_phone: "Verified phone",
};

export const RISK_LABEL: Record<MergeRisk, string> = {
  privileged_access: "holds privileged access",
  ial2: "has IAL 2 or more",
  employee: "is an employee",
};

export const CHANNEL_LABEL: Record<string, string> = {
  sponsor_invite: "Sponsor invitation",
  bulk_invite: "Bulk invitation",
  self_registration: "Self-registration",
  sis: "Student system",
  hris: "HR system",
  vms: "Contractor system",
  partner_invite: "Partner invitation",
  partner_scim: "Partner provisioning",
};

const STATUS_LABEL: Record<string, string> = {
  review: "To review",
  reverification: "Waiting for sign-in",
  linked: "Linked",
  new_person: "New person",
  rejected: "Rejected",
  superseded: "Superseded",
};

const tierTone = (t: string) => (t === "A" ? "critical" : t === "B" ? "warning" : "info") as "critical" | "warning" | "info";

export function IdentityMatches() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") ?? "review") as Tab;
  const { can } = useSession();
  const review = useApi<IdentityMatchList>("/identity-matches?status=review");
  const reverify = useApi<IdentityMatchList>("/identity-matches?status=reverification");
  const decided = useApi<IdentityMatchList>("/identity-matches?status=decided");
  const requests = useApi<{ items: MergeRequest[]; count: number }>(can("identities.merge") ? "/identity-merge-requests?status=pending" : null);
  const canSettings = can("matching.configure");
  return (
    <Page
      title="Identity matches"
      crumbs={[["Identity"], ["Users", "/directory/people"], ["Identity matches"]]}
      sub="Decide whether an invited or imported person is someone Tessera already knows. Nothing is linked until you decide, and a link into someone with privileged access, IAL 2 or an employee record needs a second reviewer."
      tabs={
        <Tabs
          label="Identity matches sections"
          value={tab}
          onChange={(t) => setParams({ tab: t }, { replace: true })}
          tabs={[
            { id: "review", label: `To review${review.data ? ` (${review.data.count})` : ""}` },
            ...(can("identities.merge") ? [{ id: "requests" as Tab, label: `Second reviewer${requests.data ? ` (${requests.data.count})` : ""}` }] : []),
            { id: "reverification", label: `Waiting for sign-in${reverify.data ? ` (${reverify.data.count})` : ""}` },
            { id: "decided", label: "Decided" },
            ...(canSettings ? [{ id: "settings" as Tab, label: "Settings" }] : []),
          ]}
        />
      }
    >
      {tab === "review" && <Queue data={review} open kind="review" />}
      {tab === "requests" && <Requests data={requests} onChanged={() => { review.reload(); reverify.reload(); decided.reload(); }} />}
      {tab === "reverification" && <Queue data={reverify} kind="reverification" />}
      {tab === "decided" && <Queue data={decided} kind="decided" />}
      {tab === "settings" && canSettings && <Settings />}
    </Page>
  );
}

type Loaded<T> = { data: T | null; error: string | null; reload: () => void };

// ------------------------------------------------------------------ the queue

function Queue({ data, kind, open }: { data: Loaded<IdentityMatchList>; kind: "review" | "reverification" | "decided"; open?: boolean }) {
  const [selected, setSelected] = useSelected();
  const items = data.data?.items ?? null;
  const current = items?.find((i) => i.id === selected || i.candidates.some((c) => c.match_id === selected));
  const cols: Column<IdentityMatchItem>[] = [
    { id: "who", header: "Invited or imported", sort: (r) => r.subject.name, cell: (r) => <span className="name-link">{r.subject.name || "Unknown"}</span> },
    { id: "source", header: "Source", sort: (r) => r.channel, cell: (r) => <Chip>{CHANNEL_LABEL[r.channel] ?? r.channel}</Chip>, hideNarrow: true },
    { id: "cand", header: "Might be", sort: (r) => r.candidates[0]?.name ?? "~",
      cell: (r) => <span className="small">{r.candidates[0].name}{r.candidates.length > 1 && <span className="faint"> +{r.candidates.length - 1}</span>}</span> },
    { id: "tier", header: "Tier", sort: (r) => r.candidates[0]?.tier ?? "Z", cell: (r) => <Badge tone={tierTone(r.candidates[0].tier)}>{r.candidates[0].tier}</Badge> },
    { id: "rule", header: "Why", hideNarrow: true, cell: (r) => <span className="small">{r.candidates[0].rules.map((x) => RULE_LABEL[x.rule] ?? x.rule).join(", ")}</span> },
    { id: "status", header: "Status", sort: (r) => r.candidates[0]?.status ?? "", cell: (r) => <StatusBadge c={r.candidates[0]} /> },
    { id: "at", header: "Received", sort: (r) => r.received_at, cell: (r) => <span className="small nowrap" title={fmtDate(r.received_at)}>{relTime(r.received_at)}</span>, hideNarrow: true },
  ];
  return (
    <>
      <DataTable
        id={`identity-matches-${kind}`}
        rows={items}
        error={data.error}
        rowKey={(r) => r.id}
        columns={cols}
        searchText={(r) => `${r.subject.name} ${r.subject.sponsor?.name ?? ""} ${r.candidates.map((c) => c.name).join(" ")}`}
        searchPlaceholder="Search invited people or candidates…"
        filters={[
          { id: "tier", label: "Tier", options: ["A", "B", "C"].map((t) => ({ value: t, label: `Tier ${t}` })), get: (r) => r.candidates[0]?.tier ?? "" },
          { id: "channel", label: "Source", options: [...new Set((items ?? []).map((r) => r.channel))].map((c) => ({ value: c, label: CHANNEL_LABEL[c] ?? c })), get: (r) => r.channel },
        ]}
        onRefresh={data.reload}
        rowLabel={(r) => r.subject.name}
        onRowClick={(r) => setSelected(r.id)}
        activeKey={current?.id ?? null}
        empty={
          <EmptyState title={kind === "review" ? "Nothing to review" : kind === "reverification" ? "Nobody is waiting" : "No decisions yet"} icon={<UserCheck size={18} />}>
            {kind === "review"
              ? "When an invitation or imported record might be someone Tessera already knows, it waits here for a decision."
              : kind === "reverification"
                ? "A link into someone verified at a higher level waits here until the person signs in as the existing account."
                : "Decisions you make appear here."}
          </EmptyState>
        }
      />
      {current && <MatchPanel item={current} decidable={!!open} onClose={() => setSelected(null)} />}
    </>
  );
}

function StatusBadge({ c }: { c: IdentityMatchCandidate }) {
  if (c.pending_request) return <Badge tone="warning">Second reviewer</Badge>;
  return <Badge tone={c.status === "linked" ? "ok" : c.status === "rejected" ? "critical" : "outline"}>{STATUS_LABEL[c.status] ?? c.status}</Badge>;
}

/** Ask for a reason, run the action and report the outcome. */
function useDecide() {
  const confirm = useConfirm();
  const toast = useToast();
  return async (o: { title: string; body?: string; confirmLabel: string; danger?: boolean; run: (reason: string) => Promise<string>; label?: string }) => {
    const reason = await confirm({ title: o.title, body: o.body, confirmLabel: o.confirmLabel, danger: o.danger,
      reason: { label: o.label ?? "Reason (kept in the audit log)", required: true, placeholder: "What did you check?" } });
    if (reason == null) return false;
    try {
      toast(await o.run(reason));
      return true;
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
      return false;
    }
  };
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

function MatchPanel({ item, decidable, onClose }: { item: IdentityMatchItem; decidable: boolean; onClose: () => void }) {
  const { can } = useSession();
  const decide = useDecide();
  const [pick, setPick] = useState(item.candidates[0].match_id);
  const c = item.candidates.find((x) => x.match_id === pick) ?? item.candidates[0];
  const allowed = can("identity_matches.review") && decidable;
  const s = item.subject;
  const outcome = (r: Awaited<ReturnType<typeof decideIdentityMatch>>) =>
    r.result === "pending_approval" ? "Waiting for a second reviewer"
    : r.result === "reverification_required" ? "Link approved. It applies when they sign in as the existing account."
    : r.result === "linked" ? "Linked"
    : r.result === "new_person" ? "Kept as a new person" : "Intake rejected";
  const act = (d: MatchDecision, o: { title: string; body: string; confirmLabel: string; danger?: boolean }) =>
    decide({ ...o, run: async (reason) => outcome(await decideIdentityMatch(c.match_id, d, reason)) }).then((ok) => ok && onClose());
  const second = c.second_reviewer_because;
  return (
    <SidePanel title={s.name || "Identity match"} sub={<span className="small muted">{CHANNEL_LABEL[item.channel] ?? item.channel} · {relTime(item.received_at)}</span>} onClose={onClose}>
      {!allowed && decidable && <Callout tone="neutral">Deciding matches needs the identity_matches.review permission (policy admins).</Callout>}
      {item.mode === "self_asserted" && (
        <Callout tone="info">
          A sponsor vouched for this person; nobody has proved it. Tessera never links a self-asserted invitation by itself. The person is not told that a match exists.
        </Callout>
      )}
      {item.claimant_says_has_account === "yes" && <Callout tone="neutral">The invited person said they already have an account. That answer links nothing.</Callout>}

      {item.candidates.length > 1 && (
        <div role="radiogroup" aria-label="Candidate" className="stack-sm">
          {item.candidates.map((x) => (
            <label key={x.match_id} className="row tight">
              <input type="radio" name="candidate" checked={x.match_id === c.match_id} onChange={() => setPick(x.match_id)} />
              <span>{x.name}</span> <Badge tone={tierTone(x.tier)}>Tier {x.tier}</Badge>
            </label>
          ))}
        </div>
      )}

      <div className="match-sides">
        <section aria-label="The invited person">
          <h3 className="h-sm">Invited or imported</h3>
          <dl className="kv kv-narrow">
            <Field label="Name">{s.name}</Field>
            <Field label="Email">{s.email ?? <span className="faint">none</span>}</Field>
            {s.population && <Field label="As">{s.population}</Field>}
            {s.sponsor && <Field label="Sponsor">{s.sponsor.name}</Field>}
            {s.purpose && <Field label="Purpose">{s.purpose}</Field>}
          </dl>
        </section>
        <section aria-label="The existing person">
          <h3 className="h-sm">Might be</h3>
          <dl className="kv kv-narrow">
            <Field label="Name">{c.name}</Field>
            <Field label="Email">{c.email ?? <span className="faint">none</span>}</Field>
            <Field label="Affiliations">
              {c.affiliations.length === 0 ? <span className="faint">none</span>
                : c.affiliations.map((a, i) => <div key={i} className="small">{a.type.replace("_", " ")} <span className="faint">({a.status}, {a.source})</span></div>)}
            </Field>
            <Field label="Privileged access">{c.privileged_access ? <Badge tone="warning">Yes</Badge> : "No"}</Field>
            <Field label="IAL"><Badge tone={c.ial >= 2 ? "accent" : "outline"}>IAL {c.ial}</Badge></Field>
          </dl>
        </section>
      </div>

      <div>
        <h3 className="h-sm">Why it matched</h3>
        <ul className="plain-list">
          {c.rules.map((r) => (
            <li key={r.rule}>
              <div className="row tight"><Badge tone={tierTone(r.tier)}>Tier {r.tier}</Badge> <b>{RULE_LABEL[r.rule] ?? r.rule}</b> <span className="small faint">score {r.score.toFixed(2)}</span></div>
              <div className="small muted">{r.why}</div>
              {Object.keys(r.compared).length > 0 && (
                <div className="row tight wrap mt-sm">{Object.entries(r.compared).map(([k, v]) => <Chip key={k} mono>{k}: {v}</Chip>)}</div>
              )}
            </li>
          ))}
        </ul>
      </div>

      {c.status === "review" && second.length > 0 && (
        <Callout tone="warn" icon={<ShieldAlert size={16} />}>
          A link needs a second reviewer, because the existing person {second.map((r) => RISK_LABEL[r]).join(" and ")}. And because they are verified at IAL {c.ial}, the invited person must sign in as the existing account before anything is linked.
        </Callout>
      )}
      {c.pending_request && (
        <Callout tone="info">Link requested by {c.pending_request.requested_by.display_name} {relTime(c.pending_request.requested_at)}. A different reviewer approves it under “Second reviewer”.</Callout>
      )}
      {c.status === "reverification" && <Callout tone="info">Approved. Nothing is linked and no access is granted until the invited person signs in as the existing account.</Callout>}
      {c.decision && c.status !== "review" && (
        <dl className="kv kv-narrow">
          <Field label="Decision">{STATUS_LABEL[c.status] ?? c.status}</Field>
          {c.decided_by && <Field label="Decided by">{c.decided_by.display_name}{c.second_reviewer && <>, approved by {c.second_reviewer.display_name}</>}</Field>}
          {c.reason && <Field label="Reason">{c.reason}</Field>}
          {c.decided_at && <Field label="When">{fmtDate(c.decided_at)}</Field>}
        </dl>
      )}

      {c.status === "review" && (
        <div className="row tight wrap">
          <Button variant="primary" size="sm" icon={<GitMerge size={14} />} disabled={!allowed || !!c.pending_request}
            onClick={() => act("link", {
              title: `Link ${s.name} to ${c.name}?`,
              body: `${c.name} will hold this invitation's sponsorship and access. Nothing of ${c.name}'s credentials moves, and the invited person's own sign-in is disabled. This can be undone for the tenant's unmerge window.`,
              confirmLabel: "Link",
            })}>Link to {c.name}</Button>
          <Button size="sm" icon={<UserPlus size={14} />} disabled={!allowed}
            onClick={() => act("new_person", { title: `Keep ${s.name} as a new person?`, body: "They stay a separate identity. The match is recorded as reviewed.", confirmLabel: "New person" })}>New person</Button>
          <Button size="sm" variant="danger" icon={<X size={14} />} disabled={!allowed}
            onClick={() => act("reject", { title: `Reject this intake?`, body: "Use this for fraud or a duplicate request. The invitation is cancelled and the sponsorship ends.", confirmLabel: "Reject intake", danger: true })}>Reject intake</Button>
        </div>
      )}
    </SidePanel>
  );
}

// ------------------------------------------------------------------ second reviewer

function Requests({ data, onChanged }: { data: Loaded<{ items: MergeRequest[]; count: number }>; onChanged: () => void }) {
  const { can, session } = useSession();
  const decide = useDecide();
  const toast = useToast();
  const me = session.user.id;
  const cols: Column<MergeRequest>[] = [
    { id: "what", header: "Merge", sort: (r) => r.merged.name, cell: (r) => <span className="small"><b>{r.merged.name}</b> into <b>{r.survivor.name}</b></span> },
    { id: "kind", header: "Kind", sort: (r) => r.kind, cell: (r) => <Badge tone="outline">{r.kind === "match_link" ? "Match link" : "Merge"}</Badge>, hideNarrow: true },
    { id: "risk", header: "Needs a second reviewer because", cell: (r) => <span className="small">{r.risk.map((x) => RISK_LABEL[x]).join(", ")}</span>, hideNarrow: true },
    { id: "by", header: "Asked by", sort: (r) => r.requested_by.display_name, cell: (r) => <span className="small">{r.requested_by.display_name}</span> },
    { id: "reason", header: "Reason", cell: (r) => <span className="small truncate" style={{ maxWidth: 260, display: "inline-block" }}>{r.reason}</span>, hideNarrow: true },
    { id: "at", header: "Asked", sort: (r) => r.requested_at, cell: (r) => <span className="small nowrap" title={fmtDate(r.requested_at)}>{relTime(r.requested_at)}</span> },
    { id: "act", header: "Actions",
      cell: (r) => {
        const mine = r.requested_by.id === me;
        return (
          <span className="row tight">
            <Button size="sm" variant="primary" icon={<Check size={14} />} disabled={!can("identities.merge") || mine} title={mine ? "A different reviewer must approve" : undefined}
              onClick={(e) => {
                e.stopPropagation();
                approveMergeRequest(r.id).then((res) => { toast(res.result === "merged" ? "Merged" : "Approved. It applies when the person signs in as the existing account."); onChanged(); data.reload(); })
                  .catch((x) => toast(String(x.message ?? x), { kind: "error" }));
              }}>Approve</Button>
            <Button size="sm" variant="ghost" icon={<X size={14} />} disabled={!can("identities.merge")}
              onClick={(e) => {
                e.stopPropagation();
                decide({ title: mine ? "Withdraw your request?" : "Reject this request?", confirmLabel: mine ? "Withdraw" : "Reject", danger: !mine,
                  run: async (reason) => { await rejectMergeRequest(r.id, reason); onChanged(); data.reload(); return mine ? "Request withdrawn" : "Request rejected"; } });
              }}>{mine ? "Withdraw" : "Reject"}</Button>
          </span>
        );
      } },
  ];
  return (
    <DataTable
      id="identity-merge-requests"
      rows={data.data?.items ?? null}
      error={data.error}
      rowKey={(r) => r.id}
      columns={cols}
      searchText={(r) => `${r.merged.name} ${r.survivor.name} ${r.reason} ${r.requested_by.display_name}`}
      searchPlaceholder="Search requests…"
      onRefresh={data.reload}
      rowLabel={(r) => `${r.merged.name} into ${r.survivor.name}`}
      empty={<EmptyState title="Nothing waits for a second reviewer" icon={<GitMerge size={18} />}>A merge or link that needs a second reviewer appears here for someone other than the person who asked.</EmptyState>}
    />
  );
}

// ------------------------------------------------------------------ settings

function Settings() {
  const { data, reload } = useApi<MatchingSettings>("/admin/matching");
  const toast = useToast();
  const [draft, setDraft] = useState<Partial<MatchingSettings>>({});
  const s = useMemo(() => (data ? { ...data, ...draft } : null), [data, draft]);
  if (!s) return <p role="status">Loading…</p>;
  const save = async () => {
    try {
      await putMatchingSettings({ auto_link_tier_b: s.auto_link_tier_b, require_review_tier_a: s.require_review_tier_a, unmerge_window_days: s.unmerge_window_days });
      setDraft({});
      reload();
      toast("Matching settings saved");
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    }
  };
  return (
    <div className="stack" style={{ maxWidth: 560 }}>
      <label className="row tight">
        <input type="checkbox" checked={s.auto_link_tier_b} onChange={(e) => setDraft({ ...draft, auto_link_tier_b: e.target.checked })} />
        Link strong (Tier B) matches automatically between authoritative sources
      </label>
      <label className="row tight">
        <input type="checkbox" checked={s.require_review_tier_a} onChange={(e) => setDraft({ ...draft, require_review_tier_a: e.target.checked })} />
        Send exact (Tier A) matches to review too
      </label>
      <label className="field">Merges can be undone for (days)
        <input className="input" type="number" min={1} max={3650} value={s.unmerge_window_days}
          onChange={(e) => setDraft({ ...draft, unmerge_window_days: Number(e.target.value) })} />
      </label>
      <p className="small muted">Self-asserted intake (sponsor invitations, self-registration) is never linked automatically, whatever these say.</p>
      <div><Button variant="primary" onClick={save} disabled={Object.keys(draft).length === 0}>Save</Button></div>
      {data?.updated_by && <p className="xs faint">Last changed by {data.updated_by.display_name} {data.updated_at && relTime(data.updated_at)}.</p>}
    </div>
  );
}
