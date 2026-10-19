import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { GitMerge, Link2, Undo2, UserX } from "lucide-react";
import {
  AccountRow,
  IdentityMerge,
  IdentityRow,
  LinkDecision,
  MatchItem,
  fmtDate,
  linkAccount,
  markNotPerson,
  releaseAccount,
  unmergeIdentity,
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
import { PersonPicker, RULE_LABEL } from "./correlation";

/**
 * Account matches (issue #160): user accounts no connector tied to a person, with the people
 * their login proposes (never linked automatically), the decisions reviewers pinned (a sync
 * never undoes them), and identity merges, which can be undone for 180 days.
 */
type Tab = "queue" | "decisions" | "merges";

export function Matches() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") ?? "queue") as Tab;
  const queue = useApi<MatchItem[]>("/correlation/queue");
  const decisions = useApi<LinkDecision[]>("/correlation/decisions");
  const merges = useApi<IdentityMerge[]>("/identity-merges");
  const open = (merges.data ?? []).filter((m) => !m.unmerged_at).length;
  return (
    <Page
      title="Account matches"
      crumbs={[["Identity"], ["Accounts", "/directory/accounts"], ["Matches"]]}
      sub="Decide who owns accounts that no connector tied to a person. Matches on email or login are only proposals; a decision stays in place across syncs."
      tabs={
        <Tabs
          label="Account matches sections"
          value={tab}
          onChange={(t) => setParams({ tab: t }, { replace: true })}
          tabs={[
            { id: "queue", label: `To review${queue.data ? ` (${queue.data.length})` : ""}` },
            { id: "decisions", label: `Decisions${decisions.data ? ` (${decisions.data.length})` : ""}` },
            { id: "merges", label: `Merges${merges.data ? ` (${open} open)` : ""}` },
          ]}
        />
      }
    >
      {tab === "queue" && <Queue q={queue} />}
      {tab === "decisions" && <Decisions d={decisions} />}
      {tab === "merges" && <Merges m={merges} />}
    </Page>
  );
}

type Loaded<T> = { data: T | null; error: import("../../api").ApiError | null; reload: () => void };

/** Ask for a reason, run the action, and report the outcome. Resolves true when it ran. */
function useDecide() {
  const confirm = useConfirm();
  const toast = useToast();
  return async (o: { title: string; body?: string; confirmLabel: string; danger?: boolean; run: (reason: string) => Promise<unknown>; done: string }) => {
    const reason = await confirm({ title: o.title, body: o.body, confirmLabel: o.confirmLabel, danger: o.danger,
      reason: { label: "Reason (kept in the audit log)", required: true, placeholder: "What did you check?" } });
    if (reason == null) return false;
    try {
      await o.run(reason);
      toast(o.done);
      return true;
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
      return false;
    }
  };
}

function Queue({ q }: { q: Loaded<MatchItem[]> }) {
  const [selected, setSelected] = useSelected();
  const open = q.data?.find((it) => String(it.account.id) === selected);
  const cols: Column<MatchItem>[] = [
    { id: "user", header: "Account", sort: (r) => r.account.username.toLowerCase(), cell: (r) => <span className="sys name-link">{r.account.username}</span> },
    { id: "system", header: "System", sort: (r) => r.account.system, cell: (r) => <Chip mono>{r.account.system}</Chip> },
    { id: "status", header: "Status", sort: (r) => r.account.status, cell: (r) => <span className="small">{r.account.status}</span>, hideNarrow: true },
    {
      id: "proposed", header: "Proposed", sort: (r) => r.candidates[0]?.name ?? "~",
      cell: (r) => (r.candidates.length === 0 ? <span className="faint">No proposal</span>
        : <span className="small">{r.candidates[0].name}{r.candidates.length > 1 && <span className="faint"> +{r.candidates.length - 1}</span>}</span>),
    },
  ];
  return (
    <>
      <DataTable
        id="account-matches"
        rows={q.data}
        error={q.error}
        rowKey={(r) => r.account.id}
        columns={cols}
        searchText={(r) => `${r.account.username} ${r.account.system} ${r.candidates.map((c) => c.name).join(" ")}`}
        searchPlaceholder="Search accounts or proposed people…"
        filters={[
          { id: "system", label: "System", options: [...new Set((q.data ?? []).map((r) => r.account.system))].sort().map((s) => ({ value: s, label: s })), get: (r) => r.account.system },
          { id: "proposal", label: "Proposal", options: [{ value: "yes", label: "Has a proposal" }, { value: "no", label: "No proposal" }], get: (r) => (r.candidates.length ? "yes" : "no") },
        ]}
        onRefresh={q.reload}
        rowLabel={(r) => r.account.username}
        onRowClick={(r) => setSelected(r.account.id)}
        activeKey={selected}
        empty={<EmptyState title="Nothing to review" icon={<Link2 size={18} />}>Every user account belongs to a person or has a decision.</EmptyState>}
      />
      {open && <MatchPanel item={open} onClose={() => setSelected(null)} />}
    </>
  );
}

function MatchPanel({ item, onClose }: { item: MatchItem; onClose: () => void }) {
  const { can } = useSession();
  const decide = useDecide();
  const [other, setOther] = useState<number | null>(null);
  const allowed = can("identities.correlate");
  const a = item.account;
  const link = (id: number, name: string) =>
    decide({
      title: `Link ${a.username} to ${name}?`,
      body: `${name} will own this ${a.system} account in every view, leaver plan and review. Syncs keep this decision until someone releases it.`,
      confirmLabel: "Link",
      run: (reason) => linkAccount(a.id, id, reason),
      done: `${a.username} linked to ${name}`,
    }).then((ok) => ok && onClose());
  const { data: people } = useApi<IdentityRow[]>("/identities");
  const otherName = people?.find((p) => p.id === other)?.name ?? "this person";
  return (
    <SidePanel title={a.username} sub={<span className="small muted">{a.system} · {a.kind} · {a.status}</span>} onClose={onClose}>
      {!allowed && <Callout tone="neutral">Linking accounts needs the identities.correlate permission (policy admins).</Callout>}
      <h3 className="h-sm mt">Proposed</h3>
      {item.candidates.length === 0 ? (
        <p className="small muted">The login matches no one's email. Pick the person below, or mark the account as not a person's.</p>
      ) : (
        <ul className="plain-list">
          {item.candidates.map((c) => (
            <li key={c.identity_id} className="row" style={{ justifyContent: "space-between" }}>
              <span>
                <b>{c.name}</b> <span className="small muted">{c.email}</span>
                <div><Badge tone="outline">{RULE_LABEL[c.rule] ?? c.rule}</Badge></div>
              </span>
              <Button size="sm" icon={<Link2 size={14} />} disabled={!allowed} onClick={() => link(c.identity_id, c.name)}>Link</Button>
            </li>
          ))}
        </ul>
      )}
      <Callout tone="info">A matching email or login is a proposal, not proof. Check with the application owner before you link.</Callout>
      <h3 className="h-sm mt">Someone else</h3>
      <PersonPicker value={other} onChange={setOther} label="Person" />
      <div className="row tight mt">
        <Button size="sm" variant="primary" icon={<Link2 size={14} />} disabled={!allowed || other == null} onClick={() => other != null && link(other, otherName)}>Link to {other == null ? "person" : otherName}</Button>
        <Button size="sm" icon={<UserX size={14} />} disabled={!allowed}
          onClick={() => decide({
            title: `Mark ${a.username} as not a person's account?`,
            body: "Use this for shared, test or break-glass logins. It leaves the queue and stays unlinked across syncs. Give it an owner as a machine identity if it needs one.",
            confirmLabel: "Not a person",
            run: (reason) => markNotPerson(a.id, reason),
            done: `${a.username} marked as not a person's`,
          }).then((ok) => ok && onClose())}
        >Not a person</Button>
      </div>
    </SidePanel>
  );
}

function Decisions({ d }: { d: Loaded<LinkDecision[]> }) {
  const { can } = useSession();
  const decide = useDecide();
  const { data: accounts } = useApi<AccountRow[]>("/accounts");
  const { data: people } = useApi<IdentityRow[]>("/identities");
  const acct = useMemo(() => new Map((accounts ?? []).map((a) => [a.id, a])), [accounts]);
  const person = useMemo(() => new Map((people ?? []).map((p) => [p.id, p])), [people]);
  const label = (r: LinkDecision) => { const a = acct.get(r.account_id); return a ? `${a.system}:${a.username}` : `account ${r.account_id}`; };
  const cols: Column<LinkDecision>[] = [
    { id: "acct", header: "Account", sort: label, cell: (r) => <span className="sys">{label(r)}</span> },
    { id: "decision", header: "Decision", sort: (r) => r.decision,
      cell: (r) => (r.decision === "link" ? <span className="small">Linked to <b>{person.get(r.identity_id ?? 0)?.name ?? `identity ${r.identity_id}`}</b></span> : <Badge tone="outline">Not a person</Badge>) },
    { id: "reason", header: "Reason", cell: (r) => <span className="small truncate" style={{ maxWidth: 320, display: "inline-block" }}>{r.reason}</span>, hideNarrow: true },
    { id: "at", header: "Decided", sort: (r) => r.decided_at, cell: (r) => <span className="small nowrap">{fmtDate(r.decided_at)}</span> },
    { id: "act", header: "Actions",
      cell: (r) => (
        <Button size="sm" variant="ghost" icon={<Undo2 size={14} />} disabled={!can("identities.correlate")}
          onClick={(e) => {
            e.stopPropagation();
            decide({ title: `Release the decision on ${label(r)}?`, body: "The account goes back to what its connector says, and the next sync applies that.",
              confirmLabel: "Release", run: () => releaseAccount(r.account_id), done: `Released ${label(r)}` });
          }}
        >Release</Button>
      ) },
  ];
  return (
    <DataTable
      id="account-decisions"
      rows={d.data}
      error={d.error}
      rowKey={(r) => r.account_id}
      columns={cols}
      searchText={(r) => `${label(r)} ${r.reason} ${person.get(r.identity_id ?? 0)?.name ?? ""}`}
      searchPlaceholder="Search decisions…"
      filters={[{ id: "decision", label: "Decision", options: [{ value: "link", label: "Linked" }, { value: "not_person", label: "Not a person" }], get: (r) => r.decision }]}
      onRefresh={d.reload}
      rowLabel={label}
      empty={<EmptyState title="No decisions yet" icon={<Link2 size={18} />}>Decisions you make in the review queue appear here.</EmptyState>}
    />
  );
}

function Merges({ m }: { m: Loaded<IdentityMerge[]> }) {
  const { can } = useSession();
  const decide = useDecide();
  const toast = useToast();
  const now = Date.now();
  const state = (r: IdentityMerge) => (r.unmerged_at ? "undone" : Date.parse(r.unmerge_before) < now ? "final" : "open");
  const cols: Column<IdentityMerge>[] = [
    { id: "what", header: "Merge", sort: (r) => r.merged_name, cell: (r) => <span className="small"><b>{r.merged_name}</b> into <b>{r.survivor_name}</b></span> },
    { id: "moved", header: "Moved", num: true, sort: (r) => r.moves.length, cell: (r) => r.moves.length, hideNarrow: true },
    { id: "reason", header: "Reason", cell: (r) => <span className="small truncate" style={{ maxWidth: 280, display: "inline-block" }}>{r.reason}</span>, hideNarrow: true },
    { id: "at", header: "Merged", sort: (r) => r.merged_at, cell: (r) => <span className="small nowrap">{fmtDate(r.merged_at)}</span> },
    { id: "state", header: "State", sort: state,
      cell: (r) => state(r) === "undone" ? <Badge tone="outline">Undone {fmtDate(r.unmerged_at)}</Badge>
        : state(r) === "final" ? <Badge>Final</Badge> : <span className="small">Can undo until {fmtDate(r.unmerge_before)}</span> },
    { id: "act", header: "Actions",
      cell: (r) => state(r) === "open" && (
        <Button size="sm" variant="ghost" icon={<Undo2 size={14} />} disabled={!can("identities.merge")}
          onClick={(e) => {
            e.stopPropagation();
            decide({
              title: `Undo the merge of ${r.merged_name} into ${r.survivor_name}?`,
              body: `Everything the merge moved goes back to ${r.merged_name}, except items that changed since; those stay and are listed in the audit log.`,
              confirmLabel: "Undo merge", danger: true,
              run: async (reason) => {
                const res = await unmergeIdentity(r.id, reason);
                if (res.kept.length) toast(`${res.kept.length} item(s) changed since the merge and stayed with ${r.survivor_name}`);
              },
              done: `Merge of ${r.merged_name} undone`,
            });
          }}
        >Undo</Button>
      ) },
  ];
  return (
    <DataTable
      id="identity-merges"
      rows={m.data}
      error={m.error}
      rowKey={(r) => r.id}
      columns={cols}
      searchText={(r) => `${r.merged_name} ${r.survivor_name} ${r.reason}`}
      searchPlaceholder="Search merges…"
      filters={[{ id: "state", label: "State", options: [{ value: "open", label: "Can undo" }, { value: "undone", label: "Undone" }, { value: "final", label: "Final" }], get: state }]}
      onRefresh={m.reload}
      rowLabel={(r) => `${r.merged_name} into ${r.survivor_name}`}
      empty={<EmptyState title="No merges" icon={<GitMerge size={18} />}>Merge duplicate identities from an identity's page (More actions → Merge into…).</EmptyState>}
    />
  );
}
