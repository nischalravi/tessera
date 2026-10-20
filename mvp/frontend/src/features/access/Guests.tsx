/**
 * Guests I sponsor (issue #65): the sponsor's page. Invite one guest or a CSV of them, see each
 * sponsorship with its state and days left, renew, transfer or end it, accept a transfer, and (for
 * approvers) approve or reject the sponsorships the sponsor policy sends for a second person.
 *
 * When a sponsorship starts, the guest gets an email with a one-time claim link (issue #69). The side
 * panel shows where the invitation stands (sent, claimed, expired, revoked) and lets the sponsor send
 * a new link or cancel it. The access bundle is granted when the groups engine reads sponsorships.
 */
import { ChangeEvent, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ArrowRightLeft, Check, CalendarPlus, FileUp, Mail, UserCheck, UserPlus, Users, X } from "lucide-react";
import {
  BulkResult, CatalogView, GuestList, GuestPopulationInfo, GuestPopulationKey, IdentityRow, Sponsorship,
  fmtDate, fmtDay, guests, relTime, useApi,
} from "../../api";
import { Badge, Button, Callout, Column, DataTable, Drawer, EmptyState, Loading, Page, SidePanel, Tabs, useConfirm, useSelected, useToast } from "../../components";
import {
  CSV_HEADER, INVITATION_LABEL, INVITATION_TONE, InviteForm, MAX_BULK_ROWS, POPULATIONS, POPULATION_LABEL, ROW_LABEL, STATE_LABEL, STATE_TONE, addDays, bundleChoices, csvRowCount,
  csvTemplate, csvTooLong, dayOf, daysLeftLabel, emptyInvite, endInstant, invitationNote, invitePayload, inviteProblems, itemIal, maxEndDay, needsApproval, requiredIal,
} from "./guestModel";

type Tab = "mine" | "all" | "approvals";

const today = () => dayOf(new Date());
const message = (e: unknown) => String((e as Error)?.message ?? e);

function StateBadge({ s }: { s: Pick<Sponsorship, "state" | "days_left"> }) {
  const tone = s.state === "ending" && (s.days_left ?? 99) <= 3 ? "critical" : STATE_TONE[s.state];
  return <Badge tone={tone} dot={tone !== "neutral"}>{STATE_LABEL[s.state]}</Badge>;
}

const cols = (showSponsor: boolean): Column<Sponsorship>[] => [
  {
    id: "guest", header: "Guest", sort: (s) => s.guest.name, csv: (s) => s.guest.name,
    cell: (s) => <><span className="name-link">{s.guest.name}</span>{s.guest.email && <div className="xs faint">{s.guest.email}</div>}</>,
  },
  { id: "pop", header: "Population", sort: (s) => s.population, csv: (s) => s.population, cell: (s) => <span className="small">{POPULATION_LABEL[s.population]}</span> },
  ...(showSponsor ? [{ id: "sponsor", header: "Sponsor", sort: (s: Sponsorship) => s.sponsor.name, csv: (s: Sponsorship) => s.sponsor.name, cell: (s: Sponsorship) => <span className="small">{s.sponsor.name}</span>, hideNarrow: true }] : []),
  { id: "purpose", header: "Purpose", sort: (s) => s.purpose, csv: (s) => s.purpose, cell: (s) => <span className="small" title={s.purpose}>{s.purpose.length > 60 ? `${s.purpose.slice(0, 59)}…` : s.purpose}</span>, hideNarrow: true },
  { id: "ends", header: "Ends", sort: (s) => s.ends_at, csv: (s) => s.ends_at, cell: (s) => <span className="small nowrap">{fmtDay(s.ends_at)}</span> },
  {
    id: "state", header: "State", sort: (s) => s.days_left ?? 99999, csv: (s) => s.state,
    cell: (s) => <><StateBadge s={s} />{s.days_left !== null && s.state !== "pending_approval" && <div className="xs faint">{daysLeftLabel(s)}</div>}</>,
  },
];

export function Guests() {
  const [params, setParams] = useSearchParams();
  const base = useApi<GuestList>(guests.paths.list({ sponsor: "me" }));
  const tab = (params.get("tab") ?? "mine") as Tab;
  const canAll = base.data?.can_read_all ?? false;
  const canApprove = base.data?.can_approve ?? false;
  const all = useApi<GuestList>(tab === "all" && canAll ? guests.paths.list({ sponsor: "all" }) : null);
  const approvals = useApi<Sponsorship[]>(tab === "approvals" && canApprove ? guests.paths.approvals : null);
  const rows = tab === "approvals" ? approvals.data : tab === "all" ? (all.data?.rows ?? null) : (base.data?.rows ?? null);
  const error = tab === "approvals" ? approvals.error : tab === "all" ? all.error : base.error;
  const reload = () => {
    base.reload();
    if (tab === "all") all.reload();
    if (tab === "approvals") approvals.reload();
  };
  const [selected, setSelected] = useSelected();
  const open = rows?.find((s) => s.id === selected);
  const [drawer, setDrawer] = useState<null | "invite" | "bulk">(null);
  const pops = base.data?.populations ?? [];
  const waiting = base.data?.rows.filter((s) => s.can_accept_transfer).length ?? 0;
  const tabs = [
    { id: "mine" as Tab, label: waiting ? `Guests I sponsor (${waiting} to accept)` : "Guests I sponsor" },
    ...(canAll ? [{ id: "all" as Tab, label: "Every guest" }] : []),
    ...(canApprove ? [{ id: "approvals" as Tab, label: "Approvals" }] : []),
  ];
  const canSponsor = base.data?.can_sponsor ?? false;
  return (
    <Page title="Guests I sponsor" crumbs={[["Access"], ["Guests I sponsor"]]}
      sub="Invite visitors, contractors, volunteers and partners, and stay accountable for them: every guest has a sponsor and an end date.">
      {tabs.length > 1 && <Tabs label="Views" value={tab} onChange={(v) => setParams(v === "mine" ? {} : { tab: v })} tabs={tabs} />}
      {base.data && !canSponsor && (
        <Callout tone="warn">You cannot sponsor guests: sponsors are active employees. You can still see guests you were asked to take over{canApprove ? " and approve sponsorships" : ""}.</Callout>
      )}
      <DataTable
        id={`guests-${tab}`}
        rows={rows}
        error={error}
        rowKey={(s) => s.id}
        columns={cols(tab !== "mine")}
        initialSort={["state", 1]}
        searchText={(s) => `${s.guest.name} ${s.guest.email ?? ""} ${s.purpose} ${s.sponsor.name} ${s.population}`}
        searchPlaceholder="Search guests, emails or purposes…"
        filters={[
          { id: "state", label: "State", options: Object.entries(STATE_LABEL).map(([value, label]) => ({ value, label })), get: (s) => s.state },
          { id: "pop", label: "Population", options: POPULATIONS.map((value) => ({ value, label: POPULATION_LABEL[value] })), get: (s) => s.population },
        ]}
        commands={[
          canSponsor && { label: "Invite guest", icon: <UserPlus size={16} />, onClick: () => setDrawer("invite") },
          canSponsor && { label: "Bulk invite", icon: <FileUp size={16} />, onClick: () => setDrawer("bulk"), title: "Invite many guests from a CSV file" },
        ]}
        onRefresh={reload}
        rowLabel={(s) => s.guest.name}
        onRowClick={(s) => setSelected(s.id)}
        activeKey={selected}
        empty={tab === "approvals"
          ? <EmptyState title="Nothing waits for approval" icon={<UserCheck size={18} />}>Contractors with privileged access need a second person to approve.</EmptyState>
          : <EmptyState title="No guests yet" icon={<Users size={18} />} action={canSponsor ? <Button variant="primary" icon={<UserPlus size={14} />} onClick={() => setDrawer("invite")}>Invite a guest</Button> : undefined}>
            Guests you invite show here with their sponsorship, end date and days left.
          </EmptyState>}
      />
      {open && (
        <SidePanel title={open.guest.name} sub={<><span className="small">{POPULATION_LABEL[open.population]}</span><StateBadge s={open} /></>} onClose={() => setSelected(null)}>
          <SponsorshipDetail id={open.id} onChanged={reload} />
        </SidePanel>
      )}
      {drawer === "invite" && <InviteDrawer pops={pops} limit={base.data?.max_invites_per_day ?? 50} onClose={() => setDrawer(null)} />}
      {drawer === "bulk" && <BulkDrawer limit={base.data?.max_invites_per_day ?? 50} onClose={() => setDrawer(null)} />}
    </Page>
  );
}

// ------------------------------------------------------------------ detail and row actions

function SponsorshipDetail({ id, onChanged }: { id: string; onChanged: () => void }) {
  const { data: s, error, reload } = useApi<Sponsorship>(guests.paths.one(id));
  const { data: list } = useApi<GuestList>(guests.paths.list({ sponsor: "me" }));
  const [drawer, setDrawer] = useState<null | "renew" | "transfer" | "end" | "reject">(null);
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  if (!s) return <Loading error={error} kind="block" />;
  const pop = list?.populations.find((p) => p.key === s.population);
  const done = (text: string) => { toast(text); reload(); onChanged(); };
  const run = async (fn: () => Promise<unknown>, text: string) => {
    setBusy(true);
    try {
      await fn();
      done(text);
    } catch (e) {
      toast(message(e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack">
      <div className="row tight wrap">
        {s.can_accept_transfer && <Button variant="primary" size="sm" icon={<Check size={14} />} disabled={busy} onClick={() => run(() => guests.acceptTransfer(s.id), `You now sponsor ${s.guest.name}`)}>Accept transfer</Button>}
        {s.can_approve && <Button variant="primary" size="sm" icon={<Check size={14} />} disabled={busy} onClick={() => run(() => guests.approve(s.id), `Approved the sponsorship of ${s.guest.name}`)}>Approve</Button>}
        {s.can_approve && <Button size="sm" icon={<X size={14} />} onClick={() => setDrawer("reject")}>Reject</Button>}
        {s.can_renew && <Button size="sm" icon={<CalendarPlus size={14} />} onClick={() => setDrawer("renew")}>Renew</Button>}
        {s.can_transfer && <Button size="sm" icon={<ArrowRightLeft size={14} />} onClick={() => setDrawer("transfer")}>Transfer</Button>}
        {s.can_end && <Button size="sm" variant="danger" onClick={() => setDrawer("end")}>End</Button>}
      </div>
      {(s.can_resend_invitation || s.can_revoke_invitation) && (
        <div className="row tight wrap">
          {s.can_resend_invitation && (
            <Button size="sm" icon={<Mail size={14} />} disabled={busy}
              onClick={() => run(() => guests.resendInvitation(s.guest.id), `A new link was sent to ${s.guest.email ?? s.guest.name}`)}>
              {s.invitation === "ready" ? "Send invitation" : "Resend invitation"}
            </Button>
          )}
          {s.can_revoke_invitation && (
            <Button size="sm" variant="danger" disabled={busy} onClick={async () => {
              const ok = await confirm({ title: `Revoke the invitation to ${s.guest.name}?`, danger: true, confirmLabel: "Revoke invitation",
                body: "The link in their email stops working and any claim in progress ends. The sponsorship itself stays; you can end it separately." });
              if (ok !== null) await run(() => guests.revokeInvitation(s.guest.id), "Invitation revoked");
            }}>Revoke invitation</Button>
          )}
        </div>
      )}
      {s.status === "pending_approval" && <Callout tone="warn">A second person must approve this sponsorship before the guest gets any standing or access. {s.can_approve ? "" : "Approvers have been asked."}</Callout>}
      {s.status === "transfer_pending" && s.transfer_to && (
        <Callout tone="warn">Waiting for {s.transfer_to.name} to accept, until {fmtDate(s.transfer_deadline)}. If nobody accepts, the sponsorship ends then.</Callout>
      )}
      <dl className="kv">
        <dt>Guest</dt><dd>{s.guest.name}{s.guest.email && <div className="xs faint">{s.guest.email} (as the sponsor wrote it, not verified)</div>}</dd>
        <dt>Sponsor</dt><dd>{s.sponsor.name}</dd>
        <dt>Population</dt><dd>{POPULATION_LABEL[s.population]}</dd>
        <dt>Purpose</dt><dd>{s.purpose}</dd>
        <dt>Term</dt><dd>{fmtDay(s.starts_at)} to {fmtDay(s.ends_at)} {s.days_left !== null && <span className="small muted">({daysLeftLabel(s)})</span>}</dd>
        <dt>Assurance</dt><dd>IAL {s.required_ial}, AAL {s.required_aal}</dd>
        <dt>Access bundle</dt>
        <dd>
          {s.bundle.length === 0 ? <span className="faint">None</span> : (
            <ul className="plain-list">{s.bundle.map((b) => <li key={b.group_id}>{b.system}:{b.name} <Badge tone={itemIal(b) ? "warning" : "neutral"}>IAL {itemIal(b)}</Badge></li>)}</ul>
          )}
          {s.bundle.length > 0 && <div className="xs faint">Granted when the groups engine reads sponsorships; nothing is granted yet.</div>}
        </dd>
        <dt>Invitation</dt>
        <dd><Badge tone={INVITATION_TONE[s.invitation]}>{INVITATION_LABEL[s.invitation]}</Badge><div className="xs faint">{invitationNote(s, fmtDate)}</div></dd>
        {s.approved_by && <><dt>Approved by</dt><dd>{s.approved_by.display_name}, {relTime(s.approved_at)}</dd></>}
        {s.end_reason && <><dt>Ended</dt><dd>{fmtDate(s.ended_at)}: {s.end_reason}</dd></>}
        <dt>Policy</dt><dd className="xs faint">{s.policy_version}</dd>
      </dl>
      {(s.events?.length ?? 0) > 0 && (
        <ol className="timeline">
          {s.events!.map((e, i) => (
            <li key={i}>
              <b>{e.event.replace(/_/g, " ")}</b> by {e.actor} <span className="faint" title={fmtDate(e.at)}>{relTime(e.at)}</span>
              {e.note && <div className="small muted">{e.note}</div>}
            </li>
          ))}
        </ol>
      )}
      {drawer === "renew" && <RenewDrawer s={s} pop={pop} onClose={() => setDrawer(null)} onDone={() => done(`Renewed the sponsorship of ${s.guest.name}`)} />}
      {drawer === "transfer" && <TransferDrawer s={s} days={list?.transfer_deadline_days ?? 14} onClose={() => setDrawer(null)} onDone={() => done("Transfer requested")} />}
      {drawer === "end" && <ReasonDrawer title={`End the sponsorship of ${s.guest.name}`} verb="End sponsorship" danger
        intro="The guest's access under this sponsorship stops now. If it is their last sponsorship, their account ends and the leaver plan runs."
        call={(r) => guests.end(s.id, r)} onClose={() => setDrawer(null)} onDone={() => done("Sponsorship ended")} />}
      {drawer === "reject" && <ReasonDrawer title={`Reject the sponsorship of ${s.guest.name}`} verb="Reject"
        intro="The sponsor is told. The invited person is withdrawn unless another sponsorship stands behind them."
        call={(r) => guests.reject(s.id, r)} onClose={() => setDrawer(null)} onDone={() => done("Sponsorship rejected")} />}
    </div>
  );
}

function useBusy() {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const go = async (fn: () => Promise<unknown>, after: () => void) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      after();
    } catch (e) {
      setErr(message(e));
    } finally {
      setBusy(false);
    }
  };
  return { busy, err, go };
}

function ReasonDrawer({ title, intro, verb, danger, call, onClose, onDone }: {
  title: string; intro: string; verb: string; danger?: boolean; call: (reason: string) => Promise<unknown>; onClose: () => void; onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const { busy, err, go } = useBusy();
  return (
    <Drawer title={title} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant={danger ? "danger" : "primary"} disabled={!reason.trim() || busy} onClick={() => go(() => call(reason.trim()), () => { onClose(); onDone(); })}>{verb}</Button></>}>
      <div className="stack">
        <p className="muted">{intro}</p>
        <label className="field">Reason (kept in the history and the audit log)<textarea className="input" data-autofocus value={reason} onChange={(e) => setReason(e.target.value)} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}

function RenewDrawer({ s, pop, onClose, onDone }: { s: Sponsorship; pop?: GuestPopulationInfo; onClose: () => void; onDone: () => void }) {
  const [ends, setEnds] = useState("");
  const [why, setWhy] = useState("");
  const { busy, err, go } = useBusy();
  const min = addDays(s.ends_at.slice(0, 10), 1);
  const max = pop ? maxEndDay("", today(), pop.max_days) : undefined;
  return (
    <Drawer title={`Renew the sponsorship of ${s.guest.name}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" disabled={!ends || !why.trim() || busy} onClick={() => go(() => guests.renew(s.id, endInstant(ends), why.trim()), () => { onClose(); onDone(); })}>Renew</Button></>}>
      <div className="stack">
        <p className="muted">Ends {fmtDay(s.ends_at)} now. A renewal is a new term{pop ? `, at most ${pop.max_days} days from today` : ""}; the sponsor policy runs again.</p>
        <label className="field">New end date (access stops at the start of this day, UTC)
          <input className="input" type="date" data-autofocus min={min} max={max} value={ends} onChange={(e) => setEnds(e.target.value)} />
        </label>
        <label className="field">Fresh justification<textarea className="input" value={why} onChange={(e) => setWhy(e.target.value)} placeholder="Why does this guest still need access?" /></label>
        {s.bundle.some((b) => itemIal(b) > 0) && <Callout tone="warn">This sponsorship has privileged access, so a second approver may be needed to renew it.</Callout>}
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}

function TransferDrawer({ s, days, onClose, onDone }: { s: Sponsorship; days: number; onClose: () => void; onDone: () => void }) {
  const { data: people } = useApi<IdentityRow[]>("/identities?type=human&status=active");
  const [to, setTo] = useState<number | "">("");
  const [reason, setReason] = useState("");
  const { busy, err, go } = useBusy();
  const choices = (people ?? []).filter((p) => p.id !== s.sponsor.id && p.id !== s.guest.id);
  return (
    <Drawer title={`Transfer the sponsorship of ${s.guest.name}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" disabled={to === "" || !reason.trim() || busy} onClick={() => go(() => guests.transfer(s.id, Number(to), reason.trim()), () => { onClose(); onDone(); })}>Ask to take over</Button></>}>
      <div className="stack">
        <p className="muted">The new sponsor must accept within {days} days. Until then you stay the sponsor; if they do not accept, the sponsorship ends at the deadline. They must be eligible to sponsor.</p>
        <label className="field">New sponsor
          <select className="input" data-autofocus value={to} onChange={(e) => setTo(e.target.value ? Number(e.target.value) : "")}>
            <option value="">Choose…</option>
            {choices.map((p) => <option key={p.id} value={p.id}>{p.name}{p.department ? ` (${p.department})` : ""}</option>)}
          </select>
        </label>
        <label className="field">Reason<textarea className="input" value={reason} onChange={(e) => setReason(e.target.value)} /></label>
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}

// ------------------------------------------------------------------ invite

function InviteDrawer({ pops, limit, onClose }: { pops: GuestPopulationInfo[]; limit: number; onClose: () => void }) {
  const toast = useToast();
  const { data: catalog } = useApi<CatalogView>("/catalog");
  const [f, setF] = useState<InviteForm>(() => emptyInvite());
  const { busy, err, go } = useBusy();
  const pop = pops.find((p) => p.key === f.population);
  const choices = useMemo(() => bundleChoices(catalog?.items ?? []), [catalog]);
  const picked = choices.filter((c) => f.bundle.includes(c.group.id)).map((c) => ({ privileged: c.group.privileged, risk: c.risk }));
  const ial = requiredIal(pop, picked);
  const problems = inviteProblems(f, pop, today());
  const set = <K extends keyof InviteForm>(k: K, v: InviteForm[K]) => setF((x) => ({ ...x, [k]: v }));
  const toggle = (id: number) => set("bundle", f.bundle.includes(id) ? f.bundle.filter((x) => x !== id) : [...f.bundle, id]);
  const send = () => go(() => guests.invite(invitePayload(f)), () => {
    toast(needsApproval(pop, picked) ? `Invitation for ${f.given_name} is waiting for a second approver` : `Invited ${f.given_name} ${f.family_name}`.trim());
    onClose();
  });
  return (
    <Drawer title="Invite a guest" sub={`At most ${limit} invitations a day.`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" icon={<UserPlus size={14} />} disabled={problems.length > 0 || busy} onClick={send}>Invite</Button></>}>
      <div className="stack">
        <label className="field">Population
          <select className="input" data-autofocus value={f.population} onChange={(e) => setF({ ...f, population: e.target.value as GuestPopulationKey, ends: "" })}>
            {(pops.length ? pops : POPULATIONS.map((key) => ({ key, name: POPULATION_LABEL[key] }))).map((p) => <option key={p.key} value={p.key}>{POPULATION_LABEL[p.key as GuestPopulationKey]}</option>)}
          </select>
        </label>
        <div className="grid g2">
          <label className="field">Given name<input className="input" value={f.given_name} onChange={(e) => set("given_name", e.target.value)} autoComplete="off" /></label>
          <label className="field">Family name<input className="input" value={f.family_name} onChange={(e) => set("family_name", e.target.value)} autoComplete="off" /></label>
        </div>
        <label className="field">Email<input className="input" type="email" value={f.email} onChange={(e) => set("email", e.target.value)} autoComplete="off" /></label>
        <p className="xs faint">Tessera does not say whether this address belongs to someone it already knows: an invitation always creates a new person, and the guest proves the address when they claim the account.</p>
        <div className="grid g2">
          <label className="field">Starts (optional, default now)<input className="input" type="date" value={f.starts} onChange={(e) => set("starts", e.target.value)} /></label>
          <label className="field">Ends (access stops at the start of this day, UTC)
            <input className="input" type="date" value={f.ends} min={addDays(f.starts || today(), 1)} max={pop ? maxEndDay(f.starts, today(), pop.max_days) : undefined} onChange={(e) => set("ends", e.target.value)} />
          </label>
        </div>
        {pop && <p className="xs faint">A {POPULATION_LABEL[pop.key].toLowerCase()} sponsorship runs at most {pop.max_days} days; you can sponsor {pop.max_active} at a time.</p>}
        <label className="field">Purpose<textarea className="input" value={f.purpose} onChange={(e) => set("purpose", e.target.value)} placeholder="e.g. Guest lecture for the security course" /></label>
        <fieldset className="field">
          <legend>Access bundle (optional)</legend>
          {!catalog ? <Loading kind="block" /> : choices.length === 0 ? <p className="small muted">No requestable catalog items are open to guests yet.</p> : (
            <ul className="plain-list">
              {choices.map((c) => (
                <li key={c.group.id}>
                  <label className="row tight">
                    <input type="checkbox" checked={f.bundle.includes(c.group.id)} onChange={() => toggle(c.group.id)} />
                    <span className="grow">{c.group.system}:{c.group.name}</span>
                    <Badge tone={itemIal({ privileged: c.group.privileged, risk: c.risk }) ? "warning" : "neutral"}>IAL {itemIal({ privileged: c.group.privileged, risk: c.risk })}</Badge>
                  </label>
                </li>
              ))}
            </ul>
          )}
          <p className="xs faint">The bundle is recorded with the sponsorship; the groups engine grants it later. Privileged or high-risk items need the guest to prove their identity to IAL 2.</p>
        </fieldset>
        <p className="small">The guest will need identity assurance <b>IAL {ial}</b>{pop ? ` and sign-in strength AAL ${pop.default_aal}` : ""}.</p>
        {needsApproval(pop, picked) && <Callout tone="warn">This contractor sponsorship has privileged access, so a second person must approve it before it starts.</Callout>}
        {f.given_name && problems.length > 0 && <p className="xs faint">Still needed: {problems.join(", ")}.</p>}
        {err && <Callout tone="bad">{err}</Callout>}
      </div>
    </Drawer>
  );
}

// ------------------------------------------------------------------ bulk invite

function RowTable({ r }: { r: BulkResult }) {
  return (
    <div className="table-scroll" role="region" aria-label="Rows" tabIndex={0}>
      <table>
        <thead><tr><th scope="col">Line</th><th scope="col">Email</th><th scope="col">Result</th><th scope="col">Why</th></tr></thead>
        <tbody>
          {r.rows.map((x) => (
            <tr key={x.row}>
              <td className="nowrap">{x.row}</td>
              <td>{x.email}</td>
              <td><Badge tone={x.status === "refused" ? "critical" : x.status === "needs_approval" ? "warning" : "ok"}>{ROW_LABEL[x.status]}</Badge></td>
              <td className="small">{x.message ?? ""}{x.code && <span className="xs faint"> ({x.code})</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BulkDrawer({ limit, onClose }: { limit: number; onClose: () => void }) {
  const toast = useToast();
  const [text, setText] = useState("");
  const [preview, setPreview] = useState<BulkResult | null>(null);
  const [sent, setSent] = useState<BulkResult | null>(null);
  const { busy, err, go } = useBusy();
  useEffect(() => setPreview(null), [text]);
  const load = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 512 * 1024) {
      toast("That file is too large for 500 rows", { kind: "error" });
      return;
    }
    file.text().then(setText, () => toast("Could not read the file", { kind: "error" }));
  };
  const template = () => {
    const url = URL.createObjectURL(new Blob([csvTemplate(today())], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "guest-invitations.csv";
    a.click();
    URL.revokeObjectURL(url);
  };
  const rows = csvRowCount(text);
  const result = sent ?? preview;
  return (
    <Drawer title="Bulk invite" sub={`Up to ${MAX_BULK_ROWS} guests at a time, at most ${limit} invitations a day.`} wide onClose={onClose}
      footer={sent ? <Button variant="primary" onClick={onClose}>Done</Button> : (
        <><Button onClick={onClose}>Cancel</Button>
          {!preview
            ? <Button variant="primary" disabled={rows === 0 || csvTooLong(text) || busy} onClick={() => go(() => guests.bulk(text, true).then(setPreview), () => undefined)}>Preview</Button>
            : <Button variant="primary" icon={<UserPlus size={14} />} disabled={preview.would_create === 0 || busy}
                onClick={() => go(() => guests.bulk(text, false).then(setSent), () => toast("Invitations sent"))}>
                Invite {preview.would_create} guest{preview.would_create === 1 ? "" : "s"}
              </Button>}
        </>)}>
      <div className="stack">
        <p className="muted">Paste a CSV with the header <code>{CSV_HEADER.join(",")}</code>. Population is visitor, contractor, volunteer or partner; dates are YYYY-MM-DD; leave starts_at blank to start now. The preview runs every row against the sponsor policy and writes nothing. A row the policy refuses never blocks the others.</p>
        <div className="row tight">
          <label className="btn"><FileUp size={14} aria-hidden /> Choose a file<input type="file" accept=".csv,text/csv" onChange={load} style={{ display: "none" }} /></label>
          <Button size="sm" onClick={template}>Download a template</Button>
        </div>
        <label className="field">CSV
          <textarea className="input mono" rows={8} data-autofocus value={text} onChange={(e) => setText(e.target.value)} disabled={!!sent} spellCheck={false} />
        </label>
        {csvTooLong(text) && <Callout tone="bad">A file has at most {MAX_BULK_ROWS} rows; this one has {rows}.</Callout>}
        {err && <Callout tone="bad">{err}</Callout>}
        {result && (
          <>
            <Callout tone={result.refused ? "warn" : "ok"}>
              {sent
                ? `${sent.created} invited, ${sent.refused} refused.`
                : `${result.would_create} of ${result.rows.length} rows can be invited, ${result.refused} refused.`}
              <span className="xs faint"> Policy {result.policy_version}</span>
            </Callout>
            <RowTable r={result} />
          </>
        )}
      </div>
    </Drawer>
  );
}
