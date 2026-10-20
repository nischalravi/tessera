import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { UserRoundCheck } from "lucide-react";
import {
  GuestLifecycleBucket, GuestLifecycleItem, GuestLifecycleOverview, GuestLifecycleSettings,
  fmtDate, fmtDay, guestLifecycle, relTime, useApi,
} from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Chip, Column, DataTable, EmptyState, FilterChips, GovernanceTabs, Loading, Page, SidePanel, useConfirm, useSelected, useToast } from "../../components";
import { BUCKET_HELP, BUCKET_LABEL, OUTCOME_LABEL, TASK_KIND_LABEL, TRIGGER_LABEL, inDays, parseDays, settingsProblem, taskActions } from "./guestLifecycleModel";

/**
 * Governance → Guest lifecycle (guest accounts design §8, issue #74): what is about to end, what waits
 * for a person, and where each person stands after their last affiliation ended. Counts come from
 * GET /api/guest-lifecycle, each list from /api/guest-lifecycle/items?bucket=. Deciding a task is the
 * server's call (the sponsor's manager, a sponsor admin or the sponsor); the page only offers the actions.
 */
type View = GuestLifecycleBucket | "tasks" | "settings";

const bucketKey = (it: GuestLifecycleItem) => it.task_id ?? it.sponsorship_id ?? `person-${it.guest.id}`;

export function GuestLifecycle() {
  const [params, setParams] = useSearchParams();
  const { can } = useSession();
  const view = (params.get("view") ?? "expiring_14") as View;
  const overview = useApi<GuestLifecycleOverview>("/guest-lifecycle");
  const mine = useApi<{ tasks: GuestLifecycleItem[] }>("/guest-lifecycle/tasks");
  const counts = overview.data?.counts;
  const canSettings = can("guest_lifecycle.configure");
  const reloadAll = () => { overview.reload(); mine.reload(); };
  const options = [
    ...(overview.data?.buckets ?? []).map((b) => ({ id: b as View, label: BUCKET_LABEL[b], count: counts?.[b] })),
    { id: "tasks" as View, label: "My tasks", count: mine.data?.tasks.length },
    ...(canSettings ? [{ id: "settings" as View, label: "Settings" }] : []),
  ];
  return (
    <Page
      title="Guest lifecycle"
      crumbs={[["Governance", "/governance/policies"], ["Guest lifecycle"]]}
      sub="Sponsorships that are about to end, tasks that wait for a sponsor or an admin, and each guest's grace and retention period after their last affiliation ended."
      tabs={<GovernanceTabs />}
    >
      {overview.error && <Callout tone="bad">{overview.error.message}</Callout>}
      <div style={{ marginBottom: 12 }}>
        <FilterChips label="Guest lifecycle lists" options={options} value={view} onChange={(v) => setParams({ view: v }, { replace: true })} />
      </div>
      {view === "settings" ? (
        canSettings ? <Settings settings={overview.data?.settings ?? null} onSaved={overview.reload} /> : null
      ) : view === "tasks" ? (
        <List key="tasks" bucket="tasks" rows={mine.data?.tasks ?? null} error={mine.error?.message ?? null} reload={reloadAll} onDeparture={overview.data?.settings.on_sponsor_departure ?? "end"} />
      ) : (
        <Bucket key={view} bucket={view} reload={reloadAll} onDeparture={overview.data?.settings.on_sponsor_departure ?? "end"} />
      )}
    </Page>
  );
}

function Bucket({ bucket, reload, onDeparture }: { bucket: GuestLifecycleBucket; reload: () => void; onDeparture: "end" | "suspend" }) {
  const { data, error, reload: reloadList } = useApi<{ bucket: string; items: GuestLifecycleItem[] }>(`/guest-lifecycle/items?bucket=${bucket}`);
  return <List bucket={bucket} rows={data?.items ?? null} error={error?.message ?? null} reload={() => { reloadList(); reload(); }} onDeparture={onDeparture} />;
}

function List({ bucket, rows, error, reload, onDeparture }: {
  bucket: GuestLifecycleBucket | "tasks"; rows: GuestLifecycleItem[] | null; error: string | null; reload: () => void; onDeparture: "end" | "suspend";
}) {
  const [selected, setSelected] = useSelected();
  const current = rows?.find((r) => bucketKey(r) === selected) ?? null;
  const stage = bucket === "in_grace" || bucket === "deprovisioned" || bucket === "purged";
  const taskish = bucket === "tasks" || bucket === "pending_transfer" || bucket === "renewal_requests" || bucket === "dual_status" || bucket === "auto_ended";
  const cols: Column<GuestLifecycleItem>[] = useMemo(() => {
    const out: Column<GuestLifecycleItem>[] = [
      { id: "guest", header: "Guest", sort: (r) => r.guest.name, cell: (r) => <span className="name-link">{r.guest.name}</span> },
    ];
    if (!stage) out.push({ id: "sponsor", header: bucket === "pending_transfer" || bucket === "tasks" ? "Sponsor" : "Sponsor", sort: (r) => r.sponsor?.name ?? "", cell: (r) => <span className="small">{r.sponsor?.name ?? ""}</span>, hideNarrow: true });
    out.push({ id: "pop", header: "As", sort: (r) => r.population ?? "", cell: (r) => <Chip>{r.population ?? ""}</Chip>, hideNarrow: true });
    if (taskish) {
      out.push({ id: "task", header: "Task", sort: (r) => r.task_kind ?? "", cell: (r) => <span className="small">{TASK_KIND_LABEL[r.task_kind ?? ""] ?? ""}{r.trigger && <span className="faint"> · {TRIGGER_LABEL[r.trigger] ?? r.trigger}</span>}</span> });
      out.push({ id: "deadline", header: "Decide by", sort: (r) => r.deadline ?? "", cell: (r) => r.deadline ? <span className="small nowrap" title={fmtDate(r.deadline)}>{fmtDay(r.deadline)}</span> : <span className="faint">none</span> });
      if (bucket === "auto_ended") out.push({ id: "outcome", header: "Outcome", cell: (r) => <Badge tone={r.outcome === "suspended" ? "warning" : "critical"}>{OUTCOME_LABEL[r.outcome ?? ""] ?? r.outcome}</Badge> });
    } else if (stage) {
      out.push({ id: "ended", header: "Ended", sort: (r) => r.ends_at ?? "", cell: (r) => <span className="small nowrap" title={fmtDate(r.ends_at)}>{relTime(r.ends_at)}</span> });
      out.push({ id: "grace", header: "Grace until", sort: (r) => r.grace_until ?? "", cell: (r) => <span className="small nowrap">{fmtDay(r.grace_until)}</span>, hideNarrow: true });
      out.push({ id: "ret", header: "Kept until", sort: (r) => r.retention_until ?? "", cell: (r) => <span className="small nowrap">{fmtDay(r.retention_until)}</span> });
      out.push({ id: "held", header: "Held access", cell: (r) => <Badge tone={r.held_access ? "info" : "outline"}>{r.held_access ? "Yes" : "No"}</Badge>, hideNarrow: true });
    } else {
      out.push({ id: "ends", header: bucket === "stepup_required" ? "Current end" : "Ends", sort: (r) => r.ends_at ?? "", cell: (r) => <span className="small nowrap" title={fmtDate(r.ends_at)}>{fmtDay(r.ends_at)}{r.days_left !== undefined && <span className="faint"> · {inDays(r.days_left)}</span>}</span> });
      if (bucket === "stepup_required") {
        out.push({ id: "ial", header: "Needs", cell: (r) => <Badge tone="accent">IAL {r.required_ial}</Badge> });
        out.push({ id: "wants", header: "Renewal asks for", sort: (r) => r.deadline ?? "", cell: (r) => <span className="small nowrap">{fmtDay(r.deadline)}</span>, hideNarrow: true });
      }
    }
    return out;
  }, [bucket, stage, taskish]);
  return (
    <>
      <p className="small muted" style={{ marginTop: 0 }}>{bucket === "tasks" ? "Tasks you may decide: a sponsor's manager and sponsor admins decide transfers; the sponsor decides renewals and dual status." : BUCKET_HELP[bucket]}</p>
      <DataTable
        id={`guest-lifecycle-${bucket}`}
        rows={rows}
        error={error}
        rowKey={bucketKey}
        columns={cols}
        searchText={(r) => `${r.guest.name} ${r.sponsor?.name ?? ""} ${r.population ?? ""}`}
        searchPlaceholder="Search guests or sponsors…"
        onRefresh={reload}
        rowLabel={(r) => r.guest.name}
        onRowClick={(r) => setSelected(bucketKey(r))}
        activeKey={current ? bucketKey(current) : null}
        empty={<EmptyState title="Nothing here" icon={<UserRoundCheck size={18} />}>{bucket === "tasks" ? "No lifecycle task waits for you." : "No guests in this list right now."}</EmptyState>}
      />
      {current && <Panel item={current} bucket={bucket} onDeparture={onDeparture} onClose={() => setSelected(null)} onChanged={reload} />}
    </>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

function Panel({ item, bucket, onDeparture, onClose, onChanged }: {
  item: GuestLifecycleItem; bucket: string; onDeparture: "end" | "suspend"; onClose: () => void; onChanged: () => void;
}) {
  const confirm = useConfirm();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const actions = item.task_id && item.can_act ? taskActions(item, onDeparture) : [];
  const run = async (a: (typeof actions)[number]) => {
    const ok = await confirm({ title: a.title, body: a.body, confirmLabel: a.label, danger: a.danger });
    if (ok === null) return;
    setBusy(true);
    try {
      const r = await guestLifecycle.resolveTask(item.task_id!, a.action);
      toast(r.outcome ? `${OUTCOME_LABEL[r.outcome] ?? r.outcome}: ${item.guest.name}` : "Done");
      onChanged();
      onClose();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <SidePanel title={item.guest.name} sub={<span className="small muted">{BUCKET_LABEL[bucket as GuestLifecycleBucket] ?? "Task"}</span>} onClose={onClose}
      fullHref={`/directory/identities/${item.guest.id}`} fullLabel="Open person">
      <dl className="kv kv-narrow">
        {item.sponsor && <Field label={item.task_kind === "sponsor_transfer" ? "Sponsor who left" : "Sponsor"}>{item.sponsor.name}</Field>}
        {item.population && <Field label="As">{item.population}</Field>}
        {item.status && <Field label="Status">{item.status.replace(/_/g, " ")}</Field>}
        {item.ends_at && <Field label={item.grace_until ? "Ended" : "Ends"}>{fmtDate(item.ends_at)}{item.days_left !== undefined && ` (${inDays(item.days_left)})`}</Field>}
        {item.task_kind && <Field label="Task">{TASK_KIND_LABEL[item.task_kind]}{item.trigger && ` · ${TRIGGER_LABEL[item.trigger] ?? item.trigger}`}</Field>}
        {item.deadline && <Field label={bucket === "stepup_required" ? "Renewal asks for" : "Decide by"}>{fmtDate(item.deadline)}</Field>}
        {item.outcome && <Field label="Outcome">{OUTCOME_LABEL[item.outcome] ?? item.outcome}</Field>}
        {item.required_ial ? <Field label="Identity assurance needed">IAL {item.required_ial}</Field> : null}
        {item.grace_until && <Field label="Grace period ends">{fmtDate(item.grace_until)}</Field>}
        {item.retention_until && <Field label="Personal data kept until">{fmtDate(item.retention_until)}</Field>}
        {item.held_access !== undefined && <Field label="Held access to systems">{item.held_access ? "Yes" : "No"}</Field>}
      </dl>
      {bucket === "stepup_required" && (
        <Callout tone="info">The renewal is recorded, but access does not extend until the guest verifies their identity at IAL {item.required_ial}. A new claim step then applies it.</Callout>
      )}
      {item.task_id && !item.can_act && <Callout tone="neutral">You can see this task but not decide it.</Callout>}
      {actions.length > 0 && (
        <div className="row tight wrap">
          {actions.map((a) => (
            <Button key={a.action} size="sm" variant={a.primary ? "primary" : a.danger ? "danger" : undefined} disabled={busy} onClick={() => run(a)}>{a.label}</Button>
          ))}
        </div>
      )}
      {item.sponsorship_id && <p className="small"><a href={`/access/guests?selected=${item.sponsorship_id}`}>Open the sponsorship</a></p>}
    </SidePanel>
  );
}

// ------------------------------------------------------------------ settings

type Draft = Omit<GuestLifecycleSettings, "updated_at">;
const toDraft = (s: GuestLifecycleSettings): Draft => { const { updated_at: _u, ...d } = s; return d; };

function Settings({ settings, onSaved }: { settings: GuestLifecycleSettings | null; onSaved: () => void }) {
  const toast = useToast();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [days, setDays] = useState("");
  useEffect(() => {
    if (settings && !draft) { setDraft(toDraft(settings)); setDays(settings.sponsor_reminder_days.join(", ")); }
  }, [settings, draft]);
  if (!settings || !draft) return <Loading kind="block" />;
  const next: Draft = { ...draft, sponsor_reminder_days: parseDays(days) };
  const problem = settingsProblem(next);
  const num = (k: keyof Draft, v: string) => setDraft({ ...draft, [k]: Number(v) } as Draft);
  const save = async () => {
    try {
      await guestLifecycle.putSettings(next);
      toast("Guest lifecycle settings saved");
      onSaved();
    } catch (e: any) {
      toast(String(e.message ?? e), { kind: "error" });
    }
  };
  return (
    <div className="stack" style={{ maxWidth: 640 }}>
      <fieldset className="stack-sm" style={{ border: 0, padding: 0 }}>
        <legend className="h-sm">Reminders and transfers</legend>
        <label className="field">Sponsor reminders, days before the end
          <input className="input" value={days} onChange={(e) => setDays(e.target.value)} aria-describedby="gl-days-help" />
        </label>
        <span id="gl-days-help" className="xs faint">Comma separated, for example 30, 14, 3.</span>
        <label className="field">Guest reminder, days before the end (0 turns it off)
          <input className="input" type="number" min={0} max={365} value={draft.guest_reminder_days} onChange={(e) => num("guest_reminder_days", e.target.value)} />
        </label>
        <label className="field">Transfer deadline after a sponsor leaves (days)
          <input className="input" type="number" min={1} max={90} value={draft.transfer_deadline_days} onChange={(e) => num("transfer_deadline_days", e.target.value)} />
        </label>
        <label className="field">If nobody takes over
          <select className="input" value={draft.on_sponsor_departure} onChange={(e) => setDraft({ ...draft, on_sponsor_departure: e.target.value as Draft["on_sponsor_departure"] })}>
            <option value="end">End the sponsorship at the deadline</option>
            <option value="suspend">Suspend the sponsorship at the deadline</option>
          </select>
        </label>
        <label className="field">When a guest or contractor is hired
          <select className="input" value={draft.conversion_dual_status} onChange={(e) => setDraft({ ...draft, conversion_dual_status: e.target.value as Draft["conversion_dual_status"] })}>
            <option value="end">End the sponsorship at the hire date</option>
            <option value="sponsor_confirms">Ask the sponsor to confirm dual status</option>
          </select>
        </label>
      </fieldset>
      <fieldset className="stack-sm" style={{ border: 0, padding: 0 }}>
        <legend className="h-sm">Grace period after the last affiliation ends (days)</legend>
        {(["visitor", "contractor", "volunteer", "partner"] as const).map((p) => (
          <label key={p} className="field" style={{ textTransform: "none" }}>{p[0].toUpperCase() + p.slice(1)}
            <input className="input" type="number" min={0} max={365} value={draft.grace_days[p]} onChange={(e) => setDraft({ ...draft, grace_days: { ...draft.grace_days, [p]: Number(e.target.value) } })} />
          </label>
        ))}
      </fieldset>
      <fieldset className="stack-sm" style={{ border: 0, padding: 0 }}>
        <legend className="h-sm">Retention</legend>
        <label className="field">Anyone who held access to in-scope systems (days)
          <input className="input" type="number" min={1} max={36500} value={draft.retention_days} onChange={(e) => num("retention_days", e.target.value)} />
        </label>
        <label className="field">Visitors who held none (days)
          <input className="input" type="number" min={1} max={36500} value={draft.retention_days_visitor} onChange={(e) => num("retention_days_visitor", e.target.value)} />
        </label>
        <label className="row tight">
          <input type="checkbox" checked={draft.keep_rematch_hashes} onChange={(e) => setDraft({ ...draft, keep_rematch_hashes: e.target.checked })} />
          Keep identifier hashes after the purge, so a returning person is matched to the same identity
        </label>
      </fieldset>
      <p className="small muted">The purge never changes the audit log. Accounts are deleted instead of left disabled only for connections whose target is set to “delete on deprovision”.</p>
      {problem && <Callout tone="warn">{problem}</Callout>}
      <div className="row tight">
        <Button variant="primary" onClick={save} disabled={!!problem}>Save</Button>
        {settings.updated_at && <span className="xs faint">Last saved {relTime(settings.updated_at)}</span>}
      </div>
    </div>
  );
}

