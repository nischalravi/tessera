import { Link } from "react-router-dom";
import { ArrowRight, FileText, GitMerge, KeyRound, Timer, Ticket, Users } from "lucide-react";
import { GuestLifecycleOverview, GuestList, GuestRecovery, MatchingSettings, guestRecoveries, fmtDate, relTime, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, Column, DataTable, EmptyState, Loading, useConfirm, useToast } from "../../components";
import { POPULATION_LABEL } from "../access/guestModel";

/**
 * Admin → Guests and external identities (guest accounts design §9.4, issue #76): one page that says where
 * each guest setting lives and what it is now. Matching, lifecycle and terms are edited on their own pages
 * (linked), where the people who work with them are; populations and the sponsor policy come from the
 * policy repository; recovery cases can be watched and cancelled here. The sections of the design that
 * have no API yet (identity-verification providers, federation metadata, partner organizations, proofing
 * agents) are listed under "Coming next" by the generic admin page, not drawn as controls that do nothing.
 */

function Card({ icon, title, to, linkLabel, children }: { icon: JSX.Element; title: string; to?: string; linkLabel?: string; children: React.ReactNode }) {
  return (
    <section className="card stack-sm" aria-label={title}>
      <h2 className="row tight">{icon} {title}</h2>
      {children}
      {to && <div><Link className="btn sm" to={to}>{linkLabel ?? "Open"} <ArrowRight size={13} aria-hidden /></Link></div>}
    </section>
  );
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function GuestsAdmin() {
  const { can } = useSession();
  const matching = useApi<MatchingSettings>(can("matching.configure") ? "/admin/matching" : null);
  const lifecycle = useApi<GuestLifecycleOverview>(can("guests.read") ? "/guest-lifecycle" : null);
  const list = useApi<GuestList>(can("guests.sponsor") ? "/guests?sponsor=me" : null);
  const terms = useApi<{ documents: { key: string }[] }>(can("guests.read") ? "/admin/terms" : null);
  const l = lifecycle.data?.settings;
  return (
    <div className="stack">
      <div className="grid g2">
        <Card icon={<GitMerge size={16} aria-hidden />} title="Identity matching" to={can("matching.configure") ? "/directory/identity-matches?tab=settings" : "/directory/identity-matches"} linkLabel={can("matching.configure") ? "Change matching settings" : "Open the review queue"}>
          {matching.data ? (
            <ul className="small plain-list">
              <li>Strong (Tier B) matches between authoritative sources: <b>{matching.data.auto_link_tier_b ? "linked automatically" : "sent to review"}</b></li>
              <li>Exact (Tier A) matches: <b>{matching.data.require_review_tier_a ? "sent to review" : "linked automatically"}</b></li>
              <li>Merges can be undone for <b>{matching.data.unmerge_window_days} days</b></li>
            </ul>
          ) : <p className="small muted">Sponsor invitations and self-registration are never linked automatically, whatever the settings say. {can("matching.configure") ? "" : "Changing the settings needs the matching.configure permission."}</p>}
        </Card>
        <Card icon={<Timer size={16} aria-hidden />} title="Guest lifecycle" to={can("guest_lifecycle.configure") ? "/governance/guest-lifecycle?view=settings" : "/governance/guest-lifecycle"} linkLabel={can("guest_lifecycle.configure") ? "Change lifecycle settings" : "Open guest lifecycle"}>
          {l ? (
            <ul className="small plain-list">
              <li>Sponsor reminded <b>{l.sponsor_reminder_days.join(", ")}</b> days before the end; guest <b>{l.guest_reminder_days || "never"}</b>{l.guest_reminder_days ? " days before" : ""}</li>
              <li>A leaver's guests: transfer within <b>{l.transfer_deadline_days} days</b>, else <b>{l.on_sponsor_departure === "suspend" ? "suspended" : "ended"}</b></li>
              <li>Grace after the last affiliation: {Object.entries(l.grace_days).map(([k, v]) => `${k} ${v}`).join(", ")} days; personal data kept {l.retention_days} days</li>
            </ul>
          ) : <p className="small muted">Reminders, sponsor-leaver transfer, grace and retention periods.</p>}
        </Card>
        <Card icon={<FileText size={16} aria-hidden />} title="Terms of use" to="/governance/terms" linkLabel="Open guest terms">
          <p className="small">{terms.data ? <>{plural(terms.data.documents.length, "document")} published. </> : null}Guests accept them at step 5 of the claim; a new version needs accepting again within its grace period.</p>
        </Card>
        <Card icon={<Ticket size={16} aria-hidden />} title="Sponsor codes" to="/access/guests?tab=registrations" linkLabel="Open the sponsor portal">
          <p className="small">Each sponsor makes their own code on <b>Guests I sponsor</b> and shares it, so a visitor can ask them without searching for their name. A code is shown once, and the request still waits for the sponsor to approve it.</p>
        </Card>
      </div>

      <section className="card flush" aria-label="Guest populations">
        <div className="card-h"><h2 className="row tight"><Users size={16} aria-hidden /> Populations and sponsor policy</h2>{list.data && <span className="xs faint">Sponsor policy {list.data.policy_version}</span>}</div>
        {!list.data ? <Loading error={list.error} kind="block" /> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th scope="col">Population</th><th scope="col" className="num">Longest term (days)</th><th scope="col" className="num">Active per sponsor</th><th scope="col">Assurance</th><th scope="col">Second approver</th></tr></thead>
              <tbody>
                {list.data.populations.map((p) => (
                  <tr key={p.key}>
                    <td><b>{POPULATION_LABEL[p.key]}</b></td>
                    <td className="num">{p.max_days}</td>
                    <td className="num">{p.max_active}</td>
                    <td className="small">IAL {p.default_ial}, AAL {p.default_aal}</td>
                    <td className="small">{p.approval_with_sensitive_bundle ? "With a sensitive bundle" : "Never"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="xs faint" style={{ padding: "8px 16px" }}>Populations and the sponsor policy are access-as-code: change them in the policy repository, then simulate on the Policies page. At most {list.data?.max_invites_per_day ?? 50} invitations per sponsor per day.</p>
      </section>

      {can("guests.read") && <Recoveries />}
    </div>
  );
}

const STATUS_TONE: Record<string, "ok" | "warning" | "critical" | "neutral" | "info"> = { issued: "info", started: "info", cooling_off: "warning", completed: "ok", cancelled: "neutral", expired: "neutral" };

/** Recovery cases (issue #73): a guest who lost their sign-in re-proves identity before a new one is set up. */
function Recoveries() {
  const { can } = useSession();
  const { data, error, reload } = useApi<{ recoveries: GuestRecovery[] }>("/guest-recoveries");
  const toast = useToast();
  const confirm = useConfirm();
  const cols: Column<GuestRecovery>[] = [
    { id: "who", header: "Person", sort: (r) => r.identity_id, cell: (r) => <Link to={`/directory/identities/${r.identity_id}`}>Identity {r.identity_id}</Link> },
    { id: "status", header: "Status", sort: (r) => r.status, csv: (r) => r.status, cell: (r) => <Badge tone={STATUS_TONE[r.status] ?? "neutral"}>{r.status.replace(/_/g, " ")}</Badge> },
    { id: "ial", header: "Proves", sort: (r) => r.required_ial, cell: (r) => <span className="small">IAL {r.required_ial}{r.privileged && " · privileged"}</span> },
    { id: "cool", header: "Cooling off until", hideNarrow: true, cell: (r) => (r.cooling_until ? <span className="small nowrap">{fmtDate(r.cooling_until)}</span> : <span className="faint">no</span>) },
    { id: "at", header: "Started", sort: (r) => r.created_at, csv: (r) => r.created_at, cell: (r) => <span className="small nowrap" title={fmtDate(r.created_at)}>{relTime(r.created_at)}</span> },
    {
      id: "act", header: "Actions",
      cell: (r) => (r.status === "issued" || r.status === "started" || r.status === "cooling_off") && can("guests.sponsor") ? (
        <Button size="sm" variant="ghost" onClick={async () => {
          const reason = await confirm({ title: "Cancel this recovery?", body: "The recovery link stops working. The person can ask again.", confirmLabel: "Cancel recovery", danger: true, reason: { label: "Reason", required: true } });
          if (reason === null) return;
          try {
            await guestRecoveries.cancel(r.id, reason);
            toast("Recovery cancelled");
            reload();
          } catch (e) {
            toast(String((e as Error).message ?? e), { kind: "error" });
          }
        }}>Cancel</Button>
      ) : null,
    },
  ];
  return (
    <section aria-label="Recovery cases" className="stack-sm">
      <h2 className="row tight"><KeyRound size={16} aria-hidden /> Recovery cases</h2>
      <p className="small muted">A sponsor or help desk starts recovery for a guest who lost their sign-in. The guest proves who they are again at the level they first reached; a sponsor's say-so alone never restores access.</p>
      {error && <Callout tone="bad">{error}</Callout>}
      <DataTable
        id="guest-recoveries"
        rows={data?.recoveries ?? null}
        error={error}
        rowKey={(r) => r.id}
        columns={cols}
        initialSort={["at", 1]}
        searchText={(r) => `${r.identity_id} ${r.status} ${r.reason}`}
        searchPlaceholder="Search recovery cases…"
        filters={[{ id: "status", label: "Status", options: Object.keys(STATUS_TONE).map((v) => ({ value: v, label: v.replace(/_/g, " ") })), get: (r) => r.status }]}
        onRefresh={reload}
        rowLabel={(r) => `Recovery for identity ${r.identity_id}`}
        empty={<EmptyState title="No recovery cases" icon={<KeyRound size={18} />}>Cases appear when a sponsor starts recovery for a guest.</EmptyState>}
      />
    </section>
  );
}
