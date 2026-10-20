import { Link } from "react-router-dom";
import { GuestList, GuestProfile, IdentityBundle, IdentityMatchList, IdentityMerge, PersonAffiliations, fmtDate, fmtDay, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, EmptyState, Loading } from "../../components";
import { INVITATION_LABEL, INVITATION_TONE, POPULATION_LABEL, STATE_LABEL as SPONSORSHIP_LABEL, STATE_TONE as SPONSORSHIP_TONE } from "../access/guestModel";
import { STATE_LABEL, STATE_TONE, claimSummary, matchesFor, mergesFor } from "./affiliationModel";

/**
 * The guest-account sections of a person's page (guest accounts design §9.4, issue #76): who they are
 * to the organization (lifecycle state, assurance, claim), the sponsorships around them, where their
 * record came from, how they were matched or merged, and which terms they accepted. Every section
 * reads an endpoint that enforces its own permission; the gates below only avoid asking for what would be
 * refused. Nothing here shows a secret: identifiers are masked, source records list attribute names only.
 */

const CLAIM_LABEL = { claimed: "Claimed", in_progress: "In progress", invited: "Invited, not claimed", expired: "Invitation expired", none: "No invitation" } as const;
const CLAIM_TONE = { claimed: "ok", in_progress: "info", invited: "info", expired: "warning", none: "neutral" } as const;

const heading = (id: string, text: string) => <h3 id={id} style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>{text}</h3>;

/** Lifecycle state, identity assurance and claim status in one card. */
export function IdentityCard({ identityId }: { identityId: number }) {
  const { can } = useSession();
  const aff = useApi<PersonAffiliations>(`/identities/${identityId}/affiliations`);
  const bundle = useApi<IdentityBundle>(can("guests.read") ? `/identities/${identityId}/access-bundle` : null);
  const list = useApi<GuestList>(can("guests.sponsor") ? `/guests?sponsor=${can("guests.read") ? "all" : "me"}` : null);
  const mine = (list.data?.rows ?? []).filter((s) => s.guest.id === identityId);
  const claim = claimSummary(mine.map((s) => s.invitation));
  if (!aff.data) return <Loading error={aff.error} kind="block" />;
  return (
    <section className="stack-sm" aria-labelledby={`idcard-${identityId}`}>
      {heading(`idcard-${identityId}`, "Lifecycle and assurance")}
      <dl className="kv">
        <dt>Lifecycle state</dt><dd><Badge tone={STATE_TONE[aff.data.lifecycle_state]}>{STATE_LABEL[aff.data.lifecycle_state]}</Badge></dd>
        {bundle.data && <><dt>Identity assurance</dt><dd>IAL {bundle.data.ial}, AAL {bundle.data.aal}</dd></>}
        {list.data && mine.length > 0 && <><dt>Claim</dt><dd><Badge tone={CLAIM_TONE[claim]}>{CLAIM_LABEL[claim]}</Badge></dd></>}
      </dl>
    </section>
  );
}

/** The sponsorships in which the person is the guest or the sponsor. */
export function SponsorshipsSection({ identityId }: { identityId: number }) {
  const { can } = useSession();
  const scope = can("guests.read") ? "all" : "me";
  const { data, error } = useApi<GuestList>(can("guests.sponsor") ? `/guests?sponsor=${scope}` : null);
  if (!can("guests.sponsor")) return null;
  if (!data) return <Loading error={error} kind="block" />;
  const rows = data.rows.filter((s) => s.guest.id === identityId || s.sponsor.id === identityId);
  return (
    <section className="stack-sm" aria-labelledby={`sp-${identityId}`}>
      {heading(`sp-${identityId}`, "Sponsorships")}
      {rows.length === 0 ? <EmptyState title="No sponsorships">This person is not a guest and sponsors nobody{scope === "me" ? " you can see" : ""}.</EmptyState> : (
        <div className="table-scroll">
          <table>
            <thead><tr><th scope="col">Role</th><th scope="col">With</th><th scope="col">Term</th><th scope="col">State</th><th scope="col">Invitation</th></tr></thead>
            <tbody>
              {rows.map((s) => {
                const asGuest = s.guest.id === identityId;
                const other = asGuest ? s.sponsor : s.guest;
                return (
                  <tr key={s.id}>
                    <td className="small">{asGuest ? `${POPULATION_LABEL[s.population]} guest` : "Sponsor"}</td>
                    <td><Link to={`/directory/identities/${other.id}`}>{other.name}</Link></td>
                    <td className="small nowrap"><Link to={`/access/guests?${scope === "all" ? "tab=all&" : ""}selected=${encodeURIComponent(s.id)}`}>{fmtDay(s.starts_at)} to {fmtDay(s.ends_at)}</Link></td>
                    <td><Badge tone={SPONSORSHIP_TONE[s.state]}>{SPONSORSHIP_LABEL[s.state]}</Badge></td>
                    <td><Badge tone={INVITATION_TONE[s.invitation]}>{INVITATION_LABEL[s.invitation]}</Badge></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** Source records (where the person's data came from) and the terms they accepted. */
export function SourceAndTerms({ identityId }: { identityId: number }) {
  const { can } = useSession();
  const { data, error } = useApi<GuestProfile>(can("guests.read") ? `/identities/${identityId}/guest-profile` : null);
  if (!can("guests.read")) return null;
  if (!data) return <Loading error={error} kind="block" />;
  return (
    <>
      <section className="stack-sm" aria-labelledby={`src-${identityId}`}>
        {heading(`src-${identityId}`, "Source records")}
        {data.source_records.length === 0 ? <EmptyState title="No source records">Nothing from an HR or student system, intake or sponsor invitation is attached.</EmptyState> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th scope="col">System</th><th scope="col">Reference</th><th scope="col">Carries</th><th scope="col">Received</th></tr></thead>
              <tbody>
                {data.source_records.map((r) => (
                  <tr key={r.id}>
                    <td>{r.system}{r.status !== "active" && <> <Badge>{r.status}</Badge></>}</td>
                    <td className="small sys">{r.system_id}</td>
                    <td className="xs faint">{r.attributes.join(", ") || "nothing"}</td>
                    <td className="small nowrap">{fmtDay(r.received_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="xs faint">References are masked and values are never shown here. Source records move with a merge and come back with an unmerge.</p>
      </section>
      <section className="stack-sm" aria-labelledby={`terms-${identityId}`}>
        {heading(`terms-${identityId}`, "Terms accepted")}
        {data.terms_acceptances.length === 0 ? <p className="small muted">No terms documents accepted.</p> : (
          <ul className="plain-list">
            {data.terms_acceptances.map((t, i) => (
              <li key={i} className="small"><b>{t.key}</b> version {t.version} <span className="faint">({t.context.replace(/_/g, " ")}, {fmtDate(t.accepted_at)})</span></li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}

/** Merges the person took part in and the matches that concerned them. Undo is on Account matches → Merges. */
export function MatchHistory({ identityId }: { identityId: number }) {
  const { can } = useSession();
  const merges = useApi<IdentityMerge[]>("/identity-merges");
  const matches = useApi<IdentityMatchList>(can("identity_matches.review") ? "/identity-matches?status=decided" : null);
  if (!merges.data) return <Loading error={merges.error} kind="block" />;
  const ms = mergesFor(merges.data, identityId);
  const xs = matches.data ? matchesFor(matches.data.items, identityId) : [];
  return (
    <section className="stack-sm" aria-labelledby={`mh-${identityId}`}>
      {heading(`mh-${identityId}`, "Match and merge history")}
      {ms.length === 0 && xs.length === 0 ? <p className="small muted">This person has never been matched or merged.</p> : (
        <ul className="timeline">
          {ms.map((m) => (
            <li key={m.id}>
              <b>{m.merged_id === identityId ? `Merged into ${m.survivor_name}` : `${m.merged_name} merged into this person`}</b>{" "}
              <span className="faint">{fmtDate(m.merged_at)} by {m.merged_by}</span>
              <div className="small muted">{m.reason}</div>
              <div className="small">{m.unmerged_at ? <Badge tone="outline">Undone {fmtDate(m.unmerged_at)}</Badge> : Date.parse(m.unmerge_before) > Date.now()
                ? <>Can be undone until {fmtDate(m.unmerge_before)}. <Link to="/directory/matches?tab=merges">Account matches → Merges</Link></> : <Badge>Final</Badge>}</div>
            </li>
          ))}
          {xs.map((i) => (
            <li key={i.id}>
              <b>Match review: {i.subject.name} ({i.candidates.find((c) => c.candidate_id === identityId)?.status.replace(/_/g, " ") ?? i.status})</b>{" "}
              <span className="faint">{fmtDate(i.received_at)}</span>
              <div className="small muted">{i.candidates[0]?.reason}</div>
            </li>
          ))}
        </ul>
      )}
      {can("identity_matches.review") && <Link className="small" to="/directory/identity-matches?tab=decided">Open decided identity matches</Link>}
    </section>
  );
}
