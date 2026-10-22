/**
 * One work queue built from several sources:
 *   approvals    pending JIT requests, the request lines you may decide now (API, routed: #165) and
 *                the removal requests you may decide (API: manager, delegate or requests.decide)
 *   reviews      undecided items in open review campaigns (API)
 *   tasks        pending joiner / mover / leaver events (API)
 *   connection   degraded connections, for their owners and admins (deployment readiness)
 *   loader       group loader runs a failsafe is holding (GET /groups/loader-tasks: those you administer)
 *   guest        sponsorship approvals, registration requests, identity-match reviews and guest lifecycle
 *                tasks (guest accounts design §9.4). Each endpoint already routes to the caller, so the
 *                list is the caller's; the permission gates only avoid asking for what would be refused.
 */
import { useEffect, useMemo, useState } from "react";
import {
  ApprovalItem, Campaign, ConnectionHealthRow, DeploymentHealth, GuestLifecycleItem, HrisEvent, IdentityMatchList, JitRequest,
  LoaderTask, ReadinessTask, RegistrationRequest, RemovalRequest, ReviewItem, Sponsorship, api, removalsPath, useApi,
} from "../../api";
import { GuestInboxItem, guestInboxItems } from "./guestItems";
import { Persona, usePersona } from "../../app/persona";
import { useSession } from "../../app/auth";

export type InboxKind = "approval" | "review" | "task" | "connection" | "guest" | "loader";

export type { GuestInboxItem } from "./guestItems";

export type InboxItem =
  | { kind: "approval"; key: string; at: string; source: "jit"; jit: JitRequest }
  | { kind: "approval"; key: string; at: string; source: "request"; item: ApprovalItem }
  | { kind: "approval"; key: string; at: string; source: "removal"; removal: RemovalRequest }
  | { kind: "review"; key: string; at: string; item: ReviewItem; campaign: Campaign }
  | { kind: "task"; key: string; at: string; event: HrisEvent }
  | { kind: "connection"; key: string; at: string; conn: ConnectionHealthRow; task?: ReadinessTask }
  | { kind: "guest"; key: string; at: string; guest: GuestInboxItem }
  | { kind: "loader"; key: string; at: string; task: LoaderTask };

/** Full detail for each open campaign; refetches when any write happens. */
export function useOpenCampaigns() {
  const { data: list } = useApi<Campaign[]>("/reviews/campaigns");
  const [details, setDetails] = useState<Campaign[] | null>(null);
  const ids = (list ?? []).filter((c) => c.status === "open").map((c) => c.id).join(",");
  const stamp = (list ?? []).map((c) => c.decided).join(",");
  useEffect(() => {
    if (!list) return;
    let alive = true;
    Promise.all(ids ? ids.split(",").map((id) => api<Campaign>(`/reviews/campaigns/${id}`)) : [])
      .then((ds) => alive && setDetails(ds))
      .catch(() => alive && setDetails([]));
    return () => {
      alive = false;
    };
  }, [ids, stamp, list]);
  return details;
}

function assigned(i: InboxItem, persona: Persona, meId: number | undefined): boolean {
  if (persona === "admin") return true;
  switch (i.kind) {
    case "review":
      return i.item.reviewer?.id === meId;
    case "approval":
      // request lines come from GET /api/approvals/inbox: the API routed them to you
      return i.source === "request" || i.source === "removal" || (persona === "manager" && i.jit.identity.id !== meId);
    case "task":
      return false;
    case "connection":
      return false; // admins see every item above; owners get theirs with RBAC (DR-10)
    case "guest":
      return true; // the API routed each of them to the signed-in person
    case "loader":
      return true; // the API lists only the runs of folders you administer
  }
}

export function useInbox(scope: "mine" | "all" = "mine") {
  const { persona, me } = usePersona();
  const { can } = useSession();
  const { data: jit, error: jitErr } = useApi<JitRequest[]>("/jit/requests");
  const { data: hris, error: hrisErr } = useApi<HrisEvent[]>("/hris/events");
  const campaigns = useOpenCampaigns();
  const { data: approvals, error: apprErr } = useApi<ApprovalItem[]>("/approvals/inbox");
  const { data: removalReqs, error: removalErr } = useApi<RemovalRequest[]>(removalsPath("approvals"));
  // Degraded connections become tasks (§7.5). A failure here must not empty the inbox.
  const { data: health } = useApi<DeploymentHealth>(persona === "admin" && can("connections.read") ? "/insights/deployment-health" : null);

  // Guest work. A failure of any source must not empty the inbox, so none of them gates `all`.
  const { data: gApprovals } = useApi<Sponsorship[]>(can("sponsorships.approve") ? "/sponsorships/approvals" : null);
  const { data: gRegs } = useApi<{ registrations: RegistrationRequest[] }>(can("guests.sponsor") ? "/guest-registrations" : null);
  const { data: gMatches } = useApi<IdentityMatchList>(can("identity_matches.review") ? "/identity-matches?status=review" : null);
  const { data: loaderTasks } = useApi<{ items: LoaderTask[] }>(can("groups.read") ? "/groups/loader-tasks" : null);
  const { data: gTasks } = useApi<{ tasks: GuestLifecycleItem[] }>(can("guests.sponsor") ? "/guest-lifecycle/tasks" : null);

  const all = useMemo<InboxItem[] | null>(() => {
    if (!jit || !hris || !campaigns || !approvals || !removalReqs) return null;
    const out: InboxItem[] = [];
    jit.filter((r) => r.status === "pending").forEach((r) => out.push({ kind: "approval", key: `jit-${r.id}`, at: r.requested_at, source: "jit", jit: r }));
    approvals.forEach((a) => out.push({ kind: "approval", key: `req-${a.line.id}`, at: a.line.requested_at, source: "request", item: a }));
    removalReqs.forEach((q) => out.push({ kind: "approval", key: `rem-${q.id}`, at: q.requested_at, source: "removal", removal: q }));
    campaigns.forEach((c) => (c.review_items ?? []).filter((it) => !it.decision).forEach((it) => out.push({ kind: "review", key: `rev-${it.id}`, at: c.created_at, item: it, campaign: c })));
    hris.filter((e) => e.status === "pending").forEach((e) => out.push({ kind: "task", key: `hris-${e.id}`, at: e.effective_at, event: e }));
    (health?.connections ?? []).filter((c) => c.state === "degraded").forEach((c) => {
      const task = health!.tasks.find((t) => t.connection_id === c.id); // the server's task carries the reason and the owner
      out.push({ kind: "connection", key: `conn-${c.id}`, at: task?.since ?? c.last_validated ?? health!.generated_at, conn: c, task });
    });
    (loaderTasks?.items ?? []).forEach((t) => out.push({ kind: "loader", key: `loader-${t.run_id}`, at: t.held_at, task: t }));
    out.push(...guestInboxItems({ sponsorships: gApprovals, registrations: gRegs?.registrations, matches: gMatches?.items, tasks: gTasks?.tasks }));
    return out;
  }, [jit, hris, campaigns, approvals, removalReqs, health, gApprovals, gRegs, gMatches, gTasks, loaderTasks]);

  const items = useMemo(() => (all ? (scope === "all" ? all : all.filter((i) => assigned(i, persona, me?.id))) : null), [all, scope, persona, me]);
  return { items, all, error: jitErr ?? hrisErr ?? apprErr ?? removalErr };
}
