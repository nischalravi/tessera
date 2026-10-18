/**
 * One work queue built from several sources:
 *   approvals    pending JIT requests and the request lines you may decide now (API, routed: #165)
 *   reviews      undecided items in open review campaigns (API)
 *   tasks        pending joiner / mover / leaver events (API)
 *   connection   degraded connections, for their owners and admins (deployment readiness)
 */
import { useEffect, useMemo, useState } from "react";
import { ApprovalItem, Campaign, ConnectionHealthRow, DeploymentHealth, HrisEvent, JitRequest, ReviewItem, api, useApi } from "../../api";
import { Persona, usePersona } from "../../app/persona";

export type InboxKind = "approval" | "review" | "task" | "connection";

export type InboxItem =
  | { kind: "approval"; key: string; at: string; source: "jit"; jit: JitRequest }
  | { kind: "approval"; key: string; at: string; source: "request"; item: ApprovalItem }
  | { kind: "review"; key: string; at: string; item: ReviewItem; campaign: Campaign }
  | { kind: "task"; key: string; at: string; event: HrisEvent }
  | { kind: "connection"; key: string; at: string; conn: ConnectionHealthRow };

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
      return i.source === "request" || (persona === "manager" && i.jit.identity.id !== meId);
    case "task":
      return false;
    case "connection":
      return false; // admins see every item above; owners get theirs with RBAC (DR-10)
  }
}

export function useInbox(scope: "mine" | "all" = "mine") {
  const { persona, me } = usePersona();
  const { data: jit, error: jitErr } = useApi<JitRequest[]>("/jit/requests");
  const { data: hris, error: hrisErr } = useApi<HrisEvent[]>("/hris/events");
  const campaigns = useOpenCampaigns();
  const { data: approvals, error: apprErr } = useApi<ApprovalItem[]>("/approvals/inbox");
  // Degraded connections become tasks (§7.5). A failure here must not empty the inbox.
  const { data: health } = useApi<DeploymentHealth>(persona === "admin" ? "/insights/deployment-health" : null);

  const all = useMemo<InboxItem[] | null>(() => {
    if (!jit || !hris || !campaigns || !approvals) return null;
    const out: InboxItem[] = [];
    jit.filter((r) => r.status === "pending").forEach((r) => out.push({ kind: "approval", key: `jit-${r.id}`, at: r.requested_at, source: "jit", jit: r }));
    approvals.forEach((a) => out.push({ kind: "approval", key: `req-${a.line.id}`, at: a.line.requested_at, source: "request", item: a }));
    campaigns.forEach((c) => (c.review_items ?? []).filter((it) => !it.decision).forEach((it) => out.push({ kind: "review", key: `rev-${it.id}`, at: c.created_at, item: it, campaign: c })));
    hris.filter((e) => e.status === "pending").forEach((e) => out.push({ kind: "task", key: `hris-${e.id}`, at: e.effective_at, event: e }));
    (health?.connections ?? []).filter((c) => c.state === "degraded").forEach((c) => out.push({ kind: "connection", key: `conn-${c.id}`, at: c.last_validated ?? health!.generated_at, conn: c }));
    return out;
  }, [jit, hris, campaigns, approvals, health]);

  const items = useMemo(() => (all ? (scope === "all" ? all : all.filter((i) => assigned(i, persona, me?.id))) : null), [all, scope, persona, me]);
  return { items, all, error: jitErr ?? hrisErr ?? apprErr };
}
