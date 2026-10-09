"""Exception-only access review campaigns.

Rather than asking managers to rubber-stamp every grant, a campaign only
contains grants that are risky: unused, implicated in a policy violation,
held by an orphaned NHI or a leaver, or privileged and not recently used.
Everything else is auto-certified with the evidence recorded.
"""
from __future__ import annotations

from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import audit
from .graph import GraphSnapshot, perms_via_edge
from .models import GrantEdge, Identity, ReviewCampaign, ReviewItem
from .policies import PolicyContext, evaluate, load_policies
from .timeutil import utcnow
from .usage import UsageIndex, build_usage_index


def generate_campaign(session: Session, name: str, unused_days: int = 60, graph: GraphSnapshot | None = None,
                      usage: UsageIndex | None = None) -> ReviewCampaign:
    now = utcnow()
    graph = graph or GraphSnapshot.from_db(session, now)
    usage = usage or build_usage_index(session, now)
    violations = evaluate(load_policies(), PolicyContext(graph, session, now))
    viol_edges: dict[tuple[str, str], list[str]] = {}
    for v in violations:
        for e in v.edges:
            viol_edges.setdefault(tuple(e), []).append(v.policy_name)
    people = {i.id: i for i in session.scalars(select(Identity))}
    security_lead = next((i for i in people.values() if i.title == "Head of Security"), None)

    # peer coverage: how common is each grant target within a department
    dept_sizes = Counter(i.department for i in people.values() if i.type == "human" and i.status == "active")
    target_by_dept: Counter = Counter()
    for iid in graph.identities():
        d = people[iid].department
        for _, dst, _ in graph.grant_edges_from_accounts(iid):
            target_by_dept[(d, dst)] += 1

    camp = ReviewCampaign(name=name, unused_days=unused_days)
    session.add(camp)
    total = 0
    for iid in graph.identities():
        ident = people[iid]
        eff = graph.effective_permissions(iid)
        owner = people.get(ident.owner_id) if ident.owner_id else None
        for acct, dst, ed in graph.grant_edges_from_accounts(iid):
            if ed.get("edge_id") is None or ed.get("source") == "jit":
                continue
            if graph.node(acct).get("status") != "active":
                continue
            via = perms_via_edge(eff, (acct, dst), graph)
            if not via:
                continue
            total += 1
            stats = [usage.get(iid, ep.perm_id) for ep in via]
            used = [s for s in stats if s.last_used and (now - s.last_used).days < unused_days]
            last = max((s.last_used for s in stats if s.last_used), default=None)
            reasons = []
            if not used:
                reasons.append(f"unused_{unused_days}d")
            privileged = graph.node(dst).get("privileged") or any(ep.privileged for ep in via)
            if privileged and (last is None or (now - last).days >= 30):
                reasons.append("privileged_idle")
            if (acct, dst) in viol_edges:
                reasons.append("policy_violation")
            if ident.status == "terminated":
                reasons.append("terminated_identity")
            if ident.type != "human" and (owner is None or owner.status != "active"):
                reasons.append("orphaned_nhi")
            if not reasons:
                continue
            if ident.type == "human":
                reviewer = people.get(ident.manager_id) if ident.manager_id else None
            else:
                reviewer = owner if owner and owner.status == "active" else None
            reviewer = reviewer or security_lead
            dept_n = dept_sizes.get(ident.department) or 0
            peers = target_by_dept[(ident.department, dst)]
            session.add(ReviewItem(
                campaign=camp, identity_id=iid, edge_id=ed["edge_id"], edge_src=acct, edge_dst=dst,
                grant_label=f"{graph.label(acct)} → {graph.label(dst)}", reasons=reasons,
                reviewer_id=reviewer.id if reviewer else None,
                context={
                    "permissions": len(via),
                    "permissions_used": len(used),
                    "last_used": last.isoformat() if last else None,
                    "days_since_used": (now - last).days if last else None,
                    "events_90d": sum(s.events_90d for s in stats),
                    "privileged": bool(privileged),
                    "sensitive": sorted({t for ep in via for t in ep.tags}),
                    "violations": sorted(set(viol_edges.get((acct, dst), []))),
                    "peer_coverage": round(peers / dept_n, 2) if ident.type == "human" and dept_n else None,
                    "sample_permissions": [f"{ep.action} on {ep.resource_name}" for ep in via[:4]],
                },
            ))
    session.flush()
    camp.total_grants = total
    camp.auto_certified = total - len(camp.items)
    audit(session, "system", "review.campaign_created", campaign=name, items=len(camp.items), total=total)
    session.commit()
    return camp


def decide(session: Session, item_id: int, decision: str, reviewer: str, comment: str | None = None) -> ReviewItem:
    if decision not in ("keep", "revoke"):
        raise ValueError("decision must be keep or revoke")
    item = session.get(ReviewItem, item_id)
    if item is None:
        raise ValueError("unknown review item")
    item.decision, item.comment, item.decided_at = decision, comment, utcnow()
    if decision == "revoke":
        e = session.scalars(select(GrantEdge).where(GrantEdge.src == item.edge_src,
                                                    GrantEdge.dst == item.edge_dst)).first()
        if e is not None:
            session.delete(e)
    audit(session, reviewer, f"review.{decision}", item_id=item.id, grant=item.grant_label)
    camp = item.campaign
    if all(i.decision for i in camp.items):
        camp.status = "completed"
    session.commit()
    return item
