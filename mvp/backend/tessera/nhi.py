"""Non-human identity and AI agent posture."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .graph import GraphSnapshot
from .models import Account, AgentDelegation, Identity, Secret
from .usage import UsageIndex

STALE_SECRET_DAYS = 90
DORMANT_DAYS = 30


def secret_view(sec: Secret, acct: Account, now) -> dict:
    ref = sec.last_rotated_at or sec.created_at
    age = (now - ref).days
    return {
        "id": sec.id, "name": sec.name, "kind": sec.kind, "system": sec.system, "account": acct.username,
        "created_at": sec.created_at.isoformat(), "age_days": age, "status": sec.status,
        "last_rotated_at": sec.last_rotated_at.isoformat() if sec.last_rotated_at else None,
        "last_used_at": sec.last_used_at.isoformat() if sec.last_used_at else None,
        "last_used_days": (now - sec.last_used_at).days if sec.last_used_at else None,
        "stale": age > STALE_SECRET_DAYS,
    }


def nhi_inventory(session: Session, graph: GraphSnapshot, usage: UsageIndex) -> list[dict]:
    now = usage.now
    people = {i.id: i for i in session.scalars(select(Identity))}
    secrets_by_identity: dict[int, list[dict]] = {}
    for sec, acct in session.execute(select(Secret, Account).join(Account, Secret.account_id == Account.id)):
        if acct.identity_id is not None:
            secrets_by_identity.setdefault(acct.identity_id, []).append(secret_view(sec, acct, now))
    delegations: dict[int, list[AgentDelegation]] = {}
    for d in session.scalars(select(AgentDelegation)):
        delegations.setdefault(d.agent_id, []).append(d)

    out = []
    for i in people.values():
        if i.type == "human":
            continue
        eff = graph.effective_permissions(i.id)
        owner = people.get(i.owner_id) if i.owner_id else None
        secrets = secrets_by_identity.get(i.id, [])
        last = usage.by_identity.get(i.id)
        flags = []
        if owner is None:
            flags.append("orphaned")
        elif owner.status != "active":
            flags.append("owner_left")
        if any(s["stale"] for s in secrets):
            flags.append("stale_secret")
        if last is None or (now - last).days >= DORMANT_DAYS:
            flags.append("dormant")
        if any(ep.privileged for ep in eff.values()):
            flags.append("privileged")
        if any("pii" in ep.tags for ep in eff.values()):
            flags.append("pii_access")
        accounts = [{"id": a.id, "system": a.system, "username": a.username, "kind": a.kind, "status": a.status}
                    for a in i.accounts]
        item = {
            "id": i.id, "name": i.name, "type": i.type, "kind": i.title, "description": i.description,
            "status": i.status,
            "owner": {"id": owner.id, "name": owner.name, "status": owner.status,
                      "department": owner.department} if owner else None,
            "systems": sorted({a["system"] for a in accounts}),
            "accounts": accounts,
            "secrets": secrets,
            "oldest_secret_days": max((s["age_days"] for s in secrets), default=None),
            "effective_permissions": len(eff),
            "privileged_permissions": sum(1 for ep in eff.values() if ep.privileged),
            "last_activity": last.isoformat() if last else None,
            "days_since_activity": (now - last).days if last else None,
            "flags": flags,
            "risk": _risk(flags),
        }
        if i.type == "ai_agent":
            item["delegations"] = [_delegation_view(d, i, people, graph) for d in delegations.get(i.id, [])]
        out.append(item)
    out.sort(key=lambda x: (-x["risk"], x["name"]))
    return out


def _risk(flags: list[str]) -> int:
    w = {"orphaned": 30, "owner_left": 30, "stale_secret": 15, "dormant": 10, "privileged": 20, "pii_access": 20}
    return min(100, sum(w.get(f, 0) for f in flags))


def _delegation_view(d: AgentDelegation, agent: Identity, people: dict, graph: GraphSnapshot) -> dict:
    principal = people.get(d.principal_id)
    agent_eff = graph.effective_permissions(agent.id)
    principal_eff = graph.effective_permissions(principal.id) if principal else {}
    exceeds = [f"{ep.action} on {ep.resource_name}" for pk, ep in agent_eff.items() if pk not in principal_eff]
    owner = people.get(agent.owner_id) if agent.owner_id else None
    chain = []
    if owner:
        chain.append({"role": "owner", "name": owner.name, "status": owner.status})
    chain.append({"role": "agent", "name": agent.name, "status": agent.status})
    if principal:
        chain.append({"role": "on_behalf_of", "name": principal.name, "status": principal.status})
    return {
        "principal": {"id": principal.id, "name": principal.name, "status": principal.status} if principal else None,
        "scopes": d.scopes,
        "chain": chain,
        "exceeds_principal": exceeds,
        "expires_at": d.expires_at.isoformat() if d.expires_at else None,
    }
