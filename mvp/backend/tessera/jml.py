"""Joiner / mover / leaver automation driven by the HRIS feed."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import audit
from .models import (
    AccessRequest,
    Account,
    AgentDelegation,
    GrantEdge,
    Group,
    HrisEvent,
    Identity,
    Secret,
)
from .timeutil import utcnow

# Birthright access by team: (system, group external id)
_ENG = [("okta", "everyone"), ("okta", "engineering"), ("github", "team/all-engineers")]
BIRTHRIGHT: dict[str, list[tuple[str, str]]] = {
    "backend": _ENG + [("okta", "eng-backend"), ("github", "team/backend")],
    "frontend": _ENG + [("okta", "eng-frontend"), ("github", "team/frontend")],
    "platform": _ENG + [("okta", "eng-platform"), ("github", "team/platform")],
    "data": [("okta", "everyone"), ("okta", "data-team"), ("github", "team/all-engineers"), ("github", "team/data"),
             ("snowflake", "role/ANALYST")],
    "security": [("okta", "everyone"), ("okta", "security-team"), ("github", "team/security")],
    "finance": [("okta", "everyone"), ("okta", "finance"), ("snowflake", "role/FINANCE_ANALYST")],
    "sales": [("okta", "everyone"), ("okta", "sales"), ("snowflake", "role/ANALYST")],
    "support": [("okta", "everyone"), ("okta", "support")],
    "people": [("okta", "everyone"), ("okta", "people-ops"), ("workday", "sg-hr-partner")],
    "exec": [("okta", "everyone"), ("okta", "executives")],
}
TEAM_BY_OKTA_GROUP = {"eng-backend": "backend", "eng-frontend": "frontend", "eng-platform": "platform",
                      "data-team": "data", "security-team": "security", "finance": "finance", "sales": "sales",
                      "support": "support", "people-ops": "people", "executives": "exec"}


def _group(session: Session, system: str, xid: str) -> Group | None:
    return session.scalars(select(Group).where(Group.system == system, Group.external_id == xid)).first()


def infer_team(session: Session, identity: Identity) -> str | None:
    for a in identity.accounts:
        if a.system != "okta":
            continue
        for e in session.scalars(select(GrantEdge).where(GrantEdge.src == f"account:{a.id}")):
            g = session.get(Group, int(e.dst.split(":")[1])) if e.dst.startswith("group:") else None
            if g and g.external_id in TEAM_BY_OKTA_GROUP:
                return TEAM_BY_OKTA_GROUP[g.external_id]
    return None


def _label(session: Session, key: str) -> str:
    kind, _, raw = key.partition(":")
    if kind == "group":
        g = session.get(Group, int(raw))
        return f"{g.system}:{g.name}" if g else key
    if kind == "account":
        a = session.get(Account, int(raw))
        return f"{a.system}:{a.username}" if a else key
    if kind == "perm":
        from .models import Permission
        p = session.get(Permission, int(raw))
        return f"{p.action} on {p.resource.name}" if p else key
    return key


# ---------------------------------------------------------------- leaver
def leaver_plan(session: Session, identity_id: int, with_impact: bool = True) -> dict:
    ident = session.get(Identity, identity_id)
    if ident is None:
        raise ValueError("unknown identity")
    manager = session.get(Identity, ident.manager_id) if ident.manager_id else None
    steps: list[dict] = []
    active_accounts = [a for a in ident.accounts if a.status == "active"]
    for a in active_accounts:
        steps.append({"action": "disable_account", "system": a.system, "target": a.username, "account_id": a.id,
                      "detail": f"Disable {a.system} account {a.username}"})
    for a in ident.accounts:
        for e in session.scalars(select(GrantEdge).where(GrantEdge.src == f"account:{a.id}")):
            steps.append({"action": "remove_grant", "system": a.system, "edge_id": e.id,
                          "target": _label(session, e.dst),
                          "detail": f"Remove {a.system}:{a.username} from {_label(session, e.dst)}"
                                    + (" (JIT)" if e.source == "jit" else "")})
    for r in session.scalars(select(AccessRequest).where(AccessRequest.identity_id == identity_id,
                                                         AccessRequest.status.in_(["pending", "approved"]))):
        steps.append({"action": "cancel_jit", "request_id": r.id, "system": "tessera",
                      "target": _label(session, f"group:{r.group_id}"),
                      "detail": f"Cancel {r.status} JIT request #{r.id}"})
    owned = session.scalars(select(Identity).where(Identity.owner_id == identity_id,
                                                   Identity.status == "active")).all()
    for nhi in owned:
        steps.append({"action": "reassign_owner", "identity_id": nhi.id, "system": "tessera", "target": nhi.name,
                      "new_owner_id": manager.id if manager else None,
                      "detail": f"Transfer ownership of {nhi.name} ({nhi.type}) to "
                                f"{manager.name if manager else 'security team'}"})
        for a in nhi.accounts:
            for s in session.scalars(select(Secret).where(Secret.account_id == a.id, Secret.status == "active")):
                steps.append({"action": "rotate_secret", "secret_id": s.id, "system": s.system, "target": s.name,
                              "detail": f"Rotate {s.kind} '{s.name}' on {nhi.name} (leaver had custody)"})
    for d in session.scalars(select(AgentDelegation).where(AgentDelegation.principal_id == identity_id)):
        agent = session.get(Identity, d.agent_id)
        steps.append({"action": "revoke_delegation", "delegation_id": d.id, "system": "tessera",
                      "target": agent.name if agent else str(d.agent_id),
                      "detail": f"Revoke delegation: {agent.name if agent else d.agent_id} acting on behalf of "
                                f"{ident.name} ({', '.join(d.scopes)})"})
    reports = session.scalars(select(Identity).where(Identity.manager_id == identity_id,
                                                     Identity.status == "active")).all()
    if reports:
        steps.append({"action": "reassign_reports", "system": "workday", "target": f"{len(reports)} direct reports",
                      "report_ids": [r.id for r in reports], "new_manager_id": manager.id if manager else None,
                      "detail": f"Move {len(reports)} direct reports to {manager.name if manager else 'TBD'}"})
    plan = {"type": "leaver", "identity": {"id": ident.id, "name": ident.name, "status": ident.status,
                                           "department": ident.department, "title": ident.title},
            "steps": steps}
    if with_impact:
        from .simulate import simulate
        sim = simulate(session, disable_account_ids=[a.id for a in active_accounts])
        mine = next((x for x in sim["identities"] if x["identity_id"] == identity_id), None)
        plan["impact"] = {
            "permissions_removed": len(mine["removed"]) if mine else 0,
            "privileged_removed": sum(1 for p in mine["removed"] if p["privileged"]) if mine else 0,
            "systems": sorted({a.system for a in active_accounts}),
            "owned_nhis": len(owned),
            "violations_resolved": sim["summary"]["violations_resolved"],
        }
    return plan


# ----------------------------------------------------------------- mover
def _birthright_groups(session: Session, team: str | None) -> dict[str, Group]:
    out = {}
    for system, xid in BIRTHRIGHT.get(team or "", []):
        g = _group(session, system, xid)
        if g:
            out[f"group:{g.id}"] = g
    return out


def mover_plan(session: Session, identity_id: int, to_team: str, from_team: str | None = None,
               new_title: str | None = None, to_department: str | None = None) -> dict:
    ident = session.get(Identity, identity_id)
    from_team = from_team or infer_team(session, ident)
    old = _birthright_groups(session, from_team)
    new = _birthright_groups(session, to_team)
    accts = {a.system: a for a in ident.accounts if a.status == "active"}
    steps = []
    for key, g in new.items():
        if key in old:
            continue
        a = accts.get(g.system)
        if a is None:
            steps.append({"action": "create_account", "system": g.system, "target": ident.email or ident.name,
                          "detail": f"Create {g.system} account for {ident.name}"})
        elif session.scalars(select(GrantEdge).where(GrantEdge.src == f"account:{a.id}", GrantEdge.dst == key)).first():
            continue
        steps.append({"action": "add_grant", "system": g.system, "group_id": g.id, "target": f"{g.system}:{g.name}",
                      "detail": f"Add to {g.system}:{g.name} (birthright for {to_team})"})
    for a in ident.accounts:
        for e in session.scalars(select(GrantEdge).where(GrantEdge.src == f"account:{a.id}")):
            if e.dst in old and e.dst not in new:
                steps.append({"action": "remove_grant", "system": a.system, "edge_id": e.id,
                              "target": _label(session, e.dst),
                              "detail": f"Remove {_label(session, e.dst)} (birthright of previous team {from_team})"})
            elif e.dst not in old and e.dst not in new:
                steps.append({"action": "review_grant", "system": a.system, "edge_id": e.id,
                              "target": _label(session, e.dst),
                              "detail": f"Flag {_label(session, e.dst)} for manager review within 30 days "
                                        f"(not birthright for {to_team})"})
    return {"type": "mover", "identity": {"id": ident.id, "name": ident.name, "department": ident.department,
                                          "title": ident.title},
            "from_team": from_team, "to_team": to_team, "new_title": new_title, "to_department": to_department,
            "steps": steps}


# ---------------------------------------------------------------- joiner
def joiner_plan(session: Session, payload: dict) -> dict:
    team = payload.get("team")
    steps = [{"action": "create_identity", "system": "tessera", "target": payload["name"],
              "detail": f"Create identity {payload['name']} ({payload.get('title')}, {payload.get('department')})"}]
    groups = _birthright_groups(session, team)
    systems = ["workday"] + sorted({g.system for g in groups.values()})
    for s in systems:
        steps.append({"action": "create_account", "system": s, "target": payload.get("email"),
                      "detail": f"Create {s} account"})
    for g in groups.values():
        steps.append({"action": "add_grant", "system": g.system, "group_id": g.id, "target": f"{g.system}:{g.name}",
                      "detail": f"Add to {g.system}:{g.name} (birthright for {team})"})
    return {"type": "joiner", "identity": {"name": payload["name"], "department": payload.get("department"),
                                           "title": payload.get("title")}, "team": team, "steps": steps}


# --------------------------------------------------------------- execute
def plan_for_event(session: Session, ev: HrisEvent, with_impact: bool = True) -> dict:
    if ev.type == "leaver":
        return leaver_plan(session, ev.identity_id, with_impact=with_impact)
    if ev.type == "mover":
        p = ev.payload
        return mover_plan(session, ev.identity_id, p["to_team"], p.get("from_team"), p.get("new_title"),
                          p.get("to_department"))
    return joiner_plan(session, ev.payload)


def _ensure_account(session: Session, ident: Identity, system: str) -> Account:
    for a in ident.accounts:
        if a.system == system and a.status == "active":
            return a
    uname = ident.email if system == "okta" else (ident.external_id if system == "workday" else
                                                  (ident.email or ident.name).split("@")[0].replace(".", "-"))
    a = Account(system=system, external_id=f"tessera-{system}-{ident.external_id}", identity_id=ident.id,
                username=uname, kind="user", status="active", created_at=utcnow())
    session.add(a)
    session.flush()
    session.refresh(ident)
    return a


def execute_event(session: Session, event_id: int, actor: str = "jml-automation") -> dict:
    ev = session.get(HrisEvent, event_id)
    if ev is None:
        raise ValueError("unknown event")
    if ev.status == "executed":
        raise ValueError("event already executed")
    plan = plan_for_event(session, ev, with_impact=False)
    now = utcnow()
    if ev.type == "joiner":
        p = ev.payload
        ident = Identity(external_id=f"emp-new-{ev.id}", name=p["name"], email=p.get("email"), type="human",
                         department=p.get("department"), title=p.get("title"), status="active", hired_at=ev.effective_at,
                         source="workday")
        mgr = session.scalars(select(Identity).where(Identity.external_id == p.get("manager_external_id"))).first()
        ident.manager_id = mgr.id if mgr else None
        session.add(ident)
        session.flush()
        ev.identity_id = ident.id
        for s in ["workday"] + sorted({st["system"] for st in plan["steps"] if st["action"] == "add_grant"}):
            _ensure_account(session, ident, s)
        for st in plan["steps"]:
            if st["action"] == "add_grant":
                _add_grant(session, ident, st)
    else:
        ident = session.get(Identity, ev.identity_id)
        for st in plan["steps"]:
            _apply_step(session, ident, st, now)
        if ev.type == "leaver":
            ident.status, ident.terminated_at = "terminated", now
        elif ev.type == "mover":
            ident.department = ev.payload.get("to_department", ident.department)
            ident.title = ev.payload.get("new_title", ident.title)
    ev.status, ev.executed_at = "executed", now
    audit(session, actor, f"jml.{ev.type}", event_id=ev.id, identity=plan["identity"]["name"],
          steps=len(plan["steps"]))
    session.commit()
    return plan


def _add_grant(session: Session, ident: Identity, st: dict) -> None:
    g = session.get(Group, st["group_id"])
    a = _ensure_account(session, ident, g.system)
    src, dst = f"account:{a.id}", f"group:{g.id}"
    if not session.scalars(select(GrantEdge).where(GrantEdge.src == src, GrantEdge.dst == dst)).first():
        session.add(GrantEdge(src=src, dst=dst, relation="member_of", source="manual"))


def _apply_step(session: Session, ident: Identity, st: dict, now: datetime) -> None:
    act = st["action"]
    if act == "disable_account":
        session.get(Account, st["account_id"]).status = "disabled"
    elif act == "remove_grant":
        e = session.get(GrantEdge, st["edge_id"])
        if e:
            session.delete(e)
    elif act == "add_grant":
        _add_grant(session, ident, st)
    elif act == "cancel_jit":
        r = session.get(AccessRequest, st["request_id"])
        r.status = "revoked" if r.status == "approved" else "denied"
        r.decided_at = now
    elif act == "reassign_owner":
        session.get(Identity, st["identity_id"]).owner_id = st["new_owner_id"]
    elif act == "rotate_secret":
        s = session.get(Secret, st["secret_id"])
        s.last_rotated_at = now
    elif act == "revoke_delegation":
        d = session.get(AgentDelegation, st["delegation_id"])
        if d:
            session.delete(d)
    elif act == "reassign_reports":
        for rid in st["report_ids"]:
            session.get(Identity, rid).manager_id = st["new_manager_id"]
    # create_account / review_grant / create_identity are informational for existing identities


def event_view(session: Session, ev: HrisEvent) -> dict:
    ident = session.get(Identity, ev.identity_id) if ev.identity_id else None
    return {"id": ev.id, "external_id": ev.external_id, "type": ev.type, "status": ev.status,
            "effective_at": ev.effective_at.isoformat(), "executed_at": ev.executed_at.isoformat() if ev.executed_at else None,
            "identity": {"id": ident.id, "name": ident.name, "department": ident.department} if ident else None,
            "payload": ev.payload}


__all__ = ["leaver_plan", "mover_plan", "joiner_plan", "execute_event", "plan_for_event", "event_view"]
