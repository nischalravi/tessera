"""Tessera REST API."""
from __future__ import annotations

import asyncio
import contextlib
from collections import Counter
from datetime import timedelta
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import jit, jml, reviews
from ..audit import audit
from ..connectors import load_connectors
from ..db import SessionLocal, get_session, init_db
from ..graph import GraphSnapshot, parse_key
from ..leastpriv import grant_recommendations, role_trim_recommendations
from ..models import (
    AccessRequest,
    Account,
    AgentDelegation,
    AuditLog,
    GrantEdge,
    Group,
    HrisEvent,
    Identity,
    Permission,
    Resource,
    ReviewCampaign,
    ReviewItem,
    Secret,
    UsageEvent,
)
from ..nhi import nhi_inventory, secret_view
from ..policies import SEVERITY_RANK, PolicyContext, evaluate, load_policies
from ..simulate import simulate
from ..timeutil import utcnow
from ..usage import build_usage_index


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    async def sweeper():
        while True:
            with contextlib.suppress(Exception):
                with SessionLocal() as s:
                    jit.sweep_expired(s)
            await asyncio.sleep(30)

    task = asyncio.create_task(sweeper())
    yield
    task.cancel()


app = FastAPI(title="Tessera", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class Ctx:
    """Per-request analysis context: graph snapshot, usage index, violations (lazy)."""

    def __init__(self, session: Session):
        self.s = session
        jit.sweep_expired(session)
        self.now = utcnow()
        self.graph = GraphSnapshot.from_db(session, self.now)
        self.usage = build_usage_index(session, self.now)
        self._violations = None
        self.policies = load_policies()

    @property
    def violations(self):
        if self._violations is None:
            self._violations = evaluate(self.policies, PolicyContext(self.graph, self.s, self.now))
        return self._violations


def ctx_dep(session: Session = Depends(get_session)) -> Ctx:
    return Ctx(session)


def _iso(d):
    return d.isoformat() if d else None


def _ident_brief(i: Identity | None) -> dict | None:
    if i is None:
        return None
    return {"id": i.id, "name": i.name, "type": i.type, "status": i.status, "department": i.department,
            "title": i.title}


def _risk_scores(c: Ctx, unused_days: int = 60) -> dict[int, dict]:
    vio = Counter()
    vio_sev = Counter()
    for v in c.violations:
        if v.identity_id is not None:
            vio[v.identity_id] += 1
            vio_sev[v.identity_id] += SEVERITY_RANK.get(v.severity, 1)
    out = {}
    for iid in c.graph.identities():
        eff = c.graph.effective_permissions(iid)
        unused = sum(1 for ep in eff.values() if c.usage.unused(iid, ep.perm_id, unused_days))
        priv = sum(1 for ep in eff.values() if ep.privileged)
        sens = sum(1 for ep in eff.values() if set(ep.tags) & {"pii", "payments", "financial", "payroll"})
        score = min(100, vio_sev[iid] * 6 + priv * 2 + sens + unused)
        out[iid] = {"effective": len(eff), "unused": unused, "privileged": priv, "sensitive": sens,
                    "violations": vio[iid], "risk": score}
    return out


# ------------------------------------------------------------------ meta
@app.get("/api/health")
def health():
    return {"status": "ok", "time": utcnow().isoformat()}


@app.get("/api/connectors")
def connectors(s: Session = Depends(get_session)):
    out = []
    for c in load_connectors():
        out.append({
            "system": c.system, "name": c.display_name, "type": type(c).__name__,
            "accounts": s.scalar(select(func.count(Account.id)).where(Account.system == c.system)),
            "groups": s.scalar(select(func.count(Group.id)).where(Group.system == c.system)),
            "resources": s.scalar(select(func.count(Resource.id)).where(Resource.system == c.system)),
            "permissions": s.scalar(select(func.count(Permission.id)).where(Permission.system == c.system)),
        })
    return out


@app.post("/api/connectors/sync")
def sync(s: Session = Depends(get_session)):
    from ..ingest import ingest_discovery
    stats = ingest_discovery(s, [c.discover() for c in load_connectors()], prune_edges=False)
    audit(s, "system", "connectors.sync", **stats)
    s.commit()
    return stats


@app.get("/api/summary")
def summary(c: Ctx = Depends(ctx_dep)):
    s = c.s
    idents = s.scalars(select(Identity)).all()
    by_type = Counter(i.type for i in idents if i.status == "active")
    risk = _risk_scores(c)
    total_eff = sum(r["effective"] for r in risk.values())
    total_unused = sum(r["unused"] for r in risk.values())
    sev = Counter(v.severity for v in c.violations)
    by_policy = Counter(v.policy_name for v in c.violations)
    nhis = nhi_inventory(s, c.graph, c.usage)
    stale = s.scalars(select(Secret)).all()
    stale_n = sum(1 for x in stale if (c.now - (x.last_rotated_at or x.created_at)).days > 90)
    recs = grant_recommendations(c.graph, c.usage, 60)
    trims = role_trim_recommendations(c.graph, c.usage, 60)
    top = sorted(((iid, r) for iid, r in risk.items()), key=lambda x: -x[1]["risk"])[:8]
    names = {i.id: i for i in idents}
    open_items = s.scalar(select(func.count(ReviewItem.id)).where(ReviewItem.decision.is_(None)))
    # daily usage trend (events across all identities)
    since = c.now - timedelta(days=90)
    trend_rows = s.execute(select(UsageEvent.day, func.sum(UsageEvent.count)).where(UsageEvent.day >= since)
                           .group_by(UsageEvent.day).order_by(UsageEvent.day)).all()
    return {
        "identities": {"human": by_type.get("human", 0), "service": by_type.get("service", 0),
                       "ai_agent": by_type.get("ai_agent", 0),
                       "terminated": sum(1 for i in idents if i.status == "terminated")},
        "accounts": s.scalar(select(func.count(Account.id))),
        "systems": s.scalar(select(func.count(func.distinct(Account.system)))),
        "grants": s.scalar(select(func.count(GrantEdge.id))),
        "effective_permissions": total_eff,
        "unused_permissions": total_unused,
        "unused_pct": round(100 * total_unused / total_eff, 1) if total_eff else 0,
        "violations": {"total": len(c.violations), "by_severity": dict(sev), "by_policy": dict(by_policy)},
        "nhi": {"orphaned": sum(1 for n in nhis if {"orphaned", "owner_left"} & set(n["flags"])),
                "stale_secrets": stale_n, "agents_with_pii": sum(1 for n in nhis if n["type"] == "ai_agent"
                                                                 and "pii_access" in n["flags"])},
        "jit": {"pending": s.scalar(select(func.count(AccessRequest.id)).where(AccessRequest.status == "pending")),
                "active": s.scalar(select(func.count(AccessRequest.id)).where(AccessRequest.status == "approved"))},
        "reviews": {"open_items": open_items},
        "recommendations": {"total": len(recs) + len(trims), "remove": sum(1 for r in recs if r["kind"] == "remove"),
                            "role_trim": len(trims)},
        "hris_pending": s.scalar(select(func.count(HrisEvent.id)).where(HrisEvent.status == "pending")),
        "top_risky": [{**_ident_brief(names[iid]), **r} for iid, r in top],
        "usage_trend": [{"day": (d if isinstance(d, str) else d.isoformat())[:10], "events": int(n)}
                        for d, n in trend_rows],
    }


# ------------------------------------------------------------ identities
@app.get("/api/identities")
def list_identities(type: str | None = None, q: str | None = None, status: str | None = None,
                    c: Ctx = Depends(ctx_dep)):
    risk = _risk_scores(c)
    stmt = select(Identity)
    if type:
        stmt = stmt.where(Identity.type == type)
    if status:
        stmt = stmt.where(Identity.status == status)
    out = []
    for i in c.s.scalars(stmt):
        if q and q.lower() not in f"{i.name} {i.email or ''} {i.department or ''} {i.title or ''}".lower():
            continue
        last = c.usage.by_identity.get(i.id)
        out.append({**_ident_brief(i), "email": i.email,
                    "accounts": len(i.accounts), "systems": sorted({a.system for a in i.accounts}),
                    "last_activity": _iso(last), **risk.get(i.id, {})})
    out.sort(key=lambda x: (-x.get("risk", 0), x["name"]))
    return out


@app.get("/api/identities/{identity_id}")
def identity_detail(identity_id: int, unused_days: int = 60, c: Ctx = Depends(ctx_dep)):
    s = c.s
    i = s.get(Identity, identity_id)
    if i is None:
        raise HTTPException(404, "identity not found")
    eff = c.graph.effective_permissions(identity_id)
    perms = []
    for ep in sorted(eff.values(), key=lambda e: (e.system, e.resource_name, e.action)):
        u = c.usage.describe(identity_id, ep.perm_id)
        perms.append({
            "perm_key": ep.perm_key, "action": ep.action, "system": ep.system, "resource": ep.resource_name,
            "resource_id": ep.resource_id, "environment": ep.environment, "tags": ep.tags,
            "privileged": ep.privileged, "standing": ep.standing, "usage": u,
            "unused": c.usage.unused(identity_id, ep.perm_id, unused_days),
            "paths": [c.graph.describe_path(p) for p in ep.paths],
        })
    secrets = []
    for a in i.accounts:
        for sec in s.scalars(select(Secret).where(Secret.account_id == a.id)):
            secrets.append(secret_view(sec, a, c.now))
    grants = []
    for acct, dst, ed in c.graph.grant_edges_from_accounts(identity_id):
        grants.append({"edge_id": ed.get("edge_id"), "src": acct, "dst": dst, "label": c.graph.label(dst),
                       "account": c.graph.label(acct), "relation": ed.get("relation"), "source": ed.get("source"),
                       "expires_at": _iso(ed.get("expires_at")),
                       "privileged": bool(c.graph.node(dst).get("privileged"))})
    delegations = []
    for d in s.scalars(select(AgentDelegation).where((AgentDelegation.agent_id == identity_id)
                                                     | (AgentDelegation.principal_id == identity_id))):
        delegations.append({"agent": _ident_brief(s.get(Identity, d.agent_id)),
                            "principal": _ident_brief(s.get(Identity, d.principal_id)), "scopes": d.scopes})
    owned = s.scalars(select(Identity).where(Identity.owner_id == identity_id)).all()
    return {
        **_ident_brief(i), "email": i.email, "description": i.description,
        "hired_at": _iso(i.hired_at), "terminated_at": _iso(i.terminated_at),
        "manager": _ident_brief(s.get(Identity, i.manager_id)) if i.manager_id else None,
        "owner": _ident_brief(s.get(Identity, i.owner_id)) if i.owner_id else None,
        "accounts": [{"id": a.id, "system": a.system, "username": a.username, "kind": a.kind, "status": a.status,
                      "last_login_at": _iso(a.last_login_at)} for a in i.accounts],
        "grants": grants,
        "effective_permissions": perms,
        "violations": [v.to_dict() for v in c.violations if v.identity_id == identity_id],
        "recommendations": grant_recommendations(c.graph, c.usage, unused_days, identity_id=identity_id)
        if i.status == "active" else [],
        "secrets": secrets,
        "delegations": delegations,
        "owned_identities": [_ident_brief(o) for o in owned],
        "risk": _risk_scores(c, unused_days).get(identity_id),
    }


@app.get("/api/groups")
def list_groups(requestable: bool | None = None, s: Session = Depends(get_session)):
    stmt = select(Group)
    if requestable is not None:
        stmt = stmt.where(Group.requestable == requestable)
    return [{"id": g.id, "key": f"group:{g.id}", "system": g.system, "name": g.name, "kind": g.kind,
             "privileged": g.privileged, "requestable": g.requestable, "description": g.description}
            for g in s.scalars(stmt.order_by(Group.system, Group.name))]


@app.get("/api/resources")
def list_resources(c: Ctx = Depends(ctx_dep)):
    out = []
    for r in c.s.scalars(select(Resource).order_by(Resource.system, Resource.name)):
        who = c.graph.who_can_access(r.id)
        types = Counter(c.graph.node(f"identity:{iid}")["type"] for iid in who)
        out.append({"id": r.id, "system": r.system, "name": r.name, "kind": r.kind, "environment": r.environment,
                    "tags": r.tags, "identities_with_access": len(who), "by_type": dict(types)})
    return out


# ----------------------------------------------------------------- graph
@app.get("/api/graph")
def graph_view(identity_id: int | None = None, resource_id: int | None = None,
               perm_key: str | None = None, c: Ctx = Depends(ctx_dep)):
    g = c.graph
    nodes: set[str] = set()
    edges: set[tuple[str, str]] = set()

    def add_path(p):
        nodes.update(p)
        edges.update(zip(p, p[1:]))

    if identity_id is not None:
        nodes.add(f"identity:{identity_id}")
        for pk, ep in g.effective_permissions(identity_id).items():
            if perm_key and pk != perm_key:
                continue
            for p in ep.paths:
                add_path(p + [f"resource:{ep.resource_id}"])
        for a in g.g.successors(f"identity:{identity_id}"):
            nodes.add(a)
            edges.add((f"identity:{identity_id}", a))
    elif resource_id is not None:
        nodes.add(f"resource:{resource_id}")
        for iid, eps in g.who_can_access(resource_id).items():
            for ep in eps:
                for p in ep.paths[:3]:
                    add_path(p + [f"resource:{resource_id}"])
    else:
        raise HTTPException(400, "identity_id or resource_id is required")

    def nd(k):
        d = g.node(k)
        return {"id": k, "kind": d["kind"], "label": d["label"], "system": d.get("system"),
                "privileged": bool(d.get("privileged")), "type": d.get("type"), "status": d.get("status"),
                "tags": d.get("tags") or [], "environment": d.get("environment")}

    return {
        "nodes": [nd(k) for k in sorted(nodes)],
        "edges": [{"source": a, "target": b, "relation": g.edge_data(a, b).get("relation"),
                   "source_kind": g.edge_data(a, b).get("source"), "edge_id": g.edge_data(a, b).get("edge_id")}
                  for a, b in sorted(edges)],
    }


# -------------------------------------------------------------- NHI / AI
@app.get("/api/nhi")
def nhi(type: Literal["service", "ai_agent"] | None = None, c: Ctx = Depends(ctx_dep)):
    items = nhi_inventory(c.s, c.graph, c.usage)
    return [x for x in items if type is None or x["type"] == type]


# ------------------------------------------------------- least privilege
@app.get("/api/least-privilege/recommendations")
def recommendations(unused_days: int = Query(60, ge=1, le=90), kind: str | None = None,
                    identity_type: str | None = None, c: Ctx = Depends(ctx_dep)):
    recs = grant_recommendations(c.graph, c.usage, unused_days) + role_trim_recommendations(c.graph, c.usage, unused_days)
    recs.sort(key=lambda r: -r["score"])
    if kind:
        recs = [r for r in recs if r["kind"] == kind]
    if identity_type:
        recs = [r for r in recs if r["identity_type"] == identity_type]
    return recs


class RevokeIn(BaseModel):
    edge_id: int
    dry_run: bool = True
    actor: str = "admin@larkspur.example"


@app.post("/api/least-privilege/revoke")
def revoke(body: RevokeIn, c: Ctx = Depends(ctx_dep)):
    e = c.s.get(GrantEdge, body.edge_id)
    if e is None:
        raise HTTPException(404, "grant not found")
    result = simulate(c.s, remove_edge_ids=[body.edge_id], now=c.now, policies=c.policies, usage=c.usage,
                      base=c.graph)
    result["dry_run"] = body.dry_run
    result["grant"] = {"edge_id": e.id, "src": e.src, "dst": e.dst,
                       "label": f"{c.graph.label(e.src)} → {c.graph.label(e.dst)}"}
    if not body.dry_run:
        audit(c.s, body.actor, "grant.revoke", edge_id=e.id, grant=result["grant"]["label"],
              permissions_removed=result["summary"]["permissions_removed"])
        c.s.delete(e)
        c.s.commit()
        result["applied"] = True
    return result


# -------------------------------------------------------------- policies
@app.get("/api/policies")
def policies(c: Ctx = Depends(ctx_dep)):
    counts = Counter(v.policy_id for v in c.violations)
    return [{"id": p.id, "name": p.name, "type": p.type, "severity": p.severity, "description": p.description,
             "enabled": p.enabled, "source": p.source, "violations": counts.get(p.id, 0)} for p in c.policies]


@app.get("/api/violations")
def violations(policy_id: str | None = None, c: Ctx = Depends(ctx_dep)):
    return [v.to_dict() for v in c.violations if policy_id is None or v.policy_id == policy_id]


class EdgeIn(BaseModel):
    src: str
    dst: str
    relation: str = "member_of"


class SimulateIn(BaseModel):
    remove_edge_ids: list[int] = Field(default_factory=list)
    add_edges: list[EdgeIn] = Field(default_factory=list)
    disable_account_ids: list[int] = Field(default_factory=list)


@app.post("/api/simulate")
def simulate_api(body: SimulateIn, c: Ctx = Depends(ctx_dep)):
    for e in body.add_edges:
        for k in (e.src, e.dst):
            if k not in c.graph.g:
                raise HTTPException(400, f"unknown node {k}")
        if parse_key(e.src)[0] != "account" and parse_key(e.src)[0] != "group":
            raise HTTPException(400, "edges must start at an account or group")
    try:
        return simulate(c.s, remove_edge_ids=body.remove_edge_ids, add_edges=[e.model_dump() for e in body.add_edges],
                        disable_account_ids=body.disable_account_ids, now=c.now, policies=c.policies,
                        usage=c.usage, base=c.graph)
    except KeyError as ex:
        raise HTTPException(400, str(ex))


# ------------------------------------------------------------------- JIT
def _req_view(s: Session, r: AccessRequest) -> dict:
    g = s.get(Group, r.group_id)
    a = s.get(Account, r.account_id)
    return {"id": r.id, "identity": _ident_brief(s.get(Identity, r.identity_id)),
            "group": {"id": g.id, "name": g.name, "system": g.system, "privileged": g.privileged},
            "account": f"{a.system}:{a.username}", "justification": r.justification,
            "duration_hours": r.duration_hours, "status": r.status, "requested_at": _iso(r.requested_at),
            "decided_at": _iso(r.decided_at), "decided_by": r.decided_by, "expires_at": _iso(r.expires_at)}


@app.get("/api/jit/requests")
def jit_requests(s: Session = Depends(get_session)):
    jit.sweep_expired(s)
    return [_req_view(s, r) for r in s.scalars(select(AccessRequest).order_by(AccessRequest.requested_at.desc()))]


class JitIn(BaseModel):
    identity_id: int
    group_id: int
    duration_hours: float = 4
    justification: str


class DecisionIn(BaseModel):
    approver: str = "security-oncall@larkspur.example"


@app.post("/api/jit/requests")
def jit_create(body: JitIn, s: Session = Depends(get_session)):
    try:
        r = jit.create_request(s, body.identity_id, body.group_id, body.duration_hours, body.justification)
    except jit.JitError as ex:
        raise HTTPException(400, str(ex))
    return _req_view(s, r)


@app.post("/api/jit/requests/{request_id}/{action}")
def jit_decide(request_id: int, action: Literal["approve", "deny", "revoke"], body: DecisionIn | None = None,
               s: Session = Depends(get_session)):
    who = (body or DecisionIn()).approver
    try:
        fn = {"approve": jit.approve, "deny": jit.deny, "revoke": jit.revoke}[action]
        r = fn(s, request_id, who)
    except jit.JitError as ex:
        raise HTTPException(400, str(ex))
    return _req_view(s, r)


@app.post("/api/jit/sweep")
def jit_sweep(s: Session = Depends(get_session)):
    return {"expired": jit.sweep_expired(s)}


# --------------------------------------------------------------- reviews
def _campaign_view(cmp: ReviewCampaign, with_items: bool, s: Session) -> dict:
    items = cmp.items
    out = {"id": cmp.id, "name": cmp.name, "status": cmp.status, "created_at": _iso(cmp.created_at),
           "unused_days": cmp.unused_days, "total_grants": cmp.total_grants, "auto_certified": cmp.auto_certified,
           "items": len(items), "decided": sum(1 for i in items if i.decision),
           "revoked": sum(1 for i in items if i.decision == "revoke"),
           "reasons": dict(Counter(r for i in items for r in i.reasons))}
    if with_items:
        people = {i.id: i for i in s.scalars(select(Identity))}
        out["review_items"] = [{
            "id": it.id, "identity": _ident_brief(people.get(it.identity_id)), "grant": it.grant_label,
            "edge_id": it.edge_id, "reasons": it.reasons, "context": it.context,
            "reviewer": _ident_brief(people.get(it.reviewer_id)), "decision": it.decision, "comment": it.comment,
            "decided_at": _iso(it.decided_at)} for it in items]
    return out


@app.get("/api/reviews/campaigns")
def campaigns(s: Session = Depends(get_session)):
    return [_campaign_view(x, False, s) for x in s.scalars(select(ReviewCampaign).order_by(ReviewCampaign.id.desc()))]


class CampaignIn(BaseModel):
    name: str = "Exception-only review"
    unused_days: int = 60


@app.post("/api/reviews/campaigns")
def create_campaign(body: CampaignIn, s: Session = Depends(get_session)):
    cmp = reviews.generate_campaign(s, body.name, body.unused_days)
    return _campaign_view(cmp, False, s)


@app.get("/api/reviews/campaigns/{campaign_id}")
def campaign(campaign_id: int, s: Session = Depends(get_session)):
    cmp = s.get(ReviewCampaign, campaign_id)
    if cmp is None:
        raise HTTPException(404, "campaign not found")
    return _campaign_view(cmp, True, s)


class ReviewDecisionIn(BaseModel):
    decision: Literal["keep", "revoke"]
    comment: str | None = None
    reviewer: str = "reviewer@larkspur.example"


@app.post("/api/reviews/items/{item_id}/decision")
def review_decide(item_id: int, body: ReviewDecisionIn, s: Session = Depends(get_session)):
    try:
        it = reviews.decide(s, item_id, body.decision, body.reviewer, body.comment)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return {"id": it.id, "decision": it.decision}


# ------------------------------------------------------------ HRIS / JML
@app.get("/api/hris/events")
def hris_events(s: Session = Depends(get_session)):
    evs = s.scalars(select(HrisEvent).order_by(HrisEvent.status.desc(), HrisEvent.effective_at.desc())).all()
    return [jml.event_view(s, e) for e in evs]


class HrisIn(BaseModel):
    type: Literal["joiner", "mover", "leaver"]
    identity_id: int | None = None
    payload: dict = Field(default_factory=dict)


@app.post("/api/hris/events")
def hris_create(body: HrisIn, s: Session = Depends(get_session)):
    """Simulate an HRIS feed event (as if Workday had emitted it)."""
    if body.type in ("mover", "leaver") and body.identity_id is None:
        raise HTTPException(400, "identity_id required")
    if body.type == "joiner" and not body.payload.get("name"):
        raise HTTPException(400, "payload.name required")
    if body.type == "mover" and not body.payload.get("to_team"):
        raise HTTPException(400, "payload.to_team required")
    n = s.scalar(select(func.count(HrisEvent.id))) + 1
    ev = HrisEvent(external_id=f"sim-evt-{n}-{int(utcnow().timestamp())}", type=body.type,
                   identity_id=body.identity_id, payload=body.payload, effective_at=utcnow())
    s.add(ev)
    s.commit()
    return jml.event_view(s, ev)


@app.get("/api/hris/events/{event_id}/plan")
def hris_plan(event_id: int, s: Session = Depends(get_session)):
    ev = s.get(HrisEvent, event_id)
    if ev is None:
        raise HTTPException(404, "event not found")
    if ev.status == "executed":
        return {"event": jml.event_view(s, ev), "plan": None}
    return {"event": jml.event_view(s, ev), "plan": jml.plan_for_event(s, ev)}


@app.post("/api/hris/events/{event_id}/execute")
def hris_execute(event_id: int, s: Session = Depends(get_session)):
    try:
        plan = jml.execute_event(s, event_id)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return {"executed": True, "plan": plan}


@app.get("/api/jml/leaver-plan/{identity_id}")
def leaver_plan(identity_id: int, s: Session = Depends(get_session)):
    try:
        return jml.leaver_plan(s, identity_id)
    except ValueError as ex:
        raise HTTPException(404, str(ex))


# ----------------------------------------------------------------- audit
@app.get("/api/audit")
def audit_log(limit: int = 100, s: Session = Depends(get_session)):
    rows = s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit))
    return [{"id": r.id, "at": _iso(r.at), "actor": r.actor, "action": r.action, "detail": r.detail} for r in rows]
