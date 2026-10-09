"""Load connector output into the database.

Ingestion is phased across *all* connectors so cross-system references resolve
(e.g. an Okta group -> AWS role edge emitted by the AWS connector):

    identities -> resources -> permissions -> groups -> accounts
    -> edges -> secrets -> delegations -> events
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .connectors.base import (
    Connector,
    DiscoveryResult,
    HrisEventRecord,
    IdentityRef,
    Ref,
    UsageRecord,
)
from .models import (
    Account,
    AgentDelegation,
    GrantEdge,
    Group,
    HrisEvent,
    Identity,
    Permission,
    Resource,
    Secret,
    UsageEvent,
)


class Resolver:
    def __init__(self, session: Session):
        self.s = session
        self.identity_by_xid: dict[str, int] = {}
        self.identity_by_email: dict[str, int] = {}
        self.ids: dict[tuple[str, str, str], int] = {}
        self.refresh()

    def refresh(self) -> None:
        for i in self.s.scalars(select(Identity)):
            self.identity_by_xid[i.external_id] = i.id
            if i.email:
                self.identity_by_email[i.email.lower()] = i.id
        for model, kind in ((Account, "account"), (Group, "group"), (Permission, "perm"), (Resource, "resource")):
            for o in self.s.scalars(select(model)):
                self.ids[(kind, o.system, o.external_id)] = o.id

    def identity(self, ref: IdentityRef | None) -> int | None:
        if ref is None:
            return None
        if ref.external_id and ref.external_id in self.identity_by_xid:
            return self.identity_by_xid[ref.external_id]
        if ref.email and ref.email.lower() in self.identity_by_email:
            return self.identity_by_email[ref.email.lower()]
        return None

    def node(self, ref: Ref) -> str | None:
        id_ = self.ids.get((ref.kind, ref.system, ref.external_id))
        return f"{ref.kind}:{id_}" if id_ is not None else None

    def id_of(self, kind: str, system: str, xid: str) -> int | None:
        return self.ids.get((kind, system, xid))


def _upsert(session: Session, model, keys: dict, values: dict):
    obj = session.scalars(select(model).filter_by(**keys)).first()
    if obj is None:
        obj = model(**keys, **values)
        session.add(obj)
    else:
        for k, v in values.items():
            setattr(obj, k, v)
    return obj


def ingest_discovery(session: Session, results: list[DiscoveryResult], prune_edges: bool = True) -> dict:
    stats = {k: 0 for k in ("identities", "resources", "permissions", "groups", "accounts", "edges",
                            "secrets", "delegations")}

    # 1. identities (two passes so manager/owner refs resolve)
    for r in results:
        for rec in r.identities:
            _upsert(session, Identity, {"external_id": rec.external_id}, {
                "name": rec.name, "email": rec.email, "type": rec.type, "department": rec.department,
                "title": rec.title, "status": rec.status, "description": rec.description,
                "hired_at": rec.hired_at, "terminated_at": rec.terminated_at,
            })
            stats["identities"] += 1
    session.flush()
    res = Resolver(session)
    for r in results:
        for rec in r.identities:
            ident = session.get(Identity, res.identity_by_xid[rec.external_id])
            ident.manager_id = res.identity(rec.manager)
            ident.owner_id = res.identity(rec.owner)

    # 2. resources
    for r in results:
        for rec in r.resources:
            _upsert(session, Resource, {"system": rec.system, "external_id": rec.external_id}, {
                "name": rec.name, "kind": rec.kind, "environment": rec.environment, "tags": list(rec.tags)})
            stats["resources"] += 1
    session.flush()
    res.refresh()

    # 3. permissions
    for r in results:
        for rec in r.permissions:
            rid = res.id_of("resource", rec.system, rec.resource_external_id)
            if rid is None:
                raise ValueError(f"permission {rec.external_id} references unknown resource {rec.resource_external_id}")
            _upsert(session, Permission, {"system": rec.system, "external_id": rec.external_id}, {
                "action": rec.action, "resource_id": rid, "privileged": rec.privileged})
            stats["permissions"] += 1

    # 4. groups
    for r in results:
        for rec in r.groups:
            _upsert(session, Group, {"system": rec.system, "external_id": rec.external_id}, {
                "name": rec.name, "kind": rec.kind, "privileged": rec.privileged,
                "requestable": rec.requestable, "description": rec.description})
            stats["groups"] += 1

    # 5. accounts
    for r in results:
        for rec in r.accounts:
            _upsert(session, Account, {"system": rec.system, "external_id": rec.external_id}, {
                "username": rec.username, "identity_id": res.identity(rec.identity), "kind": rec.kind,
                "status": rec.status, "created_at": rec.created_at, "last_login_at": rec.last_login_at})
            stats["accounts"] += 1
    session.flush()
    res.refresh()

    # 6. edges
    seen: set[tuple[str, str]] = set()
    for r in results:
        for rec in r.edges:
            src, dst = res.node(rec.src), res.node(rec.dst)
            if src is None or dst is None:
                raise ValueError(f"unresolved edge {rec.src} -> {rec.dst}")
            seen.add((src, dst))
            _upsert(session, GrantEdge, {"src": src, "dst": dst}, {"relation": rec.relation})
            stats["edges"] += 1
    if prune_edges:
        for e in session.scalars(select(GrantEdge).where(GrantEdge.source == "connector")):
            if (e.src, e.dst) not in seen:
                session.delete(e)

    # 7. secrets
    for r in results:
        for rec in r.secrets:
            aid = res.id_of("account", rec.account.system, rec.account.external_id)
            _upsert(session, Secret, {"system": rec.system, "external_id": rec.external_id}, {
                "account_id": aid, "kind": rec.kind, "name": rec.name, "created_at": rec.created_at,
                "last_rotated_at": rec.last_rotated_at, "last_used_at": rec.last_used_at})
            stats["secrets"] += 1

    # 8. delegations (replace wholesale)
    session.execute(delete(AgentDelegation))
    for r in results:
        for rec in r.delegations:
            session.add(AgentDelegation(agent_id=res.identity(rec.agent), principal_id=res.identity(rec.principal),
                                        scopes=list(rec.scopes), expires_at=rec.expires_at))
            stats["delegations"] += 1
    session.commit()
    return stats


def ingest_events(session: Session, events: Iterable, batch: int = 5000) -> dict:
    res = Resolver(session)
    rows: list[dict] = []
    stats = {"usage": 0, "hris": 0, "skipped": 0}
    for ev in events:
        if isinstance(ev, UsageRecord):
            iid = res.identity(ev.identity)
            pid = res.id_of("perm", ev.permission.system, ev.permission.external_id)
            if iid is None or pid is None:
                stats["skipped"] += 1
                continue
            aid = res.id_of("account", ev.account.system, ev.account.external_id) if ev.account else None
            rows.append({"identity_id": iid, "permission_id": pid, "account_id": aid, "day": ev.day,
                         "count": ev.count})
            stats["usage"] += 1
            if len(rows) >= batch:
                session.execute(UsageEvent.__table__.insert(), rows)
                rows.clear()
        elif isinstance(ev, HrisEventRecord):
            _upsert(session, HrisEvent, {"external_id": ev.external_id}, {
                "type": ev.type, "identity_id": res.identity(ev.identity), "payload": dict(ev.payload),
                "effective_at": ev.effective_at,
                # historical events were already handled by the legacy (manual) process
                "status": "executed" if ev.payload.get("historical") else "pending"})
            stats["hris"] += 1
    if rows:
        session.execute(UsageEvent.__table__.insert(), rows)
    session.commit()
    return stats


def sync_connectors(session: Session, connectors: list[Connector], since: datetime | None = None) -> dict:
    results = [c.discover() for c in connectors]
    d = ingest_discovery(session, results)
    events = (ev for c in connectors for ev in c.stream_events(since))
    e = ingest_events(session, events)
    return {"discovery": d, "events": e}
