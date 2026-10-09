"""Just-in-time access: time-bound group/role membership with auto-expiry."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import audit
from .models import AccessRequest, Account, GrantEdge, Group, Identity
from .timeutil import utcnow

MAX_HOURS = 72


class JitError(ValueError):
    pass


def account_for(session: Session, identity_id: int, group: Group) -> Account:
    """Pick the account that should receive the grant: same system, else the IdP (Okta) account."""
    accts = session.scalars(select(Account).where(Account.identity_id == identity_id,
                                                  Account.status == "active")).all()
    for system in (group.system, "okta"):
        for a in accts:
            if a.system == system:
                return a
    raise JitError("identity has no active account that can receive this grant")


def create_request(session: Session, identity_id: int, group_id: int, duration_hours: float,
                   justification: str) -> AccessRequest:
    ident = session.get(Identity, identity_id)
    group = session.get(Group, group_id)
    if ident is None or group is None:
        raise JitError("unknown identity or group")
    if ident.status != "active":
        raise JitError("identity is not active")
    if not group.requestable:
        raise JitError(f"{group.name} is not eligible for just-in-time access")
    if not (0 < duration_hours <= MAX_HOURS):
        raise JitError(f"duration must be between 0 and {MAX_HOURS} hours")
    if not justification.strip():
        raise JitError("justification is required")
    acct = account_for(session, identity_id, group)
    standing = session.scalars(select(GrantEdge).where(GrantEdge.src == f"account:{acct.id}",
                                                       GrantEdge.dst == f"group:{group.id}",
                                                       GrantEdge.source != "jit")).first()
    if standing is not None:
        raise JitError(f"{ident.name} already holds {group.name} as a standing grant")
    req = AccessRequest(identity_id=identity_id, account_id=acct.id, group_id=group_id,
                        duration_hours=duration_hours, justification=justification.strip())
    session.add(req)
    session.flush()
    audit(session, ident.name, "jit.request", request_id=req.id, group=group.name, hours=duration_hours)
    session.commit()
    return req


def approve(session: Session, request_id: int, approver: str, now: datetime | None = None) -> AccessRequest:
    now = now or utcnow()
    req = session.get(AccessRequest, request_id)
    if req is None or req.status != "pending":
        raise JitError("request is not pending")
    src, dst = f"account:{req.account_id}", f"group:{req.group_id}"
    existing = session.scalars(select(GrantEdge).where(GrantEdge.src == src, GrantEdge.dst == dst)).first()
    expires = now + timedelta(hours=req.duration_hours)
    if existing is not None and existing.source != "jit":
        raise JitError("identity already holds this access as a standing grant")
    if existing is None:
        existing = GrantEdge(src=src, dst=dst, relation="member_of", source="jit", expires_at=expires)
        session.add(existing)
    else:
        existing.expires_at = expires
    session.flush()
    req.status, req.decided_at, req.decided_by, req.expires_at, req.edge_id = "approved", now, approver, expires, existing.id
    audit(session, approver, "jit.approve", request_id=req.id, expires_at=expires.isoformat())
    session.commit()
    return req


def deny(session: Session, request_id: int, approver: str, now: datetime | None = None) -> AccessRequest:
    req = session.get(AccessRequest, request_id)
    if req is None or req.status != "pending":
        raise JitError("request is not pending")
    req.status, req.decided_at, req.decided_by = "denied", now or utcnow(), approver
    audit(session, approver, "jit.deny", request_id=req.id)
    session.commit()
    return req


def revoke(session: Session, request_id: int, actor: str, now: datetime | None = None) -> AccessRequest:
    req = session.get(AccessRequest, request_id)
    if req is None or req.status != "approved":
        raise JitError("request is not active")
    _drop_edge(session, req)
    req.status = "revoked"
    req.expires_at = now or utcnow()
    audit(session, actor, "jit.revoke", request_id=req.id)
    session.commit()
    return req


def _drop_edge(session: Session, req: AccessRequest) -> None:
    if req.edge_id:
        e = session.get(GrantEdge, req.edge_id)
        if e is not None and e.source == "jit":
            session.delete(e)


def sweep_expired(session: Session, now: datetime | None = None) -> int:
    """Expire approved requests past their deadline and remove their grant edges."""
    now = now or utcnow()
    n = 0
    for req in session.scalars(select(AccessRequest).where(AccessRequest.status == "approved",
                                                           AccessRequest.expires_at <= now)):
        _drop_edge(session, req)
        req.status = "expired"
        audit(session, "system", "jit.expire", request_id=req.id)
        n += 1
    # orphan JIT edges (e.g. created directly) also expire
    for e in session.scalars(select(GrantEdge).where(GrantEdge.source == "jit", GrantEdge.expires_at <= now)):
        session.delete(e)
    session.commit()
    return n
