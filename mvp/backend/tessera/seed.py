"""Seed the database from the configured connectors (demo by default).

    python -m tessera.seed
"""
from __future__ import annotations

import time
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import jit
from .connectors import load_connectors
from .db import SessionLocal, engine, init_db
from .ingest import sync_connectors
from .models import AccessRequest, Group, Identity
from .reviews import generate_campaign
from .timeutil import utcnow


def _ident(s: Session, name: str) -> Identity:
    return s.scalars(select(Identity).where(Identity.name == name)).one()


def _role(s: Session, system: str, name: str) -> Group:
    return s.scalars(select(Group).where(Group.system == system, Group.name == name)).one()


def seed_workflows(s: Session) -> None:
    """Sample JIT requests and an initial review campaign so every page has data."""
    now = utcnow()
    prod_admin = _role(s, "aws", "ProdAdmin")
    break_glass = _role(s, "aws", "BreakGlassAdmin")
    acctadmin = _role(s, "snowflake", "ACCOUNTADMIN")
    alice = _ident(s, "Alice Okafor")
    kofi = _ident(s, "Kofi Mensah")
    sre_agent = _ident(s, "SRE On-call Agent")
    # pending: an AI agent asking for prod admin, and an engineer for a hotfix
    jit.create_request(s, sre_agent.id, prod_admin.id, 1, "PagerDuty INC-4821: restart wedged ECS tasks in prod")
    jit.create_request(s, alice.id, prod_admin.id, 4, "Hotfix for orders-db connection pool exhaustion (INC-4817)")
    # active: Kofi has break-glass for 2h
    r = jit.create_request(s, kofi.id, break_glass.id, 2, "Rotate compromised KMS grant during incident INC-4790")
    jit.approve(s, r.id, "Ingrid Lindqvist", now=now - timedelta(minutes=20))
    # expired: yesterday's Snowflake admin session
    data_eng = s.scalars(select(Identity).where(Identity.department == "Data", Identity.status == "active",
                                                Identity.name != "Sana Iyer")).all()[-1]
    r2 = jit.create_request(s, data_eng.id, acctadmin.id, 3, "Resize warehouse for quarter-end backfill")
    jit.approve(s, r2.id, "Sana Iyer", now=now - timedelta(days=1))
    jit.sweep_expired(s, now)
    generate_campaign(s, "Q4 exception-only review", unused_days=60)


def main() -> None:
    t0 = time.time()
    init_db(engine, drop=True)
    with SessionLocal() as s:
        stats = sync_connectors(s, load_connectors())
        seed_workflows(s)
        n_req = len(s.scalars(select(AccessRequest)).all())
    print(f"Seeded Tessera in {time.time() - t0:.1f}s: {stats['discovery']} usage={stats['events']} jit={n_req}")


if __name__ == "__main__":
    main()
