"""Shared fixtures.

`tiny` builds a small, hand-written world through a real `Connector`
implementation (the same interface production connectors use):

    alice (human)   okta:alice -> okta:eng -> aws:DevAdmin -> s3:GetObject on customer-pii
                    okta:alice -> okta:eng -> aws:DevAdmin -> s3:PutObject on ml-artifacts
    bob (human)     okta:bob -> okta:payments-clerks -> wd:payments:create
                    okta:bob -> okta:payments-approvers -> wd:payments:approve        (SoD!)
    carol (human)   okta:carol -> okta:platform -> aws:ProdAdmin -> iam:* on prod     (standing admin)
    dave (human, terminated) owns svc-etl; manager is carol
    svc-etl (service, owner dave) -> direct s3:GetObject on customer-pii; access key 400 days old
    helper-bot (ai_agent, owner alice) -> snowflake:ANALYST -> snowflake:PII_READER -> SELECT CUSTOMERS
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tessera.connectors.base import (  # noqa: E402
    AccountRecord,
    Connector,
    DelegationRecord,
    DiscoveryResult,
    EdgeRecord,
    GroupRecord,
    IdentityRecord,
    IdentityRef,
    PermissionRecord,
    Ref,
    ResourceRecord,
    SecretRecord,
    UsageRecord,
)
from tessera.db import init_db, make_engine  # noqa: E402
from tessera.ingest import sync_connectors  # noqa: E402
from tessera.timeutil import utcnow  # noqa: E402

NOW = utcnow() - timedelta(minutes=1)


def I(x):  # noqa: E743
    return IdentityRef(external_id=x)


def acct(system, xid):
    return Ref("account", system, xid)


def grp(system, xid):
    return Ref("group", system, xid)


def perm(system, xid):
    return Ref("perm", system, xid)


class TinyConnector(Connector):
    system = "tiny"
    display_name = "Tiny test connector"

    def discover(self) -> DiscoveryResult:
        r = DiscoveryResult()
        r.identities = [
            IdentityRecord("alice", "Alice", "human", "alice@t.example", "Engineering", manager=I("carol")),
            IdentityRecord("bob", "Bob", "human", "bob@t.example", "Finance", manager=I("carol")),
            IdentityRecord("carol", "Carol", "human", "carol@t.example", "Engineering"),
            IdentityRecord("dave", "Dave", "human", "dave@t.example", "Data", status="terminated",
                           manager=I("carol"), terminated_at=NOW - timedelta(days=10)),
            IdentityRecord("svc-etl", "svc-etl", "service", owner=I("dave")),
            IdentityRecord("helper-bot", "Helper Bot", "ai_agent", owner=I("alice")),
        ]
        r.resources = [
            ResourceRecord("aws", "customer-pii", "s3://customer-pii", "s3_bucket", "prod", ["pii"]),
            ResourceRecord("aws", "ml-artifacts", "s3://ml-artifacts", "s3_bucket", "staging"),
            ResourceRecord("aws", "prod", "aws/prod", "aws_account", "prod"),
            ResourceRecord("workday", "payments", "Supplier Payments", "business_process", "prod", ["payments"]),
            ResourceRecord("snowflake", "CUSTOMERS", "snowflake/CUSTOMERS", "database", "prod", ["pii"]),
        ]
        r.permissions = [
            PermissionRecord("aws", "get-pii", "s3:GetObject", "customer-pii"),
            PermissionRecord("aws", "put-ml", "s3:PutObject", "ml-artifacts"),
            PermissionRecord("aws", "admin-prod", "iam:*", "prod", privileged=True),
            PermissionRecord("workday", "pay-create", "payments:create", "payments"),
            PermissionRecord("workday", "pay-approve", "payments:approve", "payments"),
            PermissionRecord("snowflake", "select-customers", "snowflake:SELECT", "CUSTOMERS"),
        ]
        r.groups = [
            GroupRecord("okta", "eng", "eng"),
            GroupRecord("okta", "platform", "platform"),
            GroupRecord("okta", "payments-clerks", "payments-clerks"),
            GroupRecord("okta", "payments-approvers", "payments-approvers"),
            GroupRecord("aws", "DevAdmin", "DevAdmin", "role"),
            GroupRecord("aws", "ProdAdmin", "ProdAdmin", "role", privileged=True, requestable=True),
            GroupRecord("snowflake", "ANALYST", "ANALYST", "role"),
            GroupRecord("snowflake", "PII_READER", "PII_READER", "role"),
        ]
        r.accounts = [
            AccountRecord("okta", "alice", "alice@t.example", I("alice")),
            AccountRecord("okta", "bob", "bob@t.example", I("bob")),
            AccountRecord("okta", "carol", "carol@t.example", I("carol")),
            AccountRecord("okta", "dave", "dave@t.example", I("dave"), status="disabled"),
            AccountRecord("aws", "dave-iam", "dave", I("dave")),  # missed in offboarding
            AccountRecord("aws", "svc-etl", "svc-etl", I("svc-etl"), kind="service"),
            AccountRecord("snowflake", "HELPER_BOT", "HELPER_BOT", I("helper-bot"), kind="agent"),
        ]
        r.edges = [
            EdgeRecord(acct("okta", "alice"), grp("okta", "eng"), "member_of"),
            EdgeRecord(grp("okta", "eng"), grp("aws", "DevAdmin"), "maps_to"),
            EdgeRecord(grp("aws", "DevAdmin"), perm("aws", "get-pii"), "grants"),
            EdgeRecord(grp("aws", "DevAdmin"), perm("aws", "put-ml"), "grants"),
            EdgeRecord(acct("okta", "bob"), grp("okta", "payments-clerks"), "member_of"),
            EdgeRecord(acct("okta", "bob"), grp("okta", "payments-approvers"), "member_of"),
            EdgeRecord(grp("okta", "payments-clerks"), perm("workday", "pay-create"), "grants"),
            EdgeRecord(grp("okta", "payments-approvers"), perm("workday", "pay-approve"), "grants"),
            EdgeRecord(acct("okta", "carol"), grp("okta", "platform"), "member_of"),
            EdgeRecord(acct("okta", "carol"), grp("okta", "eng"), "member_of"),
            EdgeRecord(grp("okta", "platform"), grp("aws", "ProdAdmin"), "maps_to"),
            EdgeRecord(grp("aws", "ProdAdmin"), perm("aws", "admin-prod"), "grants"),
            EdgeRecord(acct("okta", "dave"), grp("okta", "eng"), "member_of"),
            EdgeRecord(acct("aws", "dave-iam"), perm("aws", "get-pii"), "direct_grant"),
            EdgeRecord(acct("aws", "svc-etl"), perm("aws", "get-pii"), "direct_grant"),
            EdgeRecord(acct("snowflake", "HELPER_BOT"), grp("snowflake", "ANALYST"), "member_of"),
            EdgeRecord(grp("snowflake", "ANALYST"), grp("snowflake", "PII_READER"), "maps_to"),
            EdgeRecord(grp("snowflake", "PII_READER"), perm("snowflake", "select-customers"), "grants"),
        ]
        r.secrets = [
            SecretRecord("aws", "svc-etl-key", acct("aws", "svc-etl"), "access_key", "AKIAETL",
                         NOW - timedelta(days=400)),
        ]
        r.delegations = [DelegationRecord(I("helper-bot"), I("alice"), ["snowflake:query"])]
        return r

    def stream_events(self, since: datetime | None = None):
        # alice uses PutObject on ml-artifacts daily; never touches customer-pii
        for d in range(0, 90, 3):
            yield UsageRecord(I("alice"), perm("aws", "put-ml"), NOW - timedelta(days=d), 5)
        # carol last used prod admin 75 days ago
        yield UsageRecord(I("carol"), perm("aws", "admin-prod"), NOW - timedelta(days=75), 1)
        yield UsageRecord(I("bob"), perm("workday", "pay-create"), NOW - timedelta(days=1), 3)


@pytest.fixture
def engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    init_db(eng)
    return eng


@pytest.fixture
def session(engine):
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    yield s
    s.close()


@pytest.fixture
def tiny(session):
    sync_connectors(session, [TinyConnector()])
    return session


@pytest.fixture
def ids(tiny):
    from sqlalchemy import select

    from tessera.models import Account, Group, Identity
    out = {i.external_id: i.id for i in tiny.scalars(select(Identity))}
    out.update({f"acct:{a.system}:{a.external_id}": a.id for a in tiny.scalars(select(Account))})
    out.update({f"group:{g.system}:{g.external_id}": g.id for g in tiny.scalars(select(Group))})
    return out


@pytest.fixture(scope="session")
def demo_db(tmp_path_factory):
    """A full demo-company database (seeded once per test session)."""
    from tessera.connectors.demo import demo_connectors
    from tessera.connectors.demo_company import DemoCompany
    from tessera.seed import seed_workflows

    path = tmp_path_factory.mktemp("demo") / "demo.db"
    eng = make_engine(f"sqlite:///{path}")
    init_db(eng)
    s = sessionmaker(bind=eng, expire_on_commit=False)()
    sync_connectors(s, demo_connectors(DemoCompany()))
    seed_workflows(s)
    s.close()
    return eng
