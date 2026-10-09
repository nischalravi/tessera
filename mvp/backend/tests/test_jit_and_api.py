from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from tessera import jit
from tessera.graph import GraphSnapshot
from tessera.models import AccessRequest
from tessera.timeutil import utcnow


def test_jit_lifecycle(tiny, ids):
    with pytest.raises(jit.JitError):
        jit.create_request(tiny, ids["alice"], ids["group:okta:eng"], 2, "not requestable")
    req = jit.create_request(tiny, ids["alice"], ids["group:aws:ProdAdmin"], 2, "incident")
    assert req.status == "pending"
    now = utcnow()
    jit.approve(tiny, req.id, "approver", now=now)
    eff = GraphSnapshot.from_db(tiny, now).effective_permissions(ids["alice"])
    assert any(ep.action == "iam:*" and ep.jit_only for ep in eff.values())
    assert jit.sweep_expired(tiny, now + timedelta(hours=1)) == 0
    assert jit.sweep_expired(tiny, now + timedelta(hours=3)) == 1
    assert tiny.get(AccessRequest, req.id).status == "expired"
    eff = GraphSnapshot.from_db(tiny, now + timedelta(hours=3)).effective_permissions(ids["alice"])
    assert not any(ep.action == "iam:*" for ep in eff.values())


def test_jit_rejects_standing_duplicate(tiny, ids):
    from tessera.models import GrantEdge
    tiny.add(GrantEdge(src=f"account:{ids['acct:okta:alice']}", dst=f"group:{ids['group:aws:ProdAdmin']}",
                       relation="member_of", source="connector"))
    tiny.commit()
    with pytest.raises(jit.JitError, match="standing"):
        jit.create_request(tiny, ids["alice"], ids["group:aws:ProdAdmin"], 1, "already has it")


@pytest.fixture
def demo_client(demo_db):
    from tessera.api.app import app
    from tessera.db import get_session

    def override():
        s = sessionmaker(bind=demo_db, expire_on_commit=False)()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_api_smoke(demo_client):
    c = demo_client
    summary = c.get("/api/summary").json()
    assert summary["identities"]["ai_agent"] == 6 and summary["violations"]["total"] > 0
    idents = c.get("/api/identities").json()
    assert len(idents) >= 90
    alice = next(i for i in idents if i["name"] == "Alice Okafor")
    detail = c.get(f"/api/identities/{alice['id']}").json()
    assert any(p["resource"] == "s3://customer-pii" for p in detail["effective_permissions"])
    graph = c.get(f"/api/graph?identity_id={alice['id']}").json()
    assert {n["kind"] for n in graph["nodes"]} >= {"identity", "account", "group", "perm", "resource"}
    nhi = c.get("/api/nhi").json()
    assert any("orphaned" in n["flags"] for n in nhi)
    assert all(n["delegations"] for n in nhi if n["type"] == "ai_agent")
    for path in ("/api/policies", "/api/violations", "/api/jit/requests", "/api/reviews/campaigns",
                 "/api/hris/events", "/api/resources", "/api/connectors", "/api/least-privilege/recommendations"):
        r = c.get(path)
        assert r.status_code == 200, path
        assert r.json(), path
    camp = c.get("/api/reviews/campaigns").json()[0]
    assert 0 < camp["items"] < camp["total_grants"]  # exception-only


def test_accounts_list(demo_client):
    c = demo_client
    rows = c.get("/api/accounts").json()
    assert len(rows) == c.get("/api/summary").json()["accounts"]
    assert {"id", "system", "username", "kind", "status", "last_login_at", "identity"} <= rows[0].keys()
    alice = next(r for r in rows if r["identity"] and r["identity"]["name"] == "Alice Okafor" and r["system"] == "okta")
    assert alice["status"] == "active"
    aws_only = c.get("/api/accounts?system=aws").json()
    assert aws_only and all(r["system"] == "aws" for r in aws_only)
