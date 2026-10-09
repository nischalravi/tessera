from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from tessera.graph import GraphSnapshot
from tessera.leastpriv import grant_recommendations, unused_permissions
from tessera.models import GrantEdge, Identity
from tessera.usage import build_usage_index


def test_usage_index_last_used(tiny, ids):
    u = build_usage_index(tiny)
    g = GraphSnapshot.from_db(tiny)
    eff = {ep.action: ep for ep in g.effective_permissions(ids["alice"]).values()}
    assert u.get(ids["alice"], eff["s3:PutObject"].perm_id).days_since(u.now) == 0
    assert u.get(ids["alice"], eff["s3:GetObject"].perm_id).last_used is None


def test_unused_permissions_detected(tiny, ids):
    g, u = GraphSnapshot.from_db(tiny), build_usage_index(tiny)
    unused = unused_permissions(g, u, ids["alice"], 60)
    assert [g.node(k)["action"] for k in unused] == ["s3:GetObject"]
    # carol used prod admin 75 days ago: unused at 60d, used at 90d
    assert any(g.node(k)["action"] == "iam:*" for k in unused_permissions(g, u, ids["carol"], 60))
    assert not any(g.node(k)["action"] == "iam:*" for k in unused_permissions(g, u, ids["carol"], 90))


def test_recommendations_remove_vs_right_size(tiny, ids):
    g, u = GraphSnapshot.from_db(tiny), build_usage_index(tiny)
    recs = {(r["identity_id"], r["target"]): r for r in grant_recommendations(g, u, 60)}
    carol_platform = recs[(ids["carol"], "okta:platform")]
    assert carol_platform["kind"] == "remove" and carol_platform["privileged_unused"] == 1
    alice_eng = recs[(ids["alice"], "okta:eng")]
    assert alice_eng["kind"] == "right_size"  # 1 of 2 perms unused
    assert alice_eng["unused_examples"] == ["s3:GetObject on s3://customer-pii"]
    # bob's clerk grant is in active use -> no recommendation for it
    assert (ids["bob"], "okta:payments-clerks") not in recs
    assert recs[(ids["bob"], "okta:payments-approvers")]["kind"] == "remove"


def test_revoke_dry_run_and_apply_via_api(tiny, ids, engine):
    from fastapi.testclient import TestClient

    from tessera.api.app import app
    from tessera.db import get_session

    def override():
        s = sessionmaker(bind=engine, expire_on_commit=False)()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_session] = override
    try:
        client = TestClient(app)
        edge = tiny.scalars(select(GrantEdge).where(GrantEdge.src == f"account:{ids['acct:okta:carol']}",
                                                    GrantEdge.dst == f"group:{ids['group:okta:platform']}")).one()
        dry = client.post("/api/least-privilege/revoke", json={"edge_id": edge.id, "dry_run": True}).json()
        assert dry["summary"]["permissions_removed"] == 1
        assert dry["summary"]["violations_resolved"] == 1
        assert dry["identities"][0]["removed"][0]["usage"]["days_since_used"] == 75
        assert client.get(f"/api/identities/{ids['carol']}").json()["risk"]["privileged"] == 1
        applied = client.post("/api/least-privilege/revoke", json={"edge_id": edge.id, "dry_run": False}).json()
        assert applied["applied"] is True
        assert client.get(f"/api/identities/{ids['carol']}").json()["risk"]["privileged"] == 0
        assert client.get("/api/audit").json()[0]["action"] == "grant.revoke"
    finally:
        app.dependency_overrides.clear()


def test_demo_has_unused_customer_pii_for_alice(demo_db):
    s = sessionmaker(bind=demo_db)()
    alice = s.scalars(select(Identity).where(Identity.name == "Alice Okafor")).one()
    g, u = GraphSnapshot.from_db(s), build_usage_index(s)
    labels = [g.label(k) for k in unused_permissions(g, u, alice.id, 60)]
    assert "s3:GetObject on s3://customer-pii" in labels
    recs = grant_recommendations(g, u, 60)
    assert any(r["kind"] == "remove" for r in recs) and any(r["identity_type"] == "service" for r in recs)
    s.close()


def test_role_trim_flags_permission_no_holder_uses(tiny, ids):
    from tessera.leastpriv import role_trim_recommendations
    # alice and carol both hold DevAdmin's s3:GetObject on customer-pii via okta:eng; nobody uses it
    g, u = GraphSnapshot.from_db(tiny), build_usage_index(tiny)
    recs = role_trim_recommendations(g, u, 60)
    assert [r["grant"] for r in recs] == ["aws:DevAdmin → s3:GetObject on s3://customer-pii"]
    assert recs[0]["identity_name"] == "2 holders"  # dave is terminated, so not counted


def test_demo_role_trim_devadmin_pii(demo_db):
    from tessera.leastpriv import role_trim_recommendations
    s = sessionmaker(bind=demo_db)()
    g, u = GraphSnapshot.from_db(s), build_usage_index(s)
    grants = [r["grant"] for r in role_trim_recommendations(g, u, 60)]
    assert "aws:DevAdmin → s3:GetObject on s3://customer-pii" in grants
    s.close()
