from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from tessera.graph import GraphSnapshot, perms_lost_if_removed
from tessera.models import Account, GrantEdge, Identity
from tessera.timeutil import utcnow


def _by_action(eff):
    return {(ep.action, ep.resource_name): ep for ep in eff.values()}


def test_effective_permission_path_through_groups_and_roles(tiny, ids):
    g = GraphSnapshot.from_db(tiny)
    eff = _by_action(g.effective_permissions(ids["alice"]))
    ep = eff[("s3:GetObject", "s3://customer-pii")]
    assert g.path_text(ep.paths[0]) == "Alice → okta:alice@t.example → okta:eng → aws:DevAdmin → s3:GetObject on s3://customer-pii"
    assert ep.standing and not ep.privileged
    assert set(eff) == {("s3:GetObject", "s3://customer-pii"), ("s3:PutObject", "s3://ml-artifacts")}


def test_multiple_paths_are_all_reported(tiny, ids):
    g = GraphSnapshot.from_db(tiny)
    carol = _by_action(g.effective_permissions(ids["carol"]))
    assert ("iam:*", "aws/prod") in carol and ("s3:GetObject", "s3://customer-pii") in carol
    # give carol a second route to customer-pii and check both paths are returned
    g.add_edge(f"account:{ids['acct:okta:carol']}", f"group:{ids['group:aws:DevAdmin']}", "member_of")
    ep = _by_action(g.effective_permissions(ids["carol"]))[("s3:GetObject", "s3://customer-pii")]
    assert len(ep.paths) == 2


def test_role_inheritance_is_followed(tiny, ids):
    g = GraphSnapshot.from_db(tiny)
    eff = _by_action(g.effective_permissions(ids["helper-bot"]))
    ep = eff[("snowflake:SELECT", "snowflake/CUSTOMERS")]
    assert [g.label(k) for k in ep.paths[0]][2:4] == ["snowflake:ANALYST", "snowflake:PII_READER"]


def test_disabled_accounts_grant_nothing(tiny, ids):
    g = GraphSnapshot.from_db(tiny)
    dave = g.effective_permissions(ids["dave"])
    # okta account disabled -> no eng/DevAdmin perms; aws IAM user still active -> customer-pii
    assert {ep.action for ep in dave.values()} == {"s3:GetObject"}
    assert all(g.label(p[1]) == "aws:dave" for ep in dave.values() for p in ep.paths)


def test_expired_jit_edges_are_ignored(tiny, ids):
    now = utcnow()
    tiny.add(GrantEdge(src=f"account:{ids['acct:okta:alice']}", dst=f"group:{ids['group:aws:ProdAdmin']}",
                       relation="member_of", source="jit", expires_at=now + timedelta(hours=1)))
    tiny.commit()
    live = _by_action(GraphSnapshot.from_db(tiny, now).effective_permissions(ids["alice"]))
    assert live[("iam:*", "aws/prod")].jit_only
    later = _by_action(GraphSnapshot.from_db(tiny, now + timedelta(hours=2)).effective_permissions(ids["alice"]))
    assert ("iam:*", "aws/prod") not in later


def test_cycles_do_not_loop_forever(tiny, ids):
    g = GraphSnapshot.from_db(tiny)
    g.add_edge(f"group:{ids['group:aws:DevAdmin']}", f"group:{ids['group:okta:eng']}", "maps_to")
    eff = g.effective_permissions(ids["alice"])
    assert len(eff) == 2


def test_perms_lost_if_edge_removed(tiny, ids):
    g = GraphSnapshot.from_db(tiny)
    eff = g.effective_permissions(ids["carol"])
    lost = perms_lost_if_removed(eff, (f"account:{ids['acct:okta:carol']}", f"group:{ids['group:okta:platform']}"), g)
    assert [ep.action for ep in lost] == ["iam:*"]


def test_snapshot_copy_is_isolated(tiny, ids):
    g = GraphSnapshot.from_db(tiny)
    g2 = g.copy()
    g2.remove_edge(f"account:{ids['acct:okta:alice']}", f"group:{ids['group:okta:eng']}")
    assert len(g.effective_permissions(ids["alice"])) == 2
    assert len(g2.effective_permissions(ids["alice"])) == 0


def test_demo_company_alice_reaches_customer_pii(demo_db):
    s = sessionmaker(bind=demo_db)()
    alice = s.scalars(select(Identity).where(Identity.name == "Alice Okafor")).one()
    g = GraphSnapshot.from_db(s)
    texts = [g.path_text(p) for ep in g.effective_permissions(alice.id).values()
             if ep.action == "s3:GetObject" and ep.resource_name == "s3://customer-pii" for p in ep.paths]
    assert "Alice Okafor → okta:alice.okafor@larkspur.example → okta:engineering → aws:DevAdmin → s3:GetObject on s3://customer-pii" in texts
    counts = {t: s.query(Identity).filter(Identity.type == t).count() for t in ("human", "service", "ai_agent")}
    assert counts["human"] >= 60 and counts["service"] >= 25 and counts["ai_agent"] == 6
    assert s.query(Account).count() > 150
    s.close()
