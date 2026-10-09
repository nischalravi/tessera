from datetime import timedelta

from sqlalchemy.orm import sessionmaker

from tessera.graph import GraphSnapshot
from tessera.models import GrantEdge
from tessera.policies import PolicyContext, evaluate, load_policies, parse_policy
from tessera.simulate import simulate
from tessera.timeutil import utcnow

POLICIES = load_policies()


def _violations(session, policy_id=None, graph=None):
    graph = graph or GraphSnapshot.from_db(session)
    vs = evaluate(POLICIES, PolicyContext(graph, session))
    return [v for v in vs if policy_id is None or v.policy_id == policy_id]


def test_all_repo_policies_load_and_have_known_types():
    from tessera.policies import EVALUATORS
    assert {p.id for p in POLICIES} >= {"sod-payments", "no-standing-prod-admin", "ai-agents-no-pii"}
    assert all(p.type in EVALUATORS for p in POLICIES)


def test_sod_violation_detected(tiny, ids):
    vs = _violations(tiny, "sod-payments")
    assert [v.identity_id for v in vs] == [ids["bob"]]
    assert "payments:create" in vs[0].message and "payments:approve" in vs[0].message


def test_no_standing_prod_admin(tiny, ids):
    vs = _violations(tiny, "no-standing-prod-admin")
    assert [v.identity_id for v in vs] == [ids["carol"]]
    assert "okta:platform" in vs[0].evidence[0]


def test_jit_only_admin_is_not_a_violation(tiny, ids):
    tiny.add(GrantEdge(src=f"account:{ids['acct:okta:alice']}", dst=f"group:{ids['group:aws:ProdAdmin']}",
                       relation="member_of", source="jit", expires_at=utcnow() + timedelta(hours=2)))
    tiny.commit()
    assert [v.identity_id for v in _violations(tiny, "no-standing-prod-admin")] == [ids["carol"]]


def test_ai_agent_pii_via_role_inheritance(tiny, ids):
    vs = _violations(tiny, "ai-agents-no-pii")
    assert len(vs) == 1 and vs[0].identity_id == ids["helper-bot"]
    assert "PII_READER" in vs[0].evidence[0]


def test_nhi_and_secret_and_leaver_policies(tiny, ids):
    assert [v.identity_id for v in _violations(tiny, "nhi-ownership")] == [ids["svc-etl"]]  # owner dave left
    assert [v.identity_id for v in _violations(tiny, "stale-secrets")] == [ids["svc-etl"]]
    leaver = _violations(tiny, "terminated-access")
    assert [v.identity_id for v in leaver] == [ids["dave"]]


def test_simulation_remove_grant_resolves_sod(tiny, ids):
    from sqlalchemy import select
    edge = tiny.scalars(select(GrantEdge).where(GrantEdge.src == f"account:{ids['acct:okta:bob']}",
                                                GrantEdge.dst == f"group:{ids['group:okta:payments-approvers']}")).one()
    out = simulate(tiny, remove_edge_ids=[edge.id])
    assert [v["policy_id"] for v in out["violations"]["resolved"]] == ["sod-payments"]
    assert out["violations"]["introduced"] == []
    (bob,) = out["identities"]
    assert [p["action"] for p in bob["removed"]] == ["payments:approve"]
    # the database is untouched by a simulation
    assert tiny.get(GrantEdge, edge.id) is not None


def test_simulation_add_grant_introduces_violation(tiny, ids):
    out = simulate(tiny, add_edges=[{"src": f"account:{ids['acct:okta:alice']}",
                                     "dst": f"group:{ids['group:okta:platform']}"}])
    intro = out["violations"]["introduced"]
    assert [(v["policy_id"], v["identity_id"]) for v in intro] == [("no-standing-prod-admin", ids["alice"])]
    assert out["summary"]["permissions_added"] == 1


def test_inline_policy_parsing(tiny, ids):
    p = parse_policy({"id": "x", "type": "forbidden_access", "severity": "low",
                      "subjects": {"identity_types": ["human"]}, "resources": {"tags_any": ["payments"]}})
    vs = evaluate([p], PolicyContext(GraphSnapshot.from_db(tiny), tiny))
    assert {v.identity_id for v in vs} == {ids["bob"]}


def test_demo_policies_produce_expected_findings(demo_db):
    s = sessionmaker(bind=demo_db)()
    vs = _violations(s)
    by = {}
    for v in vs:
        by.setdefault(v.policy_id, []).append(v)
    assert [v.identity_name for v in by["sod-payments"]] == ["Priya Ramaswamy"]
    assert {v.identity_name for v in by["ai-agents-no-pii"]} >= {"Support Copilot", "Data Analyst Agent"}
    assert {v.identity_name for v in by["terminated-access"]} == {"Oren Whitlock", "Dmitri Ostrowski",
                                                                  "Hollis Brightwater"}
    s.close()
