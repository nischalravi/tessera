from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from tessera import jml
from tessera.graph import GraphSnapshot
from tessera.models import Account, HrisEvent, Identity
from tessera.policies import PolicyContext, evaluate, load_policies


def test_leaver_plan_contents(tiny, ids):
    plan = jml.leaver_plan(tiny, ids["alice"])
    actions = [s["action"] for s in plan["steps"]]
    assert actions.count("disable_account") == 1
    assert "remove_grant" in actions
    # alice owns helper-bot and is its delegation principal
    assert any(s["action"] == "reassign_owner" and s["target"] == "Helper Bot" for s in plan["steps"])
    assert any(s["action"] == "revoke_delegation" for s in plan["steps"])
    assert plan["impact"]["permissions_removed"] == 2


def test_leaver_plan_for_already_terminated_identity_finds_leftovers(tiny, ids):
    plan = jml.leaver_plan(tiny, ids["dave"])
    disables = [s for s in plan["steps"] if s["action"] == "disable_account"]
    assert [s["target"] for s in disables] == ["dave"]  # the forgotten AWS IAM user
    rotations = [s for s in plan["steps"] if s["action"] == "rotate_secret"]
    assert [s["target"] for s in rotations] == ["AKIAETL"]  # dave had custody of svc-etl's key
    assert any(s["action"] == "reassign_owner" and s["new_owner_id"] == ids["carol"] for s in plan["steps"])
    assert plan["impact"]["violations_resolved"] >= 1


def test_execute_leaver_event_removes_all_access(tiny, ids):
    ev = HrisEvent(external_id="t-1", type="leaver", identity_id=ids["alice"], payload={},
                   effective_at=tiny.get(Identity, ids["alice"]).created_at)
    tiny.add(ev)
    tiny.commit()
    jml.execute_event(tiny, ev.id)
    alice = tiny.get(Identity, ids["alice"])
    assert alice.status == "terminated"
    assert all(a.status == "disabled" for a in tiny.scalars(select(Account).where(Account.identity_id == alice.id)))
    g = GraphSnapshot.from_db(tiny)
    assert g.effective_permissions(alice.id) == {}
    bot = tiny.scalars(select(Identity).where(Identity.external_id == "helper-bot")).one()
    assert bot.owner_id == ids["carol"]  # reassigned to alice's manager
    vs = evaluate(load_policies(), PolicyContext(g, tiny))
    assert not [v for v in vs if v.policy_id == "terminated-access" and v.identity_id == alice.id]


def test_demo_marcus_leaver_plan(demo_db):
    s = sessionmaker(bind=demo_db, expire_on_commit=False)()
    ev = s.scalars(select(HrisEvent).where(HrisEvent.type == "leaver", HrisEvent.status == "pending")).one()
    plan = jml.plan_for_event(s, ev)
    assert plan["identity"]["name"] == "Marcus Bellweather"
    owners = {st["target"] for st in plan["steps"] if st["action"] == "reassign_owner"}
    assert "SRE On-call Agent" in owners
    assert plan["impact"]["privileged_removed"] > 0
    s.close()


def test_joiner_and_mover_plans(demo_db):
    s = sessionmaker(bind=demo_db, expire_on_commit=False)()
    joiner = s.scalars(select(HrisEvent).where(HrisEvent.type == "joiner")).one()
    jp = jml.plan_for_event(s, joiner)
    assert {st["target"] for st in jp["steps"] if st["action"] == "add_grant"} >= {"okta:data-team", "snowflake:ANALYST"}
    mover = s.scalars(select(HrisEvent).where(HrisEvent.type == "mover")).one()
    mp = jml.plan_for_event(s, mover)
    assert any(st["action"] == "remove_grant" and st["target"] == "okta:support" for st in mp["steps"])
    assert any(st["action"] == "add_grant" and st["target"] == "okta:sales" for st in mp["steps"])
    s.close()
