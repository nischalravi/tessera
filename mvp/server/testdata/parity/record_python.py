"""Record golden API fixtures from the Python (FastAPI) backend.

This script was used once, before the Go port, to capture the behaviour the Go
server must reproduce. It is kept for provenance; the Python backend it drives
has since been removed (check out the commit that added this file to re-run it).

    python record_python.py <path-to-mvp/backend> <output-dir>

Determinism
-----------
* RNG: the demo company already uses `random.Random(7)` (Mersenne Twister,
  CPython seeding). The Go port re-implements MT19937 with CPython's
  `init_by_array` seeding and the exact `random()`, `_randbelow()`, `randint()`,
  `choice()`, `shuffle()` and `uniform()` algorithms, so the same seed yields
  the same company.
* Clock: `tessera.timeutil.utcnow` is replaced *before* any other tessera
  module is imported (they bind it with `from .timeutil import utcnow`) by a
  frozen clock returning FROZEN_NOW. The Go parity test injects the same
  frozen clock, so every timestamp in the fixtures is reproducible and
  compared exactly.

Each step is saved as `NNN-<slug>.json`:
    {"name", "request": {"method", "path", "body"?, "raw_body"?},
     "response": {"status", "body"}}
Steps run in file order against one database; later steps see earlier
mutations. Volatile values are normalised at comparison time (see README.md).
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path

FROZEN_NOW = datetime(2026, 10, 8, 9, 30, 0)


def main() -> None:
    backend, out_dir = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    tmp = tempfile.mkdtemp(prefix="tessera-parity-")
    os.environ["TESSERA_DB"] = f"sqlite:///{tmp}/parity.db"
    os.environ.pop("TESSERA_CONNECTORS", None)
    sys.path.insert(0, str(backend))

    import tessera.timeutil as tu
    tu.utcnow = lambda: FROZEN_NOW  # must happen before the other imports

    from fastapi.testclient import TestClient
    from sqlalchemy import select

    from tessera.connectors import load_connectors
    from tessera.db import SessionLocal, engine, init_db
    from tessera.ingest import sync_connectors
    from tessera.models import Account, GrantEdge, Group, HrisEvent, Identity, Resource, ReviewItem
    from tessera.seed import seed_workflows
    from tessera.api.app import app

    init_db(engine, drop=True)
    with SessionLocal() as s:
        sync_connectors(s, load_connectors())
        seed_workflows(s)

    s = SessionLocal()

    def ident(name):
        return s.scalars(select(Identity).where(Identity.name == name)).one().id

    def group(system, name):
        return s.scalars(select(Group).where(Group.system == system, Group.name == name)).one().id

    def account(iid, system):
        return s.scalars(select(Account).where(Account.identity_id == iid, Account.system == system)).first().id

    def edge(src, dst):
        return s.scalars(select(GrantEdge).where(GrantEdge.src == src, GrantEdge.dst == dst)).one().id

    alice, marcus, oren = ident("Alice Okafor"), ident("Marcus Bellweather"), ident("Oren Whitlock")
    priya, kofi, sana = ident("Priya Ramaswamy"), ident("Kofi Mensah"), ident("Sana Iyer")
    sre_agent, copilot = ident("SRE On-call Agent"), ident("Support Copilot")
    legacy_etl = ident("svc-legacy-etl")
    eng_grp, plat_grp = group("okta", "engineering"), group("okta", "eng-platform")
    prod_admin, break_glass = group("aws", "ProdAdmin"), group("aws", "BreakGlassAdmin")
    acctadmin = group("snowflake", "ACCOUNTADMIN")
    ap_approver = group("workday", "AP Approver")
    alice_okta, oren_okta = account(alice, "okta"), account(oren, "okta")
    priya_wd = account(priya, "workday")
    alice_eng_edge = edge(f"account:{alice_okta}", f"group:{eng_grp}")
    priya_appr_edge = edge(f"account:{priya_wd}", f"group:{ap_approver}")
    pii = s.scalars(select(Resource).where(Resource.name == "s3://customer-pii")).one().id
    ev_leaver = s.scalars(select(HrisEvent).where(HrisEvent.external_id == "wd-evt-9001")).one().id
    ev_mover = s.scalars(select(HrisEvent).where(HrisEvent.external_id == "wd-evt-9002")).one().id
    ev_joiner = s.scalars(select(HrisEvent).where(HrisEvent.external_id == "wd-evt-9003")).one().id
    ev_hist = s.scalars(select(HrisEvent).where(HrisEvent.status == "executed")).first().id
    items = [i.id for i in s.scalars(select(ReviewItem).order_by(ReviewItem.id))]
    n_events = len(s.scalars(select(HrisEvent)).all())
    s.close()

    client = TestClient(app)
    steps: list[tuple] = []

    def step(name, method, path, body=None, raw=None):
        steps.append((name, method, path, body, raw))

    G, P = "GET", "POST"
    # ------------------------------------------------------------ read-only
    step("health", G, "/api/health")
    step("connectors", G, "/api/connectors")
    step("summary", G, "/api/summary")
    step("identities", G, "/api/identities")
    step("identities-human", G, "/api/identities?type=human")
    step("identities-service", G, "/api/identities?type=service")
    step("identities-agents", G, "/api/identities?type=ai_agent")
    step("identities-q", G, "/api/identities?q=okafor")
    step("identities-terminated", G, "/api/identities?status=terminated")
    step("identities-combined", G, "/api/identities?type=human&q=finance&status=active")
    step("identities-none", G, "/api/identities?q=zzzz")
    for nm, iid in (("alice", alice), ("marcus", marcus), ("oren", oren), ("sre-agent", sre_agent),
                    ("legacy-etl", legacy_etl), ("copilot", copilot), ("priya", priya)):
        step(f"identity-{nm}", G, f"/api/identities/{iid}")
    step("identity-alice-30d", G, f"/api/identities/{alice}?unused_days=30")
    step("identity-404", G, "/api/identities/99999")
    step("identity-422", G, "/api/identities/abc")
    step("identity-bad-unused", G, f"/api/identities/{alice}?unused_days=x")
    step("accounts", G, "/api/accounts")
    step("accounts-aws", G, "/api/accounts?system=aws")
    step("accounts-unknown-system", G, "/api/accounts?system=nope")
    step("groups", G, "/api/groups")
    step("groups-requestable", G, "/api/groups?requestable=true")
    step("groups-not-requestable", G, "/api/groups?requestable=0")
    step("groups-bad-bool", G, "/api/groups?requestable=maybe")
    step("resources", G, "/api/resources")
    step("graph-alice", G, f"/api/graph?identity_id={alice}")
    step("graph-alice-perm", G, f"/api/graph?identity_id={alice}&perm_key=perm:1")
    step("graph-agent", G, f"/api/graph?identity_id={copilot}")
    step("graph-resource", G, f"/api/graph?resource_id={pii}")
    step("graph-400", G, "/api/graph")
    step("graph-422", G, "/api/graph?identity_id=x")
    step("nhi", G, "/api/nhi")
    step("nhi-service", G, "/api/nhi?type=service")
    step("nhi-agents", G, "/api/nhi?type=ai_agent")
    step("nhi-bad-type", G, "/api/nhi?type=human")
    step("recs", G, "/api/least-privilege/recommendations")
    step("recs-30", G, "/api/least-privilege/recommendations?unused_days=30")
    step("recs-90-remove", G, "/api/least-privilege/recommendations?unused_days=90&kind=remove")
    step("recs-role-trim", G, "/api/least-privilege/recommendations?kind=role_trim")
    step("recs-right-size", G, "/api/least-privilege/recommendations?kind=right_size")
    step("recs-service", G, "/api/least-privilege/recommendations?identity_type=service")
    step("recs-0", G, "/api/least-privilege/recommendations?unused_days=0")
    step("recs-91", G, "/api/least-privilege/recommendations?unused_days=91")
    step("recs-abc", G, "/api/least-privilege/recommendations?unused_days=abc")
    step("policies", G, "/api/policies")
    step("violations", G, "/api/violations")
    step("violations-sod", G, "/api/violations?policy_id=sod-payments")
    step("violations-none", G, "/api/violations?policy_id=nope")
    step("jit-requests", G, "/api/jit/requests")
    step("campaigns", G, "/api/reviews/campaigns")
    step("campaign-1", G, "/api/reviews/campaigns/1")
    step("campaign-404", G, "/api/reviews/campaigns/999")
    step("hris-events", G, "/api/hris/events")
    step("plan-leaver", G, f"/api/hris/events/{ev_leaver}/plan")
    step("plan-mover", G, f"/api/hris/events/{ev_mover}/plan")
    step("plan-joiner", G, f"/api/hris/events/{ev_joiner}/plan")
    step("plan-historical", G, f"/api/hris/events/{ev_hist}/plan")
    step("plan-404", G, "/api/hris/events/9999/plan")
    step("leaver-plan-alice", G, f"/api/jml/leaver-plan/{alice}")
    step("leaver-plan-oren", G, f"/api/jml/leaver-plan/{oren}")
    step("leaver-plan-404", G, "/api/jml/leaver-plan/99999")
    step("audit", G, "/api/audit")
    step("audit-limit", G, "/api/audit?limit=3")
    # ------------------------------------------------------------ simulation
    step("simulate-empty", P, "/api/simulate", {})
    step("simulate-remove", P, "/api/simulate", {"remove_edge_ids": [alice_eng_edge, 999999]})
    step("simulate-add", P, "/api/simulate",
         {"add_edges": [{"src": f"account:{alice_okta}", "dst": f"group:{plat_grp}"}]})
    step("simulate-add-relation", P, "/api/simulate",
         {"add_edges": [{"src": f"group:{eng_grp}", "dst": f"group:{prod_admin}", "relation": "maps_to"}]})
    step("simulate-disable", P, "/api/simulate", {"disable_account_ids": [oren_okta]})
    step("simulate-combo", P, "/api/simulate",
         {"remove_edge_ids": [priya_appr_edge], "disable_account_ids": [oren_okta],
          "add_edges": [{"src": f"account:{alice_okta}", "dst": f"group:{plat_grp}"}]})
    step("simulate-unknown-node", P, "/api/simulate", {"add_edges": [{"src": "account:999999", "dst": "group:1"}]})
    step("simulate-bad-src", P, "/api/simulate",
         {"add_edges": [{"src": f"identity:{alice}", "dst": f"group:{plat_grp}"}]})
    step("simulate-unknown-account", P, "/api/simulate", {"disable_account_ids": [999999]})
    step("simulate-bad-types", P, "/api/simulate", {"remove_edge_ids": ["x"], "add_edges": [{"src": 1}]})
    step("simulate-not-object", P, "/api/simulate", [1, 2])
    step("simulate-bad-json", P, "/api/simulate", raw="{not json")
    step("revoke-dry-run", P, "/api/least-privilege/revoke", {"edge_id": alice_eng_edge})
    step("revoke-dry-run-explicit", P, "/api/least-privilege/revoke", {"edge_id": priya_appr_edge, "dry_run": True})
    step("revoke-404", P, "/api/least-privilege/revoke", {"edge_id": 999999})
    step("revoke-422", P, "/api/least-privilege/revoke", {"dry_run": False})
    step("revoke-no-body", P, "/api/least-privilege/revoke")
    # ------------------------------------------------------------ JIT
    step("jit-create", P, "/api/jit/requests",
         {"identity_id": priya, "group_id": break_glass, "duration_hours": 1.5, "justification": "  Quarter close  "})
    step("jit-create-default-hours", P, "/api/jit/requests",
         {"identity_id": sana, "group_id": prod_admin, "justification": "Investigate prod data job"})
    step("jit-not-requestable", P, "/api/jit/requests",
         {"identity_id": alice, "group_id": eng_grp, "duration_hours": 1, "justification": "x"})
    step("jit-zero-hours", P, "/api/jit/requests",
         {"identity_id": alice, "group_id": prod_admin, "duration_hours": 0, "justification": "x"})
    step("jit-too-long", P, "/api/jit/requests",
         {"identity_id": alice, "group_id": prod_admin, "duration_hours": 100, "justification": "x"})
    step("jit-blank", P, "/api/jit/requests",
         {"identity_id": alice, "group_id": prod_admin, "duration_hours": 1, "justification": "   "})
    step("jit-unknown-identity", P, "/api/jit/requests",
         {"identity_id": 99999, "group_id": prod_admin, "justification": "x"})
    step("jit-terminated", P, "/api/jit/requests",
         {"identity_id": oren, "group_id": prod_admin, "justification": "x"})
    step("jit-standing", P, "/api/jit/requests",
         {"identity_id": sana, "group_id": acctadmin, "justification": "x"})
    step("jit-missing-field", P, "/api/jit/requests", {"identity_id": alice, "group_id": prod_admin})
    step("jit-string-ints", P, "/api/jit/requests",
         {"identity_id": str(kofi), "group_id": str(prod_admin), "duration_hours": "2", "justification": "coerced"})
    step("jit-list", G, "/api/jit/requests")
    step("jit-approve", P, "/api/jit/requests/5/approve")
    step("jit-approve-again", P, "/api/jit/requests/5/approve", {"approver": "someone@larkspur.example"})
    step("jit-deny", P, "/api/jit/requests/1/deny", {"approver": "lead@larkspur.example"})
    step("jit-revoke", P, "/api/jit/requests/3/revoke")
    step("jit-revoke-denied", P, "/api/jit/requests/1/revoke")
    step("jit-approve-alice", P, "/api/jit/requests/2/approve", {})
    step("jit-bad-action", P, "/api/jit/requests/2/escalate")
    step("jit-unknown", P, "/api/jit/requests/9999/approve")
    step("jit-sweep", P, "/api/jit/sweep")
    step("jit-list-after", G, "/api/jit/requests")
    step("identity-alice-jit", G, f"/api/identities/{alice}")
    step("graph-alice-jit", G, f"/api/graph?identity_id={alice}")
    step("violations-after-jit", G, "/api/violations")
    # ------------------------------------------------------------ reviews
    step("review-keep", P, f"/api/reviews/items/{items[0]}/decision", {"decision": "keep", "comment": "needed"})
    step("review-revoke", P, f"/api/reviews/items/{items[1]}/decision", {"decision": "revoke"})
    step("review-bad-decision", P, f"/api/reviews/items/{items[2]}/decision", {"decision": "maybe"})
    step("review-unknown", P, "/api/reviews/items/99999/decision", {"decision": "keep"})
    step("campaign-1-after", G, "/api/reviews/campaigns/1")
    step("campaign-create", P, "/api/reviews/campaigns", {"name": "Parity review", "unused_days": 30})
    step("campaign-create-default", P, "/api/reviews/campaigns", {})
    step("campaigns-after", G, "/api/reviews/campaigns")
    step("campaign-2", G, "/api/reviews/campaigns/2")
    # ------------------------------------------------------------ revoke apply
    step("revoke-apply", P, "/api/least-privilege/revoke",
         {"edge_id": priya_appr_edge, "dry_run": False, "actor": "parity@larkspur.example"})
    step("revoke-apply-again", P, "/api/least-privilege/revoke", {"edge_id": priya_appr_edge, "dry_run": False})
    step("violations-after-revoke", G, "/api/violations?policy_id=sod-payments")
    # ------------------------------------------------------------ HRIS / JML
    step("hris-leaver-no-identity", P, "/api/hris/events", {"type": "leaver"})
    step("hris-joiner-no-name", P, "/api/hris/events", {"type": "joiner", "payload": {}})
    step("hris-mover-no-team", P, "/api/hris/events", {"type": "mover", "identity_id": alice, "payload": {}})
    step("hris-bad-type", P, "/api/hris/events", {"type": "retire"})
    step("hris-mover", P, "/api/hris/events",
         {"type": "mover", "identity_id": alice, "payload": {"to_team": "data", "to_department": "Data",
                                                             "new_title": "Data Engineer"}})
    step("hris-joiner", P, "/api/hris/events",
         {"type": "joiner", "payload": {"name": "Ada Parity", "email": "ada.parity@larkspur.example",
                                        "department": "Engineering", "team": "platform", "title": "Platform Engineer",
                                        "manager_external_id": "emp-1013"}})
    step("hris-leaver", P, "/api/hris/events", {"type": "leaver", "identity_id": kofi})
    step("hris-events-after-create", G, "/api/hris/events")
    step("plan-sim-mover", G, f"/api/hris/events/{n_events + 1}/plan")
    step("plan-sim-joiner", G, f"/api/hris/events/{n_events + 2}/plan")
    step("plan-sim-leaver", G, f"/api/hris/events/{n_events + 3}/plan")
    step("execute-leaver", P, f"/api/hris/events/{ev_leaver}/execute")
    step("execute-leaver-again", P, f"/api/hris/events/{ev_leaver}/execute")
    step("execute-mover", P, f"/api/hris/events/{ev_mover}/execute")
    step("execute-joiner", P, f"/api/hris/events/{ev_joiner}/execute")
    step("execute-sim-mover", P, f"/api/hris/events/{n_events + 1}/execute")
    step("execute-sim-joiner", P, f"/api/hris/events/{n_events + 2}/execute")
    step("execute-unknown", P, "/api/hris/events/9999/execute")
    step("hris-events-after", G, "/api/hris/events")
    step("identity-marcus-after", G, f"/api/identities/{marcus}")
    step("identity-alice-after", G, f"/api/identities/{alice}")
    step("identities-after", G, "/api/identities")
    step("accounts-after", G, "/api/accounts")
    step("nhi-after", G, "/api/nhi")
    step("violations-after", G, "/api/violations")
    step("recs-after", G, "/api/least-privilege/recommendations")
    step("summary-after", G, "/api/summary")
    step("resources-after", G, "/api/resources")
    step("leaver-plan-marcus-after", G, f"/api/jml/leaver-plan/{marcus}")
    # ------------------------------------------------------------ sync + misc
    step("connectors-sync", P, "/api/connectors/sync")
    step("summary-after-sync", G, "/api/summary")
    step("identities-after-sync", G, "/api/identities")
    step("audit-final", G, "/api/audit?limit=500")
    step("unknown-route", G, "/api/nope")
    step("wrong-method", P, "/api/summary")
    step("openapi", G, "/openapi.json")
    step("docs", G, "/docs")
    step("redoc", G, "/redoc")

    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("[0-9][0-9][0-9]-*.json"):
        old.unlink()
    for n, (name, method, path, body, raw) in enumerate(steps, 1):
        kwargs = {}
        if raw is not None:
            kwargs = {"content": raw, "headers": {"content-type": "application/json"}}
        elif body is not None:
            kwargs = {"json": body}
        r = client.request(method, path, **kwargs)
        try:
            rbody = r.json()
        except ValueError:
            rbody = r.text
        req = {"method": method, "path": path}
        if body is not None:
            req["body"] = body
        if raw is not None:
            req["raw_body"] = raw
        rec = {"name": name, "request": req, "response": {"status": r.status_code, "body": rbody}}
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        (out_dir / f"{n:03d}-{slug}.json").write_text(json.dumps(rec, indent=1, ensure_ascii=False) + "\n")
    print(f"recorded {len(steps)} fixtures into {out_dir}")


if __name__ == "__main__":
    main()
