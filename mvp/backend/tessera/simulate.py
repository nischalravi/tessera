"""What-if simulation: apply hypothetical graph changes and diff the outcome."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from .graph import GraphSnapshot, diff_effective
from .policies import PolicyContext, diff_violations, evaluate, load_policies
from .usage import UsageIndex, build_usage_index
from .timeutil import utcnow


def simulate(session: Session, remove_edge_ids=(), remove_edges=(), add_edges=(), disable_account_ids=(),
             now: datetime | None = None, policies=None, usage: UsageIndex | None = None,
             base: GraphSnapshot | None = None) -> dict:
    now = now or utcnow()
    policies = policies if policies is not None else load_policies()
    usage = usage or build_usage_index(session, now)
    base = base or GraphSnapshot.from_db(session, now)
    after = base.copy()

    applied = []
    for eid in remove_edge_ids:
        hit = after.remove_edge_id(int(eid))
        applied.append({"op": "remove", "edge_id": eid, "edge": list(hit) if hit else None,
                        "label": f"{base.label(hit[0])} → {base.label(hit[1])}" if hit else "not found"})
    for src, dst in remove_edges:
        ok = after.remove_edge(src, dst)
        applied.append({"op": "remove", "edge": [src, dst], "found": ok,
                        "label": f"{base.label(src)} → {base.label(dst)}" if src in base.g and dst in base.g else ""})
    for e in add_edges:
        after.add_edge(e["src"], e["dst"], e.get("relation", "member_of"), source=e.get("source", "simulated"))
        applied.append({"op": "add", "edge": [e["src"], e["dst"]],
                        "label": f"{base.label(e['src'])} → {base.label(e['dst'])}"})
    for aid in disable_account_ids:
        after.set_account_status(int(aid), "disabled")
        applied.append({"op": "disable_account", "account_id": aid, "label": base.label(f"account:{aid}")})

    eff_before = base.all_effective()
    eff_after = after.all_effective()
    changes = diff_effective(eff_before, eff_after)

    identities = []
    totals = {"identities_affected": 0, "permissions_removed": 0, "permissions_added": 0,
              "removed_recently_used": 0, "removed_privileged": 0}
    for iid, ch in sorted(changes.items()):
        node = base.node(f"identity:{iid}")
        removed = []
        for pk in ch["removed"]:
            ep = eff_before[iid][pk]
            u = usage.describe(iid, ep.perm_id)
            recently = u["days_since_used"] is not None and u["days_since_used"] < 30
            removed.append({"perm_key": pk, "action": ep.action, "resource": ep.resource_name, "system": ep.system,
                            "privileged": ep.privileged, "tags": ep.tags, "usage": u, "used_last_30d": recently})
            totals["removed_recently_used"] += int(recently)
            totals["removed_privileged"] += int(ep.privileged)
        added = []
        for pk in ch["added"]:
            ep = eff_after[iid][pk]
            added.append({"perm_key": pk, "action": ep.action, "resource": ep.resource_name, "system": ep.system,
                          "privileged": ep.privileged, "tags": ep.tags,
                          "path": after.path_text(ep.paths[0]) if ep.paths else ""})
        totals["identities_affected"] += 1
        totals["permissions_removed"] += len(removed)
        totals["permissions_added"] += len(added)
        identities.append({"identity_id": iid, "name": node["label"], "type": node["type"],
                           "removed": removed, "added": added})

    v_before = evaluate(policies, PolicyContext(base, session, now))
    v_after = evaluate(policies, PolicyContext(after, session, now))
    vd = diff_violations(v_before, v_after)
    return {
        "changes": applied,
        "summary": {**totals, "violations_before": len(v_before), "violations_after": len(v_after),
                    "violations_resolved": len(vd["resolved"]), "violations_introduced": len(vd["introduced"])},
        "identities": identities,
        "violations": vd,
    }
