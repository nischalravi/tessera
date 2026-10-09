"""Usage-based least-privilege recommendations."""
from __future__ import annotations

from datetime import datetime

from .graph import GraphSnapshot, perms_lost_if_removed, perms_via_edge
from .usage import UsageIndex

SENSITIVE_TAGS = {"pii", "payments", "financial", "payroll"}


def grant_recommendations(graph: GraphSnapshot, usage: UsageIndex, unused_days: int = 60,
                          identity_id: int | None = None) -> list[dict]:
    recs = []
    ids = [identity_id] if identity_id is not None else graph.identities(include_terminated=False)
    for iid in ids:
        inode = graph.node(f"identity:{iid}")
        eff = graph.effective_permissions(iid)
        if not eff:
            continue
        for acct, dst, ed in graph.grant_edges_from_accounts(iid):
            if ed.get("edge_id") is None or ed.get("source") == "jit":
                continue
            if graph.node(acct).get("status") != "active":
                continue
            edge = (acct, dst)
            via = perms_via_edge(eff, edge, graph)
            if not via:
                continue
            lost = perms_lost_if_removed(eff, edge, graph)
            unused = [ep for ep in lost if usage.unused(iid, ep.perm_id, unused_days)]
            used = [ep for ep in lost if ep not in unused]
            if lost and not used:
                kind = "remove"
            elif lost and len(unused) / len(lost) >= 0.5:
                kind = "right_size"
            elif not lost:
                kind = "redundant"
            else:
                continue
            last = [usage.get(iid, ep.perm_id).last_used for ep in via]
            last = max([d for d in last if d], default=None)
            priv_unused = sum(1 for ep in unused if ep.privileged)
            sensitive = sorted({t for ep in unused for t in ep.tags if t in SENSITIVE_TAGS})
            score = len(unused) + 5 * priv_unused + 4 * len(sensitive) + (6 if kind == "remove" else 0)
            if inode["type"] != "human":
                score += 3
            if kind == "redundant":
                score = 1
            recs.append({
                "id": f"{ed['edge_id']}",
                "edge_id": ed["edge_id"],
                "kind": kind,
                "identity_id": iid,
                "identity_name": inode["label"],
                "identity_type": inode["type"],
                "department": inode.get("department"),
                "grant": f"{graph.label(acct)} → {graph.label(dst)}",
                "target": graph.label(dst),
                "target_privileged": bool(graph.node(dst).get("privileged")),
                "permissions_via": len(via),
                "permissions_lost": len(lost),
                "unused_lost": len(unused),
                "used_lost": len(used),
                "privileged_unused": priv_unused,
                "sensitive_tags": sensitive,
                "last_used": last.isoformat() if last else None,
                "days_since_used": (usage.now - last).days if last else None,
                "unused_examples": [f"{ep.action} on {ep.resource_name}" for ep in unused[:5]],
                "used_examples": [f"{ep.action} on {ep.resource_name}" for ep in used[:5]],
                "score": score,
                "rationale": _rationale(kind, len(unused), len(lost), unused_days, last, usage.now),
            })
    recs.sort(key=lambda r: -r["score"])
    return recs


def _rationale(kind, n_unused, n_lost, days, last, now: datetime) -> str:
    if kind == "remove":
        when = "never used" if last is None else f"last used {(now - last).days} days ago"
        return f"None of the {n_lost} permissions only this grant provides were used in {days} days ({when})."
    if kind == "right_size":
        return f"{n_unused} of {n_lost} permissions from this grant are unused for {days}+ days; replace with a narrower role."
    return "Every permission from this grant is also granted through another path."


def unused_permissions(graph: GraphSnapshot, usage: UsageIndex, identity_id: int, days: int) -> list[str]:
    return [pk for pk, ep in graph.effective_permissions(identity_id).items()
            if usage.unused(identity_id, ep.perm_id, days)]


def role_trim_recommendations(graph: GraphSnapshot, usage: UsageIndex, unused_days: int = 60,
                              min_holders: int = 2) -> list[dict]:
    """Permissions inside a role/group that *no* holder has used: trim them from the role itself."""
    holders: dict[tuple[str, str], set[int]] = {}
    users: dict[tuple[str, str], set[int]] = {}
    last_seen: dict[tuple[str, str], object] = {}
    for iid in graph.identities(include_terminated=False):
        for ep in graph.effective_permissions(iid).values():
            for p in ep.paths:
                a, b = p[-2], p[-1]
                if graph.node(a)["kind"] != "group":
                    continue
                key = (a, b)
                holders.setdefault(key, set()).add(iid)
                st = usage.get(iid, ep.perm_id)
                if st.last_used and (usage.now - st.last_used).days < unused_days:
                    users.setdefault(key, set()).add(iid)
                if st.last_used and (key not in last_seen or st.last_used > last_seen[key]):
                    last_seen[key] = st.last_used
    recs = []
    for (g, p), who in holders.items():
        if len(who) < min_holders or users.get((g, p)):
            continue
        ed = graph.edge_data(g, p)
        if ed.get("edge_id") is None:
            continue
        pn = graph.node(p)
        last = last_seen.get((g, p))
        names = sorted(graph.node(f"identity:{i}")["label"] for i in who)
        score = len(who) + (8 if pn["privileged"] else 0) + (6 if set(pn["tags"]) & SENSITIVE_TAGS else 0) + 5
        recs.append({
            "id": f"role-{ed['edge_id']}", "edge_id": ed["edge_id"], "kind": "role_trim",
            "identity_id": None, "identity_name": f"{len(who)} holders", "identity_type": "role",
            "department": None, "grant": f"{graph.label(g)} → {pn['label']}", "target": graph.label(g),
            "target_privileged": bool(graph.node(g).get("privileged")),
            "permissions_via": 1, "permissions_lost": len(who), "unused_lost": len(who), "used_lost": 0,
            "privileged_unused": len(who) if pn["privileged"] else 0,
            "sensitive_tags": sorted(set(pn["tags"]) & SENSITIVE_TAGS),
            "last_used": last.isoformat() if last else None,
            "days_since_used": (usage.now - last).days if last else None,
            "unused_examples": [pn["label"]], "used_examples": [],
            "holders": names[:12],
            "score": score,
            "rationale": f"None of the {len(who)} identities that hold {pn['label']} through "
                         f"{graph.label(g)} used it in {unused_days} days. Remove it from the role.",
        })
    recs.sort(key=lambda r: -r["score"])
    return recs
