"""Effective-permissions graph.

The graph is a networkx DiGraph whose node keys are strings:

    identity:<id> -> account:<id> -> group:<id> (-> group:<id> ...) -> perm:<id>

Permission nodes carry their resource as attributes (resource nodes also exist
for visualization, linked perm -> resource). Effective permissions are every
`perm` node reachable from an identity, together with *all* simple paths that
grant it, so the UI can explain "why does alice have s3:GetObject on
customer-pii?".

A `GraphSnapshot` is cheap to copy, which is what makes what-if simulation
possible: copy, add/remove edges, recompute, diff.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Account, GrantEdge, Group, Identity, Permission, Resource
from .timeutil import utcnow

MAX_PATHS_PER_PERMISSION = 8
GRANT_RELATIONS = {"member_of", "maps_to", "grants", "direct_grant"}


@dataclass
class EffectivePermission:
    perm_key: str
    perm_id: int
    action: str
    system: str
    privileged: bool
    resource_id: int
    resource_name: str
    environment: str | None
    tags: list[str]
    paths: list[list[str]] = field(default_factory=list)
    # True when at least one path consists only of standing (non-JIT) grants.
    standing: bool = False

    @property
    def jit_only(self) -> bool:
        return not self.standing


def node_key(kind: str, id_: int) -> str:
    return f"{kind}:{id_}"


def parse_key(key: str) -> tuple[str, int]:
    kind, _, raw = key.partition(":")
    return kind, int(raw)


class GraphSnapshot:
    def __init__(self, g: nx.DiGraph | None = None):
        self.g = g if g is not None else nx.DiGraph()
        self._eff_cache: dict[int, dict[str, EffectivePermission]] = {}

    # ------------------------------------------------------------------ build
    @classmethod
    def from_db(cls, session: Session, now: datetime | None = None) -> "GraphSnapshot":
        now = now or utcnow()
        g = nx.DiGraph()
        for i in session.scalars(select(Identity)):
            g.add_node(
                node_key("identity", i.id), kind="identity", label=i.name, id=i.id,
                type=i.type, status=i.status, department=i.department, system=None,
            )
        for r in session.scalars(select(Resource)):
            g.add_node(
                node_key("resource", r.id), kind="resource", label=r.name, id=r.id,
                system=r.system, environment=r.environment, tags=list(r.tags or []), rkind=r.kind,
            )
        for a in session.scalars(select(Account)):
            k = node_key("account", a.id)
            g.add_node(
                k, kind="account", label=f"{a.system}:{a.username}", id=a.id, system=a.system,
                status=a.status, akind=a.kind, identity_id=a.identity_id,
            )
            if a.identity_id is not None:
                g.add_edge(node_key("identity", a.identity_id), k, relation="has_account",
                           edge_id=None, source="connector", expires_at=None)
        for gr in session.scalars(select(Group)):
            g.add_node(
                node_key("group", gr.id), kind="group", label=f"{gr.system}:{gr.name}", name=gr.name,
                id=gr.id, system=gr.system, gkind=gr.kind, privileged=gr.privileged,
                requestable=gr.requestable,
            )
        for p in session.scalars(select(Permission)):
            res = g.nodes[node_key("resource", p.resource_id)]
            k = node_key("perm", p.id)
            g.add_node(
                k, kind="perm", label=f"{p.action} on {res['label']}", id=p.id, system=p.system,
                action=p.action, privileged=p.privileged, resource_id=p.resource_id,
                resource_name=res["label"], environment=res["environment"], tags=res["tags"],
            )
            g.add_edge(k, node_key("resource", p.resource_id), relation="on",
                       edge_id=None, source="connector", expires_at=None)
        for e in session.scalars(select(GrantEdge)):
            if e.expires_at is not None and e.expires_at <= now:
                continue  # expired JIT grants are not effective
            if e.src not in g or e.dst not in g:
                continue
            g.add_edge(e.src, e.dst, relation=e.relation, edge_id=e.id, source=e.source,
                       expires_at=e.expires_at)
        return cls(g)

    def copy(self) -> "GraphSnapshot":
        return GraphSnapshot(self.g.copy())

    # --------------------------------------------------------------- mutation
    def remove_edge(self, src: str, dst: str) -> bool:
        if self.g.has_edge(src, dst):
            self.g.remove_edge(src, dst)
            self._eff_cache.clear()
            return True
        return False

    def remove_edge_id(self, edge_id: int) -> tuple[str, str] | None:
        for s, d, data in self.g.edges(data=True):
            if data.get("edge_id") == edge_id:
                self.g.remove_edge(s, d)
                self._eff_cache.clear()
                return s, d
        return None

    def add_edge(self, src: str, dst: str, relation: str = "member_of", source: str = "simulated",
                 expires_at: datetime | None = None) -> None:
        if src not in self.g or dst not in self.g:
            raise KeyError(f"unknown node in edge {src} -> {dst}")
        self.g.add_edge(src, dst, relation=relation, edge_id=None, source=source, expires_at=expires_at)
        self._eff_cache.clear()

    def set_account_status(self, account_id: int, status: str) -> None:
        self.g.nodes[node_key("account", account_id)]["status"] = status
        self._eff_cache.clear()

    # ------------------------------------------------------------------ query
    def node(self, key: str) -> dict:
        return self.g.nodes[key]

    def label(self, key: str) -> str:
        return self.g.nodes[key].get("label", key)

    def identities(self, include_terminated: bool = True) -> list[int]:
        out = []
        for k, d in self.g.nodes(data=True):
            if d["kind"] == "identity" and (include_terminated or d["status"] == "active"):
                out.append(d["id"])
        return out

    def edge_data(self, src: str, dst: str) -> dict:
        return self.g.edges[src, dst]

    def _traversable(self, key: str) -> bool:
        d = self.g.nodes[key]
        return not (d["kind"] == "account" and d.get("status") != "active")

    def effective_permissions(self, identity_id: int) -> dict[str, EffectivePermission]:
        if identity_id in self._eff_cache:
            return self._eff_cache[identity_id]
        start = node_key("identity", identity_id)
        result: dict[str, EffectivePermission] = {}
        if start not in self.g:
            return result

        # iterative DFS enumerating simple paths that end on perm nodes
        stack: list[tuple[str, list[str]]] = [(start, [start])]
        while stack:
            cur, path = stack.pop()
            for nxt in self.g.successors(cur):
                if nxt in path:
                    continue
                nd = self.g.nodes[nxt]
                kind = nd["kind"]
                if kind == "resource":
                    continue
                if not self._traversable(nxt):
                    continue
                new_path = path + [nxt]
                if kind == "perm":
                    ep = result.get(nxt)
                    if ep is None:
                        ep = EffectivePermission(
                            perm_key=nxt, perm_id=nd["id"], action=nd["action"], system=nd["system"],
                            privileged=nd["privileged"], resource_id=nd["resource_id"],
                            resource_name=nd["resource_name"], environment=nd["environment"],
                            tags=list(nd["tags"]),
                        )
                        result[nxt] = ep
                    if len(ep.paths) < MAX_PATHS_PER_PERMISSION:
                        ep.paths.append(new_path)
                    if not self.path_has_jit(new_path):
                        ep.standing = True
                    continue
                stack.append((nxt, new_path))
        for ep in result.values():
            ep.paths.sort(key=len)
        self._eff_cache[identity_id] = result
        return result

    def all_effective(self) -> dict[int, dict[str, EffectivePermission]]:
        return {iid: self.effective_permissions(iid) for iid in self.identities()}

    def path_has_jit(self, path: list[str]) -> bool:
        return any(self.g.edges[a, b].get("source") == "jit" for a, b in zip(path, path[1:]))

    def path_edges(self, path: list[str]) -> list[tuple[str, str]]:
        return list(zip(path, path[1:]))

    def first_hop_edge(self, path: list[str]) -> tuple[str, str] | None:
        """The grant edge leaving the account node (identity -> account -> X)."""
        return (path[1], path[2]) if len(path) >= 3 else None

    def describe_path(self, path: list[str]) -> list[dict]:
        out = []
        for i, k in enumerate(path):
            d = self.g.nodes[k]
            step = {"key": k, "kind": d["kind"], "label": d["label"], "system": d.get("system")}
            if i > 0:
                ed = self.g.edges[path[i - 1], k]
                step["via"] = {"relation": ed.get("relation"), "edge_id": ed.get("edge_id"),
                               "source": ed.get("source"),
                               "expires_at": ed["expires_at"].isoformat() if ed.get("expires_at") else None}
            out.append(step)
        return out

    def path_text(self, path: list[str]) -> str:
        return " → ".join(self.label(k) for k in path)

    def who_can_access(self, resource_id: int) -> dict[int, list[EffectivePermission]]:
        out: dict[int, list[EffectivePermission]] = {}
        for iid in self.identities():
            hits = [ep for ep in self.effective_permissions(iid).values() if ep.resource_id == resource_id]
            if hits:
                out[iid] = hits
        return out

    def grant_edges_from_accounts(self, identity_id: int) -> list[tuple[str, str, dict]]:
        start = node_key("identity", identity_id)
        out = []
        if start not in self.g:
            return out
        for acct in self.g.successors(start):
            for dst in self.g.successors(acct):
                out.append((acct, dst, self.g.edges[acct, dst]))
        return out


def perms_lost_if_removed(eff: dict[str, EffectivePermission], edge: tuple[str, str],
                          graph: GraphSnapshot) -> list[EffectivePermission]:
    """Permissions for which *every* known path traverses `edge`."""
    lost = []
    for ep in eff.values():
        if all(edge in graph.path_edges(p) for p in ep.paths):
            lost.append(ep)
    return lost


def perms_via_edge(eff: dict[str, EffectivePermission], edge: tuple[str, str],
                   graph: GraphSnapshot) -> list[EffectivePermission]:
    return [ep for ep in eff.values() if any(edge in graph.path_edges(p) for p in ep.paths)]


def diff_effective(before: dict[int, dict[str, EffectivePermission]],
                   after: dict[int, dict[str, EffectivePermission]]) -> dict[int, dict[str, list[str]]]:
    changes: dict[int, dict[str, list[str]]] = {}
    for iid in set(before) | set(after):
        b = set(before.get(iid, {}))
        a = set(after.get(iid, {}))
        if a != b:
            changes[iid] = {"added": sorted(a - b), "removed": sorted(b - a)}
    return changes
