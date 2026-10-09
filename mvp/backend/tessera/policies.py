"""Policy-as-code engine.

Policies are YAML files in `backend/policies/`. Each has an `id`, `name`,
`severity`, `type` and type-specific fields. Supported types:

- separation_of_duties: an identity must not hold permissions matching both
  `conflict.a` and `conflict.b` (each a list of action names).
- no_standing_access: permissions matching `match` (privileged / environment /
  systems / tags_any) must only be reachable through JIT grants.
- forbidden_access: identities matching `subjects` (identity_types) must not
  reach resources matching `resources` (tags_any / environment / systems).
- secret_max_age: secrets older than `max_age_days` since creation/rotation.
- nhi_ownership: service accounts and AI agents need an active human owner.
- terminated_with_access: terminated identities must not retain effective access.

Graph-based policies are evaluated against a `GraphSnapshot`, so the same code
evaluates the live graph and simulated (what-if) graphs.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from .graph import EffectivePermission, GraphSnapshot
from .models import Account, Identity, Secret
from .timeutil import utcnow

POLICY_DIR = Path(__file__).resolve().parent.parent / "policies"
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class Policy:
    id: str
    name: str
    type: str
    severity: str
    description: str
    spec: dict
    source: str = ""
    enabled: bool = True


@dataclass
class Violation:
    policy_id: str
    policy_name: str
    severity: str
    identity_id: int | None
    identity_name: str
    key: str
    message: str
    evidence: list[str] = field(default_factory=list)
    edges: list[list[str]] = field(default_factory=list)  # grant edges (src,dst) implicated

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PolicyContext:
    graph: GraphSnapshot
    session: Session | None = None
    now: datetime = field(default_factory=utcnow)
    _identities: dict[int, dict] | None = None

    @property
    def identities(self) -> dict[int, dict]:
        if self._identities is None:
            out = {}
            for k, d in self.graph.g.nodes(data=True):
                if d["kind"] == "identity":
                    out[d["id"]] = d
            self._identities = out
        return self._identities

    def eff(self, iid: int) -> dict[str, EffectivePermission]:
        return self.graph.effective_permissions(iid)


def load_policies(directory: Path | None = None) -> list[Policy]:
    directory = directory or POLICY_DIR
    out = []
    for path in sorted(directory.glob("*.y*ml")):
        text = path.read_text()
        doc = yaml.safe_load(text)
        docs = doc if isinstance(doc, list) else [doc]
        for d in docs:
            out.append(parse_policy(d, text))
    return out


def parse_policy(d: dict, source: str = "") -> Policy:
    known = {"id", "name", "type", "severity", "description", "enabled"}
    return Policy(
        id=d["id"], name=d.get("name", d["id"]), type=d["type"], severity=d.get("severity", "medium"),
        description=d.get("description", ""), spec={k: v for k, v in d.items() if k not in known},
        source=source, enabled=d.get("enabled", True),
    )


# ------------------------------------------------------------------ matchers
def _perm_matches(ep: EffectivePermission, m: dict) -> bool:
    if "actions" in m and ep.action not in m["actions"]:
        return False
    if "privileged" in m and ep.privileged != m["privileged"]:
        return False
    if "environment" in m and ep.environment != m["environment"]:
        return False
    if "systems" in m and ep.system not in m["systems"]:
        return False
    if "tags_any" in m and not set(m["tags_any"]) & set(ep.tags):
        return False
    return True


def _evidence(ctx: PolicyContext, ep: EffectivePermission, only_standing: bool = False) -> tuple[list[str], list[list[str]]]:
    paths = [p for p in ep.paths if not (only_standing and ctx.graph.path_has_jit(p))]
    texts = [ctx.graph.path_text(p) for p in paths[:3]]
    edges = []
    for p in paths[:3]:
        fh = ctx.graph.first_hop_edge(p)
        if fh and list(fh) not in edges:
            edges.append(list(fh))
    return texts, edges


def _subjects(ctx: PolicyContext, spec: dict) -> list[int]:
    types = (spec.get("subjects") or {}).get("identity_types")
    statuses = (spec.get("subjects") or {}).get("statuses", ["active"])
    return [iid for iid, d in ctx.identities.items()
            if (not types or d["type"] in types) and d["status"] in statuses]


# ---------------------------------------------------------------- evaluators
def eval_sod(policy: Policy, ctx: PolicyContext) -> list[Violation]:
    a_actions = set(policy.spec["conflict"]["a"])
    b_actions = set(policy.spec["conflict"]["b"])
    out = []
    for iid in _subjects(ctx, policy.spec):
        eff = ctx.eff(iid)
        a = [ep for ep in eff.values() if ep.action in a_actions]
        b = [ep for ep in eff.values() if ep.action in b_actions]
        if a and b:
            ev_a, ed_a = _evidence(ctx, a[0])
            ev_b, ed_b = _evidence(ctx, b[0])
            name = ctx.identities[iid]["label"]
            out.append(Violation(
                policy.id, policy.name, policy.severity, iid, name, f"{policy.id}:{iid}",
                f"{name} can both {a[0].action} and {b[0].action} on {a[0].resource_name}",
                ev_a + ev_b, ed_a + ed_b))
    return out


def eval_no_standing(policy: Policy, ctx: PolicyContext) -> list[Violation]:
    m = policy.spec.get("match", {})
    out = []
    for iid in _subjects(ctx, policy.spec):
        # one violation per standing grant (first hop from the account), listing what it exposes
        by_grant: dict[tuple[str, str], list[tuple[EffectivePermission, list[str]]]] = {}
        for ep in ctx.eff(iid).values():
            if not (_perm_matches(ep, m) and ep.standing):
                continue
            for p in ep.paths:
                if ctx.graph.path_has_jit(p):
                    continue
                by_grant.setdefault(ctx.graph.first_hop_edge(p), []).append((ep, p))
        name = ctx.identities[iid]["label"] if by_grant else ""
        for (src, dst), hits in by_grant.items():
            actions = sorted({f"{ep.action} on {ep.resource_name}" for ep, _ in hits})
            evidence = []
            for _, p in hits:
                t = ctx.graph.path_text(p)
                if t not in evidence:
                    evidence.append(t)
            out.append(Violation(
                policy.id, policy.name, policy.severity, iid, name, f"{policy.id}:{iid}:{src}->{dst}",
                f"{name} has standing privileged prod access via {ctx.graph.label(dst)}: "
                f"{', '.join(actions[:3])}{' …' if len(actions) > 3 else ''}",
                evidence[:4], [[src, dst]]))
    return out


def eval_forbidden(policy: Policy, ctx: PolicyContext) -> list[Violation]:
    m = policy.spec.get("resources", {})
    out = []
    for iid in _subjects(ctx, policy.spec):
        for ep in ctx.eff(iid).values():
            if _perm_matches(ep, m):
                name = ctx.identities[iid]["label"]
                ev, edges = _evidence(ctx, ep)
                out.append(Violation(
                    policy.id, policy.name, policy.severity, iid, name, f"{policy.id}:{iid}:{ep.perm_key}",
                    f"{name} ({ctx.identities[iid]['type']}) can {ep.action} on {ep.resource_name} "
                    f"[{', '.join(ep.tags)}]", ev, edges))
    return out


def eval_terminated(policy: Policy, ctx: PolicyContext) -> list[Violation]:
    out = []
    for iid, d in ctx.identities.items():
        if d["status"] != "terminated":
            continue
        eff = ctx.eff(iid)
        if not eff:
            continue
        accts = sorted({ctx.graph.label(p[1]) for ep in eff.values() for p in ep.paths})
        edges = sorted({tuple(ctx.graph.first_hop_edge(p)) for ep in eff.values() for p in ep.paths})
        out.append(Violation(
            policy.id, policy.name, policy.severity, iid, d["label"], f"{policy.id}:{iid}",
            f"{d['label']} is terminated but retains {len(eff)} effective permissions via {len(accts)} active "
            f"account(s)", [f"active account: {a}" for a in accts], [list(e) for e in edges]))
    return out


def eval_secret_age(policy: Policy, ctx: PolicyContext) -> list[Violation]:
    if ctx.session is None:
        return []
    max_age = policy.spec.get("max_age_days", 90)
    out = []
    rows = ctx.session.execute(
        select(Secret, Account).join(Account, Secret.account_id == Account.id).where(Secret.status == "active"))
    for sec, acct in rows:
        ref = sec.last_rotated_at or sec.created_at
        age = (ctx.now - ref).days
        if age > max_age and acct.identity_id in ctx.identities:
            d = ctx.identities[acct.identity_id]
            if d["status"] != "active":
                continue
            out.append(Violation(
                policy.id, policy.name, policy.severity, acct.identity_id, d["label"], f"{policy.id}:{sec.id}",
                f"{sec.kind} '{sec.name}' on {acct.system}:{acct.username} is {age} days old (max {max_age})",
                [f"created {sec.created_at.date()}", f"last rotated {sec.last_rotated_at.date() if sec.last_rotated_at else 'never'}"]))
    return out


def eval_nhi_ownership(policy: Policy, ctx: PolicyContext) -> list[Violation]:
    if ctx.session is None:
        return []
    out = []
    people = {i.id: i for i in ctx.session.scalars(select(Identity))}
    for i in people.values():
        if i.type not in ("service", "ai_agent") or i.status != "active":
            continue
        owner = people.get(i.owner_id) if i.owner_id else None
        if owner is None:
            msg = f"{i.name} has no owner"
        elif owner.status != "active":
            msg = f"{i.name} is owned by {owner.name}, who is {owner.status}"
        else:
            continue
        out.append(Violation(policy.id, policy.name, policy.severity, i.id, i.name, f"{policy.id}:{i.id}", msg,
                             [f"{len(ctx.eff(i.id))} effective permissions"]))
    return out


EVALUATORS: dict[str, Callable[[Policy, PolicyContext], list[Violation]]] = {
    "separation_of_duties": eval_sod,
    "no_standing_access": eval_no_standing,
    "forbidden_access": eval_forbidden,
    "terminated_with_access": eval_terminated,
    "secret_max_age": eval_secret_age,
    "nhi_ownership": eval_nhi_ownership,
}


def evaluate(policies: list[Policy], ctx: PolicyContext) -> list[Violation]:
    out: list[Violation] = []
    for p in policies:
        if not p.enabled:
            continue
        fn = EVALUATORS.get(p.type)
        if fn is None:
            raise ValueError(f"unknown policy type {p.type!r} in policy {p.id}")
        out.extend(fn(p, ctx))
    out.sort(key=lambda v: (-SEVERITY_RANK.get(v.severity, 0), v.policy_id, v.identity_name))
    return out


def diff_violations(before: list[Violation], after: list[Violation]) -> dict[str, list[dict]]:
    b = {v.key: v for v in before}
    a = {v.key: v for v in after}
    return {
        "resolved": [b[k].to_dict() for k in b.keys() - a.keys()],
        "introduced": [a[k].to_dict() for k in a.keys() - b.keys()],
    }
