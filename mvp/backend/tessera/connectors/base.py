"""Connector interface.

A connector translates one source system (Okta, AWS, GitHub, ...) into Tessera's
normalized records. It never writes to the database itself; `tessera.ingest`
upserts what `discover()` returns and what `stream_events()` yields.

Cross-system references use `Ref(kind, system, external_id)`, so a connector
can point at objects owned by another connector (e.g. an Okta group mapped to an
AWS role via SAML federation). Identities are referenced by `IdentityRef`, which
the ingester correlates by external id first, then by email.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Literal

NodeKind = Literal["account", "group", "perm"]


@dataclass(frozen=True)
class Ref:
    kind: NodeKind
    system: str
    external_id: str


@dataclass(frozen=True)
class IdentityRef:
    external_id: str | None = None
    email: str | None = None


@dataclass
class IdentityRecord:
    external_id: str
    name: str
    type: Literal["human", "service", "ai_agent"]
    email: str | None = None
    department: str | None = None
    title: str | None = None
    status: str = "active"
    manager: IdentityRef | None = None
    owner: IdentityRef | None = None
    description: str | None = None
    hired_at: datetime | None = None
    terminated_at: datetime | None = None


@dataclass
class AccountRecord:
    system: str
    external_id: str
    username: str
    identity: IdentityRef | None
    kind: str = "user"
    status: str = "active"
    created_at: datetime | None = None
    last_login_at: datetime | None = None


@dataclass
class GroupRecord:
    system: str
    external_id: str
    name: str
    kind: str = "group"
    privileged: bool = False
    requestable: bool = False
    description: str | None = None


@dataclass
class ResourceRecord:
    system: str
    external_id: str
    name: str
    kind: str
    environment: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class PermissionRecord:
    system: str
    external_id: str
    action: str
    resource_external_id: str
    privileged: bool = False


@dataclass
class EdgeRecord:
    src: Ref
    dst: Ref
    relation: str  # member_of | maps_to | grants | direct_grant


@dataclass
class SecretRecord:
    system: str
    external_id: str
    account: Ref
    kind: str
    name: str
    created_at: datetime
    last_rotated_at: datetime | None = None
    last_used_at: datetime | None = None


@dataclass
class DelegationRecord:
    agent: IdentityRef
    principal: IdentityRef
    scopes: list[str]
    expires_at: datetime | None = None


@dataclass
class DiscoveryResult:
    identities: list[IdentityRecord] = field(default_factory=list)
    accounts: list[AccountRecord] = field(default_factory=list)
    groups: list[GroupRecord] = field(default_factory=list)
    resources: list[ResourceRecord] = field(default_factory=list)
    permissions: list[PermissionRecord] = field(default_factory=list)
    edges: list[EdgeRecord] = field(default_factory=list)
    secrets: list[SecretRecord] = field(default_factory=list)
    delegations: list[DelegationRecord] = field(default_factory=list)


@dataclass
class UsageRecord:
    """Aggregated usage: `identity` exercised `permission` `count` times on `day`."""

    identity: IdentityRef
    permission: Ref
    day: datetime
    count: int = 1
    account: Ref | None = None


@dataclass
class HrisEventRecord:
    external_id: str
    type: Literal["joiner", "mover", "leaver"]
    identity: IdentityRef | None
    effective_at: datetime
    payload: dict = field(default_factory=dict)


Event = UsageRecord | HrisEventRecord


class Connector(ABC):
    """Base class for all source-system connectors."""

    #: short system name, e.g. "okta"
    system: str = ""
    #: human-readable name for the UI
    display_name: str = ""

    @abstractmethod
    def discover(self) -> DiscoveryResult:
        """Return a full snapshot of identities, accounts, entitlements and resources."""

    @abstractmethod
    def stream_events(self, since: datetime | None = None) -> Iterator[Event]:
        """Yield usage / lifecycle events that happened after `since`."""
