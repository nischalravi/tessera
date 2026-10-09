"""SQLAlchemy data model for the Tessera identity graph.

Graph shape (node kinds):
    Identity --has--> Account --member_of--> Group/Role --maps_to--> Group/Role
                                  \\--direct_grant--> Permission --on--> Resource
    Group/Role --grants--> Permission

Identity->Account and Permission->Resource are foreign keys; every other
relationship is a row in `grant_edges`, which is what revocation, JIT and
simulation operate on.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .timeutil import utcnow


class Base(DeclarativeBase):
    pass


class Identity(Base):
    __tablename__ = "identities"
    id: Mapped[int] = mapped_column(primary_key=True)
    external_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String)
    email: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    type: Mapped[str] = mapped_column(String, index=True)  # human | service | ai_agent
    department: Mapped[str | None] = mapped_column(String, nullable=True)
    title: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="active")  # active | terminated
    manager_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    source: Mapped[str | None] = mapped_column(String, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    hired_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    terminated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    accounts: Mapped[list["Account"]] = relationship(back_populates="identity")


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (UniqueConstraint("system", "external_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    system: Mapped[str] = mapped_column(String, index=True)
    external_id: Mapped[str] = mapped_column(String)
    identity_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    username: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String, default="user")  # user | service | api_key | agent
    status: Mapped[str] = mapped_column(String, default="active")  # active | disabled
    created_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    identity: Mapped[Identity | None] = relationship(back_populates="accounts")


class Group(Base):
    """Groups, teams, roles and security groups across systems."""

    __tablename__ = "groups"
    __table_args__ = (UniqueConstraint("system", "external_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    system: Mapped[str] = mapped_column(String, index=True)
    external_id: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String, default="group")  # group | role | team
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    requestable: Mapped[bool] = mapped_column(Boolean, default=False)  # eligible for JIT
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class Resource(Base):
    __tablename__ = "resources"
    __table_args__ = (UniqueConstraint("system", "external_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    system: Mapped[str] = mapped_column(String, index=True)
    external_id: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    environment: Mapped[str | None] = mapped_column(String, nullable=True)  # prod | staging | None
    tags: Mapped[list] = mapped_column(JSON, default=list)  # e.g. ["pii", "payments"]


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("system", "external_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    system: Mapped[str] = mapped_column(String, index=True)
    external_id: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String, index=True)
    resource_id: Mapped[int] = mapped_column(ForeignKey("resources.id"))
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)

    resource: Mapped[Resource] = relationship()


class GrantEdge(Base):
    """A grant relationship between two graph nodes, e.g. account:3 -> group:7.

    Node keys look like "account:12", "group:5", "perm:44".
    """

    __tablename__ = "grant_edges"
    __table_args__ = (UniqueConstraint("src", "dst"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    src: Mapped[str] = mapped_column(String, index=True)
    dst: Mapped[str] = mapped_column(String, index=True)
    relation: Mapped[str] = mapped_column(String)  # member_of | maps_to | grants | direct_grant
    source: Mapped[str] = mapped_column(String, default="connector")  # connector | jit | manual
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Secret(Base):
    __tablename__ = "secrets"
    __table_args__ = (UniqueConstraint("system", "external_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    system: Mapped[str] = mapped_column(String)
    external_id: Mapped[str] = mapped_column(String)
    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"))
    kind: Mapped[str] = mapped_column(String)  # access_key | api_token | pat | deploy_key | password
    name: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String, default="active")

    account: Mapped[Account] = relationship()


class AgentDelegation(Base):
    """An AI agent acting on behalf of a principal with a bounded set of tool scopes."""

    __tablename__ = "agent_delegations"
    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("identities.id"))
    principal_id: Mapped[int] = mapped_column(ForeignKey("identities.id"))
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class UsageEvent(Base):
    """Daily-aggregated usage of a permission by an identity."""

    __tablename__ = "usage_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), index=True)
    account_id: Mapped[int | None] = mapped_column(ForeignKey("accounts.id"), nullable=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), index=True)
    day: Mapped[datetime] = mapped_column(DateTime, index=True)
    count: Mapped[int] = mapped_column(Integer, default=1)


class AccessRequest(Base):
    __tablename__ = "access_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"))
    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"))
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"))
    justification: Mapped[str] = mapped_column(Text)
    duration_hours: Mapped[float] = mapped_column(default=4)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending|approved|denied|expired|revoked
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    edge_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ReviewCampaign(Base):
    __tablename__ = "review_campaigns"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    status: Mapped[str] = mapped_column(String, default="open")
    unused_days: Mapped[int] = mapped_column(Integer, default=60)
    total_grants: Mapped[int] = mapped_column(Integer, default=0)
    auto_certified: Mapped[int] = mapped_column(Integer, default=0)

    items: Mapped[list["ReviewItem"]] = relationship(back_populates="campaign", cascade="all, delete-orphan")


class ReviewItem(Base):
    __tablename__ = "review_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("review_campaigns.id"))
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"))
    edge_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    edge_src: Mapped[str] = mapped_column(String)
    edge_dst: Mapped[str] = mapped_column(String)
    grant_label: Mapped[str] = mapped_column(String)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    reviewer_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    decision: Mapped[str | None] = mapped_column(String, nullable=True)  # keep | revoke
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    campaign: Mapped[ReviewCampaign] = relationship(back_populates="items")


class HrisEvent(Base):
    __tablename__ = "hris_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    external_id: Mapped[str] = mapped_column(String, unique=True)
    type: Mapped[str] = mapped_column(String)  # joiner | mover | leaver
    identity_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    effective_at: Mapped[datetime] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending | executed
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
