"""Usage statistics derived from (daily aggregated) usage events."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import UsageEvent
from .timeutil import utcnow


@dataclass
class UsageStat:
    last_used: datetime | None
    events_90d: int
    active_days_90d: int

    def days_since(self, now: datetime) -> int | None:
        return None if self.last_used is None else (now - self.last_used).days


NEVER = UsageStat(None, 0, 0)


class UsageIndex:
    def __init__(self, stats: dict[tuple[int, int], UsageStat], now: datetime):
        self.stats = stats
        self.now = now
        self.by_identity: dict[int, datetime] = {}
        for (iid, _), st in stats.items():
            if st.last_used and (iid not in self.by_identity or st.last_used > self.by_identity[iid]):
                self.by_identity[iid] = st.last_used

    def get(self, identity_id: int, perm_id: int) -> UsageStat:
        return self.stats.get((identity_id, perm_id), NEVER)

    def unused(self, identity_id: int, perm_id: int, days: int) -> bool:
        st = self.get(identity_id, perm_id)
        return st.last_used is None or (self.now - st.last_used).days >= days

    def describe(self, identity_id: int, perm_id: int) -> dict:
        st = self.get(identity_id, perm_id)
        return {
            "last_used": st.last_used.isoformat() if st.last_used else None,
            "days_since_used": st.days_since(self.now),
            "events_90d": st.events_90d,
            "active_days_90d": st.active_days_90d,
        }


def build_usage_index(session: Session, now: datetime | None = None) -> UsageIndex:
    now = now or utcnow()
    since = now - timedelta(days=90)
    rows = session.execute(
        select(UsageEvent.identity_id, UsageEvent.permission_id, func.max(UsageEvent.day),
               func.sum(UsageEvent.count), func.count(UsageEvent.id))
        .where(UsageEvent.day >= since)
        .group_by(UsageEvent.identity_id, UsageEvent.permission_id)
    )
    stats = {}
    for iid, pid, last, total, days in rows:
        if isinstance(last, str):
            last = datetime.fromisoformat(last)
        stats[(iid, pid)] = UsageStat(last, int(total or 0), int(days or 0))
    # older-than-90d last-used (rare; keeps "never" honest)
    return UsageIndex(stats, now)
