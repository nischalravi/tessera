from datetime import UTC, datetime


def utcnow() -> datetime:
    """Naive UTC 'now' (SQLite stores naive datetimes)."""
    return datetime.now(UTC).replace(tzinfo=None)
