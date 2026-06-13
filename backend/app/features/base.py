from datetime import UTC, datetime


def utcnow() -> datetime:
    """Timezone-aware UTC now (all timestamps are stored in UTC)."""
    return datetime.now(UTC)
