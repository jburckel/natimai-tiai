"""Machine freshness and status filtering — shared by the console list, stats,
and command targeting so the definitions stay in one place.

``is_up_to_date`` is a derived attribute (plan §4): a machine is up to date when
Defender is on (AV + real-time protection) and its signatures are younger than
the configured threshold. It is computed on each heartbeat and stored, so reads
(list, stats) are plain aggregates.
"""

import enum
from datetime import datetime, timedelta

from sqlalchemy.sql.elements import ColumnElement
from sqlmodel import col

from app.features.machine.models import Machine


def compute_is_up_to_date(
    *,
    av_enabled: bool | None,
    rtp_enabled: bool | None,
    signature_age_days: int | None,
    max_age_days: int,
) -> bool:
    """Whether a machine is adequately protected (plan §4).

    Requires antivirus + real-time protection enabled and signatures no older
    than ``max_age_days``. Missing data is treated as not up to date.
    """
    if not av_enabled or not rtp_enabled:
        return False
    if signature_age_days is None:
        return False
    return signature_age_days <= max_age_days


class MachineStatus(enum.StrEnum):
    """Console status filters (also usable as command broadcast targets)."""

    UP_TO_DATE = "up_to_date"
    OUTDATED = (
        "outdated"  # not up to date (stale signatures / protection off / unknown)
    )
    NEEDS_VERIFICATION = "needs_verification"
    INACTIVE = "inactive"  # no heartbeat for longer than the inactivity window


def status_clause(
    status: MachineStatus, now: datetime, inactive_after_days: int
) -> ColumnElement[bool]:
    """Build the SQL predicate selecting machines in the given status."""
    match status:
        case MachineStatus.UP_TO_DATE:
            return col(Machine.is_up_to_date).is_(True)
        case MachineStatus.OUTDATED:
            # Includes explicit False and unknown (NULL): the machines to act on.
            return col(Machine.is_up_to_date).is_not(True)
        case MachineStatus.NEEDS_VERIFICATION:
            return col(Machine.needs_verification).is_(True)
        case MachineStatus.INACTIVE:
            cutoff = now - timedelta(days=inactive_after_days)
            return col(Machine.last_seen) < cutoff
