import uuid

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlmodel.ext.asyncio.session import AsyncSession

from app.features.threat.models import Threat
from app.features.threat.schemas import ThreatReport


async def upsert_threats(
    session: AsyncSession, machine_id: uuid.UUID, reports: list[ThreatReport]
) -> int:
    """Insert reported threats, deduplicated on (machine_id, detection_id).

    Uses ``INSERT ... ON CONFLICT DO NOTHING`` so the same detection reported on
    several heartbeats yields a single row. Reports without a detection_id are
    skipped (no stable key to deduplicate on). Returns the number of new rows.
    """
    rows = [
        {
            "machine_id": machine_id,
            "detection_id": r.detection_id,
            "threat_name": r.threat_name,
            "severity": r.severity,
            "category": r.category,
            "status": r.status,
            "action_taken": r.action_taken,
            "detected_at": r.detected_at,
            "raw": r.model_dump(mode="json"),
        }
        for r in reports
        if r.detection_id
    ]
    if not rows:
        return 0

    stmt = (
        pg_insert(Threat)
        .values(rows)
        .on_conflict_do_nothing(constraint="uq_threats_machine_detection")
    )
    result = await session.execute(stmt)
    return result.rowcount or 0  # type: ignore[attr-defined]
