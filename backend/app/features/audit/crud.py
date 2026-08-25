"""Writing and reading audit entries."""

from typing import Any

from sqlmodel import col, desc, func, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.features.audit.models import AuditEntry


def record(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Queue one audit entry on the caller's transaction.

    Deliberately no commit here (same contract as the outbox's queue_email):
    the entry exists exactly when the action it describes does — an action
    rolled back takes its trace down with it, and a trace is never written for
    something that did not happen.
    """
    session.add(
        AuditEntry(
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
        )
    )


async def list_entries(
    session: AsyncSession,
    *,
    action: str | None = None,
    resource_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[AuditEntry], int]:
    """Newest-first page of the log, optionally filtered."""
    filters = []
    if action:
        filters.append(col(AuditEntry.action) == action)
    if resource_id:
        filters.append(col(AuditEntry.resource_id) == resource_id)

    total_result = await session.exec(
        select(func.count()).select_from(AuditEntry).where(*filters)
    )
    total = total_result.one()

    result = await session.exec(
        select(AuditEntry)
        .where(*filters)
        .order_by(desc(col(AuditEntry.at)))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return list(result.all()), total
