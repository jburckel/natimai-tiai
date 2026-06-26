"""Command queue operations: bulk creation and expiry sweep."""

import uuid
from datetime import datetime

from sqlalchemy import update
from sqlmodel import col
from sqlmodel.ext.asyncio.session import AsyncSession

from app.features.base import utcnow
from app.features.command.models import Command, CommandStatus, CommandType


async def create_for_machines(
    session: AsyncSession,
    *,
    machine_ids: list[uuid.UUID],
    command_type: CommandType,
    created_by: str | None,
    expires_at: datetime,
) -> list[uuid.UUID]:
    """Queue one command per machine (one row per target, even in broadcast).

    Returns the created command ids. The caller commits.
    """
    commands = [
        Command(
            machine_id=machine_id,
            type=command_type.value,
            created_by=created_by,
            expires_at=expires_at,
        )
        for machine_id in machine_ids
    ]
    session.add_all(commands)
    await session.flush()
    return [c.id for c in commands]


async def mark_expired(
    session: AsyncSession, *, machine_id: uuid.UUID | None = None
) -> int:
    """Flip still-pending commands past their expiry to EXPIRED (plan §2.8).

    Only PENDING commands are expired: once delivered, the agent owns the
    command and its reported result is authoritative. Scoped to one machine when
    ``machine_id`` is given. The caller commits.
    """
    stmt = (
        update(Command)
        .where(col(Command.status) == CommandStatus.PENDING)
        .where(col(Command.expires_at) < utcnow())
        .values(status=CommandStatus.EXPIRED)
    )
    if machine_id is not None:
        stmt = stmt.where(col(Command.machine_id) == machine_id)
    result = await session.execute(stmt)
    return result.rowcount or 0  # type: ignore[attr-defined]
