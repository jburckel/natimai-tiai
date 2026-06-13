"""ARQ worker: periodic cleanup of inactive machines and alert notifications.

Run with: arq app.core.arq_worker.WorkerSettings
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from arq import cron
from sqlalchemy import update
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.arq_pool import redis_settings
from app.core.config import settings
from app.core.db import engine
from app.features.command.models import Command, CommandStatus
from app.features.machine.models import Machine


async def expire_stale_commands(ctx: dict[str, Any]) -> int:
    """Mark pending commands past their expires_at as expired."""
    now = datetime.now(UTC)
    async with AsyncSession(engine) as session:
        result = await session.execute(
            update(Command)
            .where(col(Command.status) == CommandStatus.PENDING)
            .where(col(Command.expires_at) < now)
            .values(status=CommandStatus.EXPIRED)
        )
        await session.commit()
        return result.rowcount or 0  # type: ignore[attr-defined]


async def flag_inactive_machines(ctx: dict[str, Any]) -> int:
    """Count machines that have not checked in recently (alert candidates)."""
    cutoff = datetime.now(UTC) - timedelta(days=settings.INACTIVE_AFTER_DAYS)
    async with AsyncSession(engine) as session:
        rows = await session.execute(
            select(Machine).where(col(Machine.last_seen) < cutoff)
        )
        inactive = rows.scalars().all()
        # TODO: send a digest e-mail via app.features.notification.mailgun
        return len(inactive)


class WorkerSettings:
    """ARQ worker configuration."""

    redis_settings = redis_settings()
    functions = [expire_stale_commands, flag_inactive_machines]
    cron_jobs = [
        cron(expire_stale_commands, minute=set(range(0, 60, 5))),  # every 5 min
        cron(flag_inactive_machines, hour={8}, minute={0}),  # daily 08:00 UTC
    ]
