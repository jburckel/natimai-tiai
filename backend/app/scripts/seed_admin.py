"""Seed the first admin user from FIRST_ADMIN_EMAIL / FIRST_ADMIN_PASSWORD.

Idempotent: does nothing if the user already exists or if env is unset.
Run via: python -m app.scripts.seed_admin
"""

import asyncio

from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.core.db import engine
from app.features.user import crud
from app.features.user.models import Role


async def main() -> None:
    """Create the first admin if needed."""
    if not settings.FIRST_ADMIN_EMAIL or not settings.FIRST_ADMIN_PASSWORD:
        print("seed_admin: FIRST_ADMIN_EMAIL/PASSWORD unset, skipping.")
        return

    async with AsyncSession(engine) as session:
        existing = await crud.get_by_email(session, settings.FIRST_ADMIN_EMAIL)
        if existing is not None:
            print(f"seed_admin: {settings.FIRST_ADMIN_EMAIL} already exists.")
            return
        await crud.create_user(
            session,
            email=settings.FIRST_ADMIN_EMAIL,
            password=settings.FIRST_ADMIN_PASSWORD,
            role=Role.ADMIN,
        )
        print(f"seed_admin: created admin {settings.FIRST_ADMIN_EMAIL}.")


if __name__ == "__main__":
    asyncio.run(main())
