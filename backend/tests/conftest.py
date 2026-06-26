"""Pytest fixtures.

Unit tests (security, permissions, fingerprint) need no database.

API tests use a real Postgres test database — set ``TIAI_TEST_DATABASE_URL``
(e.g. postgresql+psycopg://tiai:tiai@localhost:5432/tiai_test). Without it the
``client`` fixture skips, so ``pytest`` stays green locally and runs the full
suite in CI.
"""

import asyncio
import os
import sys

import pytest_asyncio

# psycopg's async driver cannot run on Windows' default ProactorEventLoop.
# Use the selector loop there (no-op on Linux/CI).
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

TEST_DATABASE_URL = os.getenv("TIAI_TEST_DATABASE_URL")


@pytest_asyncio.fixture
async def client():
    """Async HTTP client bound to the app with an isolated test database."""
    import pytest

    if not TEST_DATABASE_URL:
        pytest.skip("set TIAI_TEST_DATABASE_URL to run API tests")

    from httpx import ASGITransport, AsyncClient
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlmodel import SQLModel
    from sqlmodel.ext.asyncio.session import AsyncSession

    from app.core.db import get_db  # noqa: PLC0415
    from app.main import app  # noqa: PLC0415 (populates metadata)

    engine = create_async_engine(TEST_DATABASE_URL)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)

    async def override_get_db():
        async with AsyncSession(engine) as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()
    await engine.dispose()
