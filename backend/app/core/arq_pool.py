from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from app.core.config import settings


def redis_settings() -> RedisSettings:
    """ARQ/Redis connection settings."""
    return RedisSettings(host=settings.REDIS_SERVER, port=settings.REDIS_PORT)


async def get_arq_pool() -> ArqRedis:
    """Create an ARQ pool for enqueuing jobs from the API."""
    return await create_pool(redis_settings())
