from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core import security
from app.features.user.models import Role, User


async def get_by_email(session: AsyncSession, email: str) -> User | None:
    """Fetch a user by email (case-sensitive)."""
    result = await session.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def create_user(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    role: Role = Role.READONLY,
    full_name: str | None = None,
) -> User:
    """Create a user with a hashed password."""
    user = User(
        email=email,
        hashed_password=security.get_password_hash(password),
        role=role.value,
        full_name=full_name,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def authenticate(session: AsyncSession, email: str, password: str) -> User | None:
    """Return the user if credentials are valid and the account is active."""
    user = await get_by_email(session, email)
    if user is None or not user.is_active:
        return None
    if not security.verify_password(password, user.hashed_password):
        return None
    return user
