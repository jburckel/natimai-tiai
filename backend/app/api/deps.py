import uuid
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core import security
from app.core.config import settings
from app.core.db import get_db
from app.features.machine.models import Machine
from app.features.user.models import User
from app.features.user.permissions import Action, Resource, has_permission

SessionDep = Annotated[AsyncSession, Depends(get_db)]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


async def verify_enrollment_secret(
    x_enrollment_secret: Annotated[str | None, Header()] = None,
) -> None:
    """Guard for POST /agent/enroll — validates the shared enrollment secret."""
    if x_enrollment_secret != settings.ENROLLMENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid enrollment secret",
        )


async def get_current_machine(
    session: SessionDep,
    authorization: Annotated[str | None, Header()] = None,
) -> Machine:
    """Resolve the calling machine from its Bearer token (per-machine auth)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    token = authorization.removeprefix("Bearer ").strip()
    token_hash = security.hash_token(token)

    result = await session.execute(
        select(Machine).where(Machine.token_hash == token_hash)
    )
    machine: Machine | None = result.scalar_one_or_none()
    if machine is None or machine.token_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked token",
        )
    return machine


CurrentMachine = Annotated[Machine, Depends(get_current_machine)]


# --- Console user auth (JWT) -----------------------------------------------


async def get_current_user(
    session: SessionDep,
    token: Annotated[str, Depends(oauth2_scheme)],
) -> User:
    """Resolve the authenticated console user from a JWT bearer token."""
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = security.decode_access_token(token)
    except InvalidTokenError:
        raise credentials_error from None

    sub = payload.get("sub")
    if sub is None:
        raise credentials_error
    user = await session.get(User, uuid.UUID(str(sub)))
    if user is None or not user.is_active:
        raise credentials_error
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_permission(
    resource: Resource, action: Action
) -> Callable[..., Awaitable[User]]:
    """Build a dependency that authorizes the current user for (resource, action)."""

    async def checker(user: CurrentUser) -> User:
        if not has_permission(user.role, resource.value, action.value):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {resource.value}:{action.value}",
            )
        return user

    return checker
