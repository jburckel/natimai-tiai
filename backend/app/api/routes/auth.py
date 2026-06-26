"""Console authentication: login (OAuth2 password flow) and current user."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from app.api.deps import CurrentUser, SessionDep
from app.core import security
from app.core.errors import AppError, ErrorCode
from app.features.user import crud

router = APIRouter(prefix="/auth", tags=["auth"])


class Token(BaseModel):
    """JWT access token response."""

    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    """Authenticated user info."""

    id: uuid.UUID
    email: str
    full_name: str | None
    role: str

    model_config = {"from_attributes": True}


@router.post("/login", response_model=Token)
async def login(
    session: SessionDep,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """Authenticate with email (username) + password, return a JWT."""
    user = await crud.authenticate(session, form.username, form.password)
    if user is None:
        raise AppError(
            code=ErrorCode.AUTH_CREDENTIALS_INVALID,
            status_code=401,
            message="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Token(access_token=security.create_access_token(user.id))


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> UserOut:
    """Return the current authenticated user."""
    return UserOut.model_validate(user)
