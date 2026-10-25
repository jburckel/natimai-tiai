"""Console user management: list, create, update, delete, admin password reset.

Every route requires the ``user`` resource permission, which only admins hold
(app.features.user.permissions).

An admin may not delete, deactivate or demote **their own** account. That single
rule is also what guarantees the console can never end up with zero admins: the
only account an admin could remove admin rights from is someone else's, so at
least the acting admin always remains.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from app.api.deps import CurrentUser, SessionDep, require_permission
from app.api.fields import Email, Password
from app.core import security
from app.core.errors import AppError, ErrorCode
from app.core.net import client_ip
from app.features.audit import crud as audit
from app.features.base import utcnow
from app.features.user import crud
from app.features.user.models import EmailPreference, Role, User
from app.features.user.permissions import Action, Resource

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_permission(Resource.USER, Action.READ))],
)

_WRITE = Depends(require_permission(Resource.USER, Action.WRITE))


class UserOut(BaseModel):
    """A console account as shown in the users list."""

    id: uuid.UUID
    email: str
    full_name: str | None
    role: str
    is_active: bool
    # Visible to an administrator because "who gets told when a poste catches
    # something" is a property of the parc's supervision, not a private setting:
    # an account left on « aucun e-mail » is how a fleet ends up unwatched.
    email_preference: str
    # Set while the account is locked after failed logins; resetting its
    # password lifts the lock.
    locked_until: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserList(BaseModel):
    """Paginated user list."""

    items: list[UserOut]
    total: int
    page: int
    page_size: int


class UserCreate(BaseModel):
    """New account. The password is set by the admin and sent out of band."""

    email: Email
    password: Password
    full_name: str | None = None
    role: Role = Role.READONLY


class UserUpdate(BaseModel):
    """Partial update — only the supplied fields are changed."""

    email: Email | None = None
    full_name: str | None = None
    role: Role | None = None
    is_active: bool | None = None
    email_preference: EmailPreference | None = None


class PasswordReset(BaseModel):
    """Admin-driven reset. Omit ``password`` to have one generated."""

    password: Password | None = None


class PasswordResetOut(BaseModel):
    """The new password, returned once so the admin can pass it on."""

    password: str


async def _require_user(session: SessionDep, user_id: uuid.UUID) -> User:
    """Fetch a user or raise the stable not-found error."""
    user = await session.get(User, user_id)
    if user is None:
        raise AppError(
            code=ErrorCode.USER_NOT_FOUND, status_code=404, message="User not found"
        )
    return user


async def _reject_email_taken(
    session: SessionDep, email: str, *, exclude: uuid.UUID | None = None
) -> None:
    """Raise if ``email`` already belongs to another account."""
    existing = await crud.get_by_email(session, email)
    if existing is not None and existing.id != exclude:
        raise AppError(
            code=ErrorCode.USER_EMAIL_TAKEN,
            status_code=409,
            message="This email is already in use",
        )


def _reject_self(current: User, target: User, action: str) -> None:
    """Refuse an operation an admin would apply to their own account."""
    if current.id == target.id:
        raise AppError(
            code=ErrorCode.USER_SELF_FORBIDDEN,
            status_code=400,
            message=f"You cannot {action} your own account",
            details={"action": action},
        )


@router.get("", response_model=UserList)
async def list_users(
    session: SessionDep,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> UserList:
    """List console accounts, optionally filtered on email or full name."""
    users, total = await crud.list_users(
        session, search=search, page=page, page_size=page_size
    )
    return UserList(
        items=[UserOut.model_validate(u) for u in users],
        total=total,
        page=page,
        page_size=page_size,
    )


def _audit(
    session: SessionDep,
    request: Request,
    current: User,
    action: str,
    target: User,
    details: dict[str, object] | None = None,
) -> None:
    """Trace an account-management action, the target named by its e-mail.

    The e-mail rides along because the id alone stops saying anything once
    the account is deleted — and deletion is one of the actions traced.
    """
    audit.record(
        session,
        actor=current.email,
        action=action,
        resource_type="user",
        resource_id=str(target.id),
        ip=client_ip(request),
        details={"email": target.email, **(details or {})},
    )


@router.post("", response_model=UserOut, status_code=201, dependencies=[_WRITE])
async def create_user(
    payload: UserCreate, request: Request, session: SessionDep, current: CurrentUser
) -> UserOut:
    """Create an account with an admin-chosen password."""
    await _reject_email_taken(session, payload.email)
    user = await crud.create_user(
        session,
        email=payload.email,
        password=payload.password,
        role=payload.role,
        full_name=payload.full_name,
        commit=False,
    )
    _audit(session, request, current, "user.create", user, {"role": user.role})
    await session.commit()
    await session.refresh(user)
    return UserOut.model_validate(user)


@router.get("/{user_id}", response_model=UserOut)
async def get_user(user_id: uuid.UUID, session: SessionDep) -> UserOut:
    """Fetch a single account."""
    return UserOut.model_validate(await _require_user(session, user_id))


@router.patch("/{user_id}", response_model=UserOut, dependencies=[_WRITE])
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    session: SessionDep,
    current: CurrentUser,
) -> UserOut:
    """Update an account's email, name, role, activation or e-mail cadence."""
    user = await _require_user(session, user_id)
    fields = payload.model_dump(exclude_unset=True)

    if "is_active" in fields and not fields["is_active"]:
        _reject_self(current, user, "deactivate")
    if "role" in fields and fields["role"] != user.role:
        _reject_self(current, user, "change the role of")
    if "email" in fields and fields["email"] != user.email:
        await _reject_email_taken(session, fields["email"], exclude=user.id)

    # Old and new value of what actually changed — none of these fields is a
    # secret, and « role: readonly → admin » is the line an audit is read for.
    changes: dict[str, object] = {}
    for name, value in fields.items():
        # The str enums are the vocabulary of plain string columns: stored as
        # their value so a read never has to know the enum existed.
        stored = value.value if isinstance(value, Role | EmailPreference) else value
        if getattr(user, name) != stored:
            changes[name] = {"from": getattr(user, name), "to": stored}
        setattr(user, name, stored)
    user.updated_at = utcnow()
    if changes:
        _audit(session, request, current, "user.update", user, {"changes": changes})
    # What the account may do, or who it is, changed: its open sessions were
    # granted under the old terms and end now. (The e-mail cadence or the name
    # leave them alone.)
    if changes.keys() & {"role", "is_active", "email"}:
        await crud.end_sessions(session, user)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return UserOut.model_validate(user)


@router.delete("/{user_id}", status_code=204, dependencies=[_WRITE])
async def delete_user(
    user_id: uuid.UUID, request: Request, session: SessionDep, current: CurrentUser
) -> None:
    """Delete an account for good (prefer deactivation to keep the trail)."""
    user = await _require_user(session, user_id)
    _reject_self(current, user, "delete")
    _audit(session, request, current, "user.delete", user, {"role": user.role})
    await crud.delete_user(session, user)
    await session.commit()


@router.post(
    "/{user_id}/reset-password", response_model=PasswordResetOut, dependencies=[_WRITE]
)
async def reset_password(
    user_id: uuid.UUID,
    payload: PasswordReset,
    request: Request,
    session: SessionDep,
    current: CurrentUser,
) -> PasswordResetOut:
    """Set a new password for an account and return it once.

    Resetting logs the account out everywhere: tokens issued before now stop
    being accepted, and any pending "forgot password" link is dropped.
    """
    user = await _require_user(session, user_id)
    password = payload.password or security.generate_password()
    await crud.set_password(session, user, password)
    await crud.purge_reset_tokens(session, user.id)
    _audit(
        session,
        request,
        current,
        "user.reset_password",
        user,
        # Whether the admin typed it or the server drew it — never the value.
        {"generated": payload.password is None},
    )
    await session.commit()
    return PasswordResetOut(password=password)
