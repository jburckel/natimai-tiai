"""Console authentication: login (OAuth2 password flow), current user, and the
password lifecycle — self-service change, and the "forgot password" flow.
"""

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from app.api.deps import CurrentUser, SessionDep
from app.api.fields import Email, Password
from app.core import ratelimit, security
from app.core.config import settings
from app.core.errors import AppError, ErrorCode
from app.core.net import client_ip
from app.features.audit import crud as audit
from app.features.base import utcnow
from app.features.user import crud, emails
from app.features.user.models import EmailPreference, User

# The security log: authentication events, one greppable line each. Without it
# a brute-force attempt leaves no trace at all outside the rate limiter's 429s.
security_log = logging.getLogger("app.security")

router = APIRouter(prefix="/auth", tags=["auth"])

# The refresh cookie is sent to the auth routes only — never with the API calls
# that carry the access token, so it cannot ride along a forged request to them.
COOKIE_PATH = f"{settings.API_V1_STR}/auth"


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
    email_preference: str

    model_config = {"from_attributes": True}


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="strict",
        path=COOKIE_PATH,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(settings.REFRESH_COOKIE_NAME, path=COOKIE_PATH)


async def _open_session(
    session: SessionDep, response: Response, user: User, family: str
) -> Token:
    """Commit a refresh token in ``family``, set its cookie, return an access token."""
    refresh = crud.issue_refresh_token(session, user, family)
    # Read before the commit, which expires the instance: reading it after
    # would be a lazy load, and lazy IO has no place in an async session.
    access = security.create_access_token(user.id, user.security_stamp)
    await session.commit()
    _set_refresh_cookie(response, refresh)
    return Token(access_token=access)


@router.post(
    "/login",
    response_model=Token,
    dependencies=[Depends(ratelimit.rate_limit(ratelimit.login_limiter, "auth.login"))],
)
async def login(
    request: Request,
    response: Response,
    session: SessionDep,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """Authenticate with email (username) + password.

    Returns a short-lived access token in the body, and sets the refresh token
    as an HttpOnly cookie the console renews it with. A new login starts a new
    refresh family.
    """
    ip = client_ip(request)
    try:
        user = await crud.authenticate(session, form.username, form.password)
    except crud.AccountLockedError as exc:
        if exc.just_locked:
            audit.record(
                session,
                actor=exc.user.email,
                action="user.locked",
                resource_type="user",
                resource_id=str(exc.user.id),
                ip=ip,
                details={"locked_until": exc.locked_until.isoformat()},
            )
        await session.commit()
        # repr(): the field is typed by whoever is at the keyboard; a line
        # break in it must not forge a second log line.
        security_log.warning(
            "login refused for %r from %s: account locked until %s",
            form.username,
            ip,
            exc.locked_until.isoformat(),
        )
        raise AppError(
            code=ErrorCode.AUTH_ACCOUNT_LOCKED,
            status_code=423,
            message="Too many failed attempts; this account is temporarily locked",
            details={"locked_until": exc.locked_until.isoformat()},
        ) from None
    if user is None:
        # The failure counter, if the address had an account, is part of the
        # outcome: committed before answering.
        await session.commit()
        security_log.warning("login failed for %r from %s", form.username, ip)
        raise AppError(
            code=ErrorCode.AUTH_CREDENTIALS_INVALID,
            status_code=401,
            message="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    security_log.info("login ok for %s from %s", user.email, ip)
    return await _open_session(session, response, user, family=uuid.uuid4().hex)


@router.post(
    "/refresh",
    response_model=Token,
    dependencies=[
        Depends(ratelimit.rate_limit(ratelimit.refresh_limiter, "auth.refresh"))
    ],
)
async def refresh(
    request: Request,
    response: Response,
    session: SessionDep,
    refresh_cookie: Annotated[
        str | None, Cookie(alias=settings.REFRESH_COOKIE_NAME)
    ] = None,
) -> Token:
    """Trade the refresh cookie for a new access token and a new cookie.

    The presented token is marked used and the next one joins its family. A
    used token presented again is a copy: the family is revoked — unless it
    comes within seconds of its use, which is two tabs renewing at once, and
    the loser is told to retry with the cookie the winner already set.
    """
    invalid = AppError(
        code=ErrorCode.AUTH_REFRESH_INVALID,
        status_code=401,
        message="Session expired; please log in again",
    )
    if not refresh_cookie:
        raise invalid
    stored = await crud.get_refresh_token(session, refresh_cookie)
    now = utcnow()
    if stored is None or stored.revoked_at is not None or stored.expires_at <= now:
        _clear_refresh_cookie(response)
        raise invalid
    if stored.used_at is not None:
        age = (now - stored.used_at).total_seconds()
        if age <= settings.REFRESH_REUSE_GRACE_SECONDS:
            raise AppError(
                code=ErrorCode.AUTH_REFRESH_SUPERSEDED,
                status_code=409,
                message="Session already renewed; retry",
            )
        user_id, ip = stored.user_id, client_ip(request)
        await crud.revoke_family(session, stored.family)
        audit.record(
            session,
            actor="system",
            action="user.refresh_reuse",
            resource_type="user",
            resource_id=str(user_id),
            ip=ip,
            details={"family": stored.family},
        )
        await session.commit()
        security_log.warning(
            "refresh token reused for user %s from %s: family revoked", user_id, ip
        )
        raise invalid
    user = await session.get(User, stored.user_id)
    if user is None or not user.is_active:
        raise invalid
    stored.used_at = now
    session.add(stored)
    return await _open_session(session, response, user, family=stored.family)


@router.post("/logout", status_code=204)
async def logout(
    response: Response,
    session: SessionDep,
    refresh_cookie: Annotated[
        str | None, Cookie(alias=settings.REFRESH_COOKIE_NAME)
    ] = None,
) -> None:
    """End this browser's session: its refresh family is revoked.

    Works on the cookie alone, without an access token: a console whose access
    token already expired must still be able to log out for real.
    """
    if refresh_cookie:
        stored = await crud.get_refresh_token(session, refresh_cookie)
        if stored is not None:
            await crud.revoke_family(session, stored.family)
            await session.commit()
    _clear_refresh_cookie(response)


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> UserOut:
    """Return the current authenticated user."""
    return UserOut.model_validate(user)


class ProfileUpdate(BaseModel):
    """Self-service profile update — only the supplied fields are changed."""

    email_preference: EmailPreference | None = None


@router.patch("/me", response_model=UserOut)
async def update_me(
    payload: ProfileUpdate, user: CurrentUser, session: SessionDep
) -> UserOut:
    """Update one's own profile.

    Self-service, and deliberately narrow: what an account may change about
    itself here is how much mail it receives. Its role, its address and whether
    it is active stay with an administrator (``/users``) — a read-only operator
    who could edit their own row would not be read-only for long.
    """
    if payload.email_preference is not None:
        user.email_preference = payload.email_preference
    user.updated_at = utcnow()
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return UserOut.model_validate(user)


# --- Password lifecycle -----------------------------------------------------


class PasswordChange(BaseModel):
    """Self-service password change: the current password is the proof."""

    current_password: str
    new_password: Password


@router.post("/password", status_code=204)
async def change_password(
    payload: PasswordChange, user: CurrentUser, session: SessionDep
) -> None:
    """Change one's own password.

    The caller's other sessions are cut off (tokens issued before now stop
    being accepted), so the token used for *this* request is invalidated too —
    the console re-authenticates right after.
    """
    if not security.verify_password(payload.current_password, user.hashed_password):
        raise AppError(
            code=ErrorCode.PASSWORD_CURRENT_INVALID,
            status_code=400,
            message="Current password is incorrect",
        )
    await crud.set_password(session, user, payload.new_password)
    await crud.purge_reset_tokens(session, user.id)
    await session.commit()


class PasswordResetRequest(BaseModel):
    """Ask for a reset link to be mailed."""

    email: Email


@router.post(
    "/password-reset/request",
    status_code=204,
    dependencies=[
        Depends(
            ratelimit.rate_limit(
                ratelimit.password_reset_limiter, "auth.password_reset"
            )
        )
    ],
)
async def request_password_reset(
    request: Request, payload: PasswordResetRequest, session: SessionDep
) -> None:
    """Mail a reset link to the account, if it exists.

    Public endpoint. It answers 204 whatever happens — unknown address,
    deactivated account, mail failure — so it cannot be used to find out which
    e-mails have a console account. Rate-limited per source address: each
    accepted call can put a mail in a known operator's inbox.
    """
    security_log.info(
        "password reset requested for %s from %s",
        payload.email,
        client_ip(request),
    )
    user = await crud.get_by_email(session, payload.email)
    if user is None or not user.is_active:
        return
    token = await crud.create_reset_token(session, user)
    # Queued before the commit, so the mail and the token it links to are one
    # transaction: no link mailed for a token that was rolled back, no token
    # whose mail was lost to a Mailgun outage — the worker sends with retries.
    emails.send_password_reset(session, user.email, token)
    await session.commit()


class PasswordResetConfirm(BaseModel):
    """Redeem a reset token and set the new password."""

    token: str
    new_password: Password


@router.post("/password-reset/confirm", status_code=204)
async def confirm_password_reset(
    payload: PasswordResetConfirm, session: SessionDep
) -> None:
    """Set a new password from a valid reset link. Public endpoint."""
    user = await crud.consume_reset_token(session, payload.token)
    if user is None:
        raise AppError(
            code=ErrorCode.PASSWORD_RESET_TOKEN_INVALID,
            status_code=400,
            message="This reset link is invalid or has expired",
        )
    await crud.set_password(session, user, payload.new_password)
    await session.commit()
