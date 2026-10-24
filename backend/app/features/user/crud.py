import uuid
from datetime import datetime, timedelta

from sqlalchemy import delete, func, or_, update
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core import security
from app.core.config import settings
from app.features.base import utcnow
from app.features.user.models import (
    PasswordResetToken,
    RefreshToken,
    Role,
    User,
    new_security_stamp,
)


def normalize_email(email: str) -> str:
    """The stored form of an address: trimmed, lower-case.

    The domain part is case-insensitive everywhere, and no mail system in this
    product's reach treats the local part otherwise; two accounts that differ
    only in case would be one person with two passwords.
    """
    return email.strip().lower()


async def get_by_email(session: AsyncSession, email: str) -> User | None:
    """Fetch a user by email, whatever the case it is typed in."""
    result = await session.exec(
        select(User).where(func.lower(User.email) == normalize_email(email))
    )
    return result.one_or_none()


async def create_user(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    role: Role = Role.READONLY,
    full_name: str | None = None,
    commit: bool = True,
) -> User:
    """Create a user with a hashed password.

    ``commit=False`` leaves the transaction to the caller, which then has the
    row flushed (its id known) and can add the audit entry that goes with it.
    """
    user = User(
        email=normalize_email(email),
        hashed_password=security.get_password_hash(password),
        role=role.value,
        full_name=full_name,
    )
    session.add(user)
    if not commit:
        await session.flush()
        return user
    await session.commit()
    await session.refresh(user)
    return user


class AccountLockedError(Exception):
    """The account is locked after too many failed logins."""

    def __init__(self, user: User, locked_until: datetime, *, just_locked: bool):
        super().__init__(f"account locked until {locked_until.isoformat()}")
        self.user = user
        self.locked_until = locked_until
        # True on the failure that tripped the lock: the one worth auditing.
        self.just_locked = just_locked


async def authenticate(session: AsyncSession, email: str, password: str) -> User | None:
    """Return the user if credentials are valid and the account is active.

    Raises ``AccountLockedError`` while the account is locked, and on the
    failure that locks it. Failure counters are changed on the session but not
    committed: the caller commits, error or not.

    An unknown address costs one bcrypt like a known one, so the response time
    does not tell which addresses have an account.
    """
    user = await get_by_email(session, email)
    if user is None:
        security.burn_password_check(password)
        return None
    now = utcnow()
    if user.locked_until is not None and user.locked_until > now:
        raise AccountLockedError(user, user.locked_until, just_locked=False)
    if not security.verify_password(password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.LOGIN_MAX_FAILED_ATTEMPTS:
            user.failed_login_attempts = 0
            user.locked_until = now + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
            session.add(user)
            raise AccountLockedError(user, user.locked_until, just_locked=True)
        session.add(user)
        return None
    if not user.is_active:
        return None
    if user.failed_login_attempts or user.locked_until is not None:
        user.failed_login_attempts = 0
        user.locked_until = None
        session.add(user)
    return user


# --- Sessions: security stamp and refresh tokens ------------------------------


async def end_sessions(session: AsyncSession, user: User) -> None:
    """End every session of ``user``: new stamp, refresh tokens revoked.

    For every change of what the account may do — password, role, activation,
    address. Does not commit.
    """
    user.security_stamp = new_security_stamp()
    session.add(user)
    await session.exec(
        update(RefreshToken)
        .where(col(RefreshToken.user_id) == user.id)
        .where(col(RefreshToken.revoked_at).is_(None))
        .values(revoked_at=utcnow())
    )


def issue_refresh_token(session: AsyncSession, user: User, family: str) -> str:
    """Add a refresh token to ``family`` and return its clear value (for the
    cookie, once). Does not commit."""
    token = security.generate_refresh_token()
    session.add(
        RefreshToken(
            token_hash=security.hash_token(token),
            user_id=user.id,
            family=family,
            expires_at=utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
    )
    return token


async def get_refresh_token(session: AsyncSession, token: str) -> RefreshToken | None:
    """The stored row behind a cookie value, if any."""
    return await session.get(RefreshToken, security.hash_token(token))


async def revoke_family(session: AsyncSession, family: str) -> None:
    """Revoke every token of a login's family (logout, or a detected reuse)."""
    await session.exec(
        update(RefreshToken)
        .where(col(RefreshToken.family) == family)
        .where(col(RefreshToken.revoked_at).is_(None))
        .values(revoked_at=utcnow())
    )


# --- Console user management ------------------------------------------------


async def list_users(
    session: AsyncSession,
    *,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[User], int]:
    """List users (optionally filtered on email/full name), newest first."""
    stmt = select(User)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            or_(
                col(User.email).ilike(pattern),
                col(User.full_name).ilike(pattern),
            )
        )
    total = await session.scalar(select(func.count()).select_from(stmt.subquery()))
    # ``email`` behind the date: accounts seeded together share a creation
    # instant, and the list is paginated server-side — ties reordered between
    # two pages would show one account twice and another not at all.
    rows = await session.exec(
        stmt.order_by(col(User.created_at).desc(), col(User.email))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return list(rows.all()), total or 0


async def set_password(session: AsyncSession, user: User, password: str) -> None:
    """Hash and store a new password, cutting off sessions opened before now.

    Does not commit — the caller decides the transaction boundary.
    """
    user.hashed_password = security.get_password_hash(password)
    user.password_changed_at = utcnow()
    user.updated_at = utcnow()
    # A new password is also the way out of a lockout: the admin who resets
    # it, or the owner who redeems a reset link, has proved more than a guess.
    user.failed_login_attempts = 0
    user.locked_until = None
    await end_sessions(session, user)


async def delete_user(session: AsyncSession, user: User) -> None:
    """Delete a user; the database takes their pending reset tokens with them.

    The tokens used to be deleted explicitly here, because the ``ON DELETE
    CASCADE`` existed in the migration and not in the schema SQLModel builds for
    the tests — so leaning on it would have behaved differently in each. The
    model now declares it too, which makes the constraint the single statement of
    the rule instead of one of two.
    """
    await session.delete(user)


# --- Password reset tokens --------------------------------------------------


async def create_reset_token(session: AsyncSession, user: User) -> str:
    """Issue a single-use reset token, returning the clear value (mailed once).

    Any previous token for the user is dropped, so the newest link is the only
    one that works.
    """
    await session.exec(
        delete(PasswordResetToken).where(col(PasswordResetToken.user_id) == user.id)
    )
    token = security.generate_token()
    session.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=security.hash_token(token),
            expires_at=utcnow()
            + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES),
        )
    )
    return token


async def consume_reset_token(session: AsyncSession, token: str) -> User | None:
    """Validate a reset token and return its user, marking the token used.

    Returns None when the token is unknown, already used, expired, or belongs to
    a deactivated account. Does not commit.
    """
    result = await session.exec(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == security.hash_token(token)
        )
    )
    row = result.one_or_none()
    if row is None or row.used_at is not None:
        return None
    if row.expires_at < utcnow():
        return None

    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        return None

    row.used_at = utcnow()
    session.add(row)
    return user


async def purge_reset_tokens(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Drop every reset token of a user (called after a password change)."""
    await session.exec(
        delete(PasswordResetToken).where(col(PasswordResetToken.user_id) == user_id)
    )
