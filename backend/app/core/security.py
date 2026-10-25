"""Per-machine token generation and verification.

Only the SHA-256 hash of a token is stored server-side; the clear token is
returned to the agent exactly once at enrollment.
"""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

from app.core.config import settings

_TOKEN_BYTES = 32
# Entropy of a generated console password: ~128 bits, still copy-pasteable.
_PASSWORD_BYTES = 16

# --- Agent tokens (per-machine, stored hashed) -----------------------------


def generate_token() -> str:
    """Generate a strong random per-machine token (URL-safe)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Return the hex SHA-256 hash of a token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(token: str, token_hash: str) -> bool:
    """Constant-time comparison of a token against a stored hash."""
    return hmac.compare_digest(hash_token(token), token_hash)


# --- Console users (password + JWT) ----------------------------------------

ALGORITHM = "HS256"

# bcrypt only ever reads the first 72 bytes of a password. passlib, which this
# module used to go through, cut the rest off silently; the `bcrypt` API raises
# instead. The cut therefore stays here, or every account whose password is
# longer than that would stop verifying against the hash stored before the
# switch. Bytes, not characters: bcrypt works on the UTF-8 encoding, and a cut
# landing mid-codepoint is harmless because the value is never decoded back.
_BCRYPT_MAX_BYTES = 72


def _password_bytes(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def get_password_hash(password: str) -> str:
    """Hash a plaintext password (bcrypt, 12 rounds)."""
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt()).decode("ascii")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    try:
        return bcrypt.checkpw(
            _password_bytes(plain_password), hashed_password.encode("utf-8")
        )
    except ValueError:
        # Row holds something that isn't a bcrypt hash (truncated column, hand-
        # edited value). That is a failed login, not a 500 on the login route.
        return False


def generate_password() -> str:
    """Generate a random password for an admin-driven reset (shown once)."""
    return secrets.token_urlsafe(_PASSWORD_BYTES)


TOKEN_TYPE_ACCESS = "access"  # noqa: S105 — a token kind, not a secret


def create_access_token(subject: str | Any, stamp: str) -> str:
    """Create a signed JWT access token for a user id.

    ``stamp`` is the account's security stamp at issue time: rotating it (a
    password, role or activation change) ends every session at once (see
    ``app.api.deps.get_current_user``). ``iat`` stays for the password-change
    check that predates the stamp.
    """
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "exp": expire,
        "iat": now,
        "sub": str(subject),
        "type": TOKEN_TYPE_ACCESS,
        "stamp": stamp,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT access token (raises on invalid/expired).

    The ``type`` claim is checked, not just set: a JWT signed with the same
    key for another purpose must not open a session.
    """
    payload: dict[str, Any] = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[ALGORITHM],
        options={"require": ["exp", "sub", "type"]},
    )
    if payload.get("type") != TOKEN_TYPE_ACCESS:
        raise jwt.InvalidTokenError("not an access token")
    return payload


# --- Console refresh tokens (opaque, stored hashed) -------------------------


def generate_refresh_token() -> str:
    """A random refresh token for the HttpOnly cookie (never a JWT: it means
    nothing without its row, which is what makes it revocable)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


# A real bcrypt hash of nothing anyone knows, checked when the e-mail matches
# no account: the login then costs one bcrypt either way, and its duration no
# longer says whether the address has an account. Computed on first use — it
# costs a bcrypt round.
_dummy_hash: str | None = None


def burn_password_check(password: str) -> None:
    """Spend the time of a password check against a hash that never matches."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = get_password_hash(secrets.token_urlsafe(_PASSWORD_BYTES))
    verify_password(password, _dummy_hash)
