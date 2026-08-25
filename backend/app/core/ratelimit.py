"""In-memory rate limiting for the authentication surface.

In-process on purpose: this stack has no Redis (the same trade-off as the
worker and the e-mail outbox — one moving part less), and it runs one API
process, so "N attempts per window per process" simply is "N per window".
State dies with the process; so does an attacker's progress, and a legitimate
user loses nothing they had.

Sliding window over a deque of monotonic timestamps per key (client IP). No
locks: FastAPI dependencies run on the event loop and nothing here awaits.
"""

import logging
import time
from collections import deque
from collections.abc import Callable

from fastapi import Request

from app.core.config import settings
from app.core.errors import AppError, ErrorCode
from app.core.net import client_ip

security_log = logging.getLogger("app.security")


class RateLimiter:
    """Sliding-window counter: at most ``max_attempts`` per window per key."""

    def __init__(self, max_attempts: int, window_seconds: float) -> None:
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        """Record one attempt for ``key``; False when the window is full."""
        now = time.monotonic()
        window_start = now - self.window
        hits = self._hits.setdefault(key, deque())
        while hits and hits[0] <= window_start:
            hits.popleft()
        if len(hits) >= self.max_attempts:
            return False
        hits.append(now)
        # An attacker cycling through source addresses must cost memory for a
        # window at most, not for the life of the process.
        if len(self._hits) > 1024:
            self._sweep(window_start)
        return True

    def _sweep(self, window_start: float) -> None:
        for key, hits in list(self._hits.items()):
            while hits and hits[0] <= window_start:
                hits.popleft()
            if not hits:
                del self._hits[key]

    def reset(self) -> None:
        self._hits.clear()


# One limiter per guarded surface, so hammering /enroll never locks the
# console's /login. Keyed on client IP: the parc is a LAN where every poste
# has its own address, and the console reaches us through Caddy, which
# forwards the real one (app.core.net.client_ip).

# Login: a human retries a handful of times; a bcrypt oracle needs thousands.
login_limiter = RateLimiter(max_attempts=10, window_seconds=300)
# Reset requests: each accepted call may send a mail — the tightest budget,
# because the cost (mail to a known operator, Mailgun quota) starts at one.
password_reset_limiter = RateLimiter(max_attempts=5, window_seconds=900)
# Enroll: one poste enrolls once in its life, but a re-imaged salle can come
# back all at once — roomy, since each poste still arrives from its own IP.
enroll_limiter = RateLimiter(max_attempts=30, window_seconds=300)

_ALL = (login_limiter, password_reset_limiter, enroll_limiter)


def reset_all() -> None:
    """Forget every recorded attempt (tests)."""
    for limiter in _ALL:
        limiter.reset()


def rate_limit(limiter: RateLimiter, surface: str) -> Callable[[Request], None]:
    """Dependency refusing requests beyond ``limiter``'s budget with a 429.

    ``surface`` names the endpoint in the security log — the log line, not the
    429, is what an operator greps when someone reports being locked out.
    """

    def dependency(request: Request) -> None:
        if not settings.RATE_LIMIT_ENABLED:
            return
        ip = client_ip(request)
        if not limiter.allow(ip):
            security_log.warning("rate limit exceeded on %s from %s", surface, ip)
            raise AppError(
                code=ErrorCode.RATE_LIMITED,
                status_code=429,
                message="Too many attempts; try again later",
                headers={"Retry-After": str(int(limiter.window))},
            )

    return dependency
