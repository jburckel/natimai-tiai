"""Request-level network helpers."""

from fastapi import Request


def client_ip(request: Request) -> str:
    """Best client address available for this request.

    In production the backend has no published port: everything arrives
    through Caddy, which appends the real peer to ``X-Forwarded-For`` — the
    rightmost entry is therefore the one written by *our* proxy and the one to
    trust (anything left of it is client-supplied). Without the header (dev
    override's direct port, tests) the socket peer is the client itself.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.rsplit(",", 1)[-1].strip()
    return request.client.host if request.client else "unknown"
