"""Authorization model: permissions as (resource, action) pairs.

Routes ask for a capability (``require_permission(Resource.MACHINE, Action.READ)``)
rather than checking roles directly. Today the role→permission mapping is a
static table; later it can be backed by per-user / per-table grants in the
database — only ``has_permission`` changes, not the call sites.
"""

import enum

from app.features.user.models import Role


class Resource(enum.StrEnum):
    """Protected resource families."""

    MACHINE = "machine"
    THREAT = "threat"
    COMMAND = "command"
    USER = "user"


class Action(enum.StrEnum):
    """Operations on a resource."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"  # e.g. dispatch a remote command


# Resources a read-only operator may consult.
_READABLE = (Resource.MACHINE, Resource.THREAT, Resource.COMMAND)

# Static role → granted (resource, action) pairs (compared as plain strings).
ROLE_PERMISSIONS: dict[str, set[tuple[str, str]]] = {
    # Admin: full access on every resource/action.
    Role.ADMIN.value: {(r.value, a.value) for r in Resource for a in Action},
    # Read-only: read on the supervision resources.
    Role.READONLY.value: {(r.value, Action.READ.value) for r in _READABLE},
}


def has_permission(role: str, resource: str, action: str) -> bool:
    """Return whether ``role`` is granted ``(resource, action)``.

    Extension point: consult DB-backed per-user/per-table grants here before
    falling back to the static role map.
    """
    return (resource, action) in ROLE_PERMISSIONS.get(role, set())
