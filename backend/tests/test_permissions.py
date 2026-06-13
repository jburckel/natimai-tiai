from app.features.user.models import Role
from app.features.user.permissions import Action, Resource, has_permission


def test_admin_has_full_access():
    """Admin is granted every (resource, action) pair."""
    for resource in Resource:
        for action in Action:
            assert has_permission(Role.ADMIN.value, resource.value, action.value)


def test_admin_can_execute_commands():
    """The 'execute remote commands' capability is an admin right."""
    assert has_permission(
        Role.ADMIN.value, Resource.COMMAND.value, Action.EXECUTE.value
    )


def test_readonly_can_read_supervision_resources():
    """Read-only may read machines, threats and commands."""
    for resource in (Resource.MACHINE, Resource.THREAT, Resource.COMMAND):
        assert has_permission(Role.READONLY.value, resource.value, Action.READ.value)


def test_readonly_cannot_write_or_execute():
    """Read-only is denied write and execute."""
    assert not has_permission(
        Role.READONLY.value, Resource.MACHINE.value, Action.WRITE.value
    )
    assert not has_permission(
        Role.READONLY.value, Resource.COMMAND.value, Action.EXECUTE.value
    )


def test_readonly_cannot_touch_users():
    """Read-only has no access to the user resource."""
    assert not has_permission(
        Role.READONLY.value, Resource.USER.value, Action.READ.value
    )


def test_unknown_role_is_denied():
    """An unknown role is granted nothing."""
    assert not has_permission("ghost", Resource.MACHINE.value, Action.READ.value)
