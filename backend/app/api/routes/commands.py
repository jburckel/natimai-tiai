"""Console command dispatch.

Creating commands is an admin capability (command:execute). Targets can be a
list of machine ids; the broadcast-by-filter form is added in M3.
"""

import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, SessionDep, require_permission
from app.features.base import utcnow
from app.features.command.models import Command, CommandType
from app.features.user.permissions import Action, Resource

router = APIRouter(prefix="/commands", tags=["commands"])


class CreateCommands(BaseModel):
    """Queue a command for one or more machines."""

    machine_ids: list[uuid.UUID]
    type: CommandType
    ttl_minutes: int = Field(default=60, ge=1, le=60 * 24 * 30)


class CreateCommandsResponse(BaseModel):
    """Ids of the created command rows."""

    created: list[uuid.UUID]


@router.post(
    "",
    response_model=CreateCommandsResponse,
    dependencies=[Depends(require_permission(Resource.COMMAND, Action.EXECUTE))],
)
async def create_commands(
    payload: CreateCommands, session: SessionDep, user: CurrentUser
) -> CreateCommandsResponse:
    """Queue one command per target machine (admin only)."""
    expires_at = utcnow() + timedelta(minutes=payload.ttl_minutes)
    created: list[uuid.UUID] = []
    for machine_id in payload.machine_ids:
        cmd = Command(
            machine_id=machine_id,
            type=payload.type.value,
            created_by=user.email,
            expires_at=expires_at,
        )
        session.add(cmd)
        created.append(cmd.id)
    await session.commit()
    return CreateCommandsResponse(created=created)
