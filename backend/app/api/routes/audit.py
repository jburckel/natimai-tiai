"""Console-facing read of the audit log (admin only)."""

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.api.deps import SessionDep, require_permission
from app.features.audit import crud
from app.features.user.permissions import Action, Resource

router = APIRouter(
    prefix="/audit",
    tags=["audit"],
    dependencies=[Depends(require_permission(Resource.AUDIT, Action.READ))],
)


class AuditEntryOut(BaseModel):
    """One administrative action as shown in the console."""

    id: uuid.UUID
    at: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str
    details: dict[str, Any]

    model_config = {"from_attributes": True}


class AuditList(BaseModel):
    """Paginated audit log, newest first."""

    items: list[AuditEntryOut]
    total: int
    page: int
    page_size: int


@router.get("", response_model=AuditList)
async def list_audit(
    session: SessionDep,
    action: str | None = None,
    resource_id: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> AuditList:
    """The administrative actions log, newest first.

    ``action`` filters on the exact slug ("machine.revoke_token", …);
    ``resource_id`` answers "what happened to this machine/account".
    """
    entries, total = await crud.list_entries(
        session,
        action=action,
        resource_id=resource_id,
        page=page,
        page_size=page_size,
    )
    return AuditList(
        items=[AuditEntryOut.model_validate(e) for e in entries],
        total=total,
        page=page,
        page_size=page_size,
    )
