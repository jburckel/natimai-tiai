"""Console-facing endpoints: list and inspect managed machines.

Auth (admin session/JWT) is added in M5; left open for the MVP.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func
from sqlmodel import col, select

from app.api.deps import SessionDep, require_permission
from app.features.machine.models import Machine
from app.features.user.permissions import Action, Resource

router = APIRouter(
    prefix="/machines",
    tags=["machines"],
    dependencies=[Depends(require_permission(Resource.MACHINE, Action.READ))],
)


class MachineOut(BaseModel):
    """Machine summary for the console list/detail views."""

    id: uuid.UUID
    machine_uuid: str
    hostname: str | None
    domain: str | None
    os_version: str | None
    agent_version: str | None
    is_up_to_date: bool | None
    needs_verification: bool
    signature_version: str | None
    last_seen: datetime

    model_config = {"from_attributes": True}


class MachineList(BaseModel):
    """Paginated machine list."""

    items: list[MachineOut]
    total: int
    page: int
    page_size: int


@router.get("", response_model=MachineList)
async def list_machines(
    session: SessionDep,
    search: str | None = None,
    domain: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> MachineList:
    """List machines with optional search/domain filters and pagination."""
    stmt = select(Machine)
    if search:
        stmt = stmt.where(col(Machine.hostname).ilike(f"%{search}%"))
    if domain:
        stmt = stmt.where(col(Machine.domain) == domain)

    total = await session.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = await session.exec(
        stmt.order_by(col(Machine.last_seen).desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = [MachineOut.model_validate(m) for m in rows.all()]
    return MachineList(items=items, total=total or 0, page=page, page_size=page_size)


@router.get("/{machine_id}", response_model=MachineOut)
async def get_machine(machine_id: uuid.UUID, session: SessionDep) -> MachineOut:
    """Fetch a single machine by id."""
    machine = await session.get(Machine, machine_id)
    if machine is None:
        raise HTTPException(status_code=404, detail="Machine not found")
    return MachineOut.model_validate(machine)
