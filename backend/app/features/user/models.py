import enum
import uuid
from datetime import datetime

from sqlmodel import Field, SQLModel

from app.features.base import utcnow


class Role(enum.StrEnum):
    """Console roles (Phase 1).

    Coarse-grained for now. Fine-grained per-resource grants (read/write by
    table, per user) are layered on later in app.features.user.permissions
    without changing route call sites.
    """

    ADMIN = "admin"  # read + write + execute remote commands
    READONLY = "readonly"  # read only


class User(SQLModel, table=True):
    """A console operator authenticating with email + password (JWT)."""

    __tablename__ = "users"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    email: str = Field(unique=True, index=True, max_length=255)
    hashed_password: str
    full_name: str | None = Field(default=None, max_length=255)
    # Stored as a plain string; Role is a str enum used as a constant.
    role: str = Field(default=Role.READONLY)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
