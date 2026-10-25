"""Shared request-field types for route payloads."""

from typing import Annotated

from pydantic import AfterValidator, Field

from app.core.config import settings

# Any password accepted through the API must be at least this long.
Password = Annotated[str, Field(min_length=settings.PASSWORD_MIN_LENGTH)]

# Console account identifier. Deliberately looser than RFC-grade validation
# (pydantic's EmailStr): email-validator rejects special-use domains such as
# `.local` — exactly what the on-prem AD parks this tool targets use
# (admin@natimai.local). Shape check only: one @, a dotted domain, no spaces.
# Stored lower-case (app.features.user.crud.normalize_email): an address
# typed « Admin@Natimai.local » is the same account as admin@natimai.local.
Email = Annotated[
    str,
    AfterValidator(lambda v: v.strip().lower()),
    Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=255),
]
