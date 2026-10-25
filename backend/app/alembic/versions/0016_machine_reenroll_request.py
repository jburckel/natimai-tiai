"""machines: re-enrollment held for approval

Revision ID: 0016_machine_reenroll_request
Revises: 0015_machine_token_hash_index
Create Date: 2026-10-24

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_machine_reenroll_request"
down_revision: str | None = "0015_machine_token_hash_index"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "machines",
        sa.Column("reenroll_requested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "machines",
        sa.Column("reenroll_requested_ip", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("machines", "reenroll_requested_ip")
    op.drop_column("machines", "reenroll_requested_at")
