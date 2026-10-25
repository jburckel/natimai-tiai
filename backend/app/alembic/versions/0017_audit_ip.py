"""audit_log: source address of each action

Revision ID: 0017_audit_ip
Revises: 0016_machine_reenroll_request
Create Date: 2026-10-24

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_audit_ip"
down_revision: str | None = "0016_machine_reenroll_request"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("audit_log", sa.Column("ip", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_log", "ip")
