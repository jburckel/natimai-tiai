"""index machines.token_hash: every agent call looks the machine up by it

Revision ID: 0015_machine_token_hash_index
Revises: 0014_inventory
Create Date: 2026-10-23

"""
from collections.abc import Sequence

from alembic import op

revision: str = "0015_machine_token_hash_index"
down_revision: str | None = "0014_inventory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_machines_token_hash", "machines", ["token_hash"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_machines_token_hash", table_name="machines")
