"""machine identity fingerprint + needs_verification

Revision ID: 0003_fingerprint
Revises: 0002_users
Create Date: 2026-06-13

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_fingerprint"
down_revision: str | None = "0002_users"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("machine_guid", sa.String(), nullable=True))
    op.add_column("machines", sa.Column("smbios_uuid", sa.String(), nullable=True))
    op.add_column("machines", sa.Column("tpm_ek_hash", sa.String(), nullable=True))
    op.add_column(
        "machines",
        sa.Column(
            "needs_verification",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.create_index("ix_machines_smbios_uuid", "machines", ["smbios_uuid"])
    op.create_index(
        "ix_machines_needs_verification", "machines", ["needs_verification"]
    )


def downgrade() -> None:
    op.drop_index("ix_machines_needs_verification", table_name="machines")
    op.drop_index("ix_machines_smbios_uuid", table_name="machines")
    op.drop_column("machines", "needs_verification")
    op.drop_column("machines", "tpm_ek_hash")
    op.drop_column("machines", "smbios_uuid")
    op.drop_column("machines", "machine_guid")
