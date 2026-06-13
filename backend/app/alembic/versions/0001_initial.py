"""initial schema: machines, threats, commands

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-12

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "machines",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("machine_uuid", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=True),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("os_version", sa.String(), nullable=True),
        sa.Column("agent_version", sa.String(), nullable=True),
        sa.Column("rtp_enabled", sa.Boolean(), nullable=True),
        sa.Column("av_enabled", sa.Boolean(), nullable=True),
        sa.Column("signature_version", sa.String(), nullable=True),
        sa.Column("signature_last_updated", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signature_age_days", sa.Integer(), nullable=True),
        sa.Column("last_quick_scan", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_full_scan", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_up_to_date", sa.Boolean(), nullable=True),
        sa.Column("token_hash", sa.String(), nullable=True),
        sa.Column("token_revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_machines_machine_uuid", "machines", ["machine_uuid"], unique=True
    )
    op.create_index("ix_machines_hostname", "machines", ["hostname"])
    op.create_index("ix_machines_domain", "machines", ["domain"])
    op.create_index("ix_machines_last_seen", "machines", ["last_seen"])
    op.create_index("ix_machines_is_up_to_date", "machines", ["is_up_to_date"])

    op.create_table(
        "threats",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("machine_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("detection_id", sa.String(), nullable=True),
        sa.Column("threat_name", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("category", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("action_taken", sa.String(), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "machine_id", "detection_id", name="uq_threats_machine_detection"
        ),
    )
    op.create_index("ix_threats_machine_id", "threats", ["machine_id"])
    op.create_index("ix_threats_detected_at", "threats", ["detected_at"])
    op.create_index("ix_threats_status", "threats", ["status"])

    op.create_table(
        "commands",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("machine_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_output", sa.String(), nullable=True),
        sa.Column("error", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_commands_machine_status", "commands", ["machine_id", "status"]
    )
    op.create_index("ix_commands_expires_at", "commands", ["expires_at"])


def downgrade() -> None:
    op.drop_table("commands")
    op.drop_table("threats")
    op.drop_table("machines")
