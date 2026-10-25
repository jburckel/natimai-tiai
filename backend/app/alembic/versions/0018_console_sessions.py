"""console sessions: security stamp, lockout, refresh tokens, lower-case e-mails

Revision ID: 0018_console_sessions
Revises: 0017_audit_ip
Create Date: 2026-10-24

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision: str = "0018_console_sessions"
down_revision: str | None = "0017_audit_ip"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Filled for existing accounts, then left to the application: the model
    # draws a stamp per account, and a server default would hand every new row
    # the same one.
    op.add_column(
        "users",
        sa.Column(
            "security_stamp",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("md5(random()::text || clock_timestamp()::text)"),
        ),
    )
    op.alter_column("users", "security_stamp", server_default=None)
    op.add_column(
        "users",
        sa.Column(
            "failed_login_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.alter_column("users", "failed_login_attempts", server_default=None)
    op.add_column(
        "users",
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
    )
    # Addresses are compared lower-case from now on. Two accounts differing
    # only in case would make this fail on the unique index — on purpose: they
    # have to be merged by hand, not silently by the migration.
    op.execute("UPDATE users SET email = lower(email) WHERE email <> lower(email)")

    op.create_table(
        "refresh_tokens",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("family", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token_hash"),
    )
    op.create_index(
        "ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"], unique=False
    )
    op.create_index(
        "ix_refresh_tokens_family", "refresh_tokens", ["family"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_family", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_attempts")
    op.drop_column("users", "security_stamp")
