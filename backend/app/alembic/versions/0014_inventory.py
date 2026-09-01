"""hardware and software inventory: machine columns + per-machine sets + software catalogue

Revision ID: 0014_inventory
Revises: 0013_audit_log
Create Date: 2026-08-31

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_inventory"
down_revision: str | None = "0013_audit_log"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _machine_columns() -> list[sa.Column[object]]:
    """Cardinality-one inventory facts, added to ``machines``.

    All nullable: NULL means "never reported", which is distinct from a value
    the agent read as empty. The one exception is ``hw_is_virtual`` — a machine
    that never reported is not a virtual one, so false is the honest default and
    NOT NULL costs nothing.

    A factory and not a module-level list: a Column belongs to the table it was
    added to, and replaying upgrade → downgrade → upgrade in one process would
    otherwise try to re-attach the same objects.
    """
    return [
        sa.Column("hw_manufacturer", sa.String(), nullable=True),
        sa.Column("hw_model", sa.String(), nullable=True),
        sa.Column("hw_serial", sa.String(), nullable=True),
        sa.Column("hw_chassis_type", sa.String(), nullable=True),
        sa.Column(
            "hw_is_virtual", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("hw_hypervisor", sa.String(), nullable=True),
        sa.Column("mb_manufacturer", sa.String(), nullable=True),
        sa.Column("mb_model", sa.String(), nullable=True),
        sa.Column("mb_serial", sa.String(), nullable=True),
        sa.Column("bios_vendor", sa.String(), nullable=True),
        sa.Column("bios_version", sa.String(), nullable=True),
        # A Date and not a timestamptz: firmware is dated to the day.
        sa.Column("bios_date", sa.Date(), nullable=True),
        sa.Column("secure_boot", sa.Boolean(), nullable=True),
        sa.Column("tpm_version", sa.String(), nullable=True),
        sa.Column("cpu_model", sa.String(), nullable=True),
        sa.Column("cpu_manufacturer", sa.String(), nullable=True),
        sa.Column("cpu_cores", sa.Integer(), nullable=True),
        sa.Column("cpu_threads", sa.Integer(), nullable=True),
        sa.Column("cpu_speed_mhz", sa.Integer(), nullable=True),
        sa.Column("cpu_count", sa.Integer(), nullable=True),
        sa.Column("ram_total_mb", sa.Integer(), nullable=True),
        sa.Column("ram_slots_total", sa.Integer(), nullable=True),
        sa.Column("ram_slots_used", sa.Integer(), nullable=True),
        sa.Column("os_architecture", sa.String(), nullable=True),
        sa.Column("os_install_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_boot_time", sa.DateTime(timezone=True), nullable=True),
        # INTEGER and not BIGINT, here and on every *_mb column below: these
        # are mebibytes, so int4 tops out around two pebibytes — three orders
        # of magnitude past the largest drive a poste carries, and past the
        # cap the schemas already apply. It also has to match the models, or
        # the schema built by create_all (the tests) and the migrated one
        # (production) would differ — which is what alembic check is for.
        # Derived from the reported volumes, not sent as fields: the same
        # reasoning as wu_pending_count. Denormalised here because "quels postes
        # n'ont plus de place" is answered by scanning a column.
        sa.Column("system_volume_total_mb", sa.Integer(), nullable=True),
        sa.Column("system_volume_free_mb", sa.Integer(), nullable=True),
        sa.Column("inventory_hash", sa.String(), nullable=True),
        sa.Column("inventory_last_seen", sa.DateTime(timezone=True), nullable=True),
    ]


def _child_columns() -> list[sa.Column[object]]:
    """The columns every per-machine inventory table carries.

    Fresh instances each call: a Column belongs to one table and cannot be
    shared between two create_table() calls.
    """
    return [
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("machine_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    ]


def upgrade() -> None:
    for column in _machine_columns():
        op.add_column("machines", column)

    # --- Per-machine sets. Current state, not history: a row disappears when
    # the hardware does (see features/inventory/crud). Each unique constraint is
    # what its upsert keys on; each index serves the fiche's own lookup.
    op.create_table(
        "inventory_memory_modules",
        *_child_columns(),
        sa.Column("slot", sa.String(), nullable=False),
        sa.Column("capacity_mb", sa.Integer(), nullable=True),
        sa.Column("type", sa.String(), nullable=True),
        sa.Column("speed_mhz", sa.Integer(), nullable=True),
        sa.Column("manufacturer", sa.String(), nullable=True),
        sa.Column("serial", sa.String(), nullable=True),
        sa.Column("form_factor", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("machine_id", "slot", name="uq_inv_memory_machine_slot"),
    )
    op.create_index(
        "ix_inv_memory_machine_id", "inventory_memory_modules", ["machine_id"]
    )

    op.create_table(
        "inventory_disks",
        *_child_columns(),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("model", sa.String(), nullable=True),
        sa.Column("serial", sa.String(), nullable=True),
        sa.Column("firmware", sa.String(), nullable=True),
        sa.Column("media_type", sa.String(), nullable=True),
        sa.Column("bus_type", sa.String(), nullable=True),
        sa.Column("size_mb", sa.Integer(), nullable=True),
        sa.Column("health_status", sa.String(), nullable=True),
        sa.Column(
            "is_removable", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "machine_id", "device_id", name="uq_inv_disks_machine_device"
        ),
    )
    op.create_index("ix_inv_disks_machine_id", "inventory_disks", ["machine_id"])

    op.create_table(
        "inventory_volumes",
        *_child_columns(),
        sa.Column("letter", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("filesystem", sa.String(), nullable=True),
        sa.Column("total_mb", sa.Integer(), nullable=True),
        sa.Column("free_mb", sa.Integer(), nullable=True),
        sa.Column(
            "is_system", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("encryption_status", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "machine_id", "letter", name="uq_inv_volumes_machine_letter"
        ),
    )
    op.create_index("ix_inv_volumes_machine_id", "inventory_volumes", ["machine_id"])

    op.create_table(
        "inventory_nics",
        *_child_columns(),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("mac", sa.String(), nullable=True),
        sa.Column("type", sa.String(), nullable=True),
        sa.Column("speed_mbps", sa.Integer(), nullable=True),
        sa.Column("is_up", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "is_virtual", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("ip_prefix_length", sa.Integer(), nullable=True),
        sa.Column("is_dhcp", sa.Boolean(), nullable=True),
        sa.Column("gateway", sa.String(), nullable=True),
        sa.Column("driver_version", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("machine_id", "key", name="uq_inv_nics_machine_key"),
    )
    op.create_index("ix_inv_nics_machine_id", "inventory_nics", ["machine_id"])

    op.create_table(
        "inventory_gpus",
        *_child_columns(),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("chipset", sa.String(), nullable=True),
        sa.Column("memory_mb", sa.Integer(), nullable=True),
        sa.Column("driver_version", sa.String(), nullable=True),
        sa.Column("driver_date", sa.Date(), nullable=True),
        sa.Column("resolution", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("machine_id", "name", name="uq_inv_gpus_machine_name"),
    )
    op.create_index("ix_inv_gpus_machine_id", "inventory_gpus", ["machine_id"])

    # --- The software catalogue and its link table. version and publisher are
    # NOT NULL with an empty default on purpose: Postgres treats NULLs as
    # distinct in a UNIQUE constraint, so a nullable publisher would let one
    # unpublished program accumulate a catalogue row per machine — precisely the
    # duplication the catalogue exists to avoid.
    op.create_table(
        "software",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False, server_default=""),
        sa.Column("publisher", sa.String(), nullable=False, server_default=""),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "version", "publisher", name="uq_software_identity"),
    )
    op.create_index("ix_software_name", "software", ["name"])

    op.create_table(
        "machine_software",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("machine_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("software_id", sa.BigInteger(), nullable=False),
        sa.Column("install_date", sa.Date(), nullable=True),
        sa.Column("arch", sa.String(), nullable=True),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("install_location", sa.String(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["software_id"], ["software.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "machine_id", "software_id", name="uq_machine_software_identity"
        ),
    )
    op.create_index(
        "ix_machine_software_machine_id", "machine_software", ["machine_id"]
    )
    # The catalogue's own direction: "which postes carry this program", the
    # drill-down behind every row of the parc-wide software page.
    op.create_index(
        "ix_machine_software_software_id", "machine_software", ["software_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_machine_software_software_id", table_name="machine_software")
    op.drop_index("ix_machine_software_machine_id", table_name="machine_software")
    op.drop_table("machine_software")
    op.drop_index("ix_software_name", table_name="software")
    op.drop_table("software")
    op.drop_index("ix_inv_gpus_machine_id", table_name="inventory_gpus")
    op.drop_table("inventory_gpus")
    op.drop_index("ix_inv_nics_machine_id", table_name="inventory_nics")
    op.drop_table("inventory_nics")
    op.drop_index("ix_inv_volumes_machine_id", table_name="inventory_volumes")
    op.drop_table("inventory_volumes")
    op.drop_index("ix_inv_disks_machine_id", table_name="inventory_disks")
    op.drop_table("inventory_disks")
    op.drop_index("ix_inv_memory_machine_id", table_name="inventory_memory_modules")
    op.drop_table("inventory_memory_modules")
    for column in reversed(_machine_columns()):
        op.drop_column("machines", column.name)
