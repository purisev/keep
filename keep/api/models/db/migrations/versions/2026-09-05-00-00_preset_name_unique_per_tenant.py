"""fix: drop the global unique constraint on preset.name (make it per-tenant)

Revision ID: preset_name_unique_per_tenant
Revises: preset_provisioning_fields
Create Date: 2026-09-05 00:00:00.000000

This revision is carried by the fork, not by upstream Keep. The identifier is
deliberately not a random hex string so it is obvious in `alembic history` which
revision is ours.

The preset table was created (migration 54c1252b2c8a) with BOTH
UniqueConstraint("name") and UniqueConstraint("tenant_id", "name"). The former
makes preset names globally unique across every tenant, so two tenants cannot
both have a preset called e.g. "Test preset"; the second tenant's POST /preset
fails with an IntegrityError -> HTTP 500. Only the composite (tenant_id, name)
uniqueness is intended. This drops the standalone unique on name.

The constraint was created without an explicit name, so its physical name differs
per dialect: SQLite has it inline (requires a batch table rebuild), PostgreSQL
auto-names it "preset_name_key", MySQL exposes it as an index named "name".

If an upstream sync brings new migrations, resolve the resulting multiple heads
with `alembic merge`, not by re-parenting this revision.
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "preset_name_unique_per_tenant"
down_revision = "preset_provisioning_fields"
branch_labels = None
depends_on = None

# So the batch rebuild on SQLite can address the otherwise-unnamed constraints by
# a deterministic name: UniqueConstraint("name") -> uq_preset_name,
# UniqueConstraint("tenant_id", "name") -> uq_preset_tenant_id (kept).
naming_convention = {"uq": "uq_%(table_name)s_%(column_0_name)s"}


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        # SQLite cannot drop a constraint in place; batch recreates the table
        # from reflected metadata with the standalone unique on name removed.
        with op.batch_alter_table(
            "preset", schema=None, naming_convention=naming_convention
        ) as batch_op:
            batch_op.drop_constraint("uq_preset_name", type_="unique")
    elif dialect == "postgresql":
        op.drop_constraint("preset_name_key", "preset", type_="unique")
    elif dialect == "mysql":
        # A single-column unique surfaces as an index named after the column.
        op.drop_index("name", table_name="preset")
    else:
        with op.batch_alter_table(
            "preset", schema=None, naming_convention=naming_convention
        ) as batch_op:
            batch_op.drop_constraint("uq_preset_name", type_="unique")


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        with op.batch_alter_table(
            "preset", schema=None, naming_convention=naming_convention
        ) as batch_op:
            batch_op.create_unique_constraint("uq_preset_name", ["name"])
    elif dialect == "postgresql":
        op.create_unique_constraint("preset_name_key", "preset", ["name"])
    elif dialect == "mysql":
        op.create_index("name", "preset", ["name"], unique=True)
    else:
        with op.batch_alter_table(
            "preset", schema=None, naming_convention=naming_convention
        ) as batch_op:
            batch_op.create_unique_constraint("uq_preset_name", ["name"])
