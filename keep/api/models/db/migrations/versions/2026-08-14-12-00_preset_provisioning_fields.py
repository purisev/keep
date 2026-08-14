"""feat: add is_provisioned and provisioned_file to Preset

Revision ID: preset_provisioning_fields
Revises: 67ff7efffed4
Create Date: 2026-08-14 12:00:00.000000

This revision is carried by the fork, not by upstream Keep. The identifier is
deliberately not a random hex string so it is obvious in `alembic history` which
revision is ours.

When an upstream sync brings new migrations, this revision and the new upstream
head become two heads, and `alembic.command.upgrade(config, "head")` in
keep/api/core/db_on_start.py fails with "Multiple head revisions are present" —
loudly, before the application serves anything.

Resolve it with `alembic merge`, NOT by re-parenting this revision. Editing
down_revision to point at the new upstream head is safe only while this revision
has never been applied anywhere; on a database that already ran it, the
alembic_version row still names this revision, so alembic would consider the
database up to date and silently skip every upstream migration in between.

"""

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision = "preset_provisioning_fields"
down_revision = "67ff7efffed4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("preset", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "is_provisioned",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.add_column(
            sa.Column(
                "provisioned_file",
                sqlmodel.sql.sqltypes.AutoString(),
                nullable=True,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("preset", schema=None) as batch_op:
        batch_op.drop_column("provisioned_file")
        batch_op.drop_column("is_provisioned")
