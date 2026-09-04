"""feat: work item identity - rule_type on dedup rules, work_item_key on last alerts

Revision ID: work_item_identity
Revises: preset_provisioning_fields
Create Date: 2026-09-04 10:00:00.000000

This revision is carried by the fork, not by upstream Keep. See
2026-08-14-12-00_preset_provisioning_fields.py for what to do when an upstream
sync turns this into a second head: `alembic merge`, never re-parenting.

Both columns use sqlmodel's AutoString, which is what the models resolve to:
VARCHAR(255) on MySQL, VARCHAR elsewhere.

"""

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision = "work_item_identity"
down_revision = "preset_provisioning_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # rules on disk compute the alert fingerprint, which is what "split" means,
    # so the server_default is the whole backfill
    with op.batch_alter_table("alertdeduplicationrule", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "rule_type",
                sqlmodel.sql.sqltypes.AutoString(),
                nullable=False,
                server_default="split",
            )
        )

    with op.batch_alter_table("lastalert", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "work_item_key",
                sqlmodel.sql.sqltypes.AutoString(),
                nullable=True,
            )
        )
        batch_op.create_index(
            "idx_lastalert_tenant_work_item_key",
            ["tenant_id", "work_item_key"],
        )


def downgrade() -> None:
    with op.batch_alter_table("lastalert", schema=None) as batch_op:
        batch_op.drop_index("idx_lastalert_tenant_work_item_key")
        batch_op.drop_column("work_item_key")

    with op.batch_alter_table("alertdeduplicationrule", schema=None) as batch_op:
        batch_op.drop_column("rule_type")
