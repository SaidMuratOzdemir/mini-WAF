"""Phase 9A.1-C: add block_private_destinations to forward proxy profiles

Revision ID: phase9a1c_private_dest_acl
Revises: phase9a_forward_proxy_mvp
Create Date: 2026-02-24 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "phase9a1c_private_dest_acl"
down_revision = "phase9a_forward_proxy_mvp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "outbound_proxy_profiles",
        sa.Column(
            "block_private_destinations",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )


def downgrade() -> None:
    op.drop_column("outbound_proxy_profiles", "block_private_destinations")
