"""Phase 9A.2-A: add outbound_proxy_users table and auth_realm to profiles

Revision ID: phase9a2a_fwd_proxy_auth
Revises: phase9a1c_private_dest_acl
Create Date: 2026-02-24 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "phase9a2a_fwd_proxy_auth"
down_revision = "phase9a1c_private_dest_acl"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add auth_realm column to outbound_proxy_profiles
    op.add_column(
        "outbound_proxy_profiles",
        sa.Column(
            "auth_realm",
            sa.String(),
            nullable=False,
            server_default="WAF Forward Proxy",
        ),
    )

    # Create outbound_proxy_users table
    op.create_table(
        "outbound_proxy_users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(
        "ix_outbound_proxy_users_username",
        "outbound_proxy_users",
        ["username"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_outbound_proxy_users_username", table_name="outbound_proxy_users")
    op.drop_table("outbound_proxy_users")
    op.drop_column("outbound_proxy_profiles", "auth_realm")
