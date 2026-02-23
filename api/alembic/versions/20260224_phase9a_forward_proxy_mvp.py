"""Phase 9A explicit forward proxy MVP

Revision ID: phase9a_forward_proxy_mvp
Revises: phase8_proxy_tuning_profiles
Create Date: 2026-02-24 02:05:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "phase9a_forward_proxy_mvp"
down_revision = "phase8_proxy_tuning_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "outbound_proxy_profiles",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(), nullable=False, unique=True),
        sa.Column("listen_port", sa.Integer(), nullable=False, server_default=sa.text("3128")),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("require_auth", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("allow_connect_ports", sa.String(), nullable=False, server_default="443,563"),
        sa.Column("allowed_client_cidrs", sa.String(), nullable=True),
        sa.Column("default_action", sa.String(), nullable=False, server_default="deny"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_check_constraint(
        "ck_outbound_proxy_profiles_listen_port",
        "outbound_proxy_profiles",
        "listen_port >= 1 AND listen_port <= 65535",
    )
    op.create_check_constraint(
        "ck_outbound_proxy_profiles_default_action",
        "outbound_proxy_profiles",
        "default_action IN ('allow', 'deny')",
    )

    op.create_table(
        "outbound_destination_rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("profile_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("rule_type", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False, server_default=sa.text("100")),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["profile_id"], ["outbound_proxy_profiles.id"], ondelete="CASCADE"),
    )
    op.create_check_constraint(
        "ck_outbound_destination_rules_action",
        "outbound_destination_rules",
        "action IN ('allow', 'deny')",
    )
    op.create_check_constraint(
        "ck_outbound_destination_rules_rule_type",
        "outbound_destination_rules",
        "rule_type IN ('domain_exact', 'domain_suffix', 'host_exact', 'cidr', 'port')",
    )
    op.create_check_constraint(
        "ck_outbound_destination_rules_priority",
        "outbound_destination_rules",
        "priority >= 0",
    )
    op.create_index(
        "ix_outbound_destination_rules_profile_priority",
        "outbound_destination_rules",
        ["profile_id", "priority", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_outbound_destination_rules_profile_priority", table_name="outbound_destination_rules")
    op.drop_constraint("ck_outbound_destination_rules_priority", "outbound_destination_rules", type_="check")
    op.drop_constraint("ck_outbound_destination_rules_rule_type", "outbound_destination_rules", type_="check")
    op.drop_constraint("ck_outbound_destination_rules_action", "outbound_destination_rules", type_="check")
    op.drop_table("outbound_destination_rules")

    op.drop_constraint("ck_outbound_proxy_profiles_default_action", "outbound_proxy_profiles", type_="check")
    op.drop_constraint("ck_outbound_proxy_profiles_listen_port", "outbound_proxy_profiles", type_="check")
    op.drop_table("outbound_proxy_profiles")
