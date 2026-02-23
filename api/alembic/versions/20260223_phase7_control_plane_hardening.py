"""Phase 7 control-plane hardening (RBAC, audit, policy, DNS snapshot)

Revision ID: phase7_control_plane_hardening
Revises: add_tls_and_certificate_support
Create Date: 2026-02-23 22:40:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "phase7_control_plane_hardening"
down_revision = "add_tls_and_certificate_support"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("role", sa.String(), nullable=False, server_default="admin"))
    op.execute("UPDATE users SET role = 'super_admin' WHERE is_admin = true")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('admin', 'super_admin')",
    )

    op.add_column("sites", sa.Column("resolved_upstream_ips", sa.JSON(), nullable=True))
    op.add_column("sites", sa.Column("last_resolved_at", sa.DateTime(), nullable=True))

    op.create_table(
        "upstream_policies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("allow_private_upstreams", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("allowed_private_cidrs", sa.String(), nullable=True),
        sa.Column("denied_cidrs", sa.String(), nullable=True),
        sa.Column("allowed_upstream_ports", sa.String(), nullable=True),
        sa.Column("denied_hostnames", sa.String(), nullable=True),
        sa.Column("allowed_hostname_suffixes", sa.String(), nullable=True),
        sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["updated_by_user_id"], ["users.id"], ondelete="SET NULL"),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_username", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target_type", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=True),
        sa.Column("before_json", sa.JSON(), nullable=True),
        sa.Column("after_json", sa.JSON(), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("error_message", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_table("upstream_policies")

    op.drop_column("sites", "last_resolved_at")
    op.drop_column("sites", "resolved_upstream_ips")

    op.drop_constraint("ck_users_role", "users", type_="check")
    op.drop_column("users", "role")
