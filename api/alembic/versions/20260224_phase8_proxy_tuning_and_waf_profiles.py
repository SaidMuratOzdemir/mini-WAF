"""Phase 8 proxy tuning and body inspection profiles

Revision ID: phase8_proxy_tuning_profiles
Revises: phase7_control_plane_hardening
Create Date: 2026-02-24 01:35:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "phase8_proxy_tuning_profiles"
down_revision = "phase7_control_plane_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sites", sa.Column("sse_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("sites", sa.Column("client_max_body_size_mb", sa.Integer(), nullable=True))
    op.add_column("sites", sa.Column("proxy_request_buffering", sa.Boolean(), nullable=True))
    op.add_column("sites", sa.Column("proxy_read_timeout_sec", sa.Integer(), nullable=False, server_default=sa.text("60")))
    op.add_column("sites", sa.Column("proxy_send_timeout_sec", sa.Integer(), nullable=False, server_default=sa.text("60")))
    op.add_column("sites", sa.Column("proxy_connect_timeout_sec", sa.Integer(), nullable=False, server_default=sa.text("10")))
    op.add_column("sites", sa.Column("proxy_redirect_mode", sa.String(), nullable=False, server_default="default"))
    op.add_column("sites", sa.Column("cookie_rewrite_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("sites", sa.Column("waf_decision_mode", sa.String(), nullable=False, server_default="fail_close"))

    op.create_check_constraint(
        "ck_sites_body_inspection_profile_phase8",
        "sites",
        "body_inspection_profile IN ('strict', 'default', 'headers_only', 'upload_friendly', 'custom')",
    )
    op.create_check_constraint(
        "ck_sites_proxy_redirect_mode_phase8",
        "sites",
        "proxy_redirect_mode IN ('default', 'off', 'rewrite_to_public_host')",
    )
    op.create_check_constraint(
        "ck_sites_waf_decision_mode_phase8",
        "sites",
        "waf_decision_mode IN ('fail_open', 'fail_close')",
    )
    op.create_check_constraint(
        "ck_sites_proxy_read_timeout_positive_phase8",
        "sites",
        "proxy_read_timeout_sec > 0",
    )
    op.create_check_constraint(
        "ck_sites_proxy_send_timeout_positive_phase8",
        "sites",
        "proxy_send_timeout_sec > 0",
    )
    op.create_check_constraint(
        "ck_sites_proxy_connect_timeout_positive_phase8",
        "sites",
        "proxy_connect_timeout_sec > 0",
    )
    op.create_check_constraint(
        "ck_sites_client_max_body_size_positive_phase8",
        "sites",
        "client_max_body_size_mb IS NULL OR client_max_body_size_mb > 0",
    )


def downgrade() -> None:
    op.drop_constraint("ck_sites_client_max_body_size_positive_phase8", "sites", type_="check")
    op.drop_constraint("ck_sites_proxy_connect_timeout_positive_phase8", "sites", type_="check")
    op.drop_constraint("ck_sites_proxy_send_timeout_positive_phase8", "sites", type_="check")
    op.drop_constraint("ck_sites_proxy_read_timeout_positive_phase8", "sites", type_="check")
    op.drop_constraint("ck_sites_waf_decision_mode_phase8", "sites", type_="check")
    op.drop_constraint("ck_sites_proxy_redirect_mode_phase8", "sites", type_="check")
    op.drop_constraint("ck_sites_body_inspection_profile_phase8", "sites", type_="check")

    op.drop_column("sites", "waf_decision_mode")
    op.drop_column("sites", "cookie_rewrite_enabled")
    op.drop_column("sites", "proxy_redirect_mode")
    op.drop_column("sites", "proxy_connect_timeout_sec")
    op.drop_column("sites", "proxy_send_timeout_sec")
    op.drop_column("sites", "proxy_read_timeout_sec")
    op.drop_column("sites", "proxy_request_buffering")
    op.drop_column("sites", "client_max_body_size_mb")
    op.drop_column("sites", "sse_enabled")
