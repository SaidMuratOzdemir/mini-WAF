"""Add reverse-proxy site routing fields

Revision ID: add_reverse_proxy_site_fields
Revises: drop_vestigial_site_columns
Create Date: 2026-02-23 21:20:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_reverse_proxy_site_fields'
down_revision = 'drop_vestigial_site_columns'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('sites', sa.Column('upstream_url', sa.String(), nullable=True))
    op.execute("UPDATE sites SET upstream_url = 'http://' || host WHERE upstream_url IS NULL")
    op.alter_column('sites', 'upstream_url', nullable=False)

    op.add_column('sites', sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('sites', sa.Column('preserve_host_header', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('sites', sa.Column('enable_sni', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('sites', sa.Column('websocket_enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('sites', sa.Column('body_inspection_profile', sa.String(), nullable=False, server_default=sa.text("'default'")))


def downgrade() -> None:
    op.drop_column('sites', 'body_inspection_profile')
    op.drop_column('sites', 'websocket_enabled')
    op.drop_column('sites', 'enable_sni')
    op.drop_column('sites', 'preserve_host_header')
    op.drop_column('sites', 'is_active')
    op.drop_column('sites', 'upstream_url')
