"""Drop vestigial port, frontend_url, backend_url columns from sites table

Revision ID: drop_vestigial_site_columns
Revises: add_pattern_enhancements
Create Date: 2026-02-23 18:50:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'drop_vestigial_site_columns'
down_revision = 'add_pattern_enhancements'
branch_labels = None
depends_on = None


def upgrade():
    """Drop port, frontend_url, backend_url from sites table.
    
    These columns are no longer used after migration to Nginx auth_request
    architecture. The WAF no longer proxies traffic, so per-site port and
    URL mappings are vestigial.
    """
    # Drop the old unique constraint that included port
    op.drop_constraint('unique_port_host', 'sites', type_='unique')

    op.drop_column('sites', 'port')
    op.drop_column('sites', 'frontend_url')
    op.drop_column('sites', 'backend_url')

    # Add new unique constraint on host only
    op.create_unique_constraint('uq_sites_host', 'sites', ['host'])


def downgrade():
    """Re-add port, frontend_url, backend_url columns to sites table."""
    op.drop_constraint('uq_sites_host', 'sites', type_='unique')

    op.add_column('sites', sa.Column('port', sa.Integer(), nullable=True))
    op.add_column('sites', sa.Column('frontend_url', sa.String(), nullable=True))
    op.add_column('sites', sa.Column('backend_url', sa.String(), nullable=True))

    op.create_unique_constraint('unique_port_host', 'sites', ['port', 'host'])
