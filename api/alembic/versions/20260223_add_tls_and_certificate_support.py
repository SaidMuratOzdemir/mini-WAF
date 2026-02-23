"""Add TLS site fields and certificate registry

Revision ID: add_tls_and_certificate_support
Revises: add_reverse_proxy_site_fields
Create Date: 2026-02-23 22:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_tls_and_certificate_support'
down_revision = 'add_reverse_proxy_site_fields'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'certificates',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(), nullable=False, unique=True),
        sa.Column('cert_pem_path', sa.String(), nullable=False),
        sa.Column('key_pem_path', sa.String(), nullable=False),
        sa.Column('chain_pem_path', sa.String(), nullable=True),
        sa.Column('is_default', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.add_column('sites', sa.Column('tls_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('sites', sa.Column('http_redirect_to_https', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('sites', sa.Column('tls_certificate_id', sa.Integer(), nullable=True))
    op.add_column('sites', sa.Column('upstream_tls_verify', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('sites', sa.Column('upstream_tls_server_name_override', sa.String(), nullable=True))
    op.add_column('sites', sa.Column('hsts_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')))

    op.create_foreign_key(
        'fk_sites_tls_certificate_id_certificates',
        'sites',
        'certificates',
        ['tls_certificate_id'],
        ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    op.drop_constraint('fk_sites_tls_certificate_id_certificates', 'sites', type_='foreignkey')

    op.drop_column('sites', 'hsts_enabled')
    op.drop_column('sites', 'upstream_tls_server_name_override')
    op.drop_column('sites', 'upstream_tls_verify')
    op.drop_column('sites', 'tls_certificate_id')
    op.drop_column('sites', 'http_redirect_to_https')
    op.drop_column('sites', 'tls_enabled')

    op.drop_table('certificates')
