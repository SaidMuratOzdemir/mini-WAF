"""Add is_regex and is_active columns to malicious_patterns

Revision ID: add_pattern_enhancements
Revises: 5ecae12b2a86
Create Date: 2025-09-28 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_pattern_enhancements'
down_revision = '5ecae12b2a86'
branch_labels = None
depends_on = None


def upgrade():
    """Add new columns for enhanced pattern matching."""
    # Add is_regex column with default False
    op.add_column('malicious_patterns', 
                  sa.Column('is_regex', sa.Boolean(), nullable=False, server_default='false'))
    
    # Add is_active column with default True  
    op.add_column('malicious_patterns',
                  sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'))
    
    # Create index on is_active for performance
    op.create_index('idx_malicious_patterns_active', 'malicious_patterns', ['is_active'])
    
    # Create composite index for type + active queries
    op.create_index('idx_malicious_patterns_type_active', 'malicious_patterns', ['type', 'is_active'])


def downgrade():
    """Remove enhanced pattern columns."""
    # Drop indexes first
    op.drop_index('idx_malicious_patterns_type_active', table_name='malicious_patterns')
    op.drop_index('idx_malicious_patterns_active', table_name='malicious_patterns')
    
    # Drop columns
    op.drop_column('malicious_patterns', 'is_active')
    op.drop_column('malicious_patterns', 'is_regex')