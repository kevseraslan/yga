"""Add IsFavorite column to Questions table

Revision ID: add_isfavorite_column
Revises: update_question_category
Create Date: 2024-03-19
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_isfavorite_column'
down_revision = 'update_question_category'
branch_labels = None
depends_on = None

def upgrade():
    # Questions tablosuna IsFavorite sütunu ekle
    with op.batch_alter_table('Questions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('IsFavorite', sa.Boolean(), nullable=True, server_default='0'))

def downgrade():
    # IsFavorite sütununu kaldır
    with op.batch_alter_table('Questions', schema=None) as batch_op:
        batch_op.drop_column('IsFavorite') 