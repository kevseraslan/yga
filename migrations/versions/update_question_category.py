"""Update Question model with CategoryId

Revision ID: update_question_category
Revises: 5000d41cdbc0
Create Date: 2024-03-19

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime

# revision identifiers, used by Alembic.
revision = 'update_question_category'
down_revision = '5000d41cdbc0'
branch_labels = None
depends_on = None

def upgrade():
    # Önce Categories tablosunu oluştur
    op.create_table('Categories',
        sa.Column('CategoryId', sa.Integer(), nullable=False),
        sa.Column('Name', sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint('CategoryId')
    )
    
    # Mevcut kategorileri al ve Categories tablosuna ekle
    connection = op.get_bind()
    categories = connection.execute('SELECT DISTINCT Category FROM Questions').fetchall()
    
    for category in categories:
        connection.execute(
            'INSERT INTO Categories (Name) VALUES (?)',
            (category[0],)
        )
    
    # Questions tablosuna CategoryId sütunu ekle
    op.add_column('Questions', sa.Column('CategoryId', sa.Integer(), nullable=True))
    
    # Her soru için kategori ID'sini güncelle
    for category in categories:
        category_id = connection.execute(
            'SELECT CategoryId FROM Categories WHERE Name = ?',
            (category[0],)
        ).fetchone()[0]
        
        connection.execute(
            'UPDATE Questions SET CategoryId = ? WHERE Category = ?',
            (category_id, category[0])
        )
    
    # Category sütununu kaldır
    op.drop_column('Questions', 'Category')
    
    # CategoryId'yi nullable=False yap
    op.alter_column('Questions', 'CategoryId',
               existing_type=sa.Integer(),
               nullable=False)
    
    # Foreign key constraint ekle
    op.create_foreign_key('fk_question_category', 'Questions', 'Categories',
                         ['CategoryId'], ['CategoryId'])

def downgrade():
    # Foreign key constraint'i kaldır
    op.drop_constraint('fk_question_category', 'Questions', type_='foreignkey')
    
    # Category sütununu geri ekle
    op.add_column('Questions', sa.Column('Category', sa.String(length=50), nullable=True))
    
    # CategoryId'den Category'ye verileri geri taşı
    connection = op.get_bind()
    questions = connection.execute('SELECT QuestionId, CategoryId FROM Questions').fetchall()
    
    for question in questions:
        category_name = connection.execute(
            'SELECT Name FROM Categories WHERE CategoryId = ?',
            (question[1],)
        ).fetchone()[0]
        
        connection.execute(
            'UPDATE Questions SET Category = ? WHERE QuestionId = ?',
            (category_name, question[0])
        )
    
    # CategoryId sütununu kaldır
    op.drop_column('Questions', 'CategoryId')
    
    # Categories tablosunu kaldır
    op.drop_table('Categories') 