"""deleted useless fields from tables

Revision ID: 1aa5f4028116
Revises: 74f1af31ad12
Create Date: 2023-04-26 21:47:40.063257

"""
from alembic import op
import sqlalchemy as sa
import app

from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '1aa5f4028116'
down_revision = '74f1af31ad12'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('psifos_election', 'cast_url')
    op.drop_column('psifos_election', 'private_key')
    op.drop_column('psifos_trustee', 'secret')
    op.drop_column('psifos_trustee', 'secret_key')
    op.drop_column('psifos_trustee', 'pok')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('psifos_trustee', sa.Column('pok', mysql.TEXT(), nullable=True))
    op.add_column('psifos_trustee', sa.Column('secret_key', mysql.TEXT(), nullable=True))
    op.add_column('psifos_trustee', sa.Column('secret', mysql.VARCHAR(length=100), nullable=True))
    op.add_column('psifos_election', sa.Column('private_key', mysql.TEXT(), nullable=True))
    op.add_column('psifos_election', sa.Column('cast_url', mysql.VARCHAR(length=500), nullable=True))
    # ### end Alembic commands ###
