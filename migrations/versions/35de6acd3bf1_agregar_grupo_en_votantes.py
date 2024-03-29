"""agregar grupo en votantes

Revision ID: 35de6acd3bf1
Revises: 220e97984f9a
Create Date: 2023-08-17 18:20:43.748426

"""
from alembic import op
import sqlalchemy as sa
import app



# revision identifiers, used by Alembic.
revision = '35de6acd3bf1'
down_revision = '220e97984f9a'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('psifos_cast_vote', sa.Column('vote_group', sa.String(length=200), nullable=True))
    op.add_column('psifos_voter', sa.Column('group', sa.String(length=200), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('psifos_voter', 'group')
    op.drop_column('psifos_cast_vote', 'vote_group')
    # ### end Alembic commands ###
