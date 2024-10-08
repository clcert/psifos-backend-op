"""Add tally and decryption table

Revision ID: 40a8c1cb62e1
Revises: fadf87014cf2
Create Date: 2024-09-23 12:39:34.541589

"""
from alembic import op
import sqlalchemy as sa
import app

from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '40a8c1cb62e1'
down_revision = 'fadf87014cf2'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('psifos_tallies',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('election_id', sa.Integer(), nullable=False),
    sa.Column('group', sa.Text(), nullable=False),
    sa.Column('with_votes', sa.Boolean(), nullable=True),
    sa.Column('tally_type', sa.Enum('HOMOMORPHIC', 'MIXNET', 'STVNC', name='tallytypeenum'), nullable=False),
    sa.Column('q_num', sa.Integer(), nullable=False),
    sa.Column('num_options', sa.Integer(), nullable=False),
    sa.Column('computed', sa.Boolean(), nullable=True),
    sa.Column('num_tallied', sa.Integer(), nullable=False),
    sa.Column('max_answers', sa.Integer(), nullable=True),
    sa.Column('num_of_winners', sa.Integer(), nullable=True),
    sa.Column('include_blank_null', sa.Boolean(), nullable=True),
    sa.Column('tally', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['election_id'], ['psifos_election.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_psifos_tallies_id'), 'psifos_tallies', ['id'], unique=False)
    op.create_table('psifos_decryptions_homomorphic',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('trustee_id', sa.Integer(), nullable=False),
    sa.Column('group', sa.Text(), nullable=False),
    sa.Column('q_num', sa.Integer(), nullable=False),
    sa.Column('decryption_factors', app.database.custom_fields.ListOfIntegersField(), nullable=True),
    sa.Column('decryption_proofs', app.database.custom_fields.ListOfZKProofsField(), nullable=True),
    sa.ForeignKeyConstraint(['trustee_id'], ['psifos_trustee.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_psifos_decryptions_homomorphic_id'), 'psifos_decryptions_homomorphic', ['id'], unique=False)
    op.create_table('psifos_decryptions_mixnet',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('trustee_id', sa.Integer(), nullable=False),
    sa.Column('group', sa.Text(), nullable=False),
    sa.Column('q_num', sa.Integer(), nullable=False),
    sa.Column('decryption_factors', app.database.custom_fields.ListOfDecryptionFactorsField(), nullable=True),
    sa.Column('decryption_proofs', app.database.custom_fields.ListOfDecryptionProofsField(), nullable=True),
    sa.ForeignKeyConstraint(['trustee_id'], ['psifos_trustee.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_psifos_decryptions_mixnet_id'), 'psifos_decryptions_mixnet', ['id'], unique=False)
    op.drop_column('psifos_election', 'encrypted_tally')
    op.drop_column('psifos_election', 'encrypted_tally_hash')
    op.drop_column('psifos_trustee', 'decryptions')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('psifos_trustee', sa.Column('decryptions', mysql.LONGTEXT(), nullable=True))
    op.add_column('psifos_election', sa.Column('encrypted_tally_hash', mysql.TEXT(), nullable=True))
    op.add_column('psifos_election', sa.Column('encrypted_tally', mysql.LONGTEXT(), nullable=True))
    op.drop_index(op.f('ix_psifos_decryptions_mixnet_id'), table_name='psifos_decryptions_mixnet')
    op.drop_table('psifos_decryptions_mixnet')
    op.drop_index(op.f('ix_psifos_decryptions_homomorphic_id'), table_name='psifos_decryptions_homomorphic')
    op.drop_table('psifos_decryptions_homomorphic')
    op.drop_index(op.f('ix_psifos_tallies_id'), table_name='psifos_tallies')
    op.drop_table('psifos_tallies')
    # ### end Alembic commands ###
