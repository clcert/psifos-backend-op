"""update trustee models

Revision ID: 7c8d6769571e
Revises: 7a7dabf37829
Create Date: 2024-11-12 19:01:06.193695

"""
from alembic import op
import sqlalchemy as sa
import app

from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '7c8d6769571e'
down_revision = '7a7dabf37829'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('psifos_trustee_crypto',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('election_id', sa.Integer(), nullable=True),
    sa.Column('trustee_id', sa.Integer(), nullable=True),
    sa.Column('trustee_election_id', sa.Integer(), nullable=False),
    sa.Column('current_step', sa.Integer(), nullable=True),
    sa.Column('public_key_id', sa.Integer(), nullable=True),
    sa.Column('public_key_hash', sa.String(length=100), nullable=True),
    sa.Column('certificate', app.database.custom_fields.CertificateField(), nullable=True),
    sa.Column('coefficients', app.database.custom_fields.CoefficientsField(), nullable=True),
    sa.Column('acknowledgements', app.database.custom_fields.AcknowledgementsField(), nullable=True),
    sa.ForeignKeyConstraint(['election_id'], ['psifos_election.id'], onupdate='CASCADE', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['public_key_id'], ['psifos_public_keys.id'], ),
    sa.ForeignKeyConstraint(['trustee_id'], ['psifos_trustee.id'], onupdate='CASCADE', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('public_key_id')
    )
    op.create_index(op.f('ix_psifos_trustee_crypto_id'), 'psifos_trustee_crypto', ['id'], unique=False)
    op.add_column('psifos_decryptions_homomorphic', sa.Column('trustee_crypto_id', sa.Integer(), nullable=False))
    op.drop_constraint('psifos_decryptions_homomorphic_ibfk_1', 'psifos_decryptions_homomorphic', type_='foreignkey')
    op.create_foreign_key(None, 'psifos_decryptions_homomorphic', 'psifos_trustee_crypto', ['trustee_crypto_id'], ['id'], onupdate='CASCADE', ondelete='CASCADE')
    op.drop_column('psifos_decryptions_homomorphic', 'trustee_id')
    op.add_column('psifos_decryptions_mixnet', sa.Column('trustee_crypto_id', sa.Integer(), nullable=False))
    op.drop_constraint('psifos_decryptions_mixnet_ibfk_1', 'psifos_decryptions_mixnet', type_='foreignkey')
    op.create_foreign_key(None, 'psifos_decryptions_mixnet', 'psifos_trustee_crypto', ['trustee_crypto_id'], ['id'], onupdate='CASCADE', ondelete='CASCADE')
    op.drop_column('psifos_decryptions_mixnet', 'trustee_id')
    op.drop_constraint('psifos_election_ibfk_2', 'psifos_election', type_='foreignkey')
    op.create_foreign_key(None, 'psifos_election', 'psifos_public_keys', ['public_key_id'], ['id'], ondelete='CASCADE')
    op.create_unique_constraint(None, 'psifos_trustee', ['trustee_login_id'])
    op.drop_constraint('psifos_trustee_ibfk_2', 'psifos_trustee', type_='foreignkey')
    op.drop_constraint('psifos_trustee_ibfk_1', 'psifos_trustee', type_='foreignkey')
    op.drop_index('public_key_id', table_name='psifos_trustee')
    op.drop_column('psifos_trustee', 'public_key_id')
    op.drop_column('psifos_trustee', 'certificate')
    op.drop_column('psifos_trustee', 'current_step')
    op.drop_column('psifos_trustee', 'trustee_id')
    op.drop_column('psifos_trustee', 'election_id')
    op.drop_column('psifos_trustee', 'public_key_hash')
    op.drop_column('psifos_trustee', 'acknowledgements')
    op.drop_column('psifos_trustee', 'coefficients')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('psifos_trustee', sa.Column('coefficients', mysql.LONGTEXT(), nullable=True))
    op.add_column('psifos_trustee', sa.Column('acknowledgements', mysql.LONGTEXT(), nullable=True))
    op.add_column('psifos_trustee', sa.Column('public_key_hash', mysql.VARCHAR(length=100), nullable=True))
    op.add_column('psifos_trustee', sa.Column('election_id', mysql.INTEGER(), autoincrement=False, nullable=True))
    op.add_column('psifos_trustee', sa.Column('trustee_id', mysql.INTEGER(), autoincrement=False, nullable=False))
    op.add_column('psifos_trustee', sa.Column('current_step', mysql.INTEGER(), autoincrement=False, nullable=True))
    op.add_column('psifos_trustee', sa.Column('certificate', mysql.LONGTEXT(), nullable=True))
    op.add_column('psifos_trustee', sa.Column('public_key_id', mysql.INTEGER(), autoincrement=False, nullable=True))
    op.create_foreign_key('psifos_trustee_ibfk_1', 'psifos_trustee', 'psifos_election', ['election_id'], ['id'], onupdate='CASCADE', ondelete='CASCADE')
    op.create_foreign_key('psifos_trustee_ibfk_2', 'psifos_trustee', 'psifos_public_keys', ['public_key_id'], ['id'])
    op.drop_constraint(None, 'psifos_trustee', type_='unique')
    op.create_index('public_key_id', 'psifos_trustee', ['public_key_id'], unique=False)
    op.drop_constraint(None, 'psifos_election', type_='foreignkey')
    op.create_foreign_key('psifos_election_ibfk_2', 'psifos_election', 'psifos_public_keys', ['public_key_id'], ['id'])
    op.add_column('psifos_decryptions_mixnet', sa.Column('trustee_id', mysql.INTEGER(), autoincrement=False, nullable=False))
    op.drop_constraint(None, 'psifos_decryptions_mixnet', type_='foreignkey')
    op.create_foreign_key('psifos_decryptions_mixnet_ibfk_1', 'psifos_decryptions_mixnet', 'psifos_trustee', ['trustee_id'], ['id'], onupdate='CASCADE', ondelete='CASCADE')
    op.drop_column('psifos_decryptions_mixnet', 'trustee_crypto_id')
    op.add_column('psifos_decryptions_homomorphic', sa.Column('trustee_id', mysql.INTEGER(), autoincrement=False, nullable=False))
    op.drop_constraint(None, 'psifos_decryptions_homomorphic', type_='foreignkey')
    op.create_foreign_key('psifos_decryptions_homomorphic_ibfk_1', 'psifos_decryptions_homomorphic', 'psifos_trustee', ['trustee_id'], ['id'], onupdate='CASCADE', ondelete='CASCADE')
    op.drop_column('psifos_decryptions_homomorphic', 'trustee_crypto_id')
    op.drop_index(op.f('ix_psifos_trustee_crypto_id'), table_name='psifos_trustee_crypto')
    op.drop_table('psifos_trustee_crypto')
    # ### end Alembic commands ###