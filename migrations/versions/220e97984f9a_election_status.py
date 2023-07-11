"""election_status

Revision ID: 220e97984f9a
Revises: 4475e05d5f2e
Create Date: 2023-07-11 15:57:08.615071

"""
from alembic import op
import sqlalchemy as sa
import app



# revision identifiers, used by Alembic.
revision = '220e97984f9a'
down_revision = '4475e05d5f2e'
branch_labels = None
depends_on = None


def upgrade():
    # Enum 'OldStatus'
    old_status = sa.Enum('setting_up', 'started', 'ended', 'computing_tally', 'tally_computed', 'decryptions_uploaded', 'decryptions_combined', 'results_released', name='electionstatusenum')
    old_status.drop(op.get_bind(), checkfirst=False)

    # Enum 'NewStatus'
    new_status = sa.Enum('setting_up', 'started', 'ended', 'tally_computed', 'decryptions_uploaded', 'decryptions_combined', 'results_released', name='electionstatusenum')
    new_status.create(op.get_bind(), checkfirst=False)

    # Alter column
    with op.batch_alter_table('psifos_dev', schema=None) as batch_op:
        batch_op.alter_column('electionstatusenum', type_=new_status, existing_type=old_status)

def downgrade():
    # Enum 'NewStatus'
    new_status = sa.Enum('setting_up', 'started', 'ended', 'tally_computed', 'decryptions_uploaded', 'decryptions_combined', 'results_released', name='electionstatusenum')
    new_status.drop(op.get_bind(), checkfirst=False)

    # Enum 'OldStatus'
    old_status = sa.Enum('setting_up', 'started', 'ended', 'computing_tally', 'tally_computed', 'decryptions_uploaded', 'decryptions_combined', 'results_released', name='electionstatusenum')
    old_status.create(op.get_bind(), checkfirst=False)

    # Alter column
    with op.batch_alter_table('psifos_dev', schema=None) as batch_op:
        batch_op.alter_column('electionstatusenum', type_=old_status, existing_type=new_status)