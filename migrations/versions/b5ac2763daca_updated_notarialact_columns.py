"""Updated NotarialAct columns

Revision ID: b5ac2763daca
Revises: 4a7a223e4c63
Create Date: 2024-05-19 19:21:58.326088

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b5ac2763daca'
down_revision = 'existing_revision_id'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('notarial_act', schema=None) as batch_op:
        batch_op.add_column(sa.Column('other_act_type_input', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('principal_name', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('principal_addressLine1', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('principal_addressLine2', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('principal_city', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('principal_state', sa.String(length=2), nullable=True))
        batch_op.add_column(sa.Column('principal_zipCode', sa.String(length=100), nullable=True))
        batch_op.drop_column('individual_name')
        batch_op.drop_column('individual_address')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('notarial_act', schema=None) as batch_op:
        batch_op.add_column(sa.Column('individual_address', sa.VARCHAR(length=100), autoincrement=False, nullable=True))
        batch_op.add_column(sa.Column('individual_name', sa.VARCHAR(length=100), autoincrement=False, nullable=True))
        batch_op.drop_column('principal_zipCode')
        batch_op.drop_column('principal_state')
        batch_op.drop_column('principal_city')
        batch_op.drop_column('principal_addressLine2')
        batch_op.drop_column('principal_addressLine1')
        batch_op.drop_column('principal_name')
        batch_op.drop_column('other_act_type_input')

    # ### end Alembic commands ###
