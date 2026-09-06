"""add scan.technologies (spec 004, RF-17)

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-06

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan", schema=None) as batch_op:
        batch_op.add_column(sa.Column("technologies", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scan", schema=None) as batch_op:
        batch_op.drop_column("technologies")
