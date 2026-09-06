"""initial schema: user, scan, finding, setting

Revision ID: 0001
Revises:
Create Date: 2026-09-06

"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("mode", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("scope", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("options", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("authorized_by", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("tool_version", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("error", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("pages_scanned", sa.Integer(), nullable=False),
        sa.Column("counts", sa.JSON(), nullable=True),
        sa.Column("check_errors", sa.JSON(), nullable=True),
        sa.Column("warnings", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("scan", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_scan_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_scan_status"), ["status"], unique=False)

    op.create_table(
        "setting",
        sa.Column("key", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("value", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("password_hash", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_user_username"), ["username"], unique=True)

    op.create_table(
        "finding",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("check_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("title", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("description", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("location", sa.JSON(), nullable=True),
        sa.Column("remediation", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("cwe", sa.JSON(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=True),
        sa.Column("fingerprint", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_finding_scan_id"), ["scan_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_finding_scan_id"))

    op.drop_table("finding")
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_user_username"))

    op.drop_table("user")
    op.drop_table("setting")
    with op.batch_alter_table("scan", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_scan_status"))
        batch_op.drop_index(batch_op.f("ix_scan_created_at"))

    op.drop_table("scan")
