"""The instance claim: one row, taken by the first registration (#52).

A server that already has accounts is claimed by its oldest one, so
registration stays closed on it after the upgrade.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "instance_claim",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_instance_claim_id"),
    )
    op.execute(
        "INSERT INTO instance_claim (id, user_id, claimed_at) "
        "SELECT 1, id, created_at FROM users ORDER BY created_at, id LIMIT 1"
    )


def downgrade() -> None:
    op.drop_table("instance_claim")
