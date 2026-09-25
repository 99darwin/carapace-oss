"""Initial schema.

Revision ID: 0001
Revises:
Create Date: 2026-09-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _ts(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _id() -> sa.Column:
    return sa.Column("id", sa.Uuid(), primary_key=True)


def upgrade() -> None:
    op.create_table(
        "users",
        _id(),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("display_name", sa.String(100)),
        sa.Column("password_hash", sa.LargeBinary(60)),
        sa.Column("passkey_credential_id", sa.LargeBinary(1023), unique=True),
        sa.Column("passkey_public_key", sa.LargeBinary()),
        sa.Column("passkey_sign_count", sa.Integer(), nullable=False),
        sa.Column("passkey_transports", sa.JSON()),
        _ts("created_at"),
        _ts("last_login_at", nullable=True),
    )
    op.create_table(
        "refresh_tokens",
        _id(),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        _ts("expires_at"),
        _ts("revoked_at", nullable=True),
        sa.Column("user_agent", sa.String(512)),
        sa.Column("ip_address", sa.String(45)),
        _ts("created_at"),
    )
    op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"])
    op.create_table(
        "webauthn_challenges",
        _id(),
        sa.Column("email", sa.String(320), nullable=False, index=True),
        sa.Column(
            "challenge_type",
            sa.Enum("register", "authenticate", name="challenge_type"),
            nullable=False,
        ),
        sa.Column("challenge", sa.LargeBinary(64), nullable=False),
        _ts("expires_at"),
    )
    op.create_index(
        "ix_webauthn_challenges_expires_at", "webauthn_challenges", ["expires_at"]
    )
    op.create_table(
        "token_blacklist",
        _id(),
        sa.Column("jti", sa.String(36), nullable=False, unique=True),
        _ts("expires_at"),
        _ts("created_at"),
    )
    op.create_index("ix_token_blacklist_expires_at", "token_blacklist", ["expires_at"])


def downgrade() -> None:
    for table in ("token_blacklist", "webauthn_challenges", "refresh_tokens", "users"):
        op.drop_table(table)
    sa.Enum(name="challenge_type").drop(op.get_bind(), checkfirst=True)
