"""Operator commands: ``python -m carapace_server.admin users list|delete``.

For a server whose registration was open before #52 closed it: list the
accounts and delete any the operator does not know. Runs anywhere the
server's environment is set, including the migration job's image (see
docs/SELF_HOST.md, "Upgrading a server that was open").

Deleting a user cascades, in the database, to its refresh tokens, owner
keys, sealed secrets and API keys; its access tokens stop working because
the user no longer exists. Receipts are an append-only audit trail and are
kept. If the user held the instance claim, the oldest remaining account
takes it, so registration stays closed.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from carapace_server.auth.models import INSTANCE_CLAIM_ID, InstanceClaim, User
from carapace_server.config import Settings, get_settings
from carapace_server.db import create_engine, create_sessionmaker

logger = logging.getLogger(__name__)

UPGRADE_DOC = "docs/SELF_HOST.md#upgrading-a-server-that-was-open"
EXIT_ERROR = 1


class AdminError(Exception):
    """An operator command could not be carried out."""


@dataclass(frozen=True)
class Account:
    id: uuid.UUID
    email: str
    created_at: datetime
    holds_claim: bool


async def count_users(db: AsyncSession) -> int:
    return int(await db.scalar(select(func.count()).select_from(User)) or 0)


async def warn_if_accounts_predate_closing(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """Warn at startup when a closed server has more than one account.

    Those accounts were created while registration was open, and one may be
    a stranger's. Only the count is logged, never an email.
    """
    if settings.allow_signup:
        return
    try:
        async with sessionmaker() as db:
            users = await count_users(db)
    except SQLAlchemyError as exc:
        # Never block startup on this check; the migration job owns schema.
        logger.warning("could not count accounts: %s", type(exc).__name__)
        return
    if users > 1:
        logger.warning(
            "registration is closed but %d accounts exist; accounts created "
            "while it was open may not be yours. See %s",
            users,
            UPGRADE_DOC,
        )


async def list_accounts(db: AsyncSession) -> list[Account]:
    claimed = await db.scalar(
        select(InstanceClaim.user_id).where(InstanceClaim.id == INSTANCE_CLAIM_ID)
    )
    rows = await db.execute(
        select(User.id, User.email, User.created_at).order_by(User.created_at, User.id)
    )
    return [
        Account(
            id=row.id,
            email=row.email,
            created_at=row.created_at,
            holds_claim=row.id == claimed,
        )
        for row in rows
    ]


async def delete_account(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Delete one account and keep the server claimed, in one transaction."""
    if await db.get(User, user_id) is None:
        raise AdminError(f"no account with id {user_id}")
    await db.execute(delete(InstanceClaim).where(InstanceClaim.user_id == user_id))
    await db.execute(delete(User).where(User.id == user_id))
    has_claim = await db.scalar(select(InstanceClaim.id)) is not None
    oldest = await db.scalar(select(User.id).order_by(User.created_at, User.id))
    if not has_claim and oldest is not None:
        db.add(InstanceClaim(id=INSTANCE_CLAIM_ID, user_id=oldest))
    await db.commit()


async def _run(args: argparse.Namespace, settings: Settings) -> None:
    engine = create_engine(settings.database_url)
    try:
        async with create_sessionmaker(engine)() as db:
            if args.action == "list":
                for account in await list_accounts(db):
                    claim = " (claim)" if account.holds_claim else ""
                    print(
                        f"{account.id}  {account.created_at.isoformat()}  "
                        f"{account.email}{claim}"
                    )
            else:
                await delete_account(db, args.user_id)
                print(f"deleted {args.user_id}")
    finally:
        await engine.dispose()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m carapace_server.admin")
    users = parser.add_subparsers(dest="group", required=True).add_parser("users")
    actions = users.add_subparsers(dest="action", required=True)
    actions.add_parser("list", help="every account, oldest first")
    remove = actions.add_parser("delete", help="delete one account and its data")
    remove.add_argument("user_id", type=uuid.UUID)
    return parser


def main(argv: Sequence[str] | None = None, settings: Settings | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        asyncio.run(_run(args, settings or get_settings()))
    except AdminError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return 0


if __name__ == "__main__":
    sys.exit(main())
