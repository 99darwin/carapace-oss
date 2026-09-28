"""Removing an account left over from when registration was open (#52)."""

import logging
import re
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from anyio import to_thread
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from carapace_server.admin import (
    AdminError,
    delete_account,
    list_accounts,
    main,
    warn_if_accounts_predate_closing,
)
from carapace_server.apikeys.models import ApiKey, api_key_secrets
from carapace_server.auth.models import InstanceClaim, RefreshToken, User
from carapace_server.config import Settings
from carapace_server.ownerkeys.models import OwnerKey
from carapace_server.store.models import Secret

pytestmark = pytest.mark.anyio

REPO_ROOT = Path(__file__).resolve().parents[2]
SELF_HOST = REPO_ROOT / "docs" / "SELF_HOST.md"
SQL_MARKER = "<!-- delete-account-sql: tested by server/tests/test_admin.py -->"
STRANGER = "stranger@example.com"
OWNER = "owner@example.com"
T0 = datetime(2026, 1, 1, tzinfo=UTC)
PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64
NONCE_BYTES = 12
PER_USER_TABLES = (OwnerKey, Secret, ApiKey, RefreshToken)


async def _add_user(db: AsyncSession, email: str, created_at: datetime) -> uuid.UUID:
    """One user with an owner key, a secret, an API key on it and a session."""
    user = User(email=email, created_at=created_at)
    db.add(user)
    await db.flush()
    seed = uuid.uuid4().bytes
    owner_key = OwnerKey(
        user_id=user.id,
        public_key=(seed * 2)[:PUBLIC_KEY_BYTES],
        fingerprint=seed.hex()[:16],
    )
    secret = Secret(
        id=uuid.uuid4(),
        owner_id=user.id,
        name=f"secret-{email}",
        policy_json={},
        owner_pk=owner_key.public_key,
        version=1,
        signature=b"\0" * SIGNATURE_BYTES,
        wrapped_dek=b"dek",
        nonce=b"\0" * NONCE_BYTES,
        ciphertext=b"ciphertext",
    )
    db.add_all([owner_key, secret])
    await db.flush()
    api_key = ApiKey(
        user_id=user.id,
        owner_key_id=owner_key.id,
        key_hash=seed.hex() * 2,
        key_prefix="ck_",
        name="agent",
        grant_json={},
        grant_iat=0,
        grant_exp=1,
    )
    db.add(api_key)
    db.add(
        RefreshToken(
            user_id=user.id,
            family_id=uuid.uuid4(),
            token_hash=(seed.hex() * 2)[::-1],
            expires_at=created_at + timedelta(days=1),
        )
    )
    await db.flush()
    await db.execute(
        insert(api_key_secrets).values(api_key_id=api_key.id, secret_id=secret.id)
    )
    return user.id


async def _seed_open_server(db: AsyncSession) -> tuple[uuid.UUID, uuid.UUID]:
    """A stranger registered first and so holds the claim; the owner came later."""
    stranger = await _add_user(db, STRANGER, T0)
    owner = await _add_user(db, OWNER, T0 + timedelta(hours=1))
    db.add(InstanceClaim(id=1, user_id=stranger))
    await db.commit()
    return stranger, owner


async def _rows_for(db: AsyncSession, user_id: uuid.UUID) -> dict[str, int]:
    counts = {}
    for model in PER_USER_TABLES:
        column = model.owner_id if model is Secret else model.user_id
        counts[model.__tablename__] = int(
            await db.scalar(select(func.count()).where(column == user_id)) or 0
        )
    return counts


async def _assert_owner_kept_stranger_gone(
    db: AsyncSession, stranger: uuid.UUID, owner: uuid.UUID
) -> None:
    db.expire_all()
    assert await db.get(User, stranger) is None
    assert set((await _rows_for(db, stranger)).values()) == {0}
    assert set((await _rows_for(db, owner)).values()) == {1}
    links = await db.scalar(select(func.count()).select_from(api_key_secrets))
    assert links == 1
    claims = (await db.scalars(select(InstanceClaim))).all()
    assert [claim.user_id for claim in claims] == [owner]


def _documented_delete_sql() -> str:
    text = SELF_HOST.read_text()
    after = text.split(SQL_MARKER, 1)[1]
    match = re.search(r"```sql\n(.*?)```", after, re.DOTALL)
    assert match is not None, "SELF_HOST.md delete SQL block not found"
    return match.group(1)


async def test_documented_sql_removes_a_stranger_and_reclaims(
    settings: Settings, db: AsyncSession
) -> None:
    stranger, owner = await _seed_open_server(db)
    sql = _documented_delete_sql()
    assert "<id>" in sql
    database = settings.database_url.split("///", 1)[1]
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        # The operator copies the id from the documented list query.
        stored_ids = [
            row[0]
            for row in connection.execute(
                "SELECT id, email, created_at FROM users ORDER BY created_at"
            )
        ]
        assert len(stored_ids) == 2
        connection.executescript(sql.replace("<id>", stored_ids[0]))
    finally:
        connection.close()
    await _assert_owner_kept_stranger_gone(db, stranger, owner)


async def test_delete_account_removes_a_stranger_and_reclaims(
    db: AsyncSession,
) -> None:
    stranger, owner = await _seed_open_server(db)
    await delete_account(db, stranger)
    await _assert_owner_kept_stranger_gone(db, stranger, owner)


async def test_deleting_a_non_claim_account_keeps_the_claim(
    db: AsyncSession,
) -> None:
    stranger, owner = await _seed_open_server(db)
    await delete_account(db, owner)
    db.expire_all()
    claims = (await db.scalars(select(InstanceClaim))).all()
    assert [claim.user_id for claim in claims] == [stranger]
    assert set((await _rows_for(db, owner)).values()) == {0}


async def test_deleting_the_last_account_leaves_no_claim(db: AsyncSession) -> None:
    only = await _add_user(db, OWNER, T0)
    db.add(InstanceClaim(id=1, user_id=only))
    await db.commit()
    await delete_account(db, only)
    assert await db.scalar(select(func.count()).select_from(InstanceClaim)) == 0


async def test_deleting_an_unknown_account_fails(db: AsyncSession) -> None:
    await _seed_open_server(db)
    with pytest.raises(AdminError):
        await delete_account(db, uuid.uuid4())
    assert await db.scalar(select(func.count()).select_from(User)) == 2


async def test_list_accounts_is_oldest_first_and_marks_the_claim(
    db: AsyncSession,
) -> None:
    stranger, owner = await _seed_open_server(db)
    accounts = await list_accounts(db)
    assert [a.id for a in accounts] == [stranger, owner]
    assert [a.holds_claim for a in accounts] == [True, False]


async def test_admin_command_lists_and_deletes(
    settings: Settings,
    db: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    stranger, owner = await _seed_open_server(db)
    # main() starts its own event loop, so it runs in a worker thread.
    assert await to_thread.run_sync(main, ["users", "list"], settings) == 0
    listing = capsys.readouterr().out
    lines = listing.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith(str(stranger)) and lines[0].endswith("(claim)")
    assert lines[1].startswith(str(owner)) and "(claim)" not in lines[1]
    # Job output lands in Cloud Logging, so emails are opt-in.
    assert "@" not in listing

    args = ["users", "list", "--emails"]
    assert await to_thread.run_sync(main, args, settings) == 0
    lines = capsys.readouterr().out.splitlines()
    assert STRANGER in lines[0] and lines[0].endswith("(claim)")
    assert OWNER in lines[1]

    args = ["users", "delete", str(stranger)]
    assert await to_thread.run_sync(main, args, settings) == 0
    assert capsys.readouterr().out.strip() == f"deleted {stranger}"
    await _assert_owner_kept_stranger_gone(db, stranger, owner)

    args = ["users", "delete", str(stranger)]
    assert await to_thread.run_sync(main, args, settings) == 1
    assert "no account" in capsys.readouterr().err


async def test_startup_warns_with_the_count_only(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
    db: AsyncSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await _seed_open_server(db)
    closed = settings.model_copy(update={"allow_signup": False})
    with caplog.at_level(logging.WARNING, logger="carapace_server.admin"):
        await warn_if_accounts_predate_closing(sessionmaker, closed)
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "2 accounts exist" in message
    assert "upgrading-a-server-that-was-open" in message
    assert STRANGER not in caplog.text and OWNER not in caplog.text


async def test_startup_is_silent_while_signup_is_open(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
    db: AsyncSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await _seed_open_server(db)
    with caplog.at_level(logging.WARNING, logger="carapace_server.admin"):
        await warn_if_accounts_predate_closing(sessionmaker, settings)
    assert caplog.records == []


async def test_startup_is_silent_with_one_account(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
    db: AsyncSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await _add_user(db, OWNER, T0)
    await db.commit()
    closed = settings.model_copy(update={"allow_signup": False})
    with caplog.at_level(logging.WARNING, logger="carapace_server.admin"):
        await warn_if_accounts_predate_closing(sessionmaker, closed)
    assert caplog.records == []


@pytest.mark.parametrize("error", [OSError, TimeoutError])
async def test_startup_continues_when_the_probe_fails(
    settings: Settings,
    caplog: pytest.LogCaptureFixture,
    error: type[Exception],
) -> None:
    class Broken:
        """A sessionmaker whose connection fails as a raw driver error."""

        async def __aenter__(self) -> None:
            raise error("probe failed: host=db.internal")

        async def __aexit__(self, *exc: object) -> None:
            return None

    closed = settings.model_copy(update={"allow_signup": False})
    with caplog.at_level(logging.WARNING, logger="carapace_server.admin"):
        await warn_if_accounts_predate_closing(
            cast(async_sessionmaker[AsyncSession], Broken), closed
        )
    assert [r.getMessage() for r in caplog.records] == [
        f"could not count accounts: {error.__name__}"
    ]
    assert "db.internal" not in caplog.text
