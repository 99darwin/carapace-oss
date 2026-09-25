"""Key revocation against a server that lies about what it stores."""

from __future__ import annotations

from typing import Any

import pytest

from carapace_cli import CarapaceError, VerificationError
from carapace_cli.keys import revoke_api_key
from carapace_crypto import ApiKey, Grant, OwnerKey, create_grant, reissue_grant

NOW = 1_700_000_000
OWNER = OwnerKey.generate()
API_KEY = ApiKey.generate(OWNER)
LIVE = create_grant(OWNER, API_KEY, {"secret-a": 1}, now=NOW)
TOMBSTONE = reissue_grant(OWNER, LIVE, {}, now=NOW)


class _Server:
    """Stands in for :class:`ServerClient`: one listing, records posts."""

    def __init__(self, *items: dict[str, Any]) -> None:
        self.items = list(items)
        self.posts: list[tuple[str, dict[str, Any]]] = []

    def get(self, path: str, **_: Any) -> list[dict[str, Any]]:
        return self.items

    def post(self, path: str, *, json: dict[str, Any]) -> dict[str, Any]:
        self.posts.append((path, json))
        return {}


def _listed(grant: Grant, *, revoked_at: str | None = None) -> dict[str, Any]:
    return {
        "id": "key-1",
        "name": "agent",
        "key_prefix": "cp_test",
        "secret_ids": ["secret-a"],
        "grant": grant.to_dict(),
        "revoked_at": revoked_at,
    }


def test_revoke_posts_a_tombstone_for_a_live_key() -> None:
    server = _Server(_listed(LIVE))
    revoke_api_key(server, OWNER, "key-1")  # type: ignore[arg-type]
    [(path, body)] = server.posts
    assert path == "/v1/api-keys/key-1/revoke"
    tombstone = Grant.from_dict(body["grant"])
    assert tombstone.secrets == {}
    assert tombstone.key_bind == LIVE.key_bind
    assert tombstone.iat > LIVE.iat


@pytest.mark.parametrize(
    "item",
    [_listed(TOMBSTONE), _listed(LIVE, revoked_at="2026-01-01T00:00:00Z")],
    ids=["tombstone listed as live", "revoked key listed"],
)
def test_revoke_refuses_an_already_revoked_key(item: dict[str, Any]) -> None:
    server = _Server(item)
    with pytest.raises(CarapaceError, match="already revoked"):
        revoke_api_key(server, OWNER, "key-1")  # type: ignore[arg-type]
    assert server.posts == []


def test_revoke_refuses_to_re_sign_a_foreign_grant() -> None:
    other = OwnerKey.generate()
    foreign = create_grant(other, ApiKey.generate(other), {"secret-a": 1}, now=NOW)
    server = _Server(_listed(foreign))
    with pytest.raises(VerificationError, match="not signed by your owner key"):
        revoke_api_key(server, OWNER, "key-1")  # type: ignore[arg-type]
    assert server.posts == []


def test_revoke_of_an_unlisted_key_is_an_error() -> None:
    server = _Server()
    with pytest.raises(CarapaceError, match="no API key with id"):
        revoke_api_key(server, OWNER, "missing")  # type: ignore[arg-type]
    assert server.posts == []
