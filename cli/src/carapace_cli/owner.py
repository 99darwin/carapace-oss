"""Owner key lifecycle against the server."""

from __future__ import annotations

from typing import Any

from carapace_cli.errors import ServerError
from carapace_cli.session import ServerClient
from carapace_crypto import OwnerKey, b64_encode_std

HTTP_CONFLICT = 409


def register_owner_key(server: ServerClient, owner_key: OwnerKey) -> dict[str, Any]:
    """Register the public key; idempotent if it is already ours."""
    public_key = b64_encode_std(owner_key.public_key)
    try:
        return server.post("/v1/owner-keys", json={"public_key": public_key})
    except ServerError as exc:
        if exc.status != HTTP_CONFLICT:
            raise
        for record in server.get("/v1/owner-keys"):
            if record.get("public_key") == public_key and not record.get("retired_at"):
                return record
        raise
