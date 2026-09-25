"""Agent API keys, minted by the owner's CLI rather than the server.

Format (ASCII, 101 characters)::

    cpk_<fingerprint: 32 lowercase hex>_<random: 64 lowercase hex>

The fingerprint is the owner key's (:func:`carapace_crypto.ownerkey.fingerprint`)
and the random part is 32 bytes from a CSPRNG. Two hashes are derived from
the full key string, with distinct tags so neither can be computed from the
other::

    lookup = sha256("carapace-key-lookup-v1" || 0x0A || key)   # server stores
    bind   = sha256("carapace-key-bind-v1"   || 0x0A || key)   # grant binds

The server only ever sees ``lookup``: the CLI sends it at registration and
the enclave sends it to look up the grant. ``bind`` appears only inside the
owner-signed grant, and only the enclave, holding the raw key from the
agent, can check that a grant belongs to the key in hand. A database dump
therefore contains nothing that a grant binds to.

Both derivations cover the fingerprint too, so a key's hashes are tied to
the owner key it names.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Self

from carapace_crypto.hashing import tagged_sha256
from carapace_crypto.ownerkey import FINGERPRINT_SIZE, OwnerKey

KEY_TAG = "cpk_"
RANDOM_SIZE = 32
LOOKUP_TAG = b"carapace-key-lookup-v1"
BIND_TAG = b"carapace-key-bind-v1"
_KEY_RE = re.compile(
    rf"^{KEY_TAG}(?P<fp>[0-9a-f]{{{2 * FINGERPRINT_SIZE}}})"
    rf"_(?P<rand>[0-9a-f]{{{2 * RANDOM_SIZE}}})$"
)
KEY_LENGTH = len(KEY_TAG) + 2 * FINGERPRINT_SIZE + 1 + 2 * RANDOM_SIZE


class ApiKeyError(ValueError):
    """The key string is not a well-formed Carapace API key."""


@dataclass(frozen=True, slots=True)
class ApiKey:
    """A parsed API key. ``raw`` is the credential; treat it as a secret."""

    raw: str
    fingerprint: bytes

    @classmethod
    def generate(cls, owner_key: OwnerKey) -> Self:
        """Mint a new key naming ``owner_key``. Runs on the owner's device."""
        random = secrets.token_bytes(RANDOM_SIZE)
        fp = owner_key.fingerprint
        return cls(raw=f"{KEY_TAG}{fp.hex()}_{random.hex()}", fingerprint=fp)

    @classmethod
    def parse(cls, raw: str) -> Self:
        """Parse a key presented by an agent.

        Raises:
            ApiKeyError: If the string does not match the format exactly.
        """
        if not isinstance(raw, str) or len(raw) != KEY_LENGTH:
            raise ApiKeyError("malformed API key")
        match = _KEY_RE.match(raw)
        if match is None:
            raise ApiKeyError("malformed API key")
        return cls(raw=raw, fingerprint=bytes.fromhex(match["fp"]))

    @property
    def lookup_hash(self) -> bytes:
        """32-byte lookup hash: the only key-derived value the server stores."""
        return tagged_sha256(LOOKUP_TAG, self.raw.encode("ascii"))

    @property
    def bind_hash(self) -> bytes:
        """32-byte bind hash: what an owner-signed grant is issued for."""
        return tagged_sha256(BIND_TAG, self.raw.encode("ascii"))

    def __repr__(self) -> str:
        return f"ApiKey(fingerprint={self.fingerprint.hex()}, raw=<redacted>)"
