"""Owner signing keys.

Every Carapace owner holds an Ed25519 key on their own device. It signs
envelopes (:mod:`carapace_crypto.envelope`) and grants
(:mod:`carapace_crypto.grant`), and its fingerprint is embedded in every API
key (:mod:`carapace_crypto.apikey`). The enclave learns the fingerprint from
the key an agent presents, which the server never touches, and then requires
that everything the server hands it chains to that fingerprint. See
``docs/design/owner-signing.md``.

Signatures are domain separated. For a context string ``ctx`` and a JSON
object ``body``::

    signing_input = ctx || 0x0A || canonical_json(body)
    sig           = Ed25519.sign(owner_seed, signing_input)

Canonical JSON escapes control characters, so the newline after the context
is unambiguous. Context strings are ASCII, versioned, and never contain a
newline.

The fingerprint is the first 16 bytes of a tagged SHA-256 of the raw public
key. 128 bits is enough because an attacker needs a *second preimage* (a key
of their own with the victim's fingerprint), not a collision. Against many
targets at once the work is ``2**128 / targets``, still out of reach for any
plausible user count, and a matching fingerprint alone authorizes nothing:
the grant must also bind the raw key's ``bind_hash``.

Public keys must pass :func:`validate_public_key`, which rejects the
small-order points that OpenSSL would otherwise accept with a signature
valid for every message.

Storage of the seed is a CLI concern. The interface is :attr:`OwnerKey.seed`
and :meth:`OwnerKey.from_seed`; the CLI should keep the seed in a file with
mode ``0600``, optionally passphrase-wrapped, and never send it anywhere.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Self

from carapace_crypto.canonical import CanonicalJSONError, canonical_json
from carapace_crypto.hashing import tagged_sha256
from carapace_crypto.signing import KeyPair

PUBLIC_KEY_SIZE = 32
SEED_SIZE = 32
SIGNATURE_SIZE = 64
FINGERPRINT_SIZE = 16
FINGERPRINT_TAG = b"carapace-owner-fp-v1"


class SignatureError(ValueError):
    """A signature did not verify, or its inputs were malformed."""


def fingerprint(public_key: bytes) -> bytes:
    """Return the 16-byte fingerprint of a raw Ed25519 public key.

    Raises:
        SignatureError: If ``public_key`` fails :func:`validate_public_key`.
    """
    _require_public_key(public_key)
    return tagged_sha256(FINGERPRINT_TAG, public_key)[:FINGERPRINT_SIZE]


def fingerprints_match(public_key: bytes, expected: bytes) -> bool:
    """Constant-time check that ``public_key`` has fingerprint ``expected``.

    Raises:
        SignatureError: If ``public_key`` fails :func:`validate_public_key`.
    """
    return hmac.compare_digest(fingerprint(public_key), expected)


def signing_input(context: bytes, body: dict[str, Any]) -> bytes:
    """Return the exact bytes signed for ``body`` under ``context``.

    Raises:
        SignatureError: If the context is malformed or the body does not
            canonicalize.
    """
    if not context or b"\n" in context:
        raise SignatureError("context must be non-empty and newline-free")
    try:
        return context + b"\n" + canonical_json(body)
    except CanonicalJSONError as exc:
        raise SignatureError(f"body cannot be canonicalized: {exc}") from exc


def verify_object(
    public_key: bytes, context: bytes, body: dict[str, Any], signature: bytes
) -> None:
    """Verify an owner signature over ``body``. Raises on any failure.

    Raises:
        SignatureError: If the key or signature has the wrong length, the
            body does not canonicalize, or the signature does not verify.
    """
    _require_public_key(public_key)
    if len(signature) != SIGNATURE_SIZE:
        raise SignatureError("signature must be 64 bytes")
    message = signing_input(context, body)
    if not KeyPair.verify(public_key, signature, message):
        raise SignatureError("signature does not verify")


@dataclass(frozen=True, slots=True)
class OwnerKey:
    """An owner's Ed25519 signing key. Lives only on the owner's device."""

    _keypair: KeyPair

    @classmethod
    def generate(cls) -> Self:
        return cls(KeyPair.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> Self:
        """Rebuild the key from its 32-byte seed (the stored form).

        Raises:
            SignatureError: If the seed is not 32 bytes.
        """
        if len(seed) != SEED_SIZE:
            raise SignatureError("seed must be 32 bytes")
        return cls(KeyPair.from_private_bytes(seed))

    @property
    def seed(self) -> bytes:
        """The 32-byte private seed. Store it; never log or transmit it."""
        return self._keypair.private_key_bytes

    @property
    def public_key(self) -> bytes:
        return self._keypair.public_key_bytes

    @property
    def fingerprint(self) -> bytes:
        return fingerprint(self.public_key)

    def sign_object(self, context: bytes, body: dict[str, Any]) -> bytes:
        """Sign ``body`` under ``context``; see the module docstring."""
        return self._keypair.sign(signing_input(context, body))

    def __repr__(self) -> str:
        return f"OwnerKey(fingerprint={self.fingerprint.hex()})"


def validate_public_key(public_key: bytes) -> None:
    """Reject anything that is not a usable owner public key.

    Beyond the length, this rejects the encodings of the eight small-order
    points of edwards25519 (in either sign and, for ``y`` in ``{0, 1}``, the
    non-canonical aliases ``p`` and ``p + 1``) and every other non-canonical
    ``y >= p``. OpenSSL's Ed25519 verification accepts a small-order public
    key, and for such a key the signature ``R = identity, S = 0`` verifies
    over *any* message. No seed exists for these keys, so a grant or envelope
    naming one would be forgeable by anyone. Honestly generated keys never
    hit this check.

    Raises:
        SignatureError: If the key has the wrong type or length, is not
            canonically encoded, or is a small-order point.
    """
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_SIZE:
        raise SignatureError("public key must be 32 bytes")
    y = int.from_bytes(public_key, "little") & _Y_MASK
    if y in _SMALL_ORDER_Y:
        raise SignatureError("public key is a small-order point")
    if y >= _FIELD_PRIME:
        raise SignatureError("public key is not canonically encoded")


# The y-coordinates (sign bit cleared) of every encoding of a small-order
# point on edwards25519: order 1 (y = 1, alias p + 1), order 2 (y = p - 1),
# order 4 (y = 0, alias p) and order 8 (y = +/- _Y_ORDER_8). Same set as
# libsodium's ``ge25519_has_small_order`` blocklist.
_FIELD_PRIME = 2**255 - 19
_Y_MASK = (1 << 255) - 1
_Y_ORDER_8 = (
    2707385501144840649318225287225658788936804267575313519463743609750303402022
)
_SMALL_ORDER_Y = frozenset(
    {
        0,
        1,
        _Y_ORDER_8,
        _FIELD_PRIME - _Y_ORDER_8,
        _FIELD_PRIME - 1,
        _FIELD_PRIME,
        _FIELD_PRIME + 1,
    }
)


def _require_public_key(public_key: bytes) -> None:
    validate_public_key(public_key)
