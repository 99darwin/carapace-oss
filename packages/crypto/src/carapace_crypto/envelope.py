"""Envelope encryption v1.

A secret is sealed on the user's device to the enclave's Cloud KMS public key
and can only be opened by something able to unwrap the data key (in
production, the attested enclave calling KMS ``asymmetricDecrypt``)::

    dek     = random(32)
    aad     = sha256(canonical_json({"v": 1, "secret_id", "owner_id", "policy"}))
    ct      = AES-256-GCM(dek, nonce = random(12), plaintext, aad)   # ct || tag
    wrapped = RSA-OAEP(SHA-256, MGF1-SHA-256, no label)(kms_public_key, dek)

The policy travels in cleartext next to the ciphertext, but it is bound into
the AAD. Anyone who edits the stored policy, secret id or owner id makes
decryption fail. See :mod:`carapace_crypto.canonical` for the exact JSON
canonicalization.

``kms_key_version`` is *not* authenticated: it is needed before the DEK can be
unwrapped. Callers must check it against their own key ring before using it
to build a KMS resource name, and never interpolate it unchecked.

Zeroization of the DEK is best effort. The ``bytearray`` copies this module
controls are cleared, but the RNG, the RSA encryption and the unwrapper
exchange immutable ``bytes`` that Python cannot wipe.

Serialized form (``Envelope.to_dict``): a JSON object with ``v``,
``secret_id``, ``owner_id``, ``policy``, ``kms_key_version`` (string or null)
and ``wrapped``, ``nonce``, ``ct`` as standard padded base64 (RFC 4648 §4).
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from carapace_crypto.canonical import CanonicalJSONError, canonical_json

ENVELOPE_VERSION = 1
DEK_SIZE = 32
NONCE_SIZE = 12
MIN_RSA_BITS = 3072
MAX_PLAINTEXT_BYTES = 64 * 1024
GCM_TAG_SIZE = 16
MAX_RSA_BITS = 8192

DekUnwrapper = Callable[[bytes], bytes]
RandomBytes = Callable[[int], bytes]


class EnvelopeError(ValueError):
    """Raised for malformed envelopes, keys, or inputs."""


class EnvelopeDecryptionError(EnvelopeError):
    """Raised when an envelope fails authentication or unwrapping."""


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


@dataclass(frozen=True, slots=True)
class Envelope:
    """A sealed secret. Safe to store on an untrusted server."""

    secret_id: str
    owner_id: str
    policy: dict[str, Any]
    wrapped: bytes
    nonce: bytes
    ct: bytes
    kms_key_version: str | None = None
    v: int = ENVELOPE_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict with base64-encoded binary fields."""
        return {
            "v": self.v,
            "secret_id": self.secret_id,
            "owner_id": self.owner_id,
            "policy": self.policy,
            "kms_key_version": self.kms_key_version,
            "wrapped": _b64e(self.wrapped),
            "nonce": _b64e(self.nonce),
            "ct": _b64e(self.ct),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Envelope:
        """Parse the output of :meth:`to_dict`. Raises :class:`EnvelopeError`."""
        if not isinstance(data, dict):
            raise EnvelopeError("envelope must be a JSON object")
        if data.get("v") != ENVELOPE_VERSION:
            raise EnvelopeError(f"unsupported envelope version: {data.get('v')!r}")
        policy = data.get("policy")
        if not isinstance(policy, dict):
            raise EnvelopeError("policy must be a JSON object")
        key_version = data.get("kms_key_version")
        if key_version is not None and not isinstance(key_version, str):
            raise EnvelopeError("kms_key_version must be a string or null")
        secret_id = _require_id(data.get("secret_id"), "secret_id")
        owner_id = _require_id(data.get("owner_id"), "owner_id")
        compute_aad(secret_id, owner_id, policy)  # policy must canonicalize
        envelope = cls(
            secret_id=secret_id,
            owner_id=owner_id,
            policy=copy.deepcopy(policy),
            wrapped=_b64d(data.get("wrapped"), "wrapped"),
            nonce=_b64d(data.get("nonce"), "nonce"),
            ct=_b64d(data.get("ct"), "ct"),
            kms_key_version=key_version,
        )
        _check_sizes(envelope)
        return envelope


def compute_aad(secret_id: str, owner_id: str, policy: dict[str, Any]) -> bytes:
    """Return the 32-byte AAD binding a ciphertext to its identity and policy."""
    bound = {
        "v": ENVELOPE_VERSION,
        "secret_id": _require_id(secret_id, "secret_id"),
        "owner_id": _require_id(owner_id, "owner_id"),
        "policy": policy,
    }
    try:
        return hashlib.sha256(canonical_json(bound)).digest()
    except CanonicalJSONError as exc:
        raise EnvelopeError(f"policy cannot be canonicalized: {exc}") from exc


def load_rsa_public_key(public_key_pem: bytes | str) -> rsa.RSAPublicKey:
    """Load a PEM RSA public key and require at least ``MIN_RSA_BITS`` bits."""
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("ascii")
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except ValueError as exc:
        raise EnvelopeError("invalid PEM public key") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise EnvelopeError("public key must be RSA")
    if key.key_size < MIN_RSA_BITS:
        raise EnvelopeError(f"RSA key must be at least {MIN_RSA_BITS} bits")
    return key


def seal(
    public_key_pem: bytes | str,
    secret_id: str,
    owner_id: str,
    policy: dict[str, Any],
    plaintext: bytes | bytearray,
    *,
    kms_key_version: str | None = None,
) -> Envelope:
    """Encrypt ``plaintext`` so only the holder of the RSA private key can open it.

    Raises:
        EnvelopeError: On a bad key, identifiers, policy, or plaintext size.
    """
    return _seal(
        public_key_pem,
        secret_id,
        owner_id,
        policy,
        plaintext,
        kms_key_version=kms_key_version,
        random_bytes=secrets.token_bytes,
    )


def _seal(
    public_key_pem: bytes | str,
    secret_id: str,
    owner_id: str,
    policy: dict[str, Any],
    plaintext: bytes | bytearray,
    *,
    kms_key_version: str | None,
    random_bytes: RandomBytes,
) -> Envelope:
    """Implementation of :func:`seal` with an injectable RNG.

    ``random_bytes`` is replaced only by the test-vector generator; production
    callers must go through :func:`seal`.
    """
    if not 0 < len(plaintext) <= MAX_PLAINTEXT_BYTES:
        raise EnvelopeError(f"plaintext must be 1..{MAX_PLAINTEXT_BYTES} bytes")
    public_key = load_rsa_public_key(public_key_pem)
    aad = compute_aad(secret_id, owner_id, policy)

    dek = bytearray(random_bytes(DEK_SIZE))
    try:
        nonce = random_bytes(NONCE_SIZE)
        if len(dek) != DEK_SIZE or len(nonce) != NONCE_SIZE:
            raise EnvelopeError("random source returned the wrong length")
        ct = AESGCM(dek).encrypt(nonce, plaintext, aad)
        # RSA encryption requires an immutable ``bytes``; this copy is
        # unavoidable and is released immediately.
        wrapped = public_key.encrypt(bytes(dek), _oaep())
    finally:
        _zero(dek)

    return Envelope(
        secret_id=secret_id,
        owner_id=owner_id,
        policy=copy.deepcopy(policy),
        wrapped=wrapped,
        nonce=nonce,
        ct=ct,
        kms_key_version=kms_key_version,
    )


def open_with_dek_unwrapper(
    envelope: Envelope,
    unwrap: DekUnwrapper,
    *,
    expected_secret_id: str,
    expected_owner_id: str,
) -> tuple[bytes, dict[str, Any]]:
    """Decrypt an envelope and return ``(plaintext, policy)``.

    ``expected_secret_id`` and ``expected_owner_id`` must come from the
    authenticated request (the secret the agent asked for, the owner the
    agent belongs to), never from the envelope itself. Otherwise a malicious
    store could hand one owner's envelope to another owner's request.

    The returned policy is the stored one, authenticated by the AEAD tag; it
    is the only policy the caller may enforce. There is no ``expected_policy``
    because the enclave has no independent source for it.

    ``unwrap`` turns the wrapped DEK into the 32-byte DEK, for example by
    calling Cloud KMS ``asymmetricDecrypt``. Exceptions it raises propagate
    unchanged, so transport errors are not mistaken for tampering.

    Raises:
        EnvelopeError: If the envelope is malformed or belongs to a different
            secret or owner.
        EnvelopeDecryptionError: If the DEK or ciphertext fails authentication.
    """
    if envelope.v != ENVELOPE_VERSION:
        raise EnvelopeError(f"unsupported envelope version: {envelope.v!r}")
    _check_sizes(envelope)
    if (envelope.secret_id, envelope.owner_id) != (
        expected_secret_id,
        expected_owner_id,
    ):
        raise EnvelopeError("envelope does not belong to the expected secret/owner")
    policy = copy.deepcopy(envelope.policy)
    aad = compute_aad(expected_secret_id, expected_owner_id, policy)

    dek = bytearray(unwrap(envelope.wrapped))
    try:
        if len(dek) != DEK_SIZE:
            raise EnvelopeDecryptionError("unwrapped DEK has the wrong length")
        try:
            plaintext = AESGCM(dek).decrypt(envelope.nonce, envelope.ct, aad)
        except InvalidTag as exc:
            raise EnvelopeDecryptionError("ciphertext failed authentication") from exc
    finally:
        _zero(dek)
    return plaintext, policy


def rsa_oaep_unwrapper(private_key: rsa.RSAPrivateKey) -> DekUnwrapper:
    """Return a local unwrapper for tests and the mock enclave.

    Production uses Cloud KMS; never hold the real private key in process.
    """

    def unwrap(wrapped: bytes) -> bytes:
        try:
            return private_key.decrypt(wrapped, _oaep())
        except ValueError as exc:
            raise EnvelopeDecryptionError("DEK unwrap failed") from exc

    return unwrap


def _check_sizes(envelope: Envelope) -> None:
    if len(envelope.nonce) != NONCE_SIZE:
        raise EnvelopeError("nonce must be 12 bytes")
    if not MIN_RSA_BITS // 8 <= len(envelope.wrapped) <= MAX_RSA_BITS // 8:
        raise EnvelopeError("wrapped DEK has an invalid length")
    if not GCM_TAG_SIZE < len(envelope.ct) <= MAX_PLAINTEXT_BYTES + GCM_TAG_SIZE:
        raise EnvelopeError("ciphertext has an invalid length")


def _zero(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _require_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise EnvelopeError(f"{name} must be a non-empty string")
    return value


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value: Any, name: str) -> bytes:
    if not isinstance(value, str):
        raise EnvelopeError(f"{name} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EnvelopeError(f"{name} is not valid base64") from exc
