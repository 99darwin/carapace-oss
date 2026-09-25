"""Envelope encryption v1: sealed to the enclave's KMS key, signed by the owner.

A secret is sealed on the owner's device to the enclave's Cloud KMS public
key and can only be opened by something able to unwrap the data key (in
production, the attested enclave calling KMS ``asymmetricDecrypt``)::

    header  = {"v": 1, "secret_id", "owner_id", "owner_pk", "version", "policy"}
    aad     = sha256(canonical_json(header))
    dek     = random(32)
    ct      = AES-256-GCM(dek, nonce = random(12), plaintext, aad)   # ct || tag
    wrapped = RSA-OAEP(SHA-256, MGF1-SHA-256, no label)(kms_public_key, dek)
    body    = header + {"kms_key_version", "wrapped", "nonce", "ct"}
    sig     = Ed25519(owner_seed, "carapace-envelope-v1" || 0x0A
                                  || canonical_json(body))

``owner_pk`` is the owner's raw Ed25519 public key and ``version`` is a
positive integer the owner increases every time the secret is re-sealed.
Binary fields are standard padded base64 in both the stored form and the
signed body, so the signature covers the exact bytes the store holds.

The AAD detects *edits* to a stored envelope: the enclave recomputes it from
the stored header, so a widened policy makes decryption fail. The signature
detects *substitution*: the KMS public key is public, so anyone with write
access to the store could otherwise seal their own credential under the
victim's ids. The enclave takes the owner fingerprint from the API key the
agent presents, requires ``fingerprint(owner_pk)`` to match, and verifies the
signature before it calls KMS. Rollback to an older, validly signed envelope
is bounded by the ``version`` floor carried in the agent's grant; see
``docs/design/owner-signing.md``.

The canonical header is capped at ``MAX_AAD_INPUT_BYTES`` so the enclave
never canonicalizes an unbounded policy served by the untrusted store.

``kms_key_version`` is signed but not otherwise authenticated before use, so
callers must validate it against their own key ring before building a KMS
resource name from it, and never interpolate it unchecked.

Zeroization of the DEK is best effort. The ``bytearray`` copies this module
controls are cleared, but the RNG, the RSA encryption and the unwrapper
exchange immutable ``bytes`` that Python cannot wipe.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from carapace_crypto.canonical import (
    MAX_SAFE_INTEGER,
    CanonicalJSONError,
    canonical_json,
    load_json_object,
)
from carapace_crypto.encoding import b64_decode_strict, b64_encode_std
from carapace_crypto.ownerkey import (
    PUBLIC_KEY_SIZE,
    SIGNATURE_SIZE,
    OwnerKey,
    SignatureError,
    verify_object,
)

ENVELOPE_VERSION = 1
ENVELOPE_CONTEXT = b"carapace-envelope-v1"
DEK_SIZE = 32
NONCE_SIZE = 12
MIN_RSA_BITS = 3072
MAX_PLAINTEXT_BYTES = 64 * 1024
GCM_TAG_SIZE = 16
MAX_RSA_BITS = 8192
# Bound on canonical_json(header); part of the format.
MAX_AAD_INPUT_BYTES = 64 * 1024
# Longest base64 text any binary field may carry, checked before decoding.
_MAX_B64_CHARS = 4 * ((MAX_PLAINTEXT_BYTES + GCM_TAG_SIZE + 2) // 3)

DekUnwrapper = Callable[[bytes], bytes]
RandomBytes = Callable[[int], bytes]


class EnvelopeError(ValueError):
    """Raised for malformed envelopes, keys, or inputs."""


class EnvelopeSignatureError(EnvelopeError):
    """The owner signature is missing, malformed, or does not verify."""


class EnvelopeStaleError(EnvelopeError):
    """The envelope's version is below the floor the caller requires."""


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
    """A sealed, owner-signed secret. Safe to store on an untrusted server."""

    secret_id: str
    owner_id: str
    owner_pk: bytes
    version: int
    policy: dict[str, Any]
    wrapped: bytes
    nonce: bytes
    ct: bytes
    sig: bytes
    kms_key_version: str | None = None
    v: int = ENVELOPE_VERSION

    def header(self) -> dict[str, Any]:
        """The AAD input: identity, owner key, version and policy."""
        return _header(
            self.secret_id, self.owner_id, self.owner_pk, self.version, self.policy
        )

    def signed_body(self) -> dict[str, Any]:
        """Everything the owner signs: :meth:`to_dict` without ``sig``."""
        body = self.to_dict()
        del body["sig"]
        return body

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict with base64-encoded binary fields."""
        header = self.header()
        header["policy"] = copy.deepcopy(self.policy)
        return {
            **header,
            "kms_key_version": self.kms_key_version,
            "wrapped": b64_encode_std(self.wrapped),
            "nonce": b64_encode_std(self.nonce),
            "ct": b64_encode_std(self.ct),
            "sig": b64_encode_std(self.sig),
        }

    @classmethod
    def from_json(cls, data: bytes | str) -> Envelope:
        """Parse JSON text, rejecting duplicate keys. Raises :class:`EnvelopeError`."""
        try:
            return cls.from_dict(load_json_object(data))
        except CanonicalJSONError as exc:
            raise EnvelopeError(str(exc)) from exc

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Envelope:
        """Parse the output of :meth:`to_dict`. Raises :class:`EnvelopeError`.

        Only shape is checked here. Use :func:`open_with_dek_unwrapper`, which
        verifies the signature, before trusting any field. Callers holding
        JSON text must go through :meth:`from_json`.
        """
        if not isinstance(data, dict):
            raise EnvelopeError("envelope must be a JSON object")
        # ``bool`` is an ``int`` subclass and ``True == 1``; compare the type.
        version = data.get("v")
        if type(version) is not int or version != ENVELOPE_VERSION:
            raise EnvelopeError(f"unsupported envelope version: {version!r}")
        policy = data.get("policy")
        if not isinstance(policy, dict):
            raise EnvelopeError("policy must be a JSON object")
        key_version = data.get("kms_key_version")
        if key_version is not None and not isinstance(key_version, str):
            raise EnvelopeError("kms_key_version must be a string or null")
        envelope = cls(
            secret_id=_require_id(data.get("secret_id"), "secret_id"),
            owner_id=_require_id(data.get("owner_id"), "owner_id"),
            owner_pk=_b64d(data.get("owner_pk"), "owner_pk"),
            version=_require_version(data.get("version")),
            policy=copy.deepcopy(policy),
            wrapped=_b64d(data.get("wrapped"), "wrapped"),
            nonce=_b64d(data.get("nonce"), "nonce"),
            ct=_b64d(data.get("ct"), "ct"),
            sig=_b64d(data.get("sig"), "sig"),
            kms_key_version=key_version,
        )
        _check_sizes(envelope)
        compute_aad(envelope.header())  # policy must canonicalize within bounds
        return envelope


def _header(
    secret_id: str,
    owner_id: str,
    owner_pk: bytes,
    version: int,
    policy: dict[str, Any],
) -> dict[str, Any]:
    return {
        "v": ENVELOPE_VERSION,
        "secret_id": secret_id,
        "owner_id": owner_id,
        "owner_pk": b64_encode_std(owner_pk),
        "version": version,
        "policy": policy,
    }


def compute_aad(header: dict[str, Any]) -> bytes:
    """Return the 32-byte AAD for an envelope header (see :meth:`Envelope.header`).

    Raises:
        EnvelopeError: If the header does not canonicalize or is too large.
    """
    try:
        encoded = canonical_json(header)
    except CanonicalJSONError as exc:
        raise EnvelopeError(f"policy cannot be canonicalized: {exc}") from exc
    if len(encoded) > MAX_AAD_INPUT_BYTES:
        raise EnvelopeError(f"AAD input exceeds {MAX_AAD_INPUT_BYTES} bytes")
    return hashlib.sha256(encoded).digest()


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
    if not MIN_RSA_BITS <= key.key_size <= MAX_RSA_BITS:
        raise EnvelopeError(
            f"RSA key must be between {MIN_RSA_BITS} and {MAX_RSA_BITS} bits"
        )
    return key


def seal(
    public_key_pem: bytes | str,
    secret_id: str,
    owner_id: str,
    policy: dict[str, Any],
    plaintext: bytes | bytearray,
    *,
    owner_key: OwnerKey,
    version: int,
    kms_key_version: str | None = None,
) -> Envelope:
    """Encrypt ``plaintext`` for the KMS key holder and sign it as the owner.

    ``version`` must be higher than any version this secret was sealed with
    before. The CLI should use ``max(last_version + 1, now_unix_seconds)`` so
    that it stays monotonic even without local state.

    Raises:
        EnvelopeError: On a bad key, identifiers, policy, version, or size.
    """
    return _seal(
        public_key_pem,
        secret_id,
        owner_id,
        policy,
        plaintext,
        owner_key=owner_key,
        version=version,
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
    owner_key: OwnerKey,
    version: int,
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
    header = _header(
        _require_id(secret_id, "secret_id"),
        _require_id(owner_id, "owner_id"),
        owner_key.public_key,
        _require_version(version),
        copy.deepcopy(policy),
    )
    aad = compute_aad(header)

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

    unsigned = Envelope(
        secret_id=secret_id,
        owner_id=owner_id,
        owner_pk=owner_key.public_key,
        version=version,
        policy=header["policy"],
        wrapped=wrapped,
        nonce=nonce,
        ct=ct,
        sig=b"",
        kms_key_version=kms_key_version,
    )
    sig = owner_key.sign_object(ENVELOPE_CONTEXT, unsigned.signed_body())
    return Envelope(**{**_fields(unsigned), "sig": sig})


def verify_envelope_signature(envelope: Envelope) -> None:
    """Check the owner signature against the envelope's own ``owner_pk``.

    This proves the envelope was produced by whoever holds that key. Whether
    that key is the *right* one is a separate check the caller makes against
    a fingerprint from a trusted source (the agent's API key).

    Raises:
        EnvelopeSignatureError: If the signature does not verify.
    """
    try:
        verify_object(
            envelope.owner_pk, ENVELOPE_CONTEXT, envelope.signed_body(), envelope.sig
        )
    except SignatureError as exc:
        raise EnvelopeSignatureError(str(exc)) from exc


def open_with_dek_unwrapper(
    envelope: Envelope,
    unwrap: DekUnwrapper,
    *,
    expected_secret_id: str,
    expected_owner_pk: bytes,
    min_version: int = 1,
) -> tuple[bytes, dict[str, Any]]:
    """Verify, then decrypt an envelope and return ``(plaintext, policy)``.

    ``expected_secret_id`` is the secret the agent asked for and
    ``expected_owner_pk`` is the owner public key from the agent's verified
    grant (whose fingerprint matches the agent's API key). Neither may come
    from the envelope itself or from the store; otherwise a malicious store
    could substitute an envelope of its own.

    ``min_version`` is the floor from the grant. Older envelopes are refused
    even though they are validly signed, which bounds rollback.

    Checks run in this order, and ``unwrap`` (the KMS call) is reached only
    if every one of them passes: shape, identity, signature, version.

    ``unwrap`` turns the wrapped DEK into the 32-byte DEK, for example by
    calling Cloud KMS ``asymmetricDecrypt``. Exceptions it raises propagate
    unchanged, so transport errors are not mistaken for tampering.

    Raises:
        EnvelopeError: If the envelope is malformed or belongs to a different
            secret or owner key.
        EnvelopeSignatureError: If the owner signature does not verify.
        EnvelopeStaleError: If ``version < min_version``.
        EnvelopeDecryptionError: If the DEK or ciphertext fails authentication.
    """
    if envelope.v != ENVELOPE_VERSION:
        raise EnvelopeError(f"unsupported envelope version: {envelope.v!r}")
    _check_sizes(envelope)
    if envelope.secret_id != expected_secret_id:
        raise EnvelopeError("envelope does not belong to the expected secret")
    if not hmac.compare_digest(envelope.owner_pk, expected_owner_pk):
        raise EnvelopeError("envelope is not signed by the expected owner key")
    verify_envelope_signature(envelope)
    if envelope.version < _require_version(min_version):
        raise EnvelopeStaleError(
            f"envelope version {envelope.version} is below floor {min_version}"
        )
    policy = copy.deepcopy(envelope.policy)
    aad = compute_aad(envelope.header())

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
    if len(envelope.owner_pk) != PUBLIC_KEY_SIZE:
        raise EnvelopeError("owner_pk must be 32 bytes")
    if len(envelope.sig) != SIGNATURE_SIZE:
        raise EnvelopeError("sig must be 64 bytes")
    if len(envelope.nonce) != NONCE_SIZE:
        raise EnvelopeError("nonce must be 12 bytes")
    if not MIN_RSA_BITS // 8 <= len(envelope.wrapped) <= MAX_RSA_BITS // 8:
        raise EnvelopeError("wrapped DEK has an invalid length")
    if not GCM_TAG_SIZE < len(envelope.ct) <= MAX_PLAINTEXT_BYTES + GCM_TAG_SIZE:
        raise EnvelopeError("ciphertext has an invalid length")


def _fields(envelope: Envelope) -> dict[str, Any]:
    return {name: getattr(envelope, name) for name in Envelope.__slots__}


def _zero(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _require_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise EnvelopeError(f"{name} must be a non-empty string")
    return value


def _require_version(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER:
        raise EnvelopeError("version must be a positive safe integer")
    return value


def _b64d(value: Any, name: str) -> bytes:
    if isinstance(value, str) and len(value) > _MAX_B64_CHARS:
        raise EnvelopeError(f"{name} is too long")
    try:
        return b64_decode_strict(value, name=name)
    except ValueError as exc:
        raise EnvelopeError(str(exc)) from exc
