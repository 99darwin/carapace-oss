"""The owner signing key on disk: ``owner-key.json``, mode 0600.

Two forms, both JSON::

    {"v": 1, "public_key": b64, "protection": "none", "seed": b64}
    {"v": 1, "public_key": b64, "protection": "scrypt-aes256gcm",
     "kdf": {"n", "r", "p", "salt": b64}, "nonce": b64, "ciphertext": b64}

With a passphrase the 32-byte seed is sealed with AES-256-GCM under a key
derived with scrypt; the public key and KDF parameters are the AAD, so
neither can be swapped without the decryption failing. On load the public
key rebuilt from the seed must equal the stored one.

The seed is never printed, logged or put in an exception message.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from carapace_cli.errors import OwnerKeyError, StorageError
from carapace_cli.files import read_private_json, write_private_json
from carapace_crypto import (
    OwnerKey,
    SignatureError,
    b64_decode_strict,
    b64_encode_std,
    canonical_json,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
)
from carapace_crypto.symmetric import EncryptedData

OWNER_KEY_FILE = "owner-key.json"
STORE_VERSION = 1
PROTECTION_NONE = "none"
PROTECTION_SCRYPT = "scrypt-aes256gcm"
# scrypt: 2**17 * 8 * 128 bytes = 128 MiB of memory per guess.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_BYTES = 16
AES_KEY_BYTES = 32
MIN_PASSPHRASE_CHARS = 8
# Bounds on parameters read back from disk, so a tampered file cannot make
# loading hang or allocate unbounded memory.
MAX_SCRYPT_N = 2**20
MAX_SCRYPT_R = 16
MAX_SCRYPT_P = 4

PassphraseProvider = Callable[[], str]


def owner_key_path(config_dir: Path) -> Path:
    return config_dir / OWNER_KEY_FILE


def save_owner_key(
    path: Path,
    owner_key: OwnerKey,
    *,
    passphrase: str | None = None,
    scrypt_n: int = SCRYPT_N,
) -> None:
    """Write ``owner_key`` to ``path``, encrypted if ``passphrase`` is given.

    Refuses to overwrite: losing an owner key orphans every secret sealed
    under it, so replacing one is a deliberate manual step.

    Raises:
        OwnerKeyError: ``path`` exists or the passphrase is too short.
    """
    if path.exists():
        raise OwnerKeyError(f"{path} already exists; refusing to overwrite it")
    record: dict[str, Any] = {
        "v": STORE_VERSION,
        "public_key": b64_encode_std(owner_key.public_key),
    }
    if passphrase is None:
        record.update(protection=PROTECTION_NONE, seed=b64_encode_std(owner_key.seed))
    else:
        if len(passphrase) < MIN_PASSPHRASE_CHARS:
            raise OwnerKeyError(
                f"passphrase must be at least {MIN_PASSPHRASE_CHARS} characters"
            )
        record.update(_encrypt_seed(owner_key, passphrase, scrypt_n))
    write_private_json(path, record)


def load_owner_key(
    path: Path, *, passphrase: PassphraseProvider | None = None
) -> OwnerKey:
    """Load the owner key. ``passphrase`` is called only if one is needed.

    Raises:
        OwnerKeyError: Missing, malformed, wrong passphrase, or the seed
            does not match the stored public key.
    """
    try:
        record = read_private_json(path)
    except StorageError as exc:
        raise OwnerKeyError(f"cannot load owner key: {exc}") from None
    if record.get("v") != STORE_VERSION:
        raise OwnerKeyError("unsupported owner key file version")
    public_key = _b64(record.get("public_key"), "public_key")
    protection = record.get("protection")
    if protection == PROTECTION_NONE:
        seed = _b64(record.get("seed"), "seed")
    elif protection == PROTECTION_SCRYPT:
        if passphrase is None:
            raise OwnerKeyError("owner key is passphrase-protected")
        seed = _decrypt_seed(record, public_key, passphrase())
    else:
        raise OwnerKeyError("unknown owner key protection")
    try:
        owner_key = OwnerKey.from_seed(seed)
    except SignatureError:
        raise OwnerKeyError("owner key file is corrupt") from None
    if not hmac.compare_digest(owner_key.public_key, public_key):
        raise OwnerKeyError("owner key file is corrupt: public key mismatch")
    return owner_key


def is_passphrase_protected(path: Path) -> bool:
    try:
        return read_private_json(path).get("protection") == PROTECTION_SCRYPT
    except StorageError as exc:
        raise OwnerKeyError(f"cannot load owner key: {exc}") from None


def _encrypt_seed(owner_key: OwnerKey, passphrase: str, n: int) -> dict[str, Any]:
    kdf = {
        "n": n,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": b64_encode_std(secrets.token_bytes(SCRYPT_SALT_BYTES)),
    }
    key = _derive(passphrase, kdf)
    aad = _aad(owner_key.public_key, kdf)
    sealed = encrypt_aes_gcm(key, owner_key.seed, aad)
    return {
        "protection": PROTECTION_SCRYPT,
        "kdf": kdf,
        "nonce": b64_encode_std(sealed.nonce),
        "ciphertext": b64_encode_std(sealed.ciphertext),
    }


def _decrypt_seed(record: dict[str, Any], public_key: bytes, passphrase: str) -> bytes:
    kdf = record.get("kdf")
    if not isinstance(kdf, dict) or set(kdf) != {"n", "r", "p", "salt"}:
        raise OwnerKeyError("owner key file has invalid KDF parameters")
    for name, limit in (("n", MAX_SCRYPT_N), ("r", MAX_SCRYPT_R), ("p", MAX_SCRYPT_P)):
        value = kdf[name]
        if type(value) is not int or not 1 <= value <= limit:
            raise OwnerKeyError("owner key file has invalid KDF parameters")
    sealed = EncryptedData(
        nonce=_b64(record.get("nonce"), "nonce"),
        ciphertext=_b64(record.get("ciphertext"), "ciphertext"),
    )
    try:
        key = _derive(passphrase, kdf)
        return decrypt_aes_gcm(key, sealed, _aad(public_key, kdf))
    except (InvalidTag, ValueError):
        raise OwnerKeyError("wrong passphrase or corrupt owner key file") from None


def _derive(passphrase: str, kdf: dict[str, Any]) -> bytes:
    return Scrypt(
        salt=_b64(kdf["salt"], "salt"),
        length=AES_KEY_BYTES,
        n=kdf["n"],
        r=kdf["r"],
        p=kdf["p"],
    ).derive(passphrase.encode("utf-8"))


def _aad(public_key: bytes, kdf: dict[str, Any]) -> bytes:
    return canonical_json(
        {
            "v": STORE_VERSION,
            "protection": PROTECTION_SCRYPT,
            "public_key": b64_encode_std(public_key),
            "kdf": kdf,
        }
    )


def _b64(value: Any, name: str) -> bytes:
    try:
        return b64_decode_strict(value, name=name)
    except ValueError:
        raise OwnerKeyError(f"owner key file has an invalid {name}") from None
