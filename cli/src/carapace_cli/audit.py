"""``carapace audit verify``: check receipts offline.

For every boot that produced one of our receipts:

- the boot's attestation token verifies under the pinned trust policy
  (issuer, claims, allowed image digest; expiry ignored since boots are
  historical), with audience the server URL or ``carapace-attestation`` and
  nonce equal to the boot id;
- the boot id equals ``sha256(tls_spki_der || receipt_pubkey)``, so the
  receipt key is the one the hardware attested.

For every receipt:

- ``hash`` is ``sha256(canonical_json({boot_id, seq, prev_hash, payload}))``
  and the Ed25519 signature under the boot's receipt key verifies;
- seq 0 has the all-zero ``prev_hash``; consecutive seqs link by hash;
- the payload names our owner fingerprint.

The server only returns this owner's receipts, and a boot's chain
interleaves every owner's, so gaps are expected and reported, not failed.
A server can therefore withhold receipts undetectably; it cannot forge,
edit or reorder the ones it returns.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carapace_cli.attestation import (
    ATTESTATION_AUDIENCE,
    TrustPolicy,
    verify_attestation_token,
)
from carapace_cli.errors import CarapaceError, VerificationError
from carapace_cli.session import ServerClient
from carapace_cli.verify import boot_id_for
from carapace_crypto import CanonicalJSONError, b64_decode_strict, canonical_json

GENESIS_PREV_HASH = "0" * 64
PAGE_SIZE = 100
MAX_PAGES = 10_000
RECEIPT_PUBKEY_BYTES = 32


@dataclass
class AuditReport:
    receipts: int = 0
    boots: int = 0
    gaps: int = 0
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures

    def summary(self) -> str:
        """One line: the verdict and counts, explaining gaps only if any."""
        line = (
            f"{'OK' if self.ok else 'FAILED'}: {plural(self.receipts, 'receipt')} "
            f"from {plural(self.boots, 'attested boot')} verified, "
            f"{plural(self.gaps, 'gap')}"
        )
        if self.gaps:
            line += " (other owners' receipts, or withheld)"
        return line


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def fetch_receipt_pages(
    server: ServerClient, *, secret_id: str | None = None
) -> Iterator[dict[str, Any]]:
    cursor: str | None = None
    for _ in range(MAX_PAGES):
        params: dict[str, Any] = {"limit": PAGE_SIZE}
        if secret_id:
            params["secret_id"] = secret_id
        if cursor:
            params["cursor"] = cursor
        page = server.get("/v1/receipts", params=params)
        yield page
        cursor = page.get("next_cursor")
        if not cursor:
            return
    raise CarapaceError("too many receipt pages")


def load_receipt_file(path: Path) -> list[dict[str, Any]]:
    """Pages saved with ``carapace audit fetch``: a JSON list of pages."""
    try:
        data = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CarapaceError(f"cannot read {path}: {exc}") from None
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not all(isinstance(p, dict) for p in data):
        raise CarapaceError(f"{path} must hold receipt pages")
    return data


def verify_receipts(
    pages: Iterable[dict[str, Any]],
    *,
    policy: TrustPolicy,
    server_url: str,
    owner_fingerprint: str,
) -> AuditReport:
    boots: dict[str, dict[str, Any]] = {}
    receipts: dict[tuple[str, int], dict[str, Any]] = {}
    for page in pages:
        for boot in page.get("boots") or []:
            if isinstance(boot, dict) and isinstance(boot.get("boot_id"), str):
                boots.setdefault(boot["boot_id"], boot)
        for receipt in page.get("receipts") or []:
            if not isinstance(receipt, dict):
                raise VerificationError("malformed receipt")
            boot_id, seq = receipt.get("boot_id"), receipt.get("seq")
            if not isinstance(boot_id, str) or type(seq) is not int:
                raise VerificationError("malformed receipt")
            if (boot_id, seq) in receipts:
                raise VerificationError("duplicate receipt")
            receipts[boot_id, seq] = receipt

    report = AuditReport()
    boot_keys: dict[str, bytes] = {}
    for boot_id in sorted({b for b, _ in receipts}):
        boot = boots.get(boot_id)
        if boot is None:
            report.failures.append(f"boot {boot_id[:16]}: not provided")
            continue
        try:
            boot_keys[boot_id] = _verify_boot(boot, policy, server_url)
            report.boots += 1
        except VerificationError as exc:
            report.failures.append(f"boot {boot_id[:16]}: {exc}")

    previous: dict[str, tuple[int, str]] = {}
    for boot_id, seq in sorted(receipts):
        receipt = receipts[boot_id, seq]
        label = f"receipt {boot_id[:16]}#{seq}"
        pubkey = boot_keys.get(boot_id)
        if pubkey is None:
            report.failures.append(f"{label}: boot not verified")
            continue
        try:
            receipt_hash = _verify_receipt(receipt, pubkey, owner_fingerprint)
        except VerificationError as exc:
            report.failures.append(f"{label}: {exc}")
            continue
        last = previous.get(boot_id)
        if last is not None and last[0] + 1 == seq:
            if receipt["prev_hash"] != last[1]:
                report.failures.append(f"{label}: does not link to #{last[0]}")
                continue
        elif last is not None or seq != 0:
            report.gaps += 1
        previous[boot_id] = (seq, receipt_hash)
        report.receipts += 1
    return report


def _verify_boot(boot: dict[str, Any], policy: TrustPolicy, server_url: str) -> bytes:
    boot_id, token = boot.get("boot_id"), boot.get("attestation_token")
    cert_pem, pubkey_b64 = boot.get("tls_cert_pem"), boot.get("receipt_pubkey")
    if not all(isinstance(v, str) for v in (boot_id, token, cert_pem, pubkey_b64)):
        raise VerificationError("malformed boot record")
    try:
        pubkey = b64_decode_strict(pubkey_b64, name="receipt_pubkey")
        computed = boot_id_for(cert_pem, pubkey)
    except ValueError:
        raise VerificationError("malformed boot keys") from None
    if len(pubkey) != RECEIPT_PUBKEY_BYTES:
        raise VerificationError("malformed receipt key")
    if not hmac.compare_digest(computed, boot_id):
        raise VerificationError("boot id does not bind its TLS and receipt keys")
    claims = verify_attestation_token(
        token,
        policy,
        audiences=[server_url, ATTESTATION_AUDIENCE],
        nonce=boot_id,
        check_expiry=False,
    )
    if boot.get("image_digest") != claims.image_digest:
        raise VerificationError("boot image digest disagrees with its token")
    return pubkey


def _verify_receipt(
    receipt: dict[str, Any], pubkey: bytes, owner_fingerprint: str
) -> str:
    boot_id, seq = receipt.get("boot_id"), receipt.get("seq")
    prev_hash, payload = receipt.get("prev_hash"), receipt.get("payload")
    if (
        not isinstance(boot_id, str)
        or type(seq) is not int
        or seq < 0
        or not isinstance(prev_hash, str)
        or not isinstance(payload, dict)
    ):
        raise VerificationError("malformed receipt")
    if seq == 0 and prev_hash != GENESIS_PREV_HASH:
        raise VerificationError("genesis receipt has a non-zero prev_hash")
    try:
        signed = canonical_json(
            {"boot_id": boot_id, "seq": seq, "prev_hash": prev_hash, "payload": payload}
        )
        signature = b64_decode_strict(receipt.get("signature"), name="signature")
    except (CanonicalJSONError, ValueError):
        raise VerificationError("malformed receipt") from None
    computed = hashlib.sha256(signed).hexdigest()
    if receipt.get("hash") != computed:
        raise VerificationError("hash mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, signed)
    except (InvalidSignature, ValueError):
        raise VerificationError("bad signature") from None
    if payload.get("owner_fp") != owner_fingerprint:
        raise VerificationError("receipt is for another owner")
    return computed
