"""/internal/* (attested enclave API) and /v1/receipts (owner view)."""

import base64
import datetime
import json
import time
import uuid
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

from carapace_server.apikeys.service import hash_api_key
from carapace_server.internal.deps import request_signing_bytes
from carapace_server.receipts.chain import (
    GENESIS_PREV_HASH,
    boot_id_for,
    receipt_hash,
    signed_bytes,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def settings(enclave_settings):
    """Every test here runs against the mock issuer in dev mode."""
    return enclave_settings


def _self_signed_cert() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "enclave")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM).decode()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


class FakeEnclave:
    """One enclave boot: TLS cert, receipt key, and its receipt chain."""

    def __init__(self, signer) -> None:
        self.signer = signer
        self.tls_cert_pem = _self_signed_cert()
        self.receipt_key = Ed25519PrivateKey.generate()
        self.receipt_pubkey = self.receipt_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        cert = x509.load_pem_x509_certificate(self.tls_cert_pem.encode())
        spki = cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        self.boot_id = boot_id_for(spki, self.receipt_pubkey)
        self.next_seq = 0
        self.tip = GENESIS_PREV_HASH

    def headers(self, nonce: str | None = None, **claims: Any) -> dict[str, str]:
        token = self.signer.token(nonce or self.boot_id, **claims)
        return {"Authorization": f"Bearer {token}"}

    def signed_headers(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        *,
        timestamp: int | None = None,
        signed_by: Ed25519PrivateKey | None = None,
    ) -> dict[str, str]:
        timestamp = int(time.time()) if timestamp is None else timestamp
        message = request_signing_bytes(method, path, timestamp, body)
        signature = (signed_by or self.receipt_key).sign(message)
        return {
            **self.headers(),
            "X-Carapace-Timestamp": str(timestamp),
            "X-Carapace-Signature": _b64(signature),
        }

    async def call(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        **signing: Any,
    ) -> httpx.Response:
        """A signed /internal request, as a registered enclave sends it."""
        content = json.dumps(body).encode() if body is not None else b""
        headers = self.signed_headers(method, path, content, **signing)
        if body is not None:
            headers["Content-Type"] = "application/json"
        return await client.request(method, path, content=content, headers=headers)

    def registration(self) -> dict[str, str]:
        return {
            "receipt_pubkey": _b64(self.receipt_pubkey),
            "tls_cert_pem": self.tls_cert_pem,
        }

    def receipt(
        self,
        payload: dict[str, Any],
        *,
        seq: int | None = None,
        prev_hash: str | None = None,
        signed_by: Ed25519PrivateKey | None = None,
        advance: bool = True,
    ) -> dict[str, Any]:
        """Sign the next receipt; overrides build deliberately bad ones."""
        seq = self.next_seq if seq is None else seq
        prev_hash = self.tip if prev_hash is None else prev_hash
        message = signed_bytes(self.boot_id, seq, prev_hash, payload)
        signature = (signed_by or self.receipt_key).sign(message)
        if advance:
            self.next_seq, self.tip = seq + 1, receipt_hash(message)
        return {
            "boot_id": self.boot_id,
            "seq": seq,
            "prev_hash": prev_hash,
            "payload": payload,
            "signature": _b64(signature),
        }


@pytest.fixture
def enclave(mock_signer) -> FakeEnclave:
    return FakeEnclave(mock_signer)


async def _register(client: httpx.AsyncClient, enclave: FakeEnclave) -> None:
    response = await client.post(
        "/internal/boots", json=enclave.registration(), headers=enclave.headers()
    )
    assert response.status_code == 201, response.text


async def _upload(
    client: httpx.AsyncClient, enclave: FakeEnclave, *receipts: dict
) -> httpx.Response:
    return await enclave.call(
        client, "POST", "/internal/receipts", {"receipts": list(receipts)}
    )


# -- authentication ------------------------------------------------------------


async def test_boot_registration(client, enclave) -> None:
    await _register(client, enclave)
    again = await client.post(
        "/internal/boots", json=enclave.registration(), headers=enclave.headers()
    )
    assert again.status_code == 200
    assert again.json() == {"boot_id": enclave.boot_id}


async def test_boot_nonce_mismatch_rejected(client, enclave) -> None:
    response = await client.post(
        "/internal/boots",
        json=enclave.registration(),
        headers=enclave.headers(nonce="cd" * 32),
    )
    assert response.status_code == 422


async def test_boot_with_other_keys_rejected(client, enclave, mock_signer) -> None:
    """A token bound to one boot cannot register another boot's keys."""
    other = FakeEnclave(mock_signer)
    response = await client.post(
        "/internal/boots", json=other.registration(), headers=enclave.headers()
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "claims",
    [
        {"dbgstat": "enabled"},
        {"aud": "https://other.example.com"},
        {"submods": {"container": {"image_digest": "sha256:" + "00" * 32}}},
    ],
    ids=["debug", "audience", "digest"],
)
async def test_bad_attestation_is_401(client, enclave, claims) -> None:
    response = await client.post(
        "/internal/boots",
        json=enclave.registration(),
        headers=enclave.headers(**claims),
    )
    assert response.status_code == 401


async def test_missing_token_is_401(client, enclave) -> None:
    response = await client.post("/internal/boots", json=enclave.registration())
    assert response.status_code == 401


async def test_user_token_is_not_attestation(client, alice, enclave) -> None:
    response = await client.post(
        "/internal/boots", json=enclave.registration(), headers=alice.headers
    )
    assert response.status_code == 401


async def test_unregistered_boot_is_403(client, enclave) -> None:
    secret_id = uuid.uuid4()
    check = {"key_hash": "00" * 32, "secret_id": str(secret_id)}
    responses = [
        await enclave.call(client, "GET", f"/internal/secrets/{secret_id}"),
        await enclave.call(client, "POST", "/internal/keys/verify", check),
        await _upload(client, enclave, enclave.receipt({"event": "x"})),
    ]
    assert [r.status_code for r in responses] == [403, 403, 403]


# -- request signatures (proof of possession) -----------------------------------


async def test_token_alone_is_not_enough(client, enclave) -> None:
    await _register(client, enclave)
    response = await client.get(
        f"/internal/secrets/{uuid.uuid4()}", headers=enclave.headers()
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    "signing",
    [
        {"timestamp": 0},
        {"timestamp": 10**12},
        {"signed_by": Ed25519PrivateKey.generate()},
    ],
    ids=["stale", "future", "wrong_key"],
)
async def test_bad_request_signature_is_401(client, enclave, signing) -> None:
    await _register(client, enclave)
    path = f"/internal/secrets/{uuid.uuid4()}"
    response = await enclave.call(client, "GET", path, **signing)
    assert response.status_code == 401


async def test_signature_covers_body_and_path(client, enclave) -> None:
    await _register(client, enclave)
    signed_body = json.dumps({"key_hash": "00" * 32, "secret_id": str(uuid.uuid4())})
    sent_body = json.dumps({"key_hash": "11" * 32, "secret_id": str(uuid.uuid4())})
    headers = enclave.signed_headers(
        "POST", "/internal/keys/verify", signed_body.encode()
    )
    headers["Content-Type"] = "application/json"
    tampered = await client.post(
        "/internal/keys/verify", content=sent_body, headers=headers
    )
    assert tampered.status_code == 401

    other_path = enclave.signed_headers("GET", f"/internal/secrets/{uuid.uuid4()}")
    moved = await client.get(f"/internal/secrets/{uuid.uuid4()}", headers=other_path)
    assert moved.status_code == 401


async def test_owner_cannot_reuse_published_token(
    client, enclave, alice, bob, new_secret
) -> None:
    """Owners see boots' attestation tokens; those must not unlock /internal."""
    await _register(client, enclave)
    mine = await new_secret(client, alice)
    theirs = await new_secret(client, bob)
    await _upload(client, enclave, enclave.receipt({"secret_id": mine["id"]}))
    page = (await client.get("/v1/receipts", headers=alice.headers)).json()
    token = page["boots"][0]["attestation_token"]
    response = await client.get(
        f"/internal/secrets/{theirs['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


# -- secrets and keys -----------------------------------------------------------


async def test_fetch_envelope(client, enclave, alice, new_secret) -> None:
    await _register(client, enclave)
    secret = await new_secret(client, alice)
    response = await enclave.call(client, "GET", f"/internal/secrets/{secret['id']}")
    assert response.status_code == 200
    detail = await client.get(f"/v1/secrets/{secret['id']}", headers=alice.headers)
    assert response.json() == detail.json()["envelope"]

    missing = await enclave.call(client, "GET", f"/internal/secrets/{uuid.uuid4()}")
    assert missing.status_code == 404


async def test_key_verify_enforces_scope(client, enclave, alice, new_secret) -> None:
    await _register(client, enclave)
    in_scope = await new_secret(client, alice, "github")
    out_of_scope = await new_secret(client, alice, "slack")
    created = await client.post(
        "/v1/api-keys",
        json={"name": "agent", "secret_ids": [in_scope["id"]]},
        headers=alice.headers,
    )
    key_hash = hash_api_key(created.json()["api_key"])

    async def allowed(secret_id: str, digest: str = key_hash) -> bool:
        check = {"key_hash": digest, "secret_id": secret_id}
        response = await enclave.call(client, "POST", "/internal/keys/verify", check)
        assert response.status_code == 200
        return response.json()["allowed"]

    assert await allowed(in_scope["id"]) is True
    assert await allowed(out_of_scope["id"]) is False
    assert await allowed(in_scope["id"], digest="00" * 32) is False

    key_id = created.json()["id"]
    await client.delete(f"/v1/api-keys/{key_id}", headers=alice.headers)
    assert await allowed(in_scope["id"]) is False


# -- receipt ingest --------------------------------------------------------------


async def test_chain_accepted_and_retry_idempotent(client, enclave) -> None:
    await _register(client, enclave)
    first = [enclave.receipt({"event": "start", "n": i}) for i in range(3)]
    response = await _upload(client, enclave, *first)
    assert response.json() == {"accepted": 3}

    retry = await _upload(client, enclave, *first[1:], enclave.receipt({"n": 3}))
    assert retry.status_code == 200
    assert retry.json() == {"accepted": 1}


async def test_unsigned_receipt_rejected(client, enclave) -> None:
    await _register(client, enclave)
    unsigned = enclave.receipt({"event": "x"}, advance=False)
    for signature in (None, "", _b64(b"\0" * 64)):
        body = {**unsigned, "signature": signature}
        if signature is None:
            del body["signature"]
        response = await _upload(client, enclave, body)
        assert response.status_code == 422, signature


async def test_receipt_signed_by_other_key_rejected(client, enclave) -> None:
    await _register(client, enclave)
    forged = enclave.receipt({"event": "x"}, signed_by=Ed25519PrivateKey.generate())
    response = await _upload(client, enclave, forged)
    assert response.status_code == 422


async def test_tampered_payload_rejected(client, enclave) -> None:
    await _register(client, enclave)
    receipt = enclave.receipt({"event": "allowed"})
    receipt["payload"] = {"event": "denied"}
    response = await _upload(client, enclave, receipt)
    assert response.status_code == 422


@pytest.mark.parametrize(
    "bad",
    [{"seq": 1}, {"prev_hash": "11" * 32}],
    ids=["seq", "prev_hash"],
)
async def test_bad_genesis_rejected(client, enclave, bad) -> None:
    await _register(client, enclave)
    response = await _upload(client, enclave, enclave.receipt({"n": 0}, **bad))
    assert response.status_code == 422


async def test_seq_gap_rejected(client, enclave) -> None:
    await _register(client, enclave)
    await _upload(client, enclave, enclave.receipt({"n": 0}))
    response = await _upload(client, enclave, enclave.receipt({"n": 2}, seq=2))
    assert response.status_code == 422


async def test_wrong_prev_hash_mid_chain_rejected(client, enclave) -> None:
    await _register(client, enclave)
    await _upload(client, enclave, enclave.receipt({"n": 0}))
    response = await _upload(
        client, enclave, enclave.receipt({"n": 1}, prev_hash="22" * 32)
    )
    assert response.status_code == 422


async def test_batch_is_atomic(client, enclave) -> None:
    await _register(client, enclave)
    good = enclave.receipt({"n": 0})
    broken = enclave.receipt({"n": 1}, prev_hash="33" * 32)
    response = await _upload(client, enclave, good, broken)
    assert response.status_code == 422
    # Nothing was stored, so the good receipt still fits at seq 0.
    assert (await _upload(client, enclave, good)).json() == {"accepted": 1}


async def test_fork_is_conflict(client, enclave) -> None:
    await _register(client, enclave)
    await _upload(client, enclave, enclave.receipt({"n": 0}))
    fork = enclave.receipt({"n": "other"}, seq=0, prev_hash=GENESIS_PREV_HASH)
    response = await _upload(client, enclave, fork)
    assert response.status_code == 409


async def test_receipt_for_other_boot_rejected(client, enclave, mock_signer) -> None:
    other = FakeEnclave(mock_signer)
    await _register(client, enclave)
    await _register(client, other)
    response = await _upload(client, enclave, other.receipt({"n": 0}))
    assert response.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [{"latency": 1.5}, {"event": "\ud800"}, {"blob": "x" * (17 * 1024)}],
    ids=["float", "lone_surrogate", "oversized"],
)
async def test_bad_payload_rejected(client, enclave, payload) -> None:
    await _register(client, enclave)
    receipt = enclave.receipt({"n": 0})
    receipt["payload"] = payload
    response = await _upload(client, enclave, receipt)
    assert response.status_code == 422


# -- owner view -------------------------------------------------------------------


async def test_owner_sees_only_own_receipts(
    client, enclave, alice, bob, new_secret
) -> None:
    await _register(client, enclave)
    alices = await new_secret(client, alice, "github")
    alices_other = await new_secret(client, alice, "slack")
    bobs = await new_secret(client, bob, "github")
    await _upload(
        client,
        enclave,
        enclave.receipt({"secret_id": alices["id"], "decision": "allow"}),
        enclave.receipt({"secret_id": bobs["id"], "decision": "allow"}),
        enclave.receipt({"secret_id": alices_other["id"], "decision": "deny"}),
        enclave.receipt({"event": "no-secret"}),
    )

    page = (await client.get("/v1/receipts", headers=alice.headers)).json()
    assert [r["seq"] for r in page["receipts"]] == [0, 2]
    assert [b["boot_id"] for b in page["boots"]] == [enclave.boot_id]
    assert page["boots"][0]["receipt_pubkey"] == _b64(enclave.receipt_pubkey)
    assert page["next_cursor"] is None

    filtered = await client.get(
        "/v1/receipts",
        params={"secret_id": alices_other["id"]},
        headers=alice.headers,
    )
    assert [r["seq"] for r in filtered.json()["receipts"]] == [2]

    bobs_page = (await client.get("/v1/receipts", headers=bob.headers)).json()
    assert [r["seq"] for r in bobs_page["receipts"]] == [1]
    foreign = await client.get(
        "/v1/receipts", params={"secret_id": alices["id"]}, headers=bob.headers
    )
    assert foreign.json()["receipts"] == []


async def test_receipt_for_deleted_secret_reaches_owner(
    client, enclave, alice, new_secret
) -> None:
    await _register(client, enclave)
    secret = await new_secret(client, alice)
    await client.delete(f"/v1/secrets/{secret['id']}", headers=alice.headers)
    payload = {"secret_id": secret["id"], "owner_id": alice.user_id}
    await _upload(client, enclave, enclave.receipt(payload))
    page = (await client.get("/v1/receipts", headers=alice.headers)).json()
    assert [r["payload"] for r in page["receipts"]] == [payload]


async def test_owner_receipts_are_verbatim(client, enclave, alice, new_secret) -> None:
    await _register(client, enclave)
    secret = await new_secret(client, alice)
    sent = enclave.receipt({"secret_id": secret["id"], "decision": "allow"})
    await _upload(client, enclave, sent)
    stored = (await client.get("/v1/receipts", headers=alice.headers)).json()
    received = stored["receipts"][0]
    assert {k: received[k] for k in sent} == sent
    message = signed_bytes(
        sent["boot_id"], sent["seq"], sent["prev_hash"], sent["payload"]
    )
    assert received["hash"] == receipt_hash(message)
    assert stored["boots"][0]["attestation_token"]


async def test_owner_receipts_paginate(client, enclave, alice, new_secret) -> None:
    await _register(client, enclave)
    secret = await new_secret(client, alice)
    payload = {"secret_id": secret["id"]}
    await _upload(client, enclave, *[enclave.receipt(payload) for _ in range(5)])

    seen: list[int] = []
    cursor = None
    while True:
        params = {"limit": 2, **({"cursor": cursor} if cursor else {})}
        page = (
            await client.get("/v1/receipts", params=params, headers=alice.headers)
        ).json()
        seen += [r["seq"] for r in page["receipts"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == [0, 1, 2, 3, 4]


async def test_owner_receipts_bad_cursor(client, alice) -> None:
    response = await client.get(
        "/v1/receipts", params={"cursor": "nope"}, headers=alice.headers
    )
    assert response.status_code == 422


async def test_owner_receipts_require_login(client) -> None:
    assert (await client.get("/v1/receipts")).status_code == 401
