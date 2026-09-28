"""Fakes for the deploy's first run: the new server and the enclave's verify.

:class:`FakeControlPlane` answers the auth and owner-key routes the first
run calls, over ``httpx.MockTransport``. :class:`FakeEnclave` stands in for
``verify_enclave``. Nothing here reaches the network.
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from deploy_support import KEY_VERSION

from carapace_cli.attestation import TrustPolicy
from carapace_cli.deploy.first_run import FirstRunServices
from carapace_cli.errors import EnclaveError, NetworkError
from carapace_cli.pin import EnclavePin
from carapace_cli.session import ServerClient, Session, authenticate

PASSWORD = "Correct-Horse-9"  # a test value


@dataclass
class FakeControlPlane:
    """Accounts and owner keys in memory; ``unavailable`` 503s come first."""

    users: dict[str, str] = field(default_factory=dict)
    owner_keys: list[dict[str, Any]] = field(default_factory=list)
    unavailable: int = 0
    requests: list[httpx.Request] = field(default_factory=list)

    def _tokens(self, email: str, status: int = 200) -> httpx.Response:
        return httpx.Response(
            status,
            json={
                "user_id": f"user-{email}",
                "access_token": "access",
                "refresh_token": "refresh",
            },
        )

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.unavailable:
            self.unavailable -= 1
            return httpx.Response(503, json={"detail": "starting"})
        path = request.url.path
        if path in ("/v1/auth/register", "/v1/auth/login"):
            body = json.loads(request.content)
            email, password = body["email"], body["password"]
            if path == "/v1/auth/register":
                if email in self.users:
                    return httpx.Response(400, json={"detail": "Registration failed"})
                self.users[email] = password
                return self._tokens(email, 201)
            if self.users.get(email) != password:
                return httpx.Response(401, json={"detail": "Invalid credentials"})
            return self._tokens(email)
        if request.headers.get("authorization") != "Bearer access":
            return httpx.Response(401)
        if path == "/v1/owner-keys" and request.method == "GET":
            return httpx.Response(200, json=self.owner_keys)
        if path == "/v1/owner-keys" and request.method == "POST":
            public_key = json.loads(request.content)["public_key"]
            if any(k["public_key"] == public_key for k in self.owner_keys):
                return httpx.Response(409, json={"detail": "exists"})
            record = {"public_key": public_key, "fingerprint": "fp", "retired_at": None}
            self.owner_keys.append(record)
            return httpx.Response(201, json=record)
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def calls(self, path: str) -> int:
        return sum(1 for r in self.requests if r.url.path == path)


@dataclass
class FakeEnclave:
    """``verify_enclave``: attests the one allowed digest after ``booting``.

    ``refusing`` connection failures come first, as from a VM whose
    server does not listen yet, then ``booting`` 503s.
    """

    refusing: int = 0
    booting: int = 0
    kms_key_version: str = KEY_VERSION
    # Pin identity fields to report instead of the policy's (a ``verify``
    # that pins something other than what it was asked to accept).
    identity: dict[str, str] = field(default_factory=dict)
    policies: list[TrustPolicy] = field(default_factory=list)

    def __call__(
        self, enclave_url: str, server: ServerClient, policy: TrustPolicy
    ) -> EnclavePin:
        self.policies.append(policy)
        if self.refusing:
            self.refusing -= 1
            raise NetworkError("cannot connect to the enclave: ConnectionRefusedError")
        if self.booting:
            self.booting -= 1
            raise EnclaveError(503, "attestation_unavailable")
        (digest,) = policy.allowed_digests
        identity = {
            "project_id": str(policy.project_id),
            "service_account": str(policy.service_account),
            "control_plane_url": str(policy.control_plane_url),
            "kms_key_name": str(policy.kms_key_name),
        } | self.identity
        return EnclavePin(
            enclave_url=enclave_url,
            tls_cert_pem="cert",
            receipt_pubkey="receipt",
            boot_id="boot",
            image_digest=digest,
            kms_public_key_pem="pem",
            kms_key_version=self.kms_key_version,
            allowed_digests=(digest,),
            insecure_mock=False,
            mock_key_pem=None,
            verified_at=0,
            **identity,
        )


def fake_first_run(
    control_plane: FakeControlPlane | None = None,
    enclave: FakeEnclave | None = None,
    *,
    answers: dict[str, str] | None = None,
) -> FirstRunServices:
    """First-run services over the fakes; ``answers`` maps prompts to input."""
    mock = (control_plane or FakeControlPlane()).transport()
    replies = answers if answers is not None else {}

    def server(config_dir: Path, session: Session) -> ServerClient:
        return ServerClient(config_dir, session=session, transport=mock)

    def prompt(text: str, *, confirm: bool = False) -> str:
        return replies[text]

    return FirstRunServices(
        authenticate=functools.partial(authenticate, transport=mock),
        server=server,
        verify=enclave or FakeEnclave(),
        prompt=prompt,
        password_from_stdin=lambda: PASSWORD,
    )
