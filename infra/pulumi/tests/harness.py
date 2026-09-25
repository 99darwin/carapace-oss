"""Pulumi mock harness: records every declared resource for assertions."""

from __future__ import annotations

from dataclasses import dataclass, replace

import pulumi

from components.config import StackConfig
from components.stack import deploy

PROJECT_ID = "example-project"
PROJECT_NUMBER = "123456789012"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
STATIC_IP = "203.0.113.10"
GET_PROJECT_TOKEN = "gcp:organizations/getProject:getProject"  # noqa: S105


@dataclass(frozen=True)
class Recorded:
    typ: str
    name: str
    inputs: dict


class RecordingMocks(pulumi.runtime.Mocks):
    def __init__(self) -> None:
        self.resources: list[Recorded] = []

    def new_resource(self, args: pulumi.runtime.MockResourceArgs):
        self.resources.append(Recorded(args.typ, args.name, dict(args.inputs)))
        state = dict(args.inputs)
        state.update(_computed_state(args.typ, args.inputs))
        resource_id = state.pop("id", f"{args.name}_id")
        return resource_id, state

    def call(self, args: pulumi.runtime.MockCallArgs):
        if args.token == GET_PROJECT_TOKEN:
            return {"number": PROJECT_NUMBER, "projectId": PROJECT_ID}
        return {}

    def of_type(self, typ: str) -> list[Recorded]:
        return [r for r in self.resources if r.typ == typ]

    def one(self, typ: str) -> Recorded:
        matches = self.of_type(typ)
        assert len(matches) == 1, f"expected one {typ}, got {len(matches)}"
        return matches[0]


def _computed_state(typ: str, inputs: dict) -> dict:
    location = f"projects/{PROJECT_ID}/locations/{inputs.get('location')}"
    pool_path = f"projects/{PROJECT_NUMBER}/locations/global/workloadIdentityPools"
    computed = {
        "gcp:serviceaccount/account:Account": lambda: {
            "email": f"{inputs['accountId']}@{PROJECT_ID}.iam.gserviceaccount.com"
        },
        "gcp:kms/keyRing:KeyRing": lambda: {
            "id": f"{location}/keyRings/{inputs['name']}"
        },
        "gcp:kms/cryptoKey:CryptoKey": lambda: {
            "id": f"{inputs['keyRing']}/cryptoKeys/{inputs['name']}"
        },
        "gcp:iam/workloadIdentityPool:WorkloadIdentityPool": lambda: {
            "name": f"{pool_path}/{inputs['workloadIdentityPoolId']}"
        },
        "gcp:iam/workloadIdentityPoolProvider:WorkloadIdentityPoolProvider": (
            lambda: {
                "name": f"{pool_path}/{inputs['workloadIdentityPoolId']}"
                f"/providers/{inputs['workloadIdentityPoolProviderId']}"
            }
        ),
        "gcp:compute/address:Address": lambda: {"address": STATIC_IP},
        "gcp:sql/databaseInstance:DatabaseInstance": lambda: {
            "name": "db-instance",
            "connectionName": f"{PROJECT_ID}:region:db-instance",
        },
        "gcp:cloudrunv2/service:Service": lambda: {
            "uri": "https://server.example.run.app"
        },
        "gcp:secretmanager/secret:Secret": lambda: {
            "id": f"projects/{PROJECT_ID}/secrets/{inputs['secretId']}"
        },
        "gcp:secretmanager/secretVersion:SecretVersion": lambda: {"version": "1"},
        "random:index/randomPassword:RandomPassword": lambda: {
            "result": "mock-password"
        },
    }
    factory = computed.get(typ)
    return factory() if factory else {}


def make_config(**overrides: object) -> StackConfig:
    base = StackConfig(
        project=PROJECT_ID,
        prefix="cptest",
        region="us-central1",
        zone="us-central1-a",
        allowed_digests=[DIGEST_A, DIGEST_B],
        enclave_image_digest=DIGEST_A,
        server_image_digest="sha256:" + "c" * 64,
        enable_iam_alerts=True,
        alert_emails=["security@example.com"],
    )
    return replace(base, **overrides)


def run_stack(cfg: StackConfig) -> tuple[RecordingMocks, dict]:
    """Run ``deploy`` under mocks and return recorded resources + outputs."""
    mocks = RecordingMocks()
    pulumi.runtime.set_mocks(mocks, project="carapace", stack="test", preview=False)
    resolved: dict = {}

    @pulumi.runtime.test
    def program():
        outputs = deploy(cfg)
        return pulumi.Output.all(**outputs).apply(resolved.update)

    program()
    return mocks, resolved
