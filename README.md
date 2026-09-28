# Carapace

Give AI agents access to your secrets without giving them your secrets.

Carapace is a credential-injecting proxy that runs inside a hardware-isolated
enclave (GCP Confidential Space, AMD SEV). Agents ask the enclave to make an
HTTP request on their behalf; the enclave attaches the credential, enforces a
per-secret host allowlist, redacts the secret from the response, and emits a
signed receipt. The agent never sees the raw secret, and neither does the
operator running the service.

> **Status: beta.** Not independently audited; start with scoped, revocable
> tokens. The release path (deploy from a published, signed release) has
> been verified end to end on real Confidential Space hardware, and the
> web UI has been tested on a real deployment; see
> [THREAT_MODEL.md](docs/THREAT_MODEL.md#verified-on-real-gcp).

## How it works

```
agent / SDK ──attested TLS──▶ ENCLAVE (Confidential VM)
CLI / web   ──encrypt locally to KMS public key──▶ SERVER (untrusted store)
ENCLAVE     ──pulls ciphertext, authenticates with attestation JWT──▶ SERVER
ENCLAVE     ──attestation-gated asymmetricDecrypt──▶ Cloud KMS (HSM)
```

- **Client-side encryption.** Secrets are encrypted on your machine to a
  Cloud KMS public key. The server stores only ciphertext.
- **Attestation-gated decryption.** Only an enclave running a specific,
  reproducibly built image digest can decrypt, enforced by KMS IAM bound to
  the Confidential Space attestation token.
- **Tamper-evident policy.** A secret's allowlist is bound into the
  ciphertext's authenticated data. Widening it breaks decryption.
- **Verifiable.** `carapace verify` checks the enclave's attestation, the
  image digest against the digests you allow, and pins the enclave's TLS
  key.
- **Auditable.** Every authorized use produces a receipt signed by a key
  bound to the attestation. `carapace audit verify` checks them.

## Quick start

Deploy your own into a new, dedicated GCP project with billing enabled.
You need `gcloud` (run `gcloud auth application-default login`), the Pulumi
CLI 3.x, Python 3.12, [`uv`](https://docs.astral.sh/uv/) and, for
`--build`, Docker with buildx. The full prerequisites, costs and teardown
are in [docs/SELF_HOST.md](docs/SELF_HOST.md).

```bash
git clone https://github.com/99darwin/carapace-oss.git
cd carapace-oss
uv tool install --editable ./cli
carapace deploy
```

The install is editable and from the clone because `deploy` and `destroy`
run the Pulumi program in the checkout the CLI was installed from
([`cli/src/carapace_cli/deploy/infra.py`](cli/src/carapace_cli/deploy/infra.py)).

`carapace deploy` asks for the project, region, alert email, first account
and owner-key passphrase, prints what it will create and what it costs, and
waits for confirmation. By default it deploys the latest signed release,
after verifying its signature; pass `--build` to build both images from
your checkout with Docker buildx instead, so what the enclave attests is
your own build rather than a signed release. It ends by running `carapace
verify` against the new enclave, trusting only the digest it just
deployed, and saving the pin. Back up the owner key it writes
(`owner-key.json` in the [CLI config directory](cli/README.md#local-state)):
without it you cannot authorize new API keys, and recovery means
re-entering and re-sealing every secret. `carapace destroy` removes the
deployment.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): the design.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): assets, trust boundaries,
  guarantees, and the residual risks we accept.
- [docs/VERIFY.md](docs/VERIFY.md): rebuild the enclave image, verify a
  running enclave with `carapace verify`, and check receipts with
  `carapace audit verify`.
- [docs/SELF_HOST.md](docs/SELF_HOST.md): deploy your own on GCP with
  Pulumi, with costs, teardown and known gaps.
- [SECURITY.md](SECURITY.md): reporting vulnerabilities.

## Repository layout

| Path | Purpose |
|---|---|
| `packages/crypto` | Envelope encryption, signing, hashing primitives |
| `enclave/` | Credential-injecting proxy that runs in the TEE |
| `server/` | Untrusted control plane: auth, ciphertext store, API keys, receipts |
| `cli/` | `carapace` CLI and Python SDK |
| `web/` | Web UI, served by the server |
| `infra/pulumi` | One-command self-host on GCP |

## Development

```bash
uv sync --all-packages --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

## License

[Apache-2.0](LICENSE)
