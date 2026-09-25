# Carapace

Give AI agents access to your secrets without giving them your secrets.

Carapace is a credential-injecting proxy that runs inside a hardware-isolated
enclave (GCP Confidential Space, AMD SEV). Agents ask the enclave to make an
HTTP request on their behalf; the enclave attaches the credential, enforces a
per-secret host allowlist, redacts the secret from the response, and emits a
signed receipt. The agent never sees the raw secret, and neither does the
operator running the service.

> **Status: pre-alpha.** Under active development. Do not use it for real
> secrets yet.

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
