# carapace-crypto

Cryptographic primitives shared by the Carapace CLI, server, and enclave.

- `envelope`: envelope encryption v1. Secrets are sealed client-side to the
  enclave's Cloud KMS RSA public key; the secret id, owner id, and injection
  policy are bound into the AES-GCM authenticated data. See
  [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md).
- `canonical`: the canonical JSON encoding used to derive that AAD. Its module
  docstring is the normative definition.
- `signing`, `hashing`, `symmetric`, `encoding`: Ed25519, SHA-256/HMAC,
  AES-GCM, and base64/hex helpers.

## Test vectors

`tests/vectors/envelope_v1.json` holds deterministic vectors (fixed DEK and
nonce, fixed RSA test key) for implementers in other languages. The RSA
private key in that file is a public test key and must never be used for
anything else. Regenerate with:

```bash
uv run python packages/crypto/tests/vectors/generate_envelope_v1.py
```
