# carapace-crypto

Cryptographic primitives shared by the Carapace CLI, server, and enclave.

- `envelope`: envelope encryption v1. Secrets are sealed client-side to the
  enclave's Cloud KMS RSA public key; the secret id, owner id, owner public
  key, version and injection policy are bound into the AES-GCM authenticated
  data, and the whole stored object is signed by the owner key. See
  [`docs/design/owner-signing.md`](../../docs/design/owner-signing.md).
- `ownerkey`: the owner's Ed25519 key, its fingerprint, and context-separated
  signing over canonical JSON.
- `apikey`: client-minted `cpk_<fingerprint>_<random>` API keys and their
  lookup and bind hashes.
- `grant`: owner-signed grants binding an API key to secrets and version
  floors, with expiry.
- `freshness`: the enclave's per-boot monotonic cache for rollback detection.
- `canonical`: the canonical JSON encoding every signature and AAD is derived
  from. Its module docstring is the normative definition.
- `signing`, `hashing`, `symmetric`, `encoding`: Ed25519, SHA-256/HMAC,
  AES-GCM, and base64/hex helpers. Every decoder is strict.

## Test vectors

`tests/vectors/envelope_v1.json` and `tests/vectors/grant_v1.json` hold
deterministic vectors (fixed owner and attacker seeds, fixed DEK and nonce,
fixed RSA test key) for implementers in other languages, plus `tamper` lists
of objects that must be rejected with the named outcome: substituted or
re-signed envelopes, cross-context signatures, rollback below the version
floor, grants for the wrong key or secret, expired grants, duplicate JSON
keys, and malformed fields. The RSA private key and the owner seeds in those
files are public test material and must never be used for anything else.
Regenerate with:

```bash
uv run python packages/crypto/tests/vectors/generate.py
```
