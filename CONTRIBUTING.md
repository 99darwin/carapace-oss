# Contributing

## Developer Certificate of Origin

All commits must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "feat(enclave): ..."
```

CI rejects pull requests containing commits without a `Signed-off-by` line.

## Conventions

- Conventional commits: `feat:`, `fix:`, `security:`, `docs:`, `chore:`
- Python 3.12+, type hints required, `ruff` (88-char lines)
- Tests are required for business logic. Security-critical paths (envelope
  encryption, the egress executor, attestation, receipts) need explicit
  negative tests.
- Keep PRs focused and under ~500 lines where possible.

## Security invariants

Changes must not violate these:

1. Secrets are decrypted only inside an attested enclave.
2. The server never handles plaintext secrets.
3. The enclave never writes secrets to disk, and never spawns subprocesses.
4. Every secret use produces a signed receipt.
5. Agents never receive raw secret values.
