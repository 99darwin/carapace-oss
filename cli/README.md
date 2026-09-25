# carapace-cli

The `carapace` command and Python SDK. You use it to verify an enclave, seal
secrets to it, issue agent API keys and audit the receipt log.

The server is untrusted. Everything the CLI trusts comes from the enclave's
attestation, which is checked locally, and from your owner key, which never
leaves this machine.

## Quick start

```bash
carapace init                                   # owner key; passphrase prompt
carapace signup --server https://carapace.example.com --email you@example.com
carapace verify --enclave https://enclave.example.com:8443 \
    --allow-digest sha256:...                   # the digest CI printed for the release
printf %s "$TOKEN" | carapace secret add github --host api.github.com
carapace key create my-agent --secret github --output agent.key
carapace request github GET https://api.github.com/user --api-key-file agent.key
carapace audit verify
```

`secret add` reads the value from a hidden prompt, or from stdin when piped.
It never takes the value as an argument, so it cannot end up in argv or
shell history. Use `printf %s`, not `echo`, if the value must not get a
trailing newline (one trailing newline is stripped either way).

From Python:

```python
from carapace_cli import Client

client = Client()  # API key from CARAPACE_API_KEY; pin from the config dir
response = client.request(secret_id, "GET", "https://api.github.com/user")
print(response.status, response.json())
```

## Local state

Everything lives in `$CARAPACE_CONFIG_DIR`, or `$XDG_CONFIG_HOME/carapace`, or
`~/.config/carapace`. The directory is 0700 and every file is 0600.
Files are written atomically (temp file, fsync, rename) and refused on read
if group/other can access them.

| File | Contents |
| --- | --- |
| `owner-key.json` | Ed25519 owner key. Its seed is scrypt + AES-256-GCM encrypted unless you used `init --no-passphrase`. |
| `session.json` | server URL and access/refresh tokens |
| `enclave.json` | the pin: TLS cert, receipt key, boot id, image digest, KMS key, trusted digests |

The owner key is never printed. `owner show` prints only its fingerprint
and file. Losing the key orphans every secret sealed under it, so `init`
refuses to overwrite one.

## What `verify` checks

1. It learns the enclave's certificate with a handshake that sends no data.
   It then fetches `/attestation` over a connection pinned to that
   certificate. The attested `tls_cert_pem` must be the same certificate.
2. The token is RS256 and signed by Google's Confidential Space issuer
   (JWKS via OIDC discovery). The audience must be `carapace-attestation`
   and the token must not be expired. `hwmodel`, `swname`, `dbgstat`,
   `secboot` and the `STABLE` support attribute are checked.
3. The container image digest is in your allowlist (`--allow-digest`).
   With no allowlist it fails.
4. `eat_nonce` is `sha256(TLS SPKI || receipt public key)`, which binds both
   keys to this boot.
5. The server's `/v1/kms/public-key` must equal the attested KMS key and
   version. Otherwise nothing is pinned. `secret add` repeats this check and
   seals only to the pinned key.

All enclave traffic afterwards (`request`, the SDK) uses a TLS context whose
only trust anchor is the pinned certificate. It also compares the peer
certificate byte for byte and ignores proxy environment variables. There is
no `verify=False` path.

### Limits

- **Release signatures are not verified.** The CLI does not read release
  manifests or check cosign/Rekor signatures. `--allow-digest` is the only
  way to name a trusted image, and you must compare that digest with the
  one the release build printed in CI (or that you reproduced) yourself.
- `--insecure-mock --mock-issuer-key PEM` trusts the dev enclave's mock
  issuer. It is labelled loudly, stored in the pin, and accepts **only**
  `mock://local` tokens. It proves nothing about hardware; never use it
  with real secrets. Without it, mock tokens are refused.
- If the enclave reboots, its pinned certificate changes. Run `verify` again.

## API keys

`key create` signs a grant with your owner key. The grant binds the key to
the envelope versions you name, and those versions are checked against your
own signatures first. `key revoke` re-signs a tombstone grant (no secrets)
and asks the server to revoke the key. `key renew` re-signs with a new
expiry. Neither needs the raw API key.

Revocation does not cut access off immediately. A malicious server could
withhold the tombstone until the old grant expires (default TTL 30 days,
`--ttl-days`). If a key leaks, also rotate the secret at the provider.

## Audit

`audit verify` checks receipts offline against the attested boots:

- each boot's token (expiry skipped for past boots);
- `boot_id = sha256(SPKI || receipt key)`;
- each receipt's hash and Ed25519 signature, and that it is attributed to
  your owner key;
- the hash chain, including the genesis `prev_hash`.

Missing sequence numbers are reported as gaps rather than failures. They are
other owners' receipts, or receipts the server withheld. `audit fetch`
saves the pages so they can be checked later with `audit verify --file`.

## Not yet implemented

- A loopback HTTP proxy for agents that cannot use the SDK.
- Release manifests and cosign/Rekor verification of release signatures.
