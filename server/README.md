# carapace-server

Control-plane API: accounts, sessions, owner keys, the ciphertext store
and API keys.

The server is **untrusted** by design. It never sees plaintext secrets, holds
no KMS decrypt rights, and is not on the agent-to-enclave data path.

## Run locally

```bash
uv sync --all-packages
export CARAPACE_MODE=dev
uv run --package carapace-server alembic -c server/alembic.ini upgrade head
uv run --package carapace-server uvicorn carapace_server.app:create_app --factory
```

`dev` mode uses a local SQLite file and a random per-process JWT secret.
The default mode is `prod`, which refuses to start unless these are set:

| Variable | Notes |
| --- | --- |
| `CARAPACE_DATABASE_URL` | `postgresql+asyncpg://...` (SQLite rejected) |
| `CARAPACE_PUBLIC_URL` | `https://...`; also the passkey RP origin |
| `CARAPACE_JWT_SECRET` | at least 32 characters |

Behind a reverse proxy, run uvicorn with `--proxy-headers` and
`--forwarded-allow-ips` set to the proxy address so rate limits key on the
real client IP. The app never reads `X-Forwarded-For` itself.

## Design notes

- **Email is stored in plaintext** with a unique index. The old design
  sealed it with KMS, which put KMS on the login path and made uniqueness
  checks awkward. An email address is not a credential, and the server is
  already treated as untrusted, so the confidentiality it bought was small.
- Passwords: bcrypt over base64(sha256(password)) to avoid the 72-byte limit.
- Passkeys: full attestation verification with `py_webauthn`; user
  verification is required on every ceremony (a user-presence-only assertion
  is rejected); login options for unknown accounts return a deterministic
  decoy credential ID.
- Access JWTs carry `jti`, `iss`, `aud`; logout blacklists the `jti` in the
  database. Refresh tokens are single use and rotated atomically. Every
  rotation stays in the family of the login that started it; presenting an
  already-rotated token is treated as theft and revokes the whole family.
  Revoked rows are kept until they expire so that reuse remains detectable.
- No Redis or Celery: rate limiting is in-process (per replica) and expired
  rows are purged by a periodic asyncio task.

## Owner keys, secrets and API keys

Owners sign everything the enclave trusts with an Ed25519 **owner key**
whose seed stays on their device (`docs/design/owner-signing.md`). The
server stores signed objects and checks them as defense in depth; the
enclave repeats every check against the fingerprint in the agent's API key,
so a compromised server or database can deny service or replay older
owner-signed objects, but cannot forge one.

- `/v1/owner-keys` registers, lists and retires public keys. There is no
  proof of possession: a key whose seed you do not hold signs nothing. Keys
  must pass `validate_public_key` (small-order and non-canonical points are
  rejected, 422), are globally unique (409) and are capped at 10 per
  account, retired ones included (409).
- `/v1/secrets` stores owner-signed envelope v1 (`carapace_crypto.envelope`).
  The server parses it with `Envelope.from_dict`, verifies the signature
  with `verify_envelope_signature`, and requires `owner_pk` to be one of the
  caller's registered, non-retired keys (422 otherwise). It also requires
  canonical lowercase UUIDs (so the envelope it rebuilds from its columns is
  byte for byte the signed one), a policy of at most 16 KiB and a wrapped
  key of at most 512 bytes. Reads return the full signed envelope.
- The client picks the secret UUID because it is signed and bound into the
  AAD. The envelope's `secret_id` and `owner_id` must match the URL and the
  caller.
- There is no way to edit a policy on its own. `PATCH` accepts `name` and/or
  a complete new envelope with a strictly higher `version` (409 otherwise;
  the comparison is part of the `UPDATE`, so concurrent uploads cannot both
  win).
- `/v1/api-keys` never generates or sees a raw key. The owner's CLI mints
  `cpk_<fingerprint>_<random>`, signs a grant for it and registers
  `{name, lookup_hash, grant}`. The server stores the lookup hash and the
  grant verbatim, and checks the grant's signature, that it is signed by an
  active key of the caller, that every secret in it is the caller's, and
  that it is not expired or issued in the future (400 otherwise). It cannot
  check `key_bind`; the enclave does, from the raw key.
- `PUT /v1/api-keys/{id}/grant` replaces the grant with one for the same key
  (same `owner_pk` and `key_bind`) and a strictly higher `iat` (409
  otherwise). `POST /v1/api-keys/{id}/revoke` revokes, optionally storing a
  tombstone (a newer grant with no secrets) as the current grant. A
  tombstone may be signed by a retired owner key: the enclave does not know
  about retirement, so the tombstone is what stops the old grant early.
- `api_key_secrets` is an index derived from the stored grant, used for the
  owner's listing. `find_grant(lookup_hash)`, which the enclave API uses,
  returns the current grant of any known key, revoked, expired or out of
  scope included: the enclave decides from the signed grant and can only
  record a tombstone in its monotonic cache if it is served one.

## Known limitations

- Registering an existing email returns 400, which reveals the account
  exists. Closing this requires email verification, which is out of scope.
- In-process rate limits are per replica.
